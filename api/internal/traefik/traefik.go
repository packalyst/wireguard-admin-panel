package traefik

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

// Sentinel middleware names - used throughout the codebase
const (
	MiddlewareSentinelVPN       = "sentinel_vpn"
	MiddlewareSentinelVPNSilent = "sentinel_vpn_silent"
	MiddlewareSentinelDrop      = "sentinel_drop"
	// With @file suffix for router middleware lists
	MiddlewareSentinelVPNFile       = "sentinel_vpn@file"
	MiddlewareSentinelVPNSilentFile = "sentinel_vpn_silent@file"
)

// Service handles Traefik operations
type Service struct {
	traefikAPI    string
	configPath    string
	staticPath    string
	accessLogPath string
}

var instance *Service

// New creates a new Traefik service
func New() *Service {
	configDir := helper.GetEnv("TRAEFIK_CONFIG")
	configPath := configDir + "/core.yml"

	instance = &Service{
		traefikAPI:    helper.GetEnv("TRAEFIK_API"),
		configPath:    configPath,
		staticPath:    helper.GetEnv("TRAEFIK_STATIC"),
		accessLogPath: helper.GetEnv("TRAEFIK_LOGS"),
	}
	return instance
}

// GetService returns the singleton instance
func GetService() *Service {
	return instance
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetOverview":  s.handleOverview,
		"GetConfig":    s.handleGetConfig,
		"UpdateConfig": s.handleUpdateConfig,
		"GetVPNOnly":   s.handleGetVPNOnly,
		"SetVPNOnly":   s.handleSetVPNOnly,
	}
}

func (s *Service) fetchTraefikAPI(path string) (map[string]interface{}, error) {
	resp, err := http.Get(s.traefikAPI + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

func (s *Service) fetchTraefikAPIArray(path string) ([]interface{}, error) {
	resp, err := http.Get(s.traefikAPI + path)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result []interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// handleOverview fetches overview, routers, services, and middlewares in parallel
func (s *Service) handleOverview(w http.ResponseWriter, r *http.Request) {
	type result struct {
		data interface{}
		err  error
	}

	// Fetch all endpoints in parallel
	overviewCh := make(chan result, 1)
	routersCh := make(chan result, 1)
	servicesCh := make(chan result, 1)
	middlewaresCh := make(chan result, 1)

	go func() {
		data, err := s.fetchTraefikAPI("/overview")
		overviewCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchTraefikAPIArray("/http/routers")
		routersCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchTraefikAPIArray("/http/services")
		servicesCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchTraefikAPIArray("/http/middlewares")
		middlewaresCh <- result{data, err}
	}()

	// Collect results
	overview := <-overviewCh
	routers := <-routersCh
	services := <-servicesCh
	middlewares := <-middlewaresCh

	// Check for errors on overview (required)
	if overview.err != nil {
		router.JSONError(w, overview.err.Error(), http.StatusBadGateway)
		return
	}

	// Build combined response (use empty arrays for failed fetches)
	response := map[string]interface{}{
		"overview": overview.data,
	}

	if routers.err == nil {
		response["routers"] = routers.data
	} else {
		response["routers"] = []interface{}{}
	}

	if services.err == nil {
		response["services"] = services.data
	} else {
		response["services"] = []interface{}{}
	}

	if middlewares.err == nil {
		response["middlewares"] = middlewares.data
	} else {
		response["middlewares"] = []interface{}{}
	}

	router.JSON(w, response)
}

// TraefikConfig holds traefik configuration
type TraefikConfig struct {
	RateLimitAverage  int      `json:"rateLimitAverage"`
	RateLimitBurst    int      `json:"rateLimitBurst"`
	StrictRateAverage int      `json:"strictRateAverage"`
	StrictRateBurst   int      `json:"strictRateBurst"`
	SecurityHeaders   bool     `json:"securityHeaders"`
	IPAllowlist       []string `json:"ipAllowlist"`
	IPAllowEnabled    bool     `json:"ipAllowEnabled"`
	DashboardEnabled  bool     `json:"dashboardEnabled"`
}

// GetConfig returns current traefik configuration
func (s *Service) GetConfig() *TraefikConfig {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return nil
	}

	content := string(data)
	config := &TraefikConfig{
		RateLimitAverage:  extractInt(content, "rate-limit:", "average:", 100),
		RateLimitBurst:    extractInt(content, "rate-limit:", "burst:", 200),
		StrictRateAverage: extractInt(content, "rate-limit-strict:", "average:", 10),
		StrictRateBurst:   extractInt(content, "rate-limit-strict:", "burst:", 20),
		SecurityHeaders:   strings.Contains(content, "security-headers:"),
		IPAllowlist:       extractIPList(content),
		IPAllowEnabled:    strings.Contains(content, MiddlewareSentinelVPN+":"),
		DashboardEnabled:  true,
	}

	if s.staticPath != "" {
		if staticData, err := os.ReadFile(s.staticPath); err == nil {
			staticContent := string(staticData)
			config.DashboardEnabled = helper.ExtractYAMLBool(staticContent, "dashboard:", true)
		}
	}

	return config
}

func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	config := s.GetConfig()
	if config == nil {
		router.JSONError(w, "Failed to read config", http.StatusInternalServerError)
		return
	}
	router.JSON(w, config)
}

func (s *Service) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	var config struct {
		RateLimitAverage int      `json:"rateLimitAverage"`
		RateLimitBurst   int      `json:"rateLimitBurst"`
		StrictRateAvg    int      `json:"strictRateAverage"`
		StrictRateBurst  int      `json:"strictRateBurst"`
		SecurityHeaders  bool     `json:"securityHeaders"`
		IPAllowlist      []string `json:"ipAllowlist"`
		IPAllowEnabled   bool     `json:"ipAllowEnabled"`
		DashboardEnabled *bool    `json:"dashboardEnabled,omitempty"`
	}
	if !router.DecodeJSONOrError(w, r, &config) {
		return
	}

	data, err := os.ReadFile(s.configPath)
	if err != nil {
		router.JSONError(w, "Failed to read config", http.StatusInternalServerError)
		return
	}

	content := string(data)
	content = updateMiddlewareValue(content, "rate-limit:", "average:", config.RateLimitAverage)
	content = updateMiddlewareValue(content, "rate-limit:", "burst:", config.RateLimitBurst)
	content = updateMiddlewareValue(content, "rate-limit-strict:", "average:", config.StrictRateAvg)
	content = updateMiddlewareValue(content, "rate-limit-strict:", "burst:", config.StrictRateBurst)
	content = updateIPAllowlist(content, config.IPAllowlist)

	if err := os.WriteFile(s.configPath, []byte(content), 0644); err != nil {
		router.JSONError(w, "Failed to write config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update static config for dashboard if provided
	restartRequired := false
	if config.DashboardEnabled != nil && s.staticPath != "" {
		if staticData, err := os.ReadFile(s.staticPath); err == nil {
			staticContent := string(staticData)
			newStaticContent := helper.UpdateYAMLBool(staticContent, "dashboard:", *config.DashboardEnabled)
			if newStaticContent != staticContent {
				if err := os.WriteFile(s.staticPath, []byte(newStaticContent), 0644); err != nil {
					log.Printf("Failed to update static config: %v", err)
				} else {
					restartRequired = true
				}
			}
		}
		// Update dashboard entrypoint address
		if err := updateTraefikDashboardAddress(s.staticPath, *config.DashboardEnabled); err != nil {
			log.Printf("Warning: Failed to update Traefik dashboard address: %v", err)
		} else {
			restartRequired = true
		}
	}

	log.Printf("Traefik config updated")
	router.JSON(w, map[string]interface{}{
		"status":          "updated",
		"restartRequired": restartRequired,
	})
}

// updateTraefikDashboardAddress updates the traefik entrypoint address in traefik.yml
// enabled=true: 0.0.0.0:port (accessible externally)
// enabled=false: container_ip:port (internal only, accessible via docker network)
func updateTraefikDashboardAddress(configPath string, enabled bool) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	content := string(data)
	port := os.Getenv("TRAEFIK_PORT")
	if port == "" {
		return fmt.Errorf("TRAEFIK_PORT environment variable not set")
	}

	containerIP := os.Getenv("TRAEFIK_CONTAINER_IP")
	if containerIP == "" {
		containerIP = "172.18.0.2" // fallback
	}

	// Replace the traefik entrypoint address
	if enabled {
		// Enable: bind to 0.0.0.0:port (public)
		content = strings.ReplaceAll(content, `address: "`+containerIP+`:`+port+`"`, `address: ":`+port+`"`)
	} else {
		// Disable: bind to container IP only (accessible from API via docker network)
		content = strings.ReplaceAll(content, `address: ":`+port+`"`, `address: "`+containerIP+`:`+port+`"`)
	}

	return os.WriteFile(configPath, []byte(content), 0644)
}

// Helper functions
func extractInt(content, section, key string, defaultVal int) int {
	idx := strings.Index(content, section)
	if idx == -1 {
		return defaultVal
	}

	subContent := content[idx:]
	keyIdx := strings.Index(subContent, key)
	if keyIdx == -1 || keyIdx > 200 {
		return defaultVal
	}

	line := subContent[keyIdx:]
	endIdx := strings.Index(line, "\n")
	if endIdx == -1 {
		endIdx = len(line)
	}

	parts := strings.Split(line[:endIdx], ":")
	if len(parts) < 2 {
		return defaultVal
	}

	val, err := strconv.Atoi(strings.TrimSpace(parts[1]))
	if err != nil {
		return defaultVal
	}
	return val
}

func extractIPList(content string) []string {
	var ips []string
	idx := strings.Index(content, MiddlewareSentinelVPN+":")
	if idx == -1 {
		return ips
	}

	subContent := content[idx:]
	rangeIdx := strings.Index(subContent, "sourceRange:")
	if rangeIdx == -1 {
		return ips
	}

	lines := strings.Split(subContent[rangeIdx:], "\n")
	for _, line := range lines[1:] {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "-") {
			break
		}
		ip := strings.TrimPrefix(line, "-")
		ip = strings.TrimSpace(ip)
		ip = strings.Trim(ip, "\"'")
		if commentIdx := strings.Index(ip, "#"); commentIdx != -1 {
			ip = strings.TrimSpace(ip[:commentIdx])
			ip = strings.Trim(ip, "\"'")
		}
		if ip != "" {
			ips = append(ips, ip)
		}
	}
	return ips
}

func updateMiddlewareValue(content, section, key string, value int) string {
	idx := strings.Index(content, section)
	if idx == -1 {
		return content
	}

	subContent := content[idx:]
	keyIdx := strings.Index(subContent, key)
	if keyIdx == -1 || keyIdx > 200 {
		return content
	}

	absoluteIdx := idx + keyIdx
	lineEnd := strings.Index(content[absoluteIdx:], "\n")
	if lineEnd == -1 {
		lineEnd = len(content) - absoluteIdx
	}

	oldLine := content[absoluteIdx : absoluteIdx+lineEnd]
	colonIdx := strings.Index(oldLine, ":")
	if colonIdx == -1 {
		return content
	}

	newLine := oldLine[:colonIdx+1] + " " + fmt.Sprintf("%d", value)
	return content[:absoluteIdx] + newLine + content[absoluteIdx+lineEnd:]
}

func updateIPAllowlist(content string, ips []string) string {
	// Update both sentinel_vpn and sentinel_vpn_silent middlewares
	middlewares := []string{MiddlewareSentinelVPN + ":", MiddlewareSentinelVPNSilent + ":"}

	for _, middleware := range middlewares {
		content = updateMiddlewareSourceRange(content, middleware, ips)
	}

	return content
}

func updateMiddlewareSourceRange(content, middlewareName string, ips []string) string {
	idx := strings.Index(content, middlewareName)
	if idx == -1 {
		return content
	}

	// Find sourceRange within this middleware section (limit search to avoid crossing into other sections)
	searchArea := content[idx:]
	if len(searchArea) > 500 {
		searchArea = searchArea[:500]
	}

	rangeIdx := strings.Index(searchArea, "sourceRange:")
	if rangeIdx == -1 {
		return content
	}

	absoluteIdx := idx + rangeIdx
	endIdx := absoluteIdx
	lines := strings.Split(content[absoluteIdx:], "\n")
	lineCount := 1
	for i, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "-") && !strings.HasPrefix(trimmed, "#") {
			break
		}
		lineCount = i + 2
	}

	var newSection strings.Builder
	newSection.WriteString("sourceRange:")
	for _, ip := range ips {
		newSection.WriteString("\n          - \"" + ip + "\"")
	}

	for i := 0; i < lineCount; i++ {
		nlIdx := strings.Index(content[endIdx:], "\n")
		if nlIdx == -1 {
			break
		}
		endIdx += nlIdx + 1
	}

	return content[:absoluteIdx] + newSection.String() + "\n" + content[endIdx:]
}

// middlewareExists checks if a middleware is defined in the config
func middlewareExists(content, middlewareName string) bool {
	// Look for middleware definition under "middlewares:" section
	idx := strings.Index(content, "middlewares:")
	if idx == -1 {
		return false
	}
	// Check if middleware name exists as a key (with colon after it)
	return strings.Contains(content[idx:], middlewareName+":")
}

// routerHasMiddleware checks if a router has a specific middleware
func routerHasMiddleware(content, routerName, middlewareName string) bool {
	// Find the router section
	routerKey := routerName + ":"
	idx := strings.Index(content, routerKey)
	if idx == -1 {
		return false
	}

	// Find the end of this router section (next router or services/middlewares section)
	routerSection := content[idx:]
	endIdx := len(routerSection)

	// Look for next section at same indentation level
	lines := strings.Split(routerSection, "\n")
	for i, line := range lines[1:] {
		// If line starts with non-space and contains ":", it's a new section
		if len(line) > 0 && line[0] != ' ' && line[0] != '\t' && strings.Contains(line, ":") {
			endIdx = strings.Index(routerSection, "\n"+line)
			break
		}
		// If line has same indentation as router name (4 spaces for routers), it's a new router
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") && strings.Contains(line, ":") && i > 0 {
			endIdx = strings.Index(routerSection, "\n"+line)
			break
		}
	}

	if endIdx == -1 {
		endIdx = len(routerSection)
	}

	routerContent := routerSection[:endIdx]

	// Check if middlewares section exists and contains the middleware
	if !strings.Contains(routerContent, "middlewares:") {
		return false
	}

	return strings.Contains(routerContent, "- "+middlewareName)
}

// addMiddlewareToRouter adds a middleware to a router's middleware list
func (s *Service) addMiddlewareToRouter(routerName, middlewareName string) error {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	content := string(data)

	// Check if middleware exists
	if !middlewareExists(content, middlewareName) {
		return fmt.Errorf("middleware '%s' does not exist", middlewareName)
	}

	// Check if router already has middleware
	if routerHasMiddleware(content, routerName, middlewareName) {
		return nil // Already has it
	}

	// Find the router section
	routerKey := "    " + routerName + ":"
	idx := strings.Index(content, routerKey)
	if idx == -1 {
		return fmt.Errorf("router '%s' not found", routerName)
	}

	// Find end of router section
	routerStart := idx
	routerSection := content[idx:]
	lines := strings.Split(routerSection, "\n")

	// Check if router has middlewares section
	hasMiddlewares := false
	middlewaresLineIdx := -1
	entryPointsLineIdx := -1

	for i, line := range lines[1:] {
		trimmed := strings.TrimSpace(line)
		// Check for new router (4 spaces indentation)
		if strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "      ") && strings.HasSuffix(trimmed, ":") && i > 0 {
			break
		}
		// Check for new top-level section
		if len(line) > 0 && line[0] != ' ' && strings.Contains(line, ":") {
			break
		}
		if trimmed == "middlewares:" {
			hasMiddlewares = true
			middlewaresLineIdx = i + 1
		}
		if trimmed == "entryPoints:" {
			entryPointsLineIdx = i + 1
		}
	}

	var newContent string
	if hasMiddlewares {
		// Add to existing middlewares list
		insertIdx := routerStart
		for i := 0; i <= middlewaresLineIdx; i++ {
			nlIdx := strings.Index(content[insertIdx:], "\n")
			if nlIdx == -1 {
				break
			}
			insertIdx += nlIdx + 1
		}
		newContent = content[:insertIdx] + "        - " + middlewareName + "\n" + content[insertIdx:]
	} else {
		// Add middlewares section before entryPoints
		if entryPointsLineIdx == -1 {
			return fmt.Errorf("router '%s' has no entryPoints section", routerName)
		}
		insertIdx := routerStart
		for i := 0; i < entryPointsLineIdx; i++ {
			nlIdx := strings.Index(content[insertIdx:], "\n")
			if nlIdx == -1 {
				break
			}
			insertIdx += nlIdx + 1
		}
		newContent = content[:insertIdx] + "      middlewares:\n        - " + middlewareName + "\n" + content[insertIdx:]
	}

	if err := os.WriteFile(s.configPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	log.Printf("Added middleware '%s' to router '%s'", middlewareName, routerName)
	return nil
}

// removeMiddlewareFromRouter removes a middleware from a router's middleware list
func (s *Service) removeMiddlewareFromRouter(routerName, middlewareName string) error {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return fmt.Errorf("failed to read config: %w", err)
	}

	content := string(data)

	// Check if router has middleware
	if !routerHasMiddleware(content, routerName, middlewareName) {
		return nil // Doesn't have it
	}

	// Find and remove the middleware line
	routerKey := "    " + routerName + ":"
	idx := strings.Index(content, routerKey)
	if idx == -1 {
		return fmt.Errorf("router '%s' not found", routerName)
	}

	// Find the middleware line within this router section
	routerSection := content[idx:]
	middlewareLine := "        - " + middlewareName
	mwIdx := strings.Index(routerSection, middlewareLine)
	if mwIdx == -1 {
		return nil
	}

	absoluteIdx := idx + mwIdx
	lineEnd := strings.Index(content[absoluteIdx:], "\n")
	if lineEnd == -1 {
		lineEnd = len(content) - absoluteIdx
	}

	// Remove the line (including newline)
	newContent := content[:absoluteIdx] + content[absoluteIdx+lineEnd+1:]

	// Check if middlewares section is now empty and remove it
	if !strings.Contains(newContent[idx:idx+500], "        - ") {
		// Find and remove empty middlewares section
		mwSectionIdx := strings.Index(newContent[idx:], "      middlewares:\n")
		if mwSectionIdx != -1 {
			absIdx := idx + mwSectionIdx
			lineLen := len("      middlewares:\n")
			newContent = newContent[:absIdx] + newContent[absIdx+lineLen:]
		}
	}

	if err := os.WriteFile(s.configPath, []byte(newContent), 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	log.Printf("Removed middleware '%s' from router '%s'", middlewareName, routerName)
	return nil
}

// GetVPNOnlyMode returns the current VPN-only mode ("off", "403", or "silent")
func (s *Service) GetVPNOnlyMode() string {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		return "off"
	}

	content := string(data)
	if routerHasMiddleware(content, "ui", MiddlewareSentinelVPNSilent) {
		return "silent"
	} else if routerHasMiddleware(content, "ui", MiddlewareSentinelVPN) {
		return "403"
	}
	return "off"
}

// handleGetVPNOnly returns VPN-only mode status for the UI
func (s *Service) handleGetVPNOnly(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"mode": s.GetVPNOnlyMode()})
}

// handleSetVPNOnly sets VPN-only mode for the UI
// mode: "off", "403", or "silent"
func (s *Service) handleSetVPNOnly(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Mode string `json:"mode"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate mode
	if req.Mode != "off" && req.Mode != "403" && req.Mode != "silent" {
		router.JSONError(w, "invalid mode: must be 'off', '403', or 'silent'", http.StatusBadRequest)
		return
	}

	// Routers to update (HTTP and HTTPS)
	routers := []string{"ui", "ui-secure"}

	// Remove both middlewares from all routers first
	for _, rtr := range routers {
		s.removeMiddlewareFromRouter(rtr, MiddlewareSentinelVPN)
		s.removeMiddlewareFromRouter(rtr, MiddlewareSentinelVPNSilent)
	}

	// Add the appropriate middleware to all routers
	var err error
	for _, routerName := range routers {
		switch req.Mode {
		case "403":
			err = s.addMiddlewareToRouter(routerName, MiddlewareSentinelVPN)
		case "silent":
			err = s.addMiddlewareToRouter(routerName, MiddlewareSentinelVPNSilent)
		}
		if err != nil {
			// Log but continue - router may not exist (e.g., SSL not enabled)
			log.Printf("Warning: could not update router %s: %v", routerName, err)
			err = nil // Reset error so we continue
		}
	}

	router.JSON(w, map[string]string{"mode": req.Mode})
}

// escapeYAMLString escapes a string for safe YAML output
func escapeYAMLString(s string) string {
	// Replace backslashes first, then other special chars
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return s
}

// SentinelConfig represents per-domain sentinel middleware configuration
type SentinelConfig struct {
	Enabled   bool   `json:"enabled"`
	ErrorMode string `json:"errorMode,omitempty"` // "403", "404", "503", "silent"
	IPFilter  struct {
		SourceRange []string `json:"sourceRange,omitempty"`
	} `json:"ipFilter,omitempty"`
	Maintenance *struct {
		Enabled bool   `json:"enabled"`
		Message string `json:"message,omitempty"`
	} `json:"maintenance,omitempty"`
	TimeAccess *struct {
		Enabled    bool     `json:"enabled,omitempty"`
		Timezone   string   `json:"timezone,omitempty"`
		Days       []string `json:"days,omitempty"`       // mon, tue, wed, thu, fri, sat, sun
		AllowRange string   `json:"allowRange,omitempty"` // "HH:MM-HH:MM"
		DenyRange  string   `json:"denyRange,omitempty"`  // "HH:MM-HH:MM"
	} `json:"timeAccess,omitempty"`
	Headers []struct {
		Name      string   `json:"name"`
		Values    []string `json:"values,omitempty"`
		MatchType string   `json:"matchType,omitempty"` // "one", "all", "none"
		Regex     string   `json:"regex,omitempty"`
		Required  bool     `json:"required,omitempty"`
		Contains  bool     `json:"contains,omitempty"`
	} `json:"headers,omitempty"`
	UserAgents *struct {
		Enabled bool     `json:"enabled,omitempty"`
		Block   []string `json:"block,omitempty"`
		Allow   []string `json:"allow,omitempty"`
	} `json:"userAgents,omitempty"`
}

// DomainRouteConfig represents a domain route for Traefik config generation
type DomainRouteConfig struct {
	Domain         string
	TargetIP       string
	TargetPort     int
	HTTPSBackend   bool
	Middlewares    []string
	AccessMode     string          // "vpn" or "public"
	FrontendSSL    bool            // use websecure entrypoint with TLS
	SentinelConfig *SentinelConfig // per-domain sentinel middleware config
}

// GenerateDomainRoutes writes domain routes to Traefik's dynamic config directory
func GenerateDomainRoutes(configDir string, routes []DomainRouteConfig) error {
	var sb strings.Builder

	sb.WriteString("# Domain Routes - Auto-generated, do not edit manually\n")
	sb.WriteString("# Generated at: " + time.Now().Format(time.RFC3339) + "\n\n")

	if len(routes) == 0 {
		sb.WriteString("# No routes configured\n")
	} else {
		sb.WriteString("http:\n")
		sb.WriteString("  routers:\n")

		// Track routes that need per-domain middlewares
		var sentinelMiddlewares []struct {
			name   string
			config *SentinelConfig
		}

		for _, route := range routes {
			name := helper.SanitizeDomainName(route.Domain)

			// Build middlewares list
			middlewares := make([]string, len(route.Middlewares))
			copy(middlewares, route.Middlewares)

			// Add per-domain sentinel config middleware if configured and enabled
			if route.SentinelConfig != nil && route.SentinelConfig.Enabled {
				mwName := fmt.Sprintf("sentinel_domain-%s", name)
				middlewares = append([]string{mwName}, middlewares...) // prepend
				sentinelMiddlewares = append(sentinelMiddlewares, struct {
					name   string
					config *SentinelConfig
				}{mwName, route.SentinelConfig})
			}

			// HTTP router (web entrypoint) - always created
			sb.WriteString(fmt.Sprintf("    domain-%s:\n", name))
			sb.WriteString(fmt.Sprintf("      rule: \"Host(`%s`)\"\n", route.Domain))
			sb.WriteString(fmt.Sprintf("      service: domain-%s-svc\n", name))
			sb.WriteString("      priority: 50\n")
			sb.WriteString("      entryPoints:\n")
			sb.WriteString("        - web\n")
			if len(middlewares) > 0 {
				sb.WriteString("      middlewares:\n")
				for _, mw := range middlewares {
					sb.WriteString(fmt.Sprintf("        - %s\n", mw))
				}
			}
			sb.WriteString("\n")

			// HTTPS router (websecure entrypoint) - only if FrontendSSL is enabled
			if route.FrontendSSL {
				sb.WriteString(fmt.Sprintf("    domain-%s-secure:\n", name))
				sb.WriteString(fmt.Sprintf("      rule: \"Host(`%s`)\"\n", route.Domain))
				sb.WriteString(fmt.Sprintf("      service: domain-%s-svc\n", name))
				sb.WriteString("      priority: 50\n")
				sb.WriteString("      entryPoints:\n")
				sb.WriteString("        - websecure\n")
				if len(middlewares) > 0 {
					sb.WriteString("      middlewares:\n")
					for _, mw := range middlewares {
						sb.WriteString(fmt.Sprintf("        - %s\n", mw))
					}
				}
				// TLS configuration based on access mode
				if route.AccessMode == "public" {
					// Public mode: use Let's Encrypt
					sb.WriteString("      tls:\n")
					sb.WriteString("        certResolver: letsencrypt\n")
					sb.WriteString("        domains:\n")
					sb.WriteString(fmt.Sprintf("          - main: \"%s\"\n", route.Domain))
				} else {
					// VPN mode: use default/self-signed cert
					sb.WriteString("      tls: {}\n")
				}
				sb.WriteString("\n")
			}
		}

		sb.WriteString("  services:\n")
		for _, route := range routes {
			name := helper.SanitizeDomainName(route.Domain)
			protocol := "http"
			if route.HTTPSBackend {
				protocol = "https"
			}
			sb.WriteString(fmt.Sprintf("    domain-%s-svc:\n", name))
			sb.WriteString("      loadBalancer:\n")
			sb.WriteString("        servers:\n")
			sb.WriteString(fmt.Sprintf("          - url: \"%s://%s:%d\"\n", protocol, route.TargetIP, route.TargetPort))
			sb.WriteString("\n")
		}

		// Generate per-domain sentinel middlewares
		if len(sentinelMiddlewares) > 0 {
			sb.WriteString("  middlewares:\n")
			for _, mw := range sentinelMiddlewares {
				sb.WriteString(fmt.Sprintf("    %s:\n", mw.name))
				sb.WriteString("      plugin:\n")
				sb.WriteString("        sentinel:\n")

				// IP Filter
				if len(mw.config.IPFilter.SourceRange) > 0 {
					sb.WriteString("          ipFilter:\n")
					sb.WriteString("            sourceRange:\n")
					for _, ip := range mw.config.IPFilter.SourceRange {
						sb.WriteString(fmt.Sprintf("              - \"%s\"\n", escapeYAMLString(ip)))
					}
				}

				// Error Mode (whitelist valid values)
				errorMode := mw.config.ErrorMode
				switch errorMode {
				case "403", "404", "503", "silent":
					// valid
				default:
					errorMode = "403"
				}
				sb.WriteString(fmt.Sprintf("          errorMode: \"%s\"\n", errorMode))

				// Maintenance Mode
				if mw.config.Maintenance != nil && mw.config.Maintenance.Enabled {
					sb.WriteString("          maintenance:\n")
					sb.WriteString("            enabled: true\n")
					if mw.config.Maintenance.Message != "" {
						sb.WriteString(fmt.Sprintf("            message: \"%s\"\n", escapeYAMLString(mw.config.Maintenance.Message)))
					}
				}

				// Time Access
				if mw.config.TimeAccess != nil && (len(mw.config.TimeAccess.Days) > 0 || mw.config.TimeAccess.AllowRange != "" || mw.config.TimeAccess.DenyRange != "") {
					sb.WriteString("          timeAccess:\n")
					sb.WriteString("            enabled: true\n")
					if mw.config.TimeAccess.Timezone != "" {
						sb.WriteString(fmt.Sprintf("            timezone: \"%s\"\n", escapeYAMLString(mw.config.TimeAccess.Timezone)))
					}
					if len(mw.config.TimeAccess.Days) > 0 {
						sb.WriteString("            days:\n")
						for _, day := range mw.config.TimeAccess.Days {
							sb.WriteString(fmt.Sprintf("              - \"%s\"\n", escapeYAMLString(day)))
						}
					}
					if mw.config.TimeAccess.AllowRange != "" {
						sb.WriteString(fmt.Sprintf("            allowRange: \"%s\"\n", escapeYAMLString(mw.config.TimeAccess.AllowRange)))
					}
					if mw.config.TimeAccess.DenyRange != "" {
						sb.WriteString(fmt.Sprintf("            denyRange: \"%s\"\n", escapeYAMLString(mw.config.TimeAccess.DenyRange)))
					}
				}

				// Headers
				if len(mw.config.Headers) > 0 {
					sb.WriteString("          headers:\n")
					for _, h := range mw.config.Headers {
						sb.WriteString(fmt.Sprintf("            - name: \"%s\"\n", escapeYAMLString(h.Name)))
						if len(h.Values) > 0 {
							sb.WriteString("              values:\n")
							for _, v := range h.Values {
								sb.WriteString(fmt.Sprintf("                - \"%s\"\n", escapeYAMLString(v)))
							}
						}
						if h.MatchType != "" {
							matchType := h.MatchType
							switch matchType {
							case "one", "all", "none":
								// valid
							default:
								matchType = "one"
							}
							sb.WriteString(fmt.Sprintf("              matchType: \"%s\"\n", matchType))
						}
						if h.Regex != "" {
							sb.WriteString(fmt.Sprintf("              regex: \"%s\"\n", escapeYAMLString(h.Regex)))
						}
						if h.Required {
							sb.WriteString("              required: true\n")
						}
						if h.Contains {
							sb.WriteString("              contains: true\n")
						}
					}
				}

				// User Agents
				if mw.config.UserAgents != nil && (len(mw.config.UserAgents.Block) > 0 || len(mw.config.UserAgents.Allow) > 0) {
					sb.WriteString("          userAgents:\n")
					sb.WriteString("            enabled: true\n")
					if len(mw.config.UserAgents.Block) > 0 {
						sb.WriteString("            block:\n")
						for _, ua := range mw.config.UserAgents.Block {
							sb.WriteString(fmt.Sprintf("              - \"%s\"\n", escapeYAMLString(ua)))
						}
					}
					if len(mw.config.UserAgents.Allow) > 0 {
						sb.WriteString("            allow:\n")
						for _, ua := range mw.config.UserAgents.Allow {
							sb.WriteString(fmt.Sprintf("              - \"%s\"\n", escapeYAMLString(ua)))
						}
					}
				}

				sb.WriteString("\n")
			}
		}
	}

	// Write to domains.yml
	configPath := configDir + "/domains.yml"
	if err := os.WriteFile(configPath, []byte(sb.String()), 0644); err != nil {
		return fmt.Errorf("failed to write config: %v", err)
	}

	log.Printf("Generated Traefik domain routes config with %d routes", len(routes))
	return nil
}

// CertificateInfo holds certificate data parsed from acme.json
type CertificateInfo struct {
	Domain    string    `json:"domain"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	Issuer    string    `json:"issuer"`
	Status    string    `json:"status"`   // "valid", "warning", "critical", "expired"
	DaysLeft  int       `json:"daysLeft"`
}

// acmeStorage represents the structure of acme.json
type acmeStorage struct {
	Letsencrypt struct {
		Account struct {
			Email string `json:"Email"`
		} `json:"Account"`
		Certificates []struct {
			Domain struct {
				Main string   `json:"main"`
				SANs []string `json:"sans"`
			} `json:"domain"`
			Certificate string `json:"certificate"`
			Key         string `json:"key"`
		} `json:"Certificates"`
	} `json:"letsencrypt"`
}

// GetCertificates parses acme.json and returns certificate info
func GetCertificates() ([]CertificateInfo, error) {
	acmePath := helper.GetEnvOptional("TRAEFIK_ACME", "/traefik/acme.json")

	data, err := os.ReadFile(acmePath)
	if err != nil {
		if os.IsNotExist(err) {
			return []CertificateInfo{}, nil // No certificates yet
		}
		return nil, fmt.Errorf("failed to read acme.json: %v", err)
	}

	if len(data) == 0 {
		return []CertificateInfo{}, nil
	}

	var storage acmeStorage
	if err := json.Unmarshal(data, &storage); err != nil {
		return nil, fmt.Errorf("failed to parse acme.json: %v", err)
	}

	certs := []CertificateInfo{}
	now := time.Now()

	for _, cert := range storage.Letsencrypt.Certificates {
		// Decode certificate to get expiration
		certPEM, err := base64.StdEncoding.DecodeString(cert.Certificate)
		if err != nil {
			log.Printf("Warning: failed to decode certificate for %s: %v", cert.Domain.Main, err)
			continue
		}

		block, _ := pem.Decode(certPEM)
		if block == nil {
			log.Printf("Warning: failed to decode PEM block for %s", cert.Domain.Main)
			continue
		}

		x509Cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Printf("Warning: failed to parse certificate for %s: %v", cert.Domain.Main, err)
			continue
		}

		daysLeft := int(x509Cert.NotAfter.Sub(now).Hours() / 24)
		status := "valid"
		if daysLeft <= 0 {
			status = "expired"
		} else if daysLeft <= 7 {
			status = "critical"
		} else if daysLeft <= 30 {
			status = "warning"
		}

		certs = append(certs, CertificateInfo{
			Domain:    cert.Domain.Main,
			NotBefore: x509Cert.NotBefore,
			NotAfter:  x509Cert.NotAfter,
			Issuer:    x509Cert.Issuer.CommonName,
			Status:    status,
			DaysLeft:  daysLeft,
		})
	}

	return certs, nil
}
