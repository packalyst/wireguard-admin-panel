package traefik

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"api/internal/helper"
	"api/internal/router"
)

// Service handles Traefik operations
type Service struct {
	traefikAPI    string
	configPath    string
	staticPath    string
	accessLogPath string
}

// New creates a new Traefik service
func New() *Service {
	return &Service{
		traefikAPI:    helper.GetEnv("TRAEFIK_API"),
		configPath:    helper.GetEnv("TRAEFIK_CONFIG"),
		staticPath:    helper.GetEnv("TRAEFIK_STATIC"),
		accessLogPath: helper.GetEnv("TRAEFIK_LOGS"),
	}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetOverview":  s.handleOverview,
		"GetConfig":    s.handleGetConfig,
		"UpdateConfig": s.handleUpdateConfig,
		"GetLogs":      s.handleLogs,
		"GetVPNOnly":   s.handleGetVPNOnly,
		"SetVPNOnly":   s.handleSetVPNOnly,
		"Health":       s.handleHealth,
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

func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		router.JSONError(w, "Failed to read config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	content := string(data)
	config := map[string]interface{}{
		"rateLimitAverage":  extractInt(content, "rate-limit:", "average:", 100),
		"rateLimitBurst":    extractInt(content, "rate-limit:", "burst:", 200),
		"strictRateAverage": extractInt(content, "rate-limit-strict:", "average:", 10),
		"strictRateBurst":   extractInt(content, "rate-limit-strict:", "burst:", 20),
		"securityHeaders":   strings.Contains(content, "security-headers:"),
		"ipAllowlist":       extractIPList(content),
		"ipAllowEnabled":    strings.Contains(content, "vpn-only:"),
	}

	// Read static config for dashboard setting
	if s.staticPath != "" {
		if staticData, err := os.ReadFile(s.staticPath); err == nil {
			staticContent := string(staticData)
			config["dashboardEnabled"] = helper.ExtractYAMLBool(staticContent, "dashboard:", true)
		}
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

func (s *Service) handleLogs(w http.ResponseWriter, r *http.Request) {
	p := router.ParsePagination(r, 100)
	limit := p.Limit

	file, err := os.Open(s.accessLogPath)
	if err != nil {
		router.JSON(w, []map[string]interface{}{})
		return
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
		if len(lines) > limit*2 {
			lines = lines[len(lines)-limit:]
		}
	}

	if len(lines) > limit {
		lines = lines[len(lines)-limit:]
	}

	var logs []map[string]interface{}
	for i := len(lines) - 1; i >= 0 && len(logs) < limit; i-- {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		var entry map[string]interface{}
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			continue
		}

		logs = append(logs, map[string]interface{}{
			"time":      entry["time"],
			"method":    entry["RequestMethod"],
			"path":      entry["RequestPath"],
			"status":    entry["DownstreamStatus"],
			"duration":  entry["Duration"],
			"clientIP":  entry["ClientHost"],
			"router":    entry["RouterName"],
			"service":   entry["ServiceName"],
			"userAgent": entry["request_User-Agent"],
		})
	}

	router.JSON(w, logs)
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"status": "ok"})
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
	idx := strings.Index(content, "vpn-only:")
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
	// Update both vpn-only and vpn-only-silent middlewares
	middlewares := []string{"vpn-only:", "vpn-only-silent:"}

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

// handleGetVPNOnly returns VPN-only mode status for the UI
// mode: "off", "403", or "silent"
func (s *Service) handleGetVPNOnly(w http.ResponseWriter, r *http.Request) {
	data, err := os.ReadFile(s.configPath)
	if err != nil {
		router.JSONError(w, "failed to read config", http.StatusInternalServerError)
		return
	}

	content := string(data)
	mode := "off"
	if routerHasMiddleware(content, "ui", "vpn-only-silent") {
		mode = "silent"
	} else if routerHasMiddleware(content, "ui", "vpn-only") {
		mode = "403"
	}

	router.JSON(w, map[string]string{"mode": mode})
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
	for _, router := range routers {
		s.removeMiddlewareFromRouter(router, "vpn-only")
		s.removeMiddlewareFromRouter(router, "vpn-only-silent")
	}

	// Add the appropriate middleware to all routers
	var err error
	for _, routerName := range routers {
		switch req.Mode {
		case "403":
			err = s.addMiddlewareToRouter(routerName, "vpn-only")
		case "silent":
			err = s.addMiddlewareToRouter(routerName, "vpn-only-silent")
		}
		if err != nil {
			// Log but continue - router may not exist (e.g., SSL not enabled)
			log.Printf("Warning: could not update router %s: %v", routerName, err)
			err = nil // Reset error so we continue
		}
	}

	router.JSON(w, map[string]string{"mode": req.Mode})
}
