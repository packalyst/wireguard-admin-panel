package traefik

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
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
		"GetOverview":    s.handleOverview,
		"GetRouters":     s.handleRouters,
		"GetServices":    s.handleServices,
		"GetMiddlewares": s.handleMiddlewares,
		"GetConfig":      s.handleGetConfig,
		"UpdateConfig":   s.handleUpdateConfig,
		"GetLogs":        s.handleLogs,
		"Health":         s.handleHealth,
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

func (s *Service) handleOverview(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(s.traefikAPI + "/overview")
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func (s *Service) handleRouters(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(s.traefikAPI + "/http/routers")
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func (s *Service) handleServices(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(s.traefikAPI + "/http/services")
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func (s *Service) handleMiddlewares(w http.ResponseWriter, r *http.Request) {
	resp, err := http.Get(s.traefikAPI + "/http/middlewares")
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
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
	if err := json.NewDecoder(r.Body).Decode(&config); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
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
// enabled=false: 127.0.0.1:port (local only)
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

	// Replace the traefik entrypoint address
	if enabled {
		// Enable: bind to 0.0.0.0:port (public)
		content = strings.ReplaceAll(content, `address: "127.0.0.1:`+port+`"`, `address: ":`+port+`"`)
	} else {
		// Disable: bind to 127.0.0.1:port (localhost only)
		content = strings.ReplaceAll(content, `address: ":`+port+`"`, `address: "127.0.0.1:`+port+`"`)
	}

	return os.WriteFile(configPath, []byte(content), 0644)
}

func (s *Service) handleLogs(w http.ResponseWriter, r *http.Request) {
	limit := 100
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

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
	idx := strings.Index(content, "vpn-only:")
	if idx == -1 {
		return content
	}

	rangeIdx := strings.Index(content[idx:], "sourceRange:")
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
