package adguard

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"

	"api/internal/router"
	"api/internal/settings"
)

// Service handles AdGuard operations
type Service struct {
	adguardAPI string
}

// New creates a new AdGuard service
func New() *Service {
	port := os.Getenv("ADGUARD_PORT")
	if port == "" {
		port = "8083"
	}
	svc := &Service{
		adguardAPI: "http://127.0.0.1:" + port,
	}

	log.Printf("AdGuard service initialized, API: %s", svc.adguardAPI)
	return svc
}

// getCredentials fetches credentials from database, falls back to env vars
func (s *Service) getCredentials() (username, password string) {
	// Try database first
	if u, err := settings.GetSetting("adguard_username"); err == nil && u != "" {
		username = u
	}
	if p, err := settings.GetSettingEncrypted("adguard_password"); err == nil && p != "" {
		password = p
	}

	// Fallback to env vars if not in database
	if username == "" {
		username = os.Getenv("ADGUARD_USER")
	}
	if password == "" {
		password = os.Getenv("ADGUARD_PASS")
	}

	return username, password
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetStatus":              s.handleGetStatus,
		"GetStats":               s.handleGetStats,
		"GetQueryLog":            s.handleGetQueryLog,
		"GetFiltering":           s.handleGetFiltering,
		"SetFiltering":           s.handleSetFiltering,
		"AddFilter":              s.handleAddFilter,
		"RemoveFilter":           s.handleRemoveFilter,
		"ToggleFilter":           s.handleToggleFilter,
		"RefreshFilters":         s.handleRefreshFilters,
		"SetFilteringRules":      s.handleSetFilteringRules,
		"SetProtection":          s.handleSetProtection,
		"GetBlockedServices":     s.handleGetBlockedServices,
		"SetBlockedServices":     s.handleSetBlockedServices,
		"GetAllBlockedServices":  s.handleGetAllBlockedServices,
		"GetSafeBrowsing":        s.handleGetSafeBrowsing,
		"SetSafeBrowsing":        s.handleSetSafeBrowsing,
		"GetParental":            s.handleGetParental,
		"SetParental":            s.handleSetParental,
		"GetSafeSearch":          s.handleGetSafeSearch,
		"SetSafeSearch":          s.handleSetSafeSearch,
		"GetClients":             s.handleGetClients,
		"GetRewrites":            s.handleGetRewrites,
		"AddRewrite":             s.handleAddRewrite,
		"DeleteRewrite":          s.handleDeleteRewrite,
		"Health":                 s.handleHealth,
	}
}

func (s *Service) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	req, err := http.NewRequest(method, s.adguardAPI+path, body)
	if err != nil {
		return nil, err
	}

	// Only set Content-Type if there's a body
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	username, password := s.getCredentials()
	if username != "" && password != "" {
		req.SetBasicAuth(username, password)
	}

	return http.DefaultClient.Do(req)
}

func (s *Service) proxyGet(w http.ResponseWriter, path string) {
	resp, err := s.doRequest("GET", path, nil)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyError writes error response from upstream if status >= 400, returns true if error occurred
func proxyError(w http.ResponseWriter, resp *http.Response) bool {
	if resp.StatusCode >= 400 {
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
		return true
	}
	return false
}

func (s *Service) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/status")
}

func (s *Service) handleGetStats(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/stats")
}

func (s *Service) handleGetQueryLog(w http.ResponseWriter, r *http.Request) {
	limit := r.URL.Query().Get("limit")
	if limit == "" {
		limit = "100"
	}
	offset := r.URL.Query().Get("offset")
	if offset == "" {
		offset = "0"
	}

	path := "/control/querylog?limit=" + limit + "&offset=" + offset
	s.proxyGet(w, path)
}

func (s *Service) handleGetFiltering(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/filtering/status")
}

func (s *Service) handleSetFiltering(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	path := "/control/filtering/config"
	body := `{"enabled":` + strconv.FormatBool(req.Enabled) + `,"interval":24}`

	resp, err := s.doRequest("POST", path, newStringReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]bool{"enabled": req.Enabled})
}

func (s *Service) handleAddFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	body, _ := json.Marshal(map[string]interface{}{
		"name":      req.Name,
		"url":       req.URL,
		"whitelist": false,
	})

	resp, err := s.doRequest("POST", "/control/filtering/add_url", newBytesReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]string{"status": "added"})
}

func (s *Service) handleRemoveFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL string `json:"url"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	body, _ := json.Marshal(map[string]interface{}{
		"url":       req.URL,
		"whitelist": false,
	})

	resp, err := s.doRequest("POST", "/control/filtering/remove_url", newBytesReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]string{"status": "removed"})
}

func (s *Service) handleToggleFilter(w http.ResponseWriter, r *http.Request) {
	var req struct {
		URL     string `json:"url"`
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// AdGuard expects: {"url": "...", "data": {"enabled": true, "url": "...", "name": "..."}, "whitelist": false}
	body, _ := json.Marshal(map[string]interface{}{
		"url":       req.URL,
		"whitelist": false,
		"data": map[string]interface{}{
			"enabled": req.Enabled,
			"url":     req.URL,
			"name":    req.Name,
		},
	})

	resp, err := s.doRequest("POST", "/control/filtering/set_url", newBytesReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]bool{"enabled": req.Enabled})
}

func (s *Service) handleRefreshFilters(w http.ResponseWriter, r *http.Request) {
	body := `{"whitelist":false}`

	resp, err := s.doRequest("POST", "/control/filtering/refresh", newStringReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	// Proxy the response (contains updated counts)
	w.Header().Set("Content-Type", "application/json")
	io.Copy(w, resp.Body)
}

func (s *Service) handleSetFilteringRules(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Rules []string `json:"rules"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	body, _ := json.Marshal(map[string]interface{}{
		"rules": req.Rules,
	})

	resp, err := s.doRequest("POST", "/control/filtering/set_rules", newBytesReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]string{"status": "updated"})
}

func (s *Service) handleSetProtection(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	body := `{"protection_enabled":` + strconv.FormatBool(req.Enabled) + `}`

	resp, err := s.doRequest("POST", "/control/dns_config", newStringReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]bool{"protection_enabled": req.Enabled})
}

func (s *Service) handleGetBlockedServices(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/blocked_services/list")
}

func (s *Service) handleSetBlockedServices(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IDs []string `json:"ids"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// AdGuard expects: {"ids": [...], "schedule": {"time_zone": "UTC"}}
	payload := map[string]interface{}{
		"ids": req.IDs,
		"schedule": map[string]string{
			"time_zone": "UTC",
		},
	}
	body, _ := json.Marshal(payload)

	resp, err := s.doRequest("PUT", "/control/blocked_services/update", newBytesReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string][]string{"ids": req.IDs})
}

func (s *Service) handleGetAllBlockedServices(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/blocked_services/all")
}

func (s *Service) handleGetSafeBrowsing(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/safebrowsing/status")
}

func (s *Service) handleSetSafeBrowsing(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	path := "/control/safebrowsing/"
	if req.Enabled {
		path += "enable"
	} else {
		path += "disable"
	}

	resp, err := s.doRequest("POST", path, nil)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]bool{"enabled": req.Enabled})
}

func (s *Service) handleGetParental(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/parental/status")
}

func (s *Service) handleSetParental(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	path := "/control/parental/"
	if req.Enabled {
		path += "enable"
	} else {
		path += "disable"
	}

	resp, err := s.doRequest("POST", path, nil)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]bool{"enabled": req.Enabled})
}

func (s *Service) handleGetSafeSearch(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/safesearch/status")
}

func (s *Service) handleSetSafeSearch(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// SafeSearch requires specifying which services to enable
	body := `{"enabled":` + strconv.FormatBool(req.Enabled) + `}`

	resp, err := s.doRequest("PUT", "/control/safesearch/settings", newStringReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]bool{"enabled": req.Enabled})
}

func (s *Service) handleGetClients(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/clients")
}

func (s *Service) handleGetRewrites(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/control/rewrite/list")
}

func (s *Service) handleAddRewrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Answer string `json:"answer"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	body, _ := json.Marshal(req)

	resp, err := s.doRequest("POST", "/control/rewrite/add", newBytesReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, req)
}

func (s *Service) handleDeleteRewrite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Answer string `json:"answer"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	body, _ := json.Marshal(req)

	resp, err := s.doRequest("POST", "/control/rewrite/delete", newBytesReader(body))
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if proxyError(w, resp) {
		return
	}

	router.JSON(w, map[string]string{"status": "deleted"})
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"status": "ok"})
}

// Helper functions using stdlib
func newStringReader(s string) io.Reader {
	return strings.NewReader(s)
}

func newBytesReader(b []byte) io.Reader {
	return bytes.NewReader(b)
}

// Rewrite represents a DNS rewrite entry
type Rewrite struct {
	Domain string `json:"domain"`
	Answer string `json:"answer"`
}

// GetRewrites returns all DNS rewrites
func GetRewrites() ([]Rewrite, error) {
	svc := New()
	resp, err := svc.doRequest("GET", "/control/rewrite/list", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var rewrites []Rewrite
	if err := json.NewDecoder(resp.Body).Decode(&rewrites); err != nil {
		return nil, err
	}
	return rewrites, nil
}

// AddRewrite adds a DNS rewrite
func AddRewrite(domain, answer string) error {
	svc := New()
	body, _ := json.Marshal(Rewrite{Domain: domain, Answer: answer})
	resp, err := svc.doRequest("POST", "/control/rewrite/add", newBytesReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// DeleteRewrite removes a DNS rewrite
func DeleteRewrite(domain, answer string) error {
	svc := New()
	body, _ := json.Marshal(Rewrite{Domain: domain, Answer: answer})
	resp, err := svc.doRequest("POST", "/control/rewrite/delete", newBytesReader(body))
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

