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
		"GetOverview":    s.handleOverview,
		"UpdateConfig":   s.handleConfig,
		"GetFiltering":   s.handleGetFiltering,
		"UpdateFiltering": s.handleFilteringAction,
		"GetRewrites":    s.handleGetRewrites,
		"UpdateRewrites": s.handleRewriteAction,
		"GetQueryLog":    s.handleGetQueryLog,
		"Health":         s.handleHealth,
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

// fetchJSON fetches JSON from AdGuard API and decodes it
func (s *Service) fetchJSON(path string) (interface{}, error) {
	resp, err := s.doRequest("GET", path, nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// handleOverview fetches status, stats, and protection settings in parallel
func (s *Service) handleOverview(w http.ResponseWriter, r *http.Request) {
	type result struct {
		data interface{}
		err  error
	}

	// Fetch all endpoints in parallel
	statusCh := make(chan result, 1)
	statsCh := make(chan result, 1)
	safeBrowsingCh := make(chan result, 1)
	parentalCh := make(chan result, 1)
	safeSearchCh := make(chan result, 1)
	blockedCh := make(chan result, 1)
	availableCh := make(chan result, 1)

	go func() {
		data, err := s.fetchJSON("/control/status")
		statusCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/stats")
		statsCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/safebrowsing/status")
		safeBrowsingCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/parental/status")
		parentalCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/safesearch/status")
		safeSearchCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/blocked_services/list")
		blockedCh <- result{data, err}
	}()
	go func() {
		data, err := s.fetchJSON("/control/blocked_services/all")
		availableCh <- result{data, err}
	}()

	// Collect results
	status := <-statusCh
	stats := <-statsCh
	safeBrowsing := <-safeBrowsingCh
	parental := <-parentalCh
	safeSearch := <-safeSearchCh
	blocked := <-blockedCh
	available := <-availableCh

	// Check for critical errors (status is required)
	if status.err != nil {
		router.JSONError(w, status.err.Error(), http.StatusBadGateway)
		return
	}

	// Build combined response
	response := map[string]interface{}{
		"status": status.data,
	}

	if stats.err == nil {
		response["stats"] = stats.data
	}
	if safeBrowsing.err == nil {
		response["safeBrowsing"] = safeBrowsing.data
	}
	if parental.err == nil {
		response["parental"] = parental.data
	}
	if safeSearch.err == nil {
		response["safeSearch"] = safeSearch.data
	}
	if blocked.err == nil {
		response["blockedServices"] = blocked.data
	}
	if available.err == nil {
		response["availableServices"] = available.data
	}

	router.JSON(w, response)
}

var validConfigTypes = []string{"protection", "safeBrowsing", "parental", "safeSearch", "blockedServices"}

// handleConfig handles unified config updates
func (s *Service) handleConfig(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Type     string   `json:"type"`
		Enabled  *bool    `json:"enabled,omitempty"`
		Services []string `json:"services,omitempty"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate type
	if req.Type == "" {
		router.JSON(w, map[string]interface{}{
			"error":      "type field required",
			"validTypes": validConfigTypes,
		})
		return
	}

	switch req.Type {
	case "protection":
		if req.Enabled == nil {
			router.JSONError(w, "enabled field required for type: protection", http.StatusBadRequest)
			return
		}
		body := `{"protection_enabled":` + strconv.FormatBool(*req.Enabled) + `}`
		resp, err := s.doRequest("POST", "/control/dns_config", newStringReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		router.JSON(w, map[string]interface{}{"type": req.Type, "enabled": *req.Enabled})

	case "safeBrowsing":
		if req.Enabled == nil {
			router.JSONError(w, "enabled field required for type: safeBrowsing", http.StatusBadRequest)
			return
		}
		path := "/control/safebrowsing/"
		if *req.Enabled {
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
		router.JSON(w, map[string]interface{}{"type": req.Type, "enabled": *req.Enabled})

	case "parental":
		if req.Enabled == nil {
			router.JSONError(w, "enabled field required for type: parental", http.StatusBadRequest)
			return
		}
		path := "/control/parental/"
		if *req.Enabled {
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
		router.JSON(w, map[string]interface{}{"type": req.Type, "enabled": *req.Enabled})

	case "safeSearch":
		if req.Enabled == nil {
			router.JSONError(w, "enabled field required for type: safeSearch", http.StatusBadRequest)
			return
		}
		body := `{"enabled":` + strconv.FormatBool(*req.Enabled) + `}`
		resp, err := s.doRequest("PUT", "/control/safesearch/settings", newStringReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		router.JSON(w, map[string]interface{}{"type": req.Type, "enabled": *req.Enabled})

	case "blockedServices":
		if req.Services == nil {
			router.JSONError(w, "services field required for type: blockedServices", http.StatusBadRequest)
			return
		}
		payload := map[string]interface{}{
			"ids": req.Services,
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
		router.JSON(w, map[string]interface{}{"type": req.Type, "services": req.Services})

	default:
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{
			"error":      "unknown type: " + req.Type,
			"validTypes": validConfigTypes,
		})
	}
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

// Filter represents a filter entry for batch operations
type Filter struct {
	Name string `json:"name"`
	URL  string `json:"url"`
}

var validFilteringActions = []string{"add", "remove", "toggle", "refresh", "setRules"}

// handleFilteringAction handles unified filtering actions
func (s *Service) handleFilteringAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action  string   `json:"action"`
		Filters []Filter `json:"filters,omitempty"`
		URL     string   `json:"url,omitempty"`
		Name    string   `json:"name,omitempty"`
		Enabled *bool    `json:"enabled,omitempty"`
		Rules   []string `json:"rules,omitempty"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate action
	if req.Action == "" {
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{
			"error":        "action field required",
			"validActions": validFilteringActions,
		})
		return
	}

	switch req.Action {
	case "add":
		if len(req.Filters) == 0 {
			router.JSONError(w, "filters field required for action: add", http.StatusBadRequest)
			return
		}
		// Add filters in batch
		var added []string
		var errors []string
		for _, f := range req.Filters {
			body, _ := json.Marshal(map[string]interface{}{
				"name":      f.Name,
				"url":       f.URL,
				"whitelist": false,
			})
			resp, err := s.doRequest("POST", "/control/filtering/add_url", newBytesReader(body))
			if err != nil {
				errors = append(errors, f.URL+": "+err.Error())
				continue
			}
			resp.Body.Close()
			if resp.StatusCode >= 400 {
				errors = append(errors, f.URL+": failed")
				continue
			}
			added = append(added, f.URL)
		}
		result := map[string]interface{}{"action": "add", "added": added}
		if len(errors) > 0 {
			result["errors"] = errors
		}
		router.JSON(w, result)

	case "remove":
		if req.URL == "" {
			router.JSONError(w, "url field required for action: remove", http.StatusBadRequest)
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
		router.JSON(w, map[string]interface{}{"action": "remove", "url": req.URL})

	case "toggle":
		if req.URL == "" || req.Enabled == nil {
			router.JSONError(w, "url and enabled fields required for action: toggle", http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(map[string]interface{}{
			"url":       req.URL,
			"whitelist": false,
			"data": map[string]interface{}{
				"enabled": *req.Enabled,
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
		router.JSON(w, map[string]interface{}{"action": "toggle", "url": req.URL, "enabled": *req.Enabled})

	case "refresh":
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
		var result interface{}
		json.NewDecoder(resp.Body).Decode(&result)
		router.JSON(w, map[string]interface{}{"action": "refresh", "result": result})

	case "setRules":
		if req.Rules == nil {
			router.JSONError(w, "rules field required for action: setRules", http.StatusBadRequest)
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
		router.JSON(w, map[string]interface{}{"action": "setRules", "count": len(req.Rules)})

	default:
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{
			"error":        "unknown action: " + req.Action,
			"validActions": validFilteringActions,
		})
	}
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

var validRewriteActions = []string{"add", "delete"}

// handleRewriteAction handles unified rewrite actions
func (s *Service) handleRewriteAction(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Action string `json:"action"`
		Domain string `json:"domain,omitempty"`
		Answer string `json:"answer,omitempty"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate action
	if req.Action == "" {
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{
			"error":        "action field required",
			"validActions": validRewriteActions,
		})
		return
	}

	switch req.Action {
	case "add":
		if req.Domain == "" || req.Answer == "" {
			router.JSONError(w, "domain and answer fields required for action: add", http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(map[string]string{"domain": req.Domain, "answer": req.Answer})
		resp, err := s.doRequest("POST", "/control/rewrite/add", newBytesReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		router.JSON(w, map[string]interface{}{"action": "add", "domain": req.Domain, "answer": req.Answer})

	case "delete":
		if req.Domain == "" || req.Answer == "" {
			router.JSONError(w, "domain and answer fields required for action: delete", http.StatusBadRequest)
			return
		}
		body, _ := json.Marshal(map[string]string{"domain": req.Domain, "answer": req.Answer})
		resp, err := s.doRequest("POST", "/control/rewrite/delete", newBytesReader(body))
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		if proxyError(w, resp) {
			return
		}
		router.JSON(w, map[string]interface{}{"action": "delete", "domain": req.Domain})

	default:
		w.WriteHeader(http.StatusBadRequest)
		router.JSON(w, map[string]interface{}{
			"error":        "unknown action: " + req.Action,
			"validActions": validRewriteActions,
		})
	}
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

