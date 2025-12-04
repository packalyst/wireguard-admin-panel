package headscale

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"api/internal/router"
	"api/internal/settings"
)

// Service handles Headscale operations
type Service struct{}

// New creates a new Headscale service
func New() *Service {
	log.Printf("Headscale service initialized (reads config from database)")
	return &Service{}
}

// getConfig reads headscale API URL and API key from database
func (s *Service) getConfig() (string, string, error) {
	url, err := settings.GetSetting("headscale_api_url")
	if err != nil {
		return "", "", fmt.Errorf("headscale not configured: %v", err)
	}

	apiKey, err := settings.GetSettingEncrypted("headscale_api_key")
	if err != nil {
		return "", "", fmt.Errorf("headscale API key not configured: %v", err)
	}

	return url, apiKey, nil
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetUsers":          s.handleGetUsers,
		"CreateUser":        s.handleCreateUser,
		"DeleteUser":        s.handleDeleteUser,
		"RenameUser":        s.handleRenameUser,
		"GetNodes":          s.handleGetNodes,
		"DeleteNode":        s.handleDeleteNode,
		"RenameNode":        s.handleRenameNode,
		"ExpireNode":        s.handleExpireNode,
		"GetNodeRoutes":     s.handleGetNodeRoutes,
		"UpdateNodeTags":    s.handleUpdateNodeTags,
		"GetRoutes":         s.handleGetRoutes,
		"EnableRoute":       s.handleEnableRoute,
		"DisableRoute":      s.handleDisableRoute,
		"DeleteRoute":       s.handleDeleteRoute,
		"GetPreAuthKeys":    s.handleGetPreAuthKeys,
		"CreatePreAuthKey":  s.handleCreatePreAuthKey,
		"ExpirePreAuthKey":  s.handleExpirePreAuthKey,
		"GetAPIKeys":        s.handleGetAPIKeys,
		"CreateAPIKey":      s.handleCreateAPIKey,
		"DeleteAPIKey":      s.handleDeleteAPIKey,
		"Health":            s.handleHealth,
	}
}

// --- HTTP helpers ---

func (s *Service) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	url, apiKey, err := s.getConfig()
	if err != nil {
		return nil, err
	}

	if !strings.HasSuffix(url, "/api/v1") {
		url = strings.TrimSuffix(url, "/") + "/api/v1"
	}

	req, err := http.NewRequest(method, url+path, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	return http.DefaultClient.Do(req)
}

// proxyResponse writes the Headscale response to the client
func (s *Service) proxyResponse(w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyGet proxies a GET request to Headscale
func (s *Service) proxyGet(w http.ResponseWriter, path string) {
	resp, err := s.doRequest("GET", path, nil)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.proxyResponse(w, resp)
}

// proxyPost proxies a POST request to Headscale with optional JSON body
func (s *Service) proxyPost(w http.ResponseWriter, path string, body string) {
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	resp, err := s.doRequest("POST", path, reader)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.proxyResponse(w, resp)
}

// proxyDelete proxies a DELETE request to Headscale
func (s *Service) proxyDelete(w http.ResponseWriter, path string) {
	resp, err := s.doRequest("DELETE", path, nil)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.proxyResponse(w, resp)
}

// extractPathSegment extracts a segment from URL path after prefix
// e.g., extractPathSegment("/api/hs/nodes/123/routes", "/api/hs/nodes/", 0) returns "123"
func extractPathSegment(urlPath, prefix string, index int) string {
	path := strings.TrimPrefix(urlPath, prefix)
	parts := strings.Split(path, "/")
	if index < len(parts) {
		return parts[index]
	}
	return ""
}

// --- Users ---

func (s *Service) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/user")
}

func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, _ := json.Marshal(req)
	s.proxyPost(w, "/user", string(body))
}

func (s *Service) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/hs/users/")
	s.proxyDelete(w, "/user/"+name)
}

func (s *Service) handleRenameUser(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hs/users/")
	parts := strings.Split(path, "/rename/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/user/"+parts[0]+"/rename/"+parts[1], "")
}

// --- Nodes ---

func (s *Service) handleGetNodes(w http.ResponseWriter, r *http.Request) {
	path := "/node"
	if user := r.URL.Query().Get("user"); user != "" {
		path += "?user=" + user
	}
	s.proxyGet(w, path)
}

func (s *Service) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/nodes/")
	s.proxyDelete(w, "/node/"+id)
}

func (s *Service) handleRenameNode(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hs/nodes/")
	parts := strings.Split(path, "/rename/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/node/"+parts[0]+"/rename/"+parts[1], "")
}

func (s *Service) handleExpireNode(w http.ResponseWriter, r *http.Request) {
	id := extractPathSegment(r.URL.Path, "/api/hs/nodes/", 0)
	s.proxyPost(w, "/node/"+id+"/expire", "")
}

func (s *Service) handleGetNodeRoutes(w http.ResponseWriter, r *http.Request) {
	id := extractPathSegment(r.URL.Path, "/api/hs/nodes/", 0)
	s.proxyGet(w, "/node/"+id+"/routes")
}

func (s *Service) handleUpdateNodeTags(w http.ResponseWriter, r *http.Request) {
	id := extractPathSegment(r.URL.Path, "/api/hs/nodes/", 0)

	var req struct {
		Tags []string `json:"tags"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	body, _ := json.Marshal(map[string][]string{"tags": req.Tags})
	s.proxyPost(w, "/node/"+id+"/tags", string(body))
}

// --- Routes ---

func (s *Service) handleGetRoutes(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/routes")
}

func (s *Service) handleEnableRoute(w http.ResponseWriter, r *http.Request) {
	id := extractPathSegment(r.URL.Path, "/api/hs/routes/", 0)
	s.proxyPost(w, "/routes/"+id+"/enable", "")
}

func (s *Service) handleDisableRoute(w http.ResponseWriter, r *http.Request) {
	id := extractPathSegment(r.URL.Path, "/api/hs/routes/", 0)
	s.proxyPost(w, "/routes/"+id+"/disable", "")
}

func (s *Service) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/routes/")
	s.proxyDelete(w, "/routes/"+id)
}

// --- PreAuth Keys ---

func (s *Service) handleGetPreAuthKeys(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		router.JSONError(w, "user parameter required", http.StatusBadRequest)
		return
	}
	s.proxyGet(w, "/preauthkey?user="+user)
}

func (s *Service) handleCreatePreAuthKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User       string `json:"user"`
		Reusable   bool   `json:"reusable"`
		Ephemeral  bool   `json:"ephemeral"`
		Expiration string `json:"expiration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	body, _ := json.Marshal(req)
	s.proxyPost(w, "/preauthkey", string(body))
}

func (s *Service) handleExpirePreAuthKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		User string `json:"user"`
		Key  string `json:"key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, _ := json.Marshal(req)
	s.proxyPost(w, "/preauthkey/expire", string(body))
}

// --- API Keys ---

func (s *Service) handleGetAPIKeys(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/apikey")
}

func (s *Service) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Expiration string `json:"expiration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	body, _ := json.Marshal(req)
	s.proxyPost(w, "/apikey", string(body))
}

func (s *Service) handleDeleteAPIKey(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/apikeys/")
	body, _ := json.Marshal(map[string]string{"prefix": id})
	s.proxyPost(w, "/apikey/expire", string(body))
}

// --- Health ---

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"status": "ok"})
}
