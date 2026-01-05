package headscale

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"regexp"
	"strings"

	"api/internal/database"
	"api/internal/domains"
	"api/internal/helper"
	"api/internal/router"
)

// validName matches valid Headscale user/node names (alphanumeric, underscore, dash)
var validName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

// validNodeID matches valid Headscale node IDs (numeric only)
var validNodeID = regexp.MustCompile(`^[0-9]+$`)

// Service handles Headscale operations
type Service struct{}

// New creates a new Headscale service
func New() *Service {
	log.Printf("Headscale service initialized (reads config from database)")
	return &Service{}
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
	}
}

// --- HTTP helpers ---

// proxyResponse writes the Headscale response to the client
func (s *Service) proxyResponse(w http.ResponseWriter, resp *http.Response) {
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

// proxyGet proxies a GET request to Headscale
func (s *Service) proxyGet(w http.ResponseWriter, path string) {
	resp, err := helper.HeadscaleGet(path)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.proxyResponse(w, resp)
}

// proxyPost proxies a POST request to Headscale with optional JSON body
func (s *Service) proxyPost(w http.ResponseWriter, path string, body string) {
	resp, err := helper.HeadscalePost(path, body)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.proxyResponse(w, resp)
}

// proxyDelete proxies a DELETE request to Headscale
func (s *Service) proxyDelete(w http.ResponseWriter, path string) {
	resp, err := helper.HeadscaleDelete(path)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadGateway)
		return
	}
	s.proxyResponse(w, resp)
}

// --- Users ---

func (s *Service) handleGetUsers(w http.ResponseWriter, r *http.Request) {
	s.proxyGet(w, "/user")
}

func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	body, _ := json.Marshal(req)
	s.proxyPost(w, "/user", string(body))
}

func (s *Service) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/hs/users/")
	if !validName.MatchString(name) {
		router.JSONError(w, "invalid user name", http.StatusBadRequest)
		return
	}
	s.proxyDelete(w, "/user/"+name)
}

func (s *Service) handleRenameUser(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hs/users/")
	parts := strings.Split(path, "/rename/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	if !validName.MatchString(parts[0]) || !validName.MatchString(parts[1]) {
		router.JSONError(w, "invalid user name", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/user/"+parts[0]+"/rename/"+parts[1], "")
}

// --- Nodes ---

func (s *Service) handleGetNodes(w http.ResponseWriter, r *http.Request) {
	path := "/node"
	if user := r.URL.Query().Get("user"); user != "" {
		if !validName.MatchString(user) {
			router.JSONError(w, "invalid user name", http.StatusBadRequest)
			return
		}
		path += "?user=" + user
	}
	s.proxyGet(w, path)
}

func (s *Service) handleDeleteNode(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/nodes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}

	// Auto-delete from vpn_clients for unified view
	if db, err := database.GetDB(); err == nil {
		// Get client ID and delete associated domain routes first
		var clientID int
		err := db.QueryRow(`SELECT id FROM vpn_clients WHERE external_id = ? AND type = 'headscale'`, id).Scan(&clientID)
		if err == nil && clientID > 0 {
			domains.DeleteClientRoutes(clientID)
		}
		db.Exec(`DELETE FROM vpn_clients WHERE external_id = ? AND type = 'headscale'`, id)
	}

	s.proxyDelete(w, "/node/"+id)
}

func (s *Service) handleRenameNode(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/hs/nodes/")
	parts := strings.Split(path, "/rename/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	if !validNodeID.MatchString(parts[0]) || !validName.MatchString(parts[1]) {
		router.JSONError(w, "invalid node id or name", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/node/"+parts[0]+"/rename/"+parts[1], "")
}

func (s *Service) handleExpireNode(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/nodes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/node/"+id+"/expire", "")
}

func (s *Service) handleGetNodeRoutes(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/nodes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}
	s.proxyGet(w, "/node/"+id+"/routes")
}

func (s *Service) handleUpdateNodeTags(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/nodes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}

	var req struct {
		Tags []string `json:"tags"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
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
	id := router.ExtractPathParam(r, "/api/hs/routes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid route id", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/routes/"+id+"/enable", "")
}

func (s *Service) handleDisableRoute(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/routes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid route id", http.StatusBadRequest)
		return
	}
	s.proxyPost(w, "/routes/"+id+"/disable", "")
}

func (s *Service) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/hs/routes/")
	if !validNodeID.MatchString(id) {
		router.JSONError(w, "invalid route id", http.StatusBadRequest)
		return
	}
	s.proxyDelete(w, "/routes/"+id)
}

// --- PreAuth Keys ---

func (s *Service) handleGetPreAuthKeys(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		router.JSONError(w, "user parameter required", http.StatusBadRequest)
		return
	}
	if !validName.MatchString(user) {
		router.JSONError(w, "invalid user name", http.StatusBadRequest)
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
	if !router.DecodeJSONOrError(w, r, &req) {
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
	if !router.DecodeJSONOrError(w, r, &req) {
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
	if !router.DecodeJSONOrError(w, r, &req) {
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

