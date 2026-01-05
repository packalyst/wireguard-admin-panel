package headscale

import (
	"encoding/json"
	"fmt"
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
// Headscale 0.26+ requires user ID instead of name for delete/rename operations

// HeadscaleUser represents a user from the Headscale API
type HeadscaleUser struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// getUserIDByName looks up a user's ID by their name
func getUserIDByName(name string) (string, error) {
	var result struct {
		Users []HeadscaleUser `json:"users"`
	}
	if err := helper.HeadscaleGetJSON("/user", &result); err != nil {
		return "", err
	}
	for _, user := range result.Users {
		if user.Name == name {
			return user.ID, nil
		}
	}
	return "", fmt.Errorf("user '%s' not found", name)
}

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
	// Headscale 0.26+: Need to lookup user ID by name
	userID, err := getUserIDByName(name)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	s.proxyDelete(w, "/user/"+userID)
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
	// Headscale 0.26+: Need to lookup user ID by name
	userID, err := getUserIDByName(parts[0])
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	s.proxyPost(w, "/user/"+userID+"/rename/"+parts[1], "")
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
// Headscale 0.27+ removed the dedicated /routes API.
// Routes are now managed via the Node API using approve_routes endpoint.

// RouteInfo represents a route in the format expected by the frontend
type RouteInfo struct {
	ID         string   `json:"id"`
	Prefix     string   `json:"prefix"`
	Enabled    bool     `json:"enabled"`
	Advertised bool     `json:"advertised"`
	IsPrimary  bool     `json:"isPrimary"`
	Node       NodeInfo `json:"node"`
}

// NodeInfo represents minimal node info for routes
type NodeInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	GivenName string `json:"givenName"`
}

// HeadscaleNode represents a node from the Headscale API
// Note: Headscale API uses snake_case for JSON fields
type HeadscaleNode struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	GivenName       string   `json:"givenName"`
	ApprovedRoutes  []string `json:"approved_routes"`
	AvailableRoutes []string `json:"available_routes"`
	SubnetRoutes    []string `json:"subnet_routes"`
}

func (s *Service) handleGetRoutes(w http.ResponseWriter, r *http.Request) {
	// Get all nodes to extract route information
	var nodeResult struct {
		Nodes []HeadscaleNode `json:"nodes"`
	}
	if err := helper.HeadscaleGetJSON("/node", &nodeResult); err != nil {
		router.JSONError(w, "failed to get nodes: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Build routes list from all nodes
	var routes []RouteInfo
	routeID := 1

	for _, node := range nodeResult.Nodes {
		nodeInfo := NodeInfo{
			ID:        node.ID,
			Name:      node.Name,
			GivenName: node.GivenName,
		}

		// Create a set of approved routes for quick lookup
		approvedSet := make(map[string]bool)
		for _, route := range node.ApprovedRoutes {
			approvedSet[route] = true
		}

		// Add all available routes (advertised by the node)
		for _, prefix := range node.AvailableRoutes {
			routes = append(routes, RouteInfo{
				ID:         fmt.Sprintf("%s-%d", node.ID, routeID),
				Prefix:     prefix,
				Enabled:    approvedSet[prefix],
				Advertised: true,
				IsPrimary:  false, // Headscale 0.27 doesn't expose primary info directly
				Node:       nodeInfo,
			})
			routeID++
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"routes": routes,
	})
}

func (s *Service) handleEnableRoute(w http.ResponseWriter, r *http.Request) {
	// Route ID format: nodeID-routeIndex (e.g., "5-1")
	// We need to parse nodeID and get the route prefix, then add it to approved routes
	routeIDParam := router.ExtractPathParam(r, "/api/hs/routes/")

	// Parse the request body for the route info
	var req struct {
		NodeID string `json:"nodeId"`
		Prefix string `json:"prefix"`
	}

	// First try to get info from query params (for simple enable toggle)
	req.NodeID = r.URL.Query().Get("nodeId")
	req.Prefix = r.URL.Query().Get("prefix")

	// If not in query, try request body
	if req.NodeID == "" || req.Prefix == "" {
		router.DecodeJSONOrError(w, r, &req)
	}

	// If still no info, try to parse from route ID format (nodeID-index)
	if req.NodeID == "" && strings.Contains(routeIDParam, "-") {
		parts := strings.SplitN(routeIDParam, "-", 2)
		req.NodeID = parts[0]
	}

	if req.NodeID == "" {
		router.JSONError(w, "nodeId required", http.StatusBadRequest)
		return
	}
	if !validNodeID.MatchString(req.NodeID) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}

	// Get current approved routes for this node
	var nodeResult struct {
		Node HeadscaleNode `json:"node"`
	}
	if err := helper.HeadscaleGetJSON("/node/"+req.NodeID, &nodeResult); err != nil {
		router.JSONError(w, "failed to get node: "+err.Error(), http.StatusBadGateway)
		return
	}

	// If prefix not provided, we need to find it from available routes
	if req.Prefix == "" {
		router.JSONError(w, "prefix required - specify the route to enable", http.StatusBadRequest)
		return
	}

	// Add the route to approved list if not already there
	approvedRoutes := nodeResult.Node.ApprovedRoutes
	alreadyApproved := false
	for _, route := range approvedRoutes {
		if route == req.Prefix {
			alreadyApproved = true
			break
		}
	}
	if !alreadyApproved {
		approvedRoutes = append(approvedRoutes, req.Prefix)
	}

	// Call approve_routes endpoint
	body, _ := json.Marshal(map[string][]string{"routes": approvedRoutes})
	s.proxyPost(w, "/node/"+req.NodeID+"/approve_routes", string(body))
}

func (s *Service) handleDisableRoute(w http.ResponseWriter, r *http.Request) {
	routeIDParam := router.ExtractPathParam(r, "/api/hs/routes/")

	var req struct {
		NodeID string `json:"nodeId"`
		Prefix string `json:"prefix"`
	}

	req.NodeID = r.URL.Query().Get("nodeId")
	req.Prefix = r.URL.Query().Get("prefix")

	if req.NodeID == "" || req.Prefix == "" {
		router.DecodeJSONOrError(w, r, &req)
	}

	if req.NodeID == "" && strings.Contains(routeIDParam, "-") {
		parts := strings.SplitN(routeIDParam, "-", 2)
		req.NodeID = parts[0]
	}

	if req.NodeID == "" {
		router.JSONError(w, "nodeId required", http.StatusBadRequest)
		return
	}
	if !validNodeID.MatchString(req.NodeID) {
		router.JSONError(w, "invalid node id", http.StatusBadRequest)
		return
	}

	// Get current approved routes
	var nodeResult struct {
		Node HeadscaleNode `json:"node"`
	}
	if err := helper.HeadscaleGetJSON("/node/"+req.NodeID, &nodeResult); err != nil {
		router.JSONError(w, "failed to get node: "+err.Error(), http.StatusBadGateway)
		return
	}

	if req.Prefix == "" {
		router.JSONError(w, "prefix required - specify the route to disable", http.StatusBadRequest)
		return
	}

	// Remove the route from approved list
	var newApproved []string
	for _, route := range nodeResult.Node.ApprovedRoutes {
		if route != req.Prefix {
			newApproved = append(newApproved, route)
		}
	}

	body, _ := json.Marshal(map[string][]string{"routes": newApproved})
	s.proxyPost(w, "/node/"+req.NodeID+"/approve_routes", string(body))
}

func (s *Service) handleDeleteRoute(w http.ResponseWriter, r *http.Request) {
	// In Headscale 0.27+, routes can't be "deleted" - they're advertised by nodes.
	// We can only unapprove them (same as disable).
	s.handleDisableRoute(w, r)
}

// --- PreAuth Keys ---
// Headscale 0.26+ requires user ID instead of name for preauth key operations

func (s *Service) handleGetPreAuthKeys(w http.ResponseWriter, r *http.Request) {
	user := r.URL.Query().Get("user")
	if user == "" {
		router.JSONError(w, "user parameter required", http.StatusBadRequest)
		return
	}
	// Headscale 0.26+: Need to lookup user ID by name
	userID, err := getUserIDByName(user)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusNotFound)
		return
	}
	s.proxyGet(w, "/preauthkey?user="+userID)
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

	// Headscale 0.26+: Need to lookup user ID by name
	userID, err := getUserIDByName(req.User)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusNotFound)
		return
	}

	// Send request with user ID instead of name
	body, _ := json.Marshal(map[string]interface{}{
		"user":       userID,
		"reusable":   req.Reusable,
		"ephemeral":  req.Ephemeral,
		"expiration": req.Expiration,
	})
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

	// Headscale 0.26+: Need to lookup user ID by name
	userID, err := getUserIDByName(req.User)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusNotFound)
		return
	}

	body, _ := json.Marshal(map[string]interface{}{
		"user": userID,
		"key":  req.Key,
	})
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

