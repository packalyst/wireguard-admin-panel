package vpn

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api/internal/database"
	"api/internal/domains"
	"api/internal/helper"
	"api/internal/nftables"
	"api/internal/router"
	"api/internal/settings"
	"api/internal/wireguard"
	"api/internal/ws"
)

// syncClient upserts a VPN client into the database
func syncClient(db *sql.DB, existing map[string]int, seen map[string]bool,
	name, ip, clientType, externalID, rawData string, added *int) {
	seen[ip] = true
	if id, exists := existing[ip]; exists {
		db.Exec(`UPDATE vpn_clients SET name = ?, raw_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			name, rawData, id)
	} else {
		_, err := db.Exec(`INSERT INTO vpn_clients (name, ip, type, external_id, raw_data, acl_policy) VALUES (?, ?, ?, ?, ?, ?)`,
			name, ip, clientType, externalID, rawData, helper.DefaultACLPolicy)
		if err == nil {
			*added++
		}
	}
}

// GetNodeStats returns current VPN node statistics from the database
func GetNodeStats() ws.NodeStats {
	db, err := database.GetDB()
	if err != nil {
		return ws.NodeStats{}
	}

	var stats ws.NodeStats

	rows, err := db.Query(`SELECT type, raw_data FROM vpn_clients`)
	if err != nil {
		return stats
	}
	defer rows.Close()

	for rows.Next() {
		var clientType string
		var rawData []byte
		if err := rows.Scan(&clientType, &rawData); err != nil {
			continue
		}

		switch clientType {
		case "headscale":
			stats.HsNodes++
		case "wireguard":
			stats.WgPeers++
		}

		if len(rawData) > 0 && isNodeOnline(rawData) {
			stats.Online++
		} else {
			stats.Offline++
		}
	}

	return stats
}

// isNodeOnline checks if the raw JSON data indicates the node is online
func isNodeOnline(rawData []byte) bool {
	// Simple byte scan for "online":true pattern
	// More efficient than full JSON parsing
	for i := 0; i < len(rawData)-12; i++ {
		if rawData[i] == '"' && rawData[i+1] == 'o' && rawData[i+2] == 'n' &&
			rawData[i+3] == 'l' && rawData[i+4] == 'i' && rawData[i+5] == 'n' &&
			rawData[i+6] == 'e' && rawData[i+7] == '"' && rawData[i+8] == ':' {
			// Found "online":, check for true
			j := i + 9
			for j < len(rawData) && rawData[j] == ' ' {
				j++
			}
			if j+4 <= len(rawData) && rawData[j] == 't' && rawData[j+1] == 'r' &&
				rawData[j+2] == 'u' && rawData[j+3] == 'e' {
				return true
			}
		}
	}
	return false
}

// Service handles unified VPN client management and ACL
type Service struct {
	wgIPRange string
	hsIPRange string
}

// VPNClient represents a unified view of a VPN client (WireGuard or Headscale)
type VPNClient struct {
	ID         int             `json:"id"`
	Name       string          `json:"name"`
	IP         string          `json:"ip"`
	Type       string          `json:"type"` // "wireguard" or "headscale"
	ExternalID string          `json:"externalId,omitempty"`
	RawData    json.RawMessage `json:"rawData,omitempty"` // Full data from source system
	ACLPolicy  string          `json:"aclPolicy"`         // block_all, selected, allow_all
	CreatedAt  time.Time       `json:"createdAt"`
	UpdatedAt  time.Time       `json:"updatedAt"`
	// Enriched fields (not stored in DB)
	AllowedCount int `json:"allowedCount,omitempty"`
}

// ACLRule represents an ACL rule between two clients (source can reach target)
type ACLRule struct {
	ID             int       `json:"id"`
	SourceClientID int       `json:"sourceClientId"`
	TargetClientID int       `json:"targetClientId"`
	CreatedAt      time.Time `json:"createdAt"`
	// Enriched fields
	TargetName      string `json:"targetName,omitempty"`
	TargetIP        string `json:"targetIp,omitempty"`
	TargetType      string `json:"targetType,omitempty"`
	TargetPolicy    string `json:"targetPolicy,omitempty"`    // For UI to know if bidirectional is possible
	IsBidirectional bool   `json:"isBidirectional,omitempty"` // True if reverse rule exists
}

// ClientACLUpdate is the request body for updating a client's ACL
type ClientACLUpdate struct {
	Policy           string          `json:"policy"`
	AllowedClientIDs []int           `json:"allowedClientIds"`
	Bidirectional    map[int]bool    `json:"bidirectional"` // targetId -> add reverse rule
}

// New creates a new VPN service
func New() *Service {
	wgRange := helper.GetEnv("WG_IP_RANGE")
	hsRange := helper.GetEnv("HEADSCALE_IP_RANGE")

	log.Printf("VPN service initialized (WG: %s, HS: %s)", wgRange, hsRange)
	return &Service{
		wgIPRange: wgRange,
		hsIPRange: hsRange,
	}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		// Clients & ACL
		"GetClients":  s.handleGetClients,
		"GetClient":   s.handleGetClient,
		"UpdateACL":   s.handleUpdateACL,
		"ApplyRules":  s.handleApplyRules,
		"ToggleDNS":   s.handleToggleDNS,
		// Port Scanner
		"ScanPorts": s.handleScanPorts,
		// Router Management
		"GetRouterStatus": s.handleGetRouterStatus,
		"SetupRouter":     s.handleSetupRouter,
		"RestartRouter":   s.handleRestartRouter,
		"RemoveRouter":    s.handleRemoveRouter,
	}
}

// --- Client Handlers ---

func (s *Service) handleGetClients(w http.ResponseWriter, r *http.Request) {
	// Auto-sync to get fresh data from WireGuard and Headscale
	s.SyncClients()

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// Use LEFT JOIN with subquery to avoid N+1 query problem
	rows, err := db.Query(`
		SELECT c.id, c.name, c.ip, c.type, c.external_id, c.raw_data,
		       c.acl_policy, c.created_at, c.updated_at,
		       COALESCE(counts.cnt, 0) as allowed_count
		FROM vpn_clients c
		LEFT JOIN (
			SELECT source_client_id, COUNT(*) as cnt
			FROM vpn_acl_rules
			GROUP BY source_client_id
		) counts ON c.id = counts.source_client_id
		ORDER BY c.type, c.name
	`)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	clients := []VPNClient{}
	for rows.Next() {
		var c VPNClient
		var externalID, rawData sql.NullString
		if err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.Type, &externalID, &rawData, &c.ACLPolicy, &c.CreatedAt, &c.UpdatedAt, &c.AllowedCount); err != nil {
			continue
		}
		if externalID.Valid {
			c.ExternalID = externalID.String
		}
		if rawData.Valid {
			c.RawData = json.RawMessage(rawData.String)
		}
		clients = append(clients, c)
	}

	router.JSON(w, clients)
}

func (s *Service) handleGetClient(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/vpn/clients/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var c VPNClient
	var externalID sql.NullString
	err = db.QueryRow(`
		SELECT id, name, ip, type, external_id, acl_policy, created_at, updated_at
		FROM vpn_clients WHERE id = ?
	`, id).Scan(&c.ID, &c.Name, &c.IP, &c.Type, &externalID, &c.ACLPolicy, &c.CreatedAt, &c.UpdatedAt)
	if err == sql.ErrNoRows {
		router.JSONError(w, "client not found", http.StatusNotFound)
		return
	}
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if externalID.Valid {
		c.ExternalID = externalID.String
	}

	// Get ACL rules for this client
	rules := s.getClientACLRules(c.ID)

	router.JSON(w, map[string]interface{}{
		"client": c,
		"rules":  rules,
		"hasDNS": HasClientDNS(c.Name),
	})
}

func (s *Service) handleToggleDNS(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/vpn/clients/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		router.JSONError(w, "invalid client ID", http.StatusBadRequest)
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var name, ip string
	err = db.QueryRow(`SELECT name, ip FROM vpn_clients WHERE id = ?`, id).Scan(&name, &ip)
	if err != nil {
		router.JSONError(w, "client not found", http.StatusNotFound)
		return
	}

	if req.Enabled {
		err = AddClientDNS(name, ip)
	} else {
		err = RemoveClientDNS(name, ip)
	}

	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]bool{"enabled": req.Enabled})
}

func (s *Service) handleUpdateACL(w http.ResponseWriter, r *http.Request) {
	// Extract ID from path like /api/vpn/clients/123/acl
	path := strings.TrimPrefix(r.URL.Path, "/api/vpn/clients/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	id, err := strconv.Atoi(parts[0])
	if err != nil {
		router.JSONError(w, "invalid client ID", http.StatusBadRequest)
		return
	}

	var req ClientACLUpdate
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate policy
	if !helper.IsValidACLPolicy(req.Policy) {
		router.JSONError(w, "invalid policy", http.StatusBadRequest)
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	tx, err := db.Begin()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer tx.Rollback()

	// Update client policy
	_, err = tx.Exec(`
		UPDATE vpn_clients
		SET acl_policy = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, req.Policy, id)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Handle different policies
	switch req.Policy {
	case helper.ACLPolicyBlockAll:
		// Client is isolated - delete all rules where they are source OR target
		_, err = tx.Exec(`DELETE FROM vpn_acl_rules WHERE source_client_id = ? OR target_client_id = ?`, id, id)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case helper.ACLPolicyAllowAll:
		// Client can reach everyone - no need for individual rules, delete where source=this
		_, err = tx.Exec(`DELETE FROM vpn_acl_rules WHERE source_client_id = ?`, id)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}

	case helper.ACLPolicySelected:
		// Delete existing rules where this client is source
		_, err = tx.Exec(`DELETE FROM vpn_acl_rules WHERE source_client_id = ?`, id)
		if err != nil {
			router.JSONError(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Pre-fetch policies for all target clients to avoid N+1 queries
		targetPolicies := make(map[int]string)
		if len(req.AllowedClientIDs) > 0 {
			// Build query with placeholders
			placeholders := make([]string, len(req.AllowedClientIDs))
			args := make([]interface{}, len(req.AllowedClientIDs))
			for i, tid := range req.AllowedClientIDs {
				placeholders[i] = "?"
				args[i] = tid
			}
			policyRows, err := tx.Query(
				`SELECT id, acl_policy FROM vpn_clients WHERE id IN (`+strings.Join(placeholders, ",")+`)`,
				args...,
			)
			if err == nil {
				for policyRows.Next() {
					var tid int
					var policy string
					if err := policyRows.Scan(&tid, &policy); err == nil {
						targetPolicies[tid] = policy
					}
				}
				policyRows.Close()
			}
		}

		// Add rules for selected clients
		for _, targetID := range req.AllowedClientIDs {
			if targetID == id {
				continue // Can't allow self
			}
			// Insert rule: this client can reach target
			_, err = tx.Exec(`
				INSERT OR IGNORE INTO vpn_acl_rules (source_client_id, target_client_id)
				VALUES (?, ?)
			`, id, targetID)
			if err != nil {
				router.JSONError(w, err.Error(), http.StatusInternalServerError)
				return
			}

			// Handle bidirectional: if checked, add reverse rule (only if target has "selected" policy)
			if req.Bidirectional != nil && req.Bidirectional[targetID] {
				// Only add reverse rule if target has "selected" policy
				if targetPolicies[targetID] == helper.ACLPolicySelected {
					_, err = tx.Exec(`
						INSERT OR IGNORE INTO vpn_acl_rules (source_client_id, target_client_id)
						VALUES (?, ?)
					`, targetID, id)
					if err != nil {
						router.JSONError(w, err.Error(), http.StatusInternalServerError)
						return
					}
				}
			}
		}
	}

	if err := tx.Commit(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]string{"status": "ok"})
}

func (s *Service) handleApplyRules(w http.ResponseWriter, r *http.Request) {
	if err := s.ApplyRules(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]string{"status": "ok"})
}

// --- Router Handlers ---

func (s *Service) handleGetRouterStatus(w http.ResponseWriter, r *http.Request) {
	status := GetRouterStatus()
	router.JSON(w, status)
}

func (s *Service) handleSetupRouter(w http.ResponseWriter, r *http.Request) {
	if err := SetupRouter(); err != nil {
		log.Printf("Router setup error: %v", err)
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "starting"})
}

func (s *Service) handleRestartRouter(w http.ResponseWriter, r *http.Request) {
	if err := RestartRouter(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "ok"})
}

func (s *Service) handleRemoveRouter(w http.ResponseWriter, r *http.Request) {
	if err := RemoveRouter(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "ok"})
}

// --- Helper Methods ---

func (s *Service) getClientACLRules(clientID int) []ACLRule {
	db, err := database.GetDB()
	if err != nil {
		return nil
	}

	// Get rules where this client is source, include target's policy and check if reverse rule exists
	// Uses subquery to check for bidirectional in single query (avoids N+1)
	rows, err := db.Query(`
		SELECT r.id, r.source_client_id, r.target_client_id, r.created_at,
		       c.name, c.ip, c.type, c.acl_policy,
		       EXISTS(SELECT 1 FROM vpn_acl_rules rev
		              WHERE rev.source_client_id = r.target_client_id
		              AND rev.target_client_id = r.source_client_id) as is_bidirectional
		FROM vpn_acl_rules r
		JOIN vpn_clients c ON r.target_client_id = c.id
		WHERE r.source_client_id = ?
		ORDER BY c.name
	`, clientID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	rules := []ACLRule{}
	for rows.Next() {
		var r ACLRule
		if err := rows.Scan(&r.ID, &r.SourceClientID, &r.TargetClientID, &r.CreatedAt,
			&r.TargetName, &r.TargetIP, &r.TargetType, &r.TargetPolicy, &r.IsBidirectional); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	return rules
}

// SyncClients synchronizes VPN clients from WireGuard and Headscale
func (s *Service) SyncClients() (added int, removed int, err error) {
	db, err := database.GetDB()
	if err != nil {
		return 0, 0, err
	}

	// Get existing clients
	existing := make(map[string]int) // ip -> id
	rows, err := db.Query(`SELECT id, ip FROM vpn_clients`)
	if err != nil {
		return 0, 0, err
	}
	for rows.Next() {
		var id int
		var ip string
		if err := rows.Scan(&id, &ip); err != nil {
			continue
		}
		existing[ip] = id
	}
	rows.Close()

	seen := make(map[string]bool)

	// Sync WireGuard peers with full data
	wgSvc := wireguard.GetService()
	if wgSvc != nil {
		peers := wgSvc.ListPeersWithStatus()
		for _, peer := range peers {
			// Strip sensitive keys before storing in database
			peerCopy := *peer
			peerCopy.PrivateKey = ""
			peerCopy.PresharedKey = ""
			rawData, _ := json.Marshal(peerCopy)
			syncClient(db, existing, seen, peer.Name, peer.IPAddress, "wireguard", peer.ID, string(rawData), &added)
		}
	}

	// Sync Headscale nodes with full data
	hsNodes, rawNodes, err := s.getHeadscaleNodesWithRaw()
	if err != nil {
		log.Printf("Warning: failed to get Headscale nodes: %v", err)
	} else {
		routerName := helper.GetEnvOptional("VPN_ROUTER_NAME", "vpn-router")
		for i, node := range hsNodes {
			// Skip router node
			if node.Name == routerName {
				continue
			}
			syncClient(db, existing, seen, node.Name, node.IP, "headscale", node.ID, rawNodes[i], &added)
		}
	}

	// Remove stale clients (no longer in WireGuard or Headscale)
	for ip, id := range existing {
		if !seen[ip] {
			// Delete domain routes for this client first
			domains.DeleteClientRoutes(id)
			// ACL rules are automatically deleted via ON DELETE CASCADE
			_, err := db.Exec(`DELETE FROM vpn_clients WHERE id = ?`, id)
			if err == nil {
				removed++
			}
		}
	}

	// Broadcast node stats update if anything changed
	if added > 0 || removed > 0 {
		ws.BroadcastNodeStats()
	}

	return added, removed, nil
}

type hsNode struct {
	ID   string
	Name string
	IP   string
}

// getHeadscaleNodesWithRaw returns nodes along with their raw JSON data
func (s *Service) getHeadscaleNodesWithRaw() ([]hsNode, []string, error) {
	resp, err := helper.HeadscaleGet("/node")
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, fmt.Errorf("failed to get Headscale nodes: %s", string(body))
	}

	var result struct {
		Nodes []json.RawMessage `json:"nodes"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, nil, err
	}

	nodes := make([]hsNode, 0, len(result.Nodes))
	rawNodes := make([]string, 0, len(result.Nodes))

	for _, rawNode := range result.Nodes {
		var n struct {
			ID        string   `json:"id"`
			Name      string   `json:"name"`
			GivenName string   `json:"givenName"`
			IPAddrs   []string `json:"ipAddresses"`
		}
		if err := json.Unmarshal(rawNode, &n); err != nil {
			continue
		}

		name := n.GivenName
		if name == "" {
			name = n.Name
		}
		ip := ""
		for _, addr := range n.IPAddrs {
			// Prefer IPv4
			if !strings.Contains(addr, ":") {
				ip = addr
				break
			}
		}
		if ip == "" && len(n.IPAddrs) > 0 {
			ip = n.IPAddrs[0]
		}
		nodes = append(nodes, hsNode{ID: n.ID, Name: name, IP: ip})
		rawNodes = append(rawNodes, string(rawNode))
	}
	return nodes, rawNodes, nil
}

// ApplyRules triggers nftables apply and generates Headscale ACL
func (s *Service) ApplyRules() error {
	// Request nftables apply (debounced, applies all registered tables including VPN ACL)
	if nftSvc := nftables.GetService(); nftSvc != nil {
		nftSvc.RequestApply()
	}

	// Generate and apply Headscale ACL
	if err := GenerateAndApplyHeadscaleACL(); err != nil {
		return fmt.Errorf("failed to apply Headscale ACL: %v", err)
	}

	return nil
}

// --- Port Scanner ---

// ScanRequest for POST /api/vpn/clients/{id}/scan
type ScanRequest struct {
	Mode string `json:"mode"` // "common", "range", "full"
}

func (s *Service) handleScanPorts(w http.ResponseWriter, r *http.Request) {
	// Extract client ID from path
	path := strings.TrimPrefix(r.URL.Path, "/api/vpn/clients/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "scan" {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	clientID := parts[0]

	// Get client IP from database
	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var clientIP string
	err = db.QueryRow("SELECT ip FROM vpn_clients WHERE id = ?", clientID).Scan(&clientIP)
	if err == sql.ErrNoRows {
		router.JSONError(w, "client not found", http.StatusNotFound)
		return
	}
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Parse request
	var req ScanRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if req.Mode == "" {
		req.Mode = "common"
	}

	// Get scanner settings
	config := helper.ScanConfig{
		PortStart:  settings.GetSettingInt("scanner_port_start", 1),
		PortEnd:    settings.GetSettingInt("scanner_port_end", 5000),
		Concurrent: settings.GetSettingInt("scanner_concurrent", 100),
		PauseMs:    settings.GetSettingInt("scanner_pause_ms", 0),
		TimeoutMs:  settings.GetSettingInt("scanner_timeout_ms", 500),
	}

	// Create context with timeout (max 5 minutes for full scan)
	ctx, cancel := context.WithTimeout(r.Context(), helper.PortScanTimeout)
	defer cancel()

	var results []helper.PortResult

	switch req.Mode {
	case "common":
		results, err = helper.ScanCommonPorts(ctx, clientIP, config, nil)
	case "range":
		results, err = helper.ScanRange(ctx, clientIP, config.PortStart, config.PortEnd, config, nil)
	case "full":
		results, err = helper.ScanFull(ctx, clientIP, config, nil)
	default:
		router.JSONError(w, "invalid mode: use 'common', 'range', or 'full'", http.StatusBadRequest)
		return
	}

	if err != nil {
		router.JSONError(w, "scan failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]interface{}{
		"clientId": clientID,
		"ip":       clientIP,
		"mode":     req.Mode,
		"ports":    results,
		"count":    len(results),
	})
}
