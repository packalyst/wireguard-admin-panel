package vpn

import (
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
	"api/internal/helper"
	"api/internal/router"
	"api/internal/wireguard"
)

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
		"GetClients":    s.handleGetClients,
		"GetClient":     s.handleGetClient,
		"UpdateACL":     s.handleUpdateACL,
		"SyncClients":   s.handleSyncClients,
		"ApplyRules":    s.handleApplyRules,
		"ToggleDNS":     s.handleToggleDNS,
		// Router Management
		"GetRouterStatus": s.handleGetRouterStatus,
		"SetupRouter":     s.handleSetupRouter,
		"RestartRouter":   s.handleRestartRouter,
		"RemoveRouter":    s.handleRemoveRouter,
		// Health
		"Health": s.handleHealth,
	}
}

// --- Client Handlers ---

func (s *Service) handleGetClients(w http.ResponseWriter, r *http.Request) {
	// Auto-sync to get fresh data from WireGuard and Headscale
	s.SyncClients()

	db := database.Get()
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
	id, err := strconv.Atoi(idStr)
	if err != nil {
		router.JSONError(w, "invalid client ID", http.StatusBadRequest)
		return
	}

	db := database.Get()
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

	db := database.Get()
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

	db := database.Get()
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

func (s *Service) handleSyncClients(w http.ResponseWriter, r *http.Request) {
	added, removed, err := s.SyncClients()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]interface{}{
		"status":  "ok",
		"added":   added,
		"removed": removed,
	})
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

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"status": "ok"})
}

// --- Helper Methods ---

func (s *Service) getClientACLRules(clientID int) []ACLRule {
	db := database.Get()

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
	db := database.Get()

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
			seen[peer.IPAddress] = true
			// Strip sensitive keys before storing in database
			peerCopy := *peer
			peerCopy.PrivateKey = ""
			peerCopy.PresharedKey = ""
			rawData, _ := json.Marshal(peerCopy)

			if id, exists := existing[peer.IPAddress]; exists {
				// Update existing record with fresh data
				db.Exec(`
					UPDATE vpn_clients SET name = ?, raw_data = ?, updated_at = CURRENT_TIMESTAMP
					WHERE id = ?
				`, peer.Name, string(rawData), id)
			} else {
				// Insert new record
				_, err := db.Exec(`
					INSERT INTO vpn_clients (name, ip, type, external_id, raw_data, acl_policy)
					VALUES (?, ?, 'wireguard', ?, ?, ?)
				`, peer.Name, peer.IPAddress, peer.ID, string(rawData), helper.DefaultACLPolicy)
				if err == nil {
					added++
				}
			}
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
			seen[node.IP] = true

			if id, exists := existing[node.IP]; exists {
				// Update existing record with fresh data
				db.Exec(`
					UPDATE vpn_clients SET name = ?, raw_data = ?, updated_at = CURRENT_TIMESTAMP
					WHERE id = ?
				`, node.Name, rawNodes[i], id)
			} else {
				// Insert new record
				_, err := db.Exec(`
					INSERT INTO vpn_clients (name, ip, type, external_id, raw_data, acl_policy)
					VALUES (?, ?, 'headscale', ?, ?, ?)
				`, node.Name, node.IP, node.ID, rawNodes[i], helper.DefaultACLPolicy)
				if err == nil {
					added++
				}
			}
		}
	}

	// Remove stale clients (no longer in WireGuard or Headscale)
	for ip, id := range existing {
		if !seen[ip] {
			_, err := db.Exec(`DELETE FROM vpn_clients WHERE id = ?`, id)
			if err == nil {
				removed++
			}
		}
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

// ApplyRules generates and applies nftables rules and Headscale ACL
func (s *Service) ApplyRules() error {
	// Generate and apply nftables rules
	if err := GenerateAndApplyNftables(); err != nil {
		return fmt.Errorf("failed to apply nftables: %v", err)
	}

	// Generate and apply Headscale ACL
	if err := GenerateAndApplyHeadscaleACL(); err != nil {
		return fmt.Errorf("failed to apply Headscale ACL: %v", err)
	}

	return nil
}
