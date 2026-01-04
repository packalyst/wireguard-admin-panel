package domains

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"api/internal/adguard"
	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"
	"api/internal/traefik"
)


// Service handles domain routes
type Service struct {
	traefikConfigDir string
	traefikIP        string
}

// DomainRoute represents a domain to port mapping
type DomainRoute struct {
	ID            int       `json:"id"`
	Domain        string    `json:"domain"`
	TargetIP      string    `json:"targetIp"`
	TargetPort    int       `json:"targetPort"`
	VPNClientID   *int      `json:"vpnClientId,omitempty"`
	Enabled       bool      `json:"enabled"`
	HTTPSBackend  bool      `json:"httpsBackend"`
	Middlewares   []string  `json:"middlewares"`
	Description   string    `json:"description"`
	CreatedAt     time.Time `json:"createdAt"`
	UpdatedAt     time.Time `json:"updatedAt"`
	VPNClientName string    `json:"vpnClientName,omitempty"`
}


// New creates a new domains service
func New() *Service {
	svc := &Service{
		traefikConfigDir: helper.GetEnvOptional("TRAEFIK_CONFIG", "/traefik/dynamic"),
		traefikIP:        helper.GetEnvOptional("SERVER_IP", "127.0.0.1"), // Use public IP for DNS rewrites
	}
	log.Printf("Domains service initialized, Traefik config: %s, DNS rewrite IP: %s", svc.traefikConfigDir, svc.traefikIP)
	return svc
}

// ApplyRoutes generates Traefik config and syncs AdGuard DNS (exported for use by other packages)
func ApplyRoutes() error {
	traefikConfigDir := helper.GetEnvOptional("TRAEFIK_CONFIG", "/traefik/dynamic")
	traefikIP := helper.GetEnvOptional("SERVER_IP", "127.0.0.1")

	db, err := database.GetDB()
	if err != nil {
		return err
	}

	// Get all enabled routes
	rows, err := db.Query(`
		SELECT domain, target_ip, target_port, https_backend, middlewares
		FROM domain_routes
		WHERE enabled = 1
		ORDER BY domain
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	routes := []traefik.DomainRouteConfig{}
	for rows.Next() {
		var rc traefik.DomainRouteConfig
		var middlewaresJSON string
		if err := rows.Scan(&rc.Domain, &rc.TargetIP, &rc.TargetPort, &rc.HTTPSBackend, &middlewaresJSON); err != nil {
			continue
		}
		if err := json.Unmarshal([]byte(middlewaresJSON), &rc.Middlewares); err != nil {
			rc.Middlewares = []string{}
		}
		routes = append(routes, rc)
	}

	// Generate Traefik config
	if err := traefik.GenerateDomainRoutes(traefikConfigDir, routes); err != nil {
		return fmt.Errorf("failed to generate Traefik config: %v", err)
	}

	// Convert to adguard.DomainRoute for DNS sync
	adguardDomains := make([]adguard.DomainRoute, len(routes))
	for i, r := range routes {
		adguardDomains[i] = adguard.DomainRoute{Domain: r.Domain}
	}

	// Sync AdGuard DNS (log errors but don't fail the operation)
	dnsErrors := adguard.SyncDomainRewrites(adguardDomains, traefikIP)
	if len(dnsErrors) > 0 {
		log.Printf("DNS sync warnings: %v", dnsErrors)
	}

	log.Printf("Applied %d domain routes", len(routes))
	return nil
}

// applyRoutes calls the exported ApplyRoutes function (internal wrapper for service methods)
func (s *Service) applyRoutes() error {
	return ApplyRoutes()
}

// DeleteClientRoutes removes all domain routes for a VPN client and applies changes
func DeleteClientRoutes(clientID int) (int, error) {
	db, err := database.GetDB()
	if err != nil {
		return 0, err
	}

	result, err := db.Exec(`DELETE FROM domain_routes WHERE vpn_client_id = ?`, clientID)
	if err != nil {
		return 0, err
	}

	rows, _ := result.RowsAffected()
	if rows > 0 {
		log.Printf("Deleted %d domain routes for VPN client %d", rows, clientID)
		if err := ApplyRoutes(); err != nil {
			log.Printf("Warning: failed to apply routes after client deletion: %v", err)
		}
	}

	return int(rows), nil
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"List":   s.handleList,
		"Get":    s.handleGet,
		"Create": s.handleCreate,
		"Update": s.handleUpdate,
		"Delete": s.handleDelete,
		"Toggle": s.handleToggle,
	}
}

func (s *Service) handleList(w http.ResponseWriter, r *http.Request) {
	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, err := db.Query(`
		SELECT d.id, d.domain, d.target_ip, d.target_port, d.vpn_client_id,
		       d.enabled, d.https_backend, d.middlewares, d.description,
		       d.created_at, d.updated_at, COALESCE(v.name, '') as vpn_client_name
		FROM domain_routes d
		LEFT JOIN vpn_clients v ON d.vpn_client_id = v.id
		ORDER BY d.domain
	`)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	routes := []DomainRoute{}
	for rows.Next() {
		var route DomainRoute
		var vpnClientID sql.NullInt64
		var middlewaresJSON string
		if err := rows.Scan(
			&route.ID, &route.Domain, &route.TargetIP, &route.TargetPort,
			&vpnClientID, &route.Enabled, &route.HTTPSBackend, &middlewaresJSON,
			&route.Description, &route.CreatedAt, &route.UpdatedAt, &route.VPNClientName,
		); err != nil {
			continue
		}
		if vpnClientID.Valid {
			id := int(vpnClientID.Int64)
			route.VPNClientID = &id
		}
		// Parse middlewares JSON
		if err := json.Unmarshal([]byte(middlewaresJSON), &route.Middlewares); err != nil {
			route.Middlewares = []string{}
		}
		routes = append(routes, route)
	}

	router.JSON(w, map[string]interface{}{
		"routes": routes,
		"count":  len(routes),
	})
}

func (s *Service) handleGet(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/domains/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	var route DomainRoute
	var vpnClientID sql.NullInt64
	var middlewaresJSON string
	err = db.QueryRow(`
		SELECT d.id, d.domain, d.target_ip, d.target_port, d.vpn_client_id,
		       d.enabled, d.https_backend, d.middlewares, d.description,
		       d.created_at, d.updated_at, COALESCE(v.name, '') as vpn_client_name
		FROM domain_routes d
		LEFT JOIN vpn_clients v ON d.vpn_client_id = v.id
		WHERE d.id = ?
	`, id).Scan(
		&route.ID, &route.Domain, &route.TargetIP, &route.TargetPort,
		&vpnClientID, &route.Enabled, &route.HTTPSBackend, &middlewaresJSON,
		&route.Description, &route.CreatedAt, &route.UpdatedAt, &route.VPNClientName,
	)
	if err == sql.ErrNoRows {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if vpnClientID.Valid {
		id := int(vpnClientID.Int64)
		route.VPNClientID = &id
	}
	if err := json.Unmarshal([]byte(middlewaresJSON), &route.Middlewares); err != nil {
		route.Middlewares = []string{}
	}

	router.JSON(w, route)
}

// CreateRequest for creating a domain route
type CreateRequest struct {
	Domain       string   `json:"domain"`
	TargetIP     string   `json:"targetIp"`
	TargetPort   int      `json:"targetPort"`
	VPNClientID  *int     `json:"vpnClientId,omitempty"`
	HTTPSBackend bool     `json:"httpsBackend"`
	Middlewares  []string `json:"middlewares"`
	Description  string   `json:"description"`
}

func (s *Service) handleCreate(w http.ResponseWriter, r *http.Request) {
	var req CreateRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate domain
	req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
	if err := helper.ValidateDomain(req.Domain); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate IP
	req.TargetIP = strings.TrimSpace(req.TargetIP)
	if err := helper.ValidateIP(req.TargetIP); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate port
	if err := helper.ValidatePort(req.TargetPort); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Serialize middlewares to JSON
	middlewaresJSON, _ := json.Marshal(req.Middlewares)
	if req.Middlewares == nil {
		middlewaresJSON = []byte("[]")
	}

	result, err := db.Exec(`
		INSERT INTO domain_routes (domain, target_ip, target_port, vpn_client_id, https_backend, middlewares, description)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`, req.Domain, req.TargetIP, req.TargetPort, req.VPNClientID, req.HTTPSBackend, string(middlewaresJSON), req.Description)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			router.JSONError(w, "domain already exists", http.StatusConflict)
			return
		}
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	id, _ := result.LastInsertId()

	// Auto-apply after create
	if err := s.applyRoutes(); err != nil {
		log.Printf("Warning: failed to apply routes after create: %v", err)
	}

	router.JSON(w, map[string]interface{}{
		"id":      id,
		"message": "route created and applied",
	})
}

// UpdateRequest for updating a domain route
type UpdateRequest struct {
	Domain       *string   `json:"domain,omitempty"`
	TargetIP     *string   `json:"targetIp,omitempty"`
	TargetPort   *int      `json:"targetPort,omitempty"`
	VPNClientID  *int      `json:"vpnClientId,omitempty"`
	HTTPSBackend *bool     `json:"httpsBackend,omitempty"`
	Middlewares  *[]string `json:"middlewares,omitempty"`
	Description  *string   `json:"description,omitempty"`
}

func (s *Service) handleUpdate(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/domains/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	var req UpdateRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	// Validate fields if provided
	if req.Domain != nil {
		domain := strings.TrimSpace(strings.ToLower(*req.Domain))
		if err := helper.ValidateDomain(domain); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		*req.Domain = domain
	}
	if req.TargetIP != nil {
		ip := strings.TrimSpace(*req.TargetIP)
		if err := helper.ValidateIP(ip); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
		*req.TargetIP = ip
	}
	if req.TargetPort != nil {
		if err := helper.ValidatePort(*req.TargetPort); err != nil {
			router.JSONError(w, err.Error(), http.StatusBadRequest)
			return
		}
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Build dynamic update query
	updates := []string{}
	args := []interface{}{}

	if req.Domain != nil {
		updates = append(updates, "domain = ?")
		args = append(args, *req.Domain)
	}
	if req.TargetIP != nil {
		updates = append(updates, "target_ip = ?")
		args = append(args, *req.TargetIP)
	}
	if req.TargetPort != nil {
		updates = append(updates, "target_port = ?")
		args = append(args, *req.TargetPort)
	}
	if req.VPNClientID != nil {
		updates = append(updates, "vpn_client_id = ?")
		args = append(args, *req.VPNClientID)
	}
	if req.HTTPSBackend != nil {
		updates = append(updates, "https_backend = ?")
		args = append(args, *req.HTTPSBackend)
	}
	if req.Middlewares != nil {
		middlewaresJSON, _ := json.Marshal(*req.Middlewares)
		updates = append(updates, "middlewares = ?")
		args = append(args, string(middlewaresJSON))
	}
	if req.Description != nil {
		updates = append(updates, "description = ?")
		args = append(args, *req.Description)
	}

	if len(updates) == 0 {
		router.JSONError(w, "no fields to update", http.StatusBadRequest)
		return
	}

	updates = append(updates, "updated_at = CURRENT_TIMESTAMP")
	args = append(args, id)

	query := fmt.Sprintf("UPDATE domain_routes SET %s WHERE id = ?", strings.Join(updates, ", "))
	result, err := db.Exec(query, args...)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			router.JSONError(w, "domain already exists", http.StatusConflict)
			return
		}
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}

	// Auto-apply after update
	if err := s.applyRoutes(); err != nil {
		log.Printf("Warning: failed to apply routes after update: %v", err)
	}

	router.JSON(w, map[string]string{"message": "route updated and applied"})
}

func (s *Service) handleDelete(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/domains/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Get domain first (need it for AdGuard cleanup)
	var domain string
	err = db.QueryRow("SELECT domain FROM domain_routes WHERE id = ?", id).Scan(&domain)
	if err != nil {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}

	// Step 1: Delete AdGuard rewrite first
	if err := adguard.DeleteDomainRewrite(domain, s.traefikIP); err != nil {
		router.JSONError(w, "failed to delete DNS rewrite: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Step 2: Delete from database
	result, err := db.Exec("DELETE FROM domain_routes WHERE id = ?", id)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}

	// Step 3: Regenerate Traefik config
	if err := s.applyRoutes(); err != nil {
		router.JSONError(w, "route deleted but failed to update Traefik: "+err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]string{"message": "route deleted and applied"})
}

func (s *Service) handleToggle(w http.ResponseWriter, r *http.Request) {
	idStr := router.ExtractPathParam(r, "/api/domains/")
	id, ok := router.ParseIDOrError(w, idStr)
	if !ok {
		return
	}

	db, err := database.GetDB()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	result, err := db.Exec(`
		UPDATE domain_routes
		SET enabled = NOT enabled, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, id)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		router.JSONError(w, "route not found", http.StatusNotFound)
		return
	}

	// Get new state
	var enabled bool
	if err := db.QueryRow("SELECT enabled FROM domain_routes WHERE id = ?", id).Scan(&enabled); err != nil {
		router.JSONError(w, "failed to get new state", http.StatusInternalServerError)
		return
	}

	// Auto-apply after toggle
	if err := s.applyRoutes(); err != nil {
		log.Printf("Warning: failed to apply routes after toggle: %v", err)
	}

	router.JSON(w, map[string]interface{}{
		"message": "route toggled and applied",
		"enabled": enabled,
	})
}
