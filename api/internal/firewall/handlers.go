package firewall

import (
	"fmt"
	"log"
	"net/http"

	"api/internal/router"
)

// validSQLIdentifiers whitelists allowed table and column names for dynamic SQL
// This prevents SQL injection when interpolating identifiers
var validSQLIdentifiers = map[string]bool{
	// Tables
	"blocked_ips":   true,
	"attempts":      true,
	"traffic_logs":  true,
	"allowed_ports": true,
	"jails":         true,
	// Columns
	"jail_name": true,
	"client_ip": true,
	"ip":        true,
	"port":      true,
	"protocol":  true,
}

// isValidSQLIdentifier checks if a table or column name is whitelisted
func isValidSQLIdentifier(name string) bool {
	if !validSQLIdentifiers[name] {
		log.Printf("Warning: invalid SQL identifier rejected: %s", name)
		return false
	}
	return true
}

// handleStatus returns firewall status summary
func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	var blockedCount, attemptsCount, portsCount, jailsCount int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM blocked_ips WHERE expires_at IS NULL OR expires_at > datetime('now')").Scan(&blockedCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM attempts").Scan(&attemptsCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM allowed_ports").Scan(&portsCount)
	_ = s.db.QueryRow("SELECT COUNT(*) FROM jails WHERE enabled = 1").Scan(&jailsCount)

	router.JSON(w, map[string]interface{}{
		"enabled":        true,
		"defaultPolicy":  "drop",
		"blockedIPCount": blockedCount,
		"recentAttempts": attemptsCount,
		"allowedPorts":   portsCount,
		"activeJails":    jailsCount,
	})
}

// handleGetConfig returns current configuration
func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, s.config)
}

// handleUpdateConfig updates configuration
func (s *Service) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if !router.DecodeJSONOrError(w, r, &s.config) {
		return
	}
	router.JSON(w, s.config)
}

// handleApplyRules manually applies firewall rules
func (s *Service) handleApplyRules(w http.ResponseWriter, r *http.Request) {
	if err := s.ApplyRules(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "applied"})
}

// Helper functions

// getDistinctJails returns distinct jail names from a table
func (s *Service) getDistinctJails(table, whereClause string) []string {
	if !isValidSQLIdentifier(table) {
		return []string{}
	}

	query := fmt.Sprintf("SELECT DISTINCT jail_name FROM %s", table)
	if whereClause != "" {
		query += " WHERE " + whereClause
	}
	query += " ORDER BY jail_name"

	rows, err := s.db.Query(query)
	if err != nil {
		return []string{}
	}
	defer rows.Close()

	jails := []string{}
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			continue
		}
		jails = append(jails, j)
	}
	return jails
}

// getDistinctValues returns distinct values from a column
func (s *Service) getDistinctValues(table, column string) []string {
	if !isValidSQLIdentifier(table) || !isValidSQLIdentifier(column) {
		return []string{}
	}

	query := fmt.Sprintf("SELECT DISTINCT %s FROM %s ORDER BY %s", column, table, column)

	rows, err := s.db.Query(query)
	if err != nil {
		return []string{}
	}
	defer rows.Close()

	values := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			continue
		}
		values = append(values, v)
	}
	return values
}
