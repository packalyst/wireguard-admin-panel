package firewall

import (
	"fmt"
	"net/http"
	"strings"

	"api/internal/helper"
	"api/internal/router"
)

// handleTraffic returns traffic logs with pagination
func (s *Service) handleTraffic(w http.ResponseWriter, r *http.Request) {
	p := router.ParsePagination(r, helper.DefaultPaginationLimit)
	search := r.URL.Query().Get("search")
	clientIP := r.URL.Query().Get("client")

	where := "1=1"
	args := []interface{}{}

	if clientIP != "" {
		where += " AND client_ip = ?"
		args = append(args, clientIP)
	}

	if search != "" {
		where += " AND (client_ip LIKE ? ESCAPE '\\' OR dest_ip LIKE ? ESCAPE '\\' OR domain LIKE ? ESCAPE '\\' OR protocol LIKE ? ESCAPE '\\' OR CAST(dest_port AS TEXT) LIKE ? ESCAPE '\\')"
		searchPattern := "%" + escapeLikePattern(search) + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM traffic_logs WHERE " + where
	_ = s.db.QueryRow(countQuery, args...).Scan(&total)

	clients := s.getDistinctValues("traffic_logs", "client_ip")

	query := fmt.Sprintf(`SELECT id, timestamp, client_ip, dest_ip, dest_port, protocol, domain, COALESCE(country, '')
		FROM traffic_logs WHERE %s ORDER BY timestamp DESC LIMIT ? OFFSET ?`, where)
	args = append(args, p.Limit, p.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	logs := []TrafficLog{}
	for rows.Next() {
		var t TrafficLog
		if err := rows.Scan(&t.ID, &t.Timestamp, &t.ClientIP, &t.DestIP, &t.DestPort, &t.Protocol, &t.Domain, &t.Country); err != nil {
			continue
		}
		logs = append(logs, t)
	}

	router.JSON(w, map[string]interface{}{
		"logs":    logs,
		"total":   total,
		"limit":   p.Limit,
		"offset":  p.Offset,
		"clients": clients,
	})
}

// handleTrafficStats returns traffic statistics
func (s *Service) handleTrafficStats(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`SELECT dest_ip, domain, COUNT(*) as connections, MAX(timestamp) as last_seen,
		GROUP_CONCAT(DISTINCT client_ip) as clients FROM traffic_logs
		GROUP BY dest_ip ORDER BY connections DESC LIMIT 100`)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	type Stats struct {
		DestIP      string   `json:"destIP"`
		Domain      string   `json:"domain"`
		Connections int      `json:"connections"`
		LastSeen    string   `json:"lastSeen"`
		Clients     []string `json:"clients"`
	}

	stats := []Stats{}
	for rows.Next() {
		var st Stats
		var clients string
		if err := rows.Scan(&st.DestIP, &st.Domain, &st.Connections, &st.LastSeen, &clients); err != nil {
			continue
		}
		if clients != "" {
			st.Clients = strings.Split(clients, ",")
		}
		stats = append(stats, st)
	}
	router.JSON(w, stats)
}

// handleTrafficLive returns live traffic metrics
func (s *Service) handleTrafficLive(w http.ResponseWriter, r *http.Request) {
	var totalConns, uniqueDests, activeClients int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM traffic_logs WHERE timestamp > datetime('now', '-5 minutes')").Scan(&totalConns)
	_ = s.db.QueryRow("SELECT COUNT(DISTINCT dest_ip) FROM traffic_logs WHERE timestamp > datetime('now', '-5 minutes')").Scan(&uniqueDests)
	_ = s.db.QueryRow("SELECT COUNT(DISTINCT client_ip) FROM traffic_logs WHERE timestamp > datetime('now', '-5 minutes')").Scan(&activeClients)

	router.JSON(w, map[string]interface{}{
		"totalConnections":   totalConns,
		"uniqueDestinations": uniqueDests,
		"activeClients":      activeClients,
		"periodMinutes":      5,
	})
}
