package firewall

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

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

// handleGetBlocked returns blocked IPs with pagination
func (s *Service) handleGetBlocked(w http.ResponseWriter, r *http.Request) {
	p := router.ParsePagination(r, 25)
	search := r.URL.Query().Get("search")
	jailFilter := r.URL.Query().Get("jail")

	where := "(expires_at IS NULL OR expires_at > datetime('now'))"
	args := []interface{}{}

	if jailFilter != "" {
		where += " AND jail_name = ?"
		args = append(args, jailFilter)
	}

	if search != "" {
		where += " AND (ip LIKE ? ESCAPE '\\' OR jail_name LIKE ? ESCAPE '\\' OR reason LIKE ? ESCAPE '\\')"
		searchPattern := "%" + escapeLikePattern(search) + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM blocked_ips WHERE " + where
	_ = s.db.QueryRow(countQuery, args...).Scan(&total)

	jails := s.getDistinctJails("blocked_ips", "expires_at IS NULL OR expires_at > datetime('now')")

	query := fmt.Sprintf(`SELECT id, ip, jail_name, reason, blocked_at, expires_at, hit_count, manual,
		COALESCE(is_range, 0), COALESCE(escalated_from, ''), COALESCE(source, 'manual')
		FROM blocked_ips WHERE %s ORDER BY blocked_at DESC LIMIT ? OFFSET ?`, where)
	args = append(args, p.Limit, p.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	blocked := []BlockedIP{}
	for rows.Next() {
		var b BlockedIP
		var expiresAt sql.NullString
		if err := rows.Scan(&b.ID, &b.IP, &b.JailName, &b.Reason, &b.BlockedAt, &expiresAt, &b.HitCount, &b.Manual, &b.IsRange, &b.EscalatedFrom, &b.Source); err != nil {
			continue
		}
		if expiresAt.Valid {
			b.ExpiresAt = expiresAt.String
		}
		blocked = append(blocked, b)
	}

	router.JSON(w, map[string]interface{}{
		"blocked": blocked,
		"total":   total,
		"limit":   p.Limit,
		"offset":  p.Offset,
		"jails":   jails,
	})
}

// handleBlockIP manually blocks an IP
func (s *Service) handleBlockIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP      string `json:"ip"`
		Reason  string `json:"reason"`
		BanTime int    `json:"banTime"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	normalizedIP, isRange, err := validateIPOrCIDR(req.IP)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	var expiresAt interface{}
	if req.BanTime > 0 {
		expiresAt = time.Now().Add(time.Duration(req.BanTime) * time.Second)
	}

	_, err = s.db.Exec(`INSERT INTO blocked_ips (ip, jail_name, reason, expires_at, manual, is_range, source) VALUES (?, 'manual', ?, ?, 1, ?, 'manual')`,
		normalizedIP, req.Reason, expiresAt, isRange)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.ApplyRules()
	router.JSON(w, map[string]interface{}{"status": "blocked", "ip": normalizedIP, "isRange": isRange})
}

// handleUnblockIP removes an IP from the block list
func (s *Service) handleUnblockIP(w http.ResponseWriter, r *http.Request) {
	ip := router.ExtractPathParam(r, "/api/fw/blocked/")
	s.db.Exec("DELETE FROM blocked_ips WHERE ip = ?", ip)
	s.ApplyRules()
	w.WriteHeader(http.StatusNoContent)
}

// handleAttempts returns connection attempts with pagination
func (s *Service) handleAttempts(w http.ResponseWriter, r *http.Request) {
	p := router.ParsePagination(r, 25)
	search := r.URL.Query().Get("search")
	jailFilter := r.URL.Query().Get("jail")

	where := "1=1"
	args := []interface{}{}

	if jailFilter != "" {
		where += " AND jail_name = ?"
		args = append(args, jailFilter)
	}

	if search != "" {
		where += " AND (source_ip LIKE ? ESCAPE '\\' OR jail_name LIKE ? ESCAPE '\\' OR protocol LIKE ? ESCAPE '\\' OR CAST(dest_port AS TEXT) LIKE ? ESCAPE '\\')"
		searchPattern := "%" + escapeLikePattern(search) + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern)
	}

	var total int
	countQuery := "SELECT COUNT(*) FROM attempts WHERE " + where
	_ = s.db.QueryRow(countQuery, args...).Scan(&total)

	jails := s.getDistinctJails("attempts", "")

	query := fmt.Sprintf(`SELECT id, timestamp, source_ip, dest_port, protocol, jail_name, action
		FROM attempts WHERE %s ORDER BY timestamp DESC LIMIT ? OFFSET ?`, where)
	args = append(args, p.Limit, p.Offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	attempts := []Attempt{}
	for rows.Next() {
		var a Attempt
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.SourceIP, &a.DestPort, &a.Protocol, &a.JailName, &a.Action); err != nil {
			continue
		}
		attempts = append(attempts, a)
	}

	router.JSON(w, map[string]interface{}{
		"attempts": attempts,
		"total":    total,
		"limit":    p.Limit,
		"offset":   p.Offset,
		"jails":    jails,
	})
}

// handleGetPorts returns allowed ports
func (s *Service) handleGetPorts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT port, protocol, essential, COALESCE(service, '') FROM allowed_ports ORDER BY port")
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	ports := []AllowedPort{}
	for rows.Next() {
		var p AllowedPort
		if err := rows.Scan(&p.Port, &p.Protocol, &p.Essential, &p.Service); err != nil {
			continue
		}
		ports = append(ports, p)
	}

	// Add Docker exposed ports
	dockerPorts := s.getDockerExposedPorts()
	for _, dp := range dockerPorts {
		found := false
		for i, existing := range ports {
			if existing.Port == dp.Port && existing.Protocol == dp.Protocol {
				if existing.Service != "" && dp.Service != "" {
					ports[i].Service = existing.Service + ", " + dp.Service
				} else if dp.Service != "" {
					ports[i].Service = dp.Service
				}
				found = true
				break
			}
		}
		if !found {
			ports = append(ports, dp)
		}
	}

	router.JSON(w, ports)
}

// handleAddPort adds an allowed port
func (s *Service) handleAddPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	isEssential := false
	for _, ep := range s.config.EssentialPorts {
		if req.Port == ep.Port && req.Protocol == ep.Protocol {
			isEssential = true
			if req.Service == "" {
				req.Service = ep.Service
			}
			break
		}
	}

	s.db.Exec("INSERT OR IGNORE INTO allowed_ports (port, protocol, essential, service) VALUES (?, ?, ?, ?)",
		req.Port, req.Protocol, isEssential, req.Service)
	s.ApplyRules()
	router.JSON(w, map[string]interface{}{"port": req.Port, "protocol": req.Protocol, "essential": isEssential, "service": req.Service})
}

// handleRemovePort removes an allowed port
func (s *Service) handleRemovePort(w http.ResponseWriter, r *http.Request) {
	portStr := router.ExtractPathParam(r, "/api/fw/ports/")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		router.JSONError(w, "invalid port", http.StatusBadRequest)
		return
	}

	var essential bool
	_ = s.db.QueryRow("SELECT essential FROM allowed_ports WHERE port = ?", port).Scan(&essential)
	if essential {
		router.JSONError(w, "cannot remove essential port", http.StatusForbidden)
		return
	}

	s.db.Exec("DELETE FROM allowed_ports WHERE port = ?", port)
	s.ApplyRules()
	w.WriteHeader(http.StatusNoContent)
}

// handleGetJails returns all jails
func (s *Service) handleGetJails(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`
		SELECT j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action,
			COUNT(CASE WHEN b.id IS NOT NULL AND (b.expires_at IS NULL OR b.expires_at > datetime('now')) THEN 1 END) as currently_banned,
			COUNT(b.id) as total_banned,
			COALESCE(j.escalate_enabled, 0), COALESCE(j.escalate_threshold, 3), COALESCE(j.escalate_window, 3600)
		FROM jails j
		LEFT JOIN blocked_ips b ON j.name = b.jail_name
		GROUP BY j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action,
			j.escalate_enabled, j.escalate_threshold, j.escalate_window`)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	jails := []Jail{}
	for rows.Next() {
		var j Jail
		if err := rows.Scan(&j.ID, &j.Name, &j.Enabled, &j.LogFile, &j.FilterRegex, &j.MaxRetry, &j.FindTime, &j.BanTime, &j.Port, &j.Action,
			&j.CurrentlyBanned, &j.TotalBanned, &j.EscalateEnabled, &j.EscalateThreshold, &j.EscalateWindow); err != nil {
			continue
		}
		jails = append(jails, j)
	}
	router.JSON(w, jails)
}

// handleCreateJail creates a new jail
func (s *Service) handleCreateJail(w http.ResponseWriter, r *http.Request) {
	var jail Jail
	if !router.DecodeJSONOrError(w, r, &jail) {
		return
	}

	if jail.FilterRegex != "" {
		if _, err := regexp.Compile(jail.FilterRegex); err != nil {
			router.JSONError(w, "invalid regex pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	if jail.EscalateThreshold == 0 {
		jail.EscalateThreshold = 3
	}
	if jail.EscalateWindow == 0 {
		jail.EscalateWindow = 3600
	}

	result, err := s.db.Exec(`INSERT INTO jails (name, enabled, log_file, filter_regex, max_retry, find_time, ban_time, port, action,
		escalate_enabled, escalate_threshold, escalate_window)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		jail.Name, jail.Enabled, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.Port, jail.Action,
		jail.EscalateEnabled, jail.EscalateThreshold, jail.EscalateWindow)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jail.ID, _ = result.LastInsertId()

	if jail.Enabled {
		s.startJailMonitor(jail.ID, jail.Name, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, 0)
	}

	router.JSON(w, jail)
}

// handleGetJail returns a single jail
func (s *Service) handleGetJail(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/fw/jails/")
	var jail Jail
	err := s.db.QueryRow(`
		SELECT j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action,
			COUNT(CASE WHEN b.id IS NOT NULL AND (b.expires_at IS NULL OR b.expires_at > datetime('now')) THEN 1 END) as currently_banned,
			COUNT(b.id) as total_banned,
			COALESCE(j.escalate_enabled, 0), COALESCE(j.escalate_threshold, 3), COALESCE(j.escalate_window, 3600)
		FROM jails j
		LEFT JOIN blocked_ips b ON j.name = b.jail_name
		WHERE j.name = ?
		GROUP BY j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action,
			j.escalate_enabled, j.escalate_threshold, j.escalate_window`,
		name).Scan(&jail.ID, &jail.Name, &jail.Enabled, &jail.LogFile, &jail.FilterRegex,
		&jail.MaxRetry, &jail.FindTime, &jail.BanTime, &jail.Port, &jail.Action, &jail.CurrentlyBanned, &jail.TotalBanned,
		&jail.EscalateEnabled, &jail.EscalateThreshold, &jail.EscalateWindow)
	if err != nil {
		router.JSONError(w, "jail not found", http.StatusNotFound)
		return
	}
	router.JSON(w, jail)
}

// handleUpdateJail updates a jail
func (s *Service) handleUpdateJail(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/fw/jails/")
	var jail Jail
	if !router.DecodeJSONOrError(w, r, &jail) {
		return
	}

	if jail.FilterRegex != "" {
		if _, err := regexp.Compile(jail.FilterRegex); err != nil {
			router.JSONError(w, "invalid regex pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	var jailID int64
	_ = s.db.QueryRow("SELECT id FROM jails WHERE name = ?", name).Scan(&jailID)

	_, err := s.db.Exec(`UPDATE jails SET enabled = ?, log_file = ?, filter_regex = ?, max_retry = ?,
		find_time = ?, ban_time = ?, port = ?, action = ?,
		escalate_enabled = ?, escalate_threshold = ?, escalate_window = ? WHERE name = ?`,
		jail.Enabled, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.Port, jail.Action,
		jail.EscalateEnabled, jail.EscalateThreshold, jail.EscalateWindow, name)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if jailID > 0 {
		s.restartJailMonitor(jailID)
	}

	jail.ID = jailID
	router.JSON(w, jail)
}

// handleDeleteJail deletes a jail
func (s *Service) handleDeleteJail(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/fw/jails/")

	var jailID int64
	_ = s.db.QueryRow("SELECT id FROM jails WHERE name = ?", name).Scan(&jailID)
	if jailID > 0 {
		s.stopJailMonitor(jailID)
	}

	s.db.Exec("DELETE FROM jails WHERE name = ?", name)
	s.db.Exec("DELETE FROM blocked_ips WHERE jail_name = ?", name)
	s.ApplyRules()
	w.WriteHeader(http.StatusNoContent)
}

// handleTraffic returns traffic logs with pagination
func (s *Service) handleTraffic(w http.ResponseWriter, r *http.Request) {
	p := router.ParsePagination(r, 25)
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

	query := fmt.Sprintf(`SELECT id, timestamp, client_ip, dest_ip, dest_port, protocol, domain
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
		if err := rows.Scan(&t.ID, &t.Timestamp, &t.ClientIP, &t.DestIP, &t.DestPort, &t.Protocol, &t.Domain); err != nil {
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

// handleHealth returns health status
func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"status": "ok"})
}

// handleGetSSHPort returns current SSH port
func (s *Service) handleGetSSHPort(w http.ResponseWriter, r *http.Request) {
	port := helper.GetSSHPort()
	router.JSON(w, map[string]interface{}{"port": port})
}

// handleChangeSSHPort changes the SSH port
func (s *Service) handleChangeSSHPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port int `json:"port"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		router.JSONError(w, "invalid port number (must be 1-65535)", http.StatusBadRequest)
		return
	}

	if req.Port < 1024 && req.Port != 22 {
		log.Printf("Warning: changing SSH to privileged port %d", req.Port)
	}

	oldPort := helper.GetSSHPort()
	if oldPort == req.Port {
		router.JSON(w, map[string]interface{}{
			"status":  "unchanged",
			"port":    req.Port,
			"message": "SSH is already on this port",
		})
		return
	}

	// Add new port to firewall
	_, err := s.db.Exec("INSERT OR IGNORE INTO allowed_ports (port, protocol, essential, service) VALUES (?, 'tcp', 1, 'SSH')", req.Port)
	if err != nil {
		router.JSONError(w, "failed to add new port to firewall: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.ApplyRules(); err != nil {
		router.JSONError(w, "failed to apply firewall rules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update sshd_config
	_, err = helper.SetSSHPort(req.Port)
	if err != nil {
		s.db.Exec("DELETE FROM allowed_ports WHERE port = ? AND service = 'SSH'", req.Port)
		s.ApplyRules()
		router.JSONError(w, "failed to update sshd_config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Restart SSH service
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "restart", "sshd")
	if _, err := cmd.CombinedOutput(); err != nil {
		cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "restart", "ssh")
		if _, err2 := cmd.CombinedOutput(); err2 != nil {
			helper.SetSSHPort(oldPort)
			s.db.Exec("DELETE FROM allowed_ports WHERE port = ? AND service = 'SSH'", req.Port)
			s.ApplyRules()
			router.JSONError(w, "failed to restart SSH", http.StatusInternalServerError)
			return
		}
	}

	// Remove old port from firewall
	if oldPort != req.Port {
		s.db.Exec("DELETE FROM allowed_ports WHERE port = ? AND service = 'SSH'", oldPort)
		s.config.EssentialPorts = helper.BuildEssentialPorts()
		s.ApplyRules()
	}

	// Update sshd jail
	s.db.Exec("UPDATE jails SET port = ? WHERE name = 'sshd'", strconv.Itoa(req.Port))

	router.JSON(w, map[string]interface{}{
		"status":  "success",
		"oldPort": oldPort,
		"newPort": req.Port,
		"message": fmt.Sprintf("SSH port changed from %d to %d", oldPort, req.Port),
	})
}

// handleGetBlocklists returns available blocklist sources
func (s *Service) handleGetBlocklists(w http.ResponseWriter, r *http.Request) {
	sources := []BlocklistSource{}
	for _, src := range blocklistSources {
		sources = append(sources, src)
	}
	router.JSON(w, sources)
}

// handleImportBlocklist imports IPs from a blocklist
func (s *Service) handleImportBlocklist(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Source string `json:"source"`
		URL    string `json:"url"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	var entries []string
	var sourceName string

	if req.Source != "" {
		src, exists := blocklistSources[req.Source]
		if !exists {
			router.JSONError(w, "unknown blocklist source", http.StatusBadRequest)
			return
		}
		sourceName = req.Source

		if src.Type == "static" {
			entries = src.Ranges
		} else {
			var err error
			entries, err = s.fetchBlocklist(src.URL, src.MinScore)
			if err != nil {
				router.JSONError(w, "failed to fetch blocklist: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
	} else if req.URL != "" {
		sourceName = "custom"
		var err error
		entries, err = s.fetchBlocklist(req.URL, 0)
		if err != nil {
			router.JSONError(w, "failed to fetch blocklist: "+err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		router.JSONError(w, "source or url required", http.StatusBadRequest)
		return
	}

	added := 0
	skipped := 0
	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" || isPrivateRange(entry) {
			skipped++
			continue
		}

		normalizedIP, isRange, err := validateIPOrCIDR(entry)
		if err != nil {
			skipped++
			continue
		}

		var count int
		_ = s.db.QueryRow("SELECT COUNT(*) FROM blocked_ips WHERE ip = ?", normalizedIP).Scan(&count)
		if count > 0 {
			skipped++
			continue
		}

		_, err = s.db.Exec(`INSERT INTO blocked_ips (ip, jail_name, reason, manual, is_range, source)
			VALUES (?, 'blocklist', ?, 0, ?, ?)`,
			normalizedIP, fmt.Sprintf("Imported from %s", sourceName), isRange, sourceName)
		if err == nil {
			added++
		} else {
			skipped++
		}
	}

	if added > 0 {
		s.ApplyRules()
	}

	router.JSON(w, map[string]interface{}{
		"status":  "imported",
		"source":  sourceName,
		"added":   added,
		"skipped": skipped,
		"total":   len(entries),
	})
}

// handleDeleteBlockedSource deletes all IPs from a source
func (s *Service) handleDeleteBlockedSource(w http.ResponseWriter, r *http.Request) {
	source := router.ExtractPathParam(r, "/api/fw/blocked/source/")
	if source == "" {
		router.JSONError(w, "source required", http.StatusBadRequest)
		return
	}

	result, err := s.db.Exec("DELETE FROM blocked_ips WHERE source = ?", source)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		s.ApplyRules()
	}

	router.JSON(w, map[string]interface{}{
		"status":  "deleted",
		"source":  source,
		"deleted": deleted,
	})
}

// Country blocking handlers

// handleGetCountries returns all available countries
func (s *Service) handleGetCountries(w http.ResponseWriter, r *http.Request) {
	countries := []map[string]interface{}{}
	for _, c := range countryConfigs {
		countries = append(countries, map[string]interface{}{
			"code": c.Code,
			"name": c.Name,
			"flag": c.Flag,
		})
	}
	router.JSON(w, countries)
}

// handleGetBlockedCountries returns blocked countries
func (s *Service) handleGetBlockedCountries(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query(`
		SELECT b.country_code, b.name, b.direction, b.enabled, b.created_at,
			COALESCE(LENGTH(c.zones) - LENGTH(REPLACE(c.zones, char(10), '')) + 1, 0) as range_count
		FROM blocked_countries b
		LEFT JOIN country_zones_cache c ON b.country_code = c.country_code
		ORDER BY b.created_at DESC
	`)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	countries := []BlockedCountry{}
	for rows.Next() {
		var c BlockedCountry
		if err := rows.Scan(&c.CountryCode, &c.Name, &c.Direction, &c.Enabled, &c.CreatedAt, &c.RangeCount); err != nil {
			continue
		}
		countries = append(countries, c)
	}
	router.JSON(w, countries)
}

// blockSingleCountry blocks a single country and returns result info
func (s *Service) blockSingleCountry(countryCode, direction string) (name string, rangeCount int, warning string, err error) {
	countryCode = strings.ToUpper(countryCode)
	if len(countryCode) != 2 {
		return "", 0, "", fmt.Errorf("invalid country code: %s", countryCode)
	}

	name = countryCode
	if cfg, exists := countryConfigs[countryCode]; exists {
		name = cfg.Name
	}

	if direction == "" {
		direction = "inbound"
	}

	var cachedZones string
	queryErr := s.db.QueryRow("SELECT zones FROM country_zones_cache WHERE country_code = ?", countryCode).Scan(&cachedZones)
	zonesExist := queryErr == nil && cachedZones != ""

	_, err = s.db.Exec(`
		INSERT INTO blocked_countries (country_code, name, direction, enabled)
		VALUES (?, ?, ?, 1)
		ON CONFLICT(country_code) DO UPDATE SET direction = ?, enabled = 1
	`, countryCode, name, direction, direction)
	if err != nil {
		return name, 0, "", err
	}

	if !zonesExist {
		zones, fetchErr := s.fetchCountryZones(countryCode)
		if fetchErr != nil {
			log.Printf("Warning: failed to fetch zones for %s: %v", countryCode, fetchErr)
			return name, 0, "failed to fetch zones: " + fetchErr.Error(), nil
		}

		_, err = s.db.Exec(`
			INSERT INTO country_zones_cache (country_code, zones, updated_at)
			VALUES (?, ?, datetime('now'))
			ON CONFLICT(country_code) DO UPDATE SET zones = ?, updated_at = datetime('now')
		`, countryCode, zones, zones)
		if err != nil {
			log.Printf("Warning: failed to cache zones for %s: %v", countryCode, err)
		}
		rangeCount = strings.Count(zones, "\n") + 1
		log.Printf("Country blocked: %s (%s), %d ranges (fetched)", countryCode, name, rangeCount)
	} else {
		rangeCount = strings.Count(cachedZones, "\n") + 1
		if direction == "both" {
			if err := s.updateCountryOutboundSet(cachedZones, true); err != nil {
				log.Printf("Warning: failed to add to outbound set: %v", err)
			}
		} else {
			if err := s.updateCountryOutboundSet(cachedZones, false); err != nil {
				log.Printf("Warning: failed to remove from outbound set: %v", err)
			}
		}
		log.Printf("Country direction updated: %s (%s) -> %s (fast path)", countryCode, name, direction)
	}

	return name, rangeCount, "", nil
}

// handleBlockCountry blocks one or more countries
func (s *Service) handleBlockCountry(w http.ResponseWriter, r *http.Request) {
	var req struct {
		CountryCode  string   `json:"countryCode"`
		CountryCodes []string `json:"countryCodes"`
		Direction    string   `json:"direction"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Direction == "" {
		req.Direction = "inbound"
	}
	if req.Direction != "inbound" && req.Direction != "both" {
		router.JSONError(w, "direction must be 'inbound' or 'both'", http.StatusBadRequest)
		return
	}

	// Build list of country codes to block
	var codes []string
	if len(req.CountryCodes) > 0 {
		codes = req.CountryCodes
	} else if req.CountryCode != "" {
		codes = []string{req.CountryCode}
	} else {
		router.JSONError(w, "countryCode or countryCodes required", http.StatusBadRequest)
		return
	}

	// Block each country
	type result struct {
		CountryCode string `json:"countryCode"`
		Name        string `json:"name"`
		RangeCount  int    `json:"rangeCount"`
		Warning     string `json:"warning,omitempty"`
		Error       string `json:"error,omitempty"`
	}
	results := make([]result, 0, len(codes))
	successCount := 0

	for _, code := range codes {
		name, rangeCount, warning, err := s.blockSingleCountry(code, req.Direction)
		r := result{CountryCode: strings.ToUpper(code), Name: name, RangeCount: rangeCount}
		if err != nil {
			r.Error = err.Error()
		} else {
			successCount++
			if warning != "" {
				r.Warning = warning
			}
		}
		results = append(results, r)
	}

	// Apply rules once after all countries are blocked
	if successCount > 0 {
		if err := s.ApplyRules(); err != nil {
			log.Printf("Warning: failed to apply rules after blocking countries: %v", err)
		}
	}

	// Return single result for single country (backwards compatibility)
	if len(codes) == 1 {
		r := results[0]
		resp := map[string]interface{}{
			"status":      "added",
			"countryCode": r.CountryCode,
			"name":        r.Name,
			"rangeCount":  r.RangeCount,
		}
		if r.Warning != "" {
			resp["warning"] = r.Warning
		}
		if r.Error != "" {
			router.JSONError(w, r.Error, http.StatusInternalServerError)
			return
		}
		router.JSON(w, resp)
		return
	}

	// Return bulk result
	router.JSON(w, map[string]interface{}{
		"status":   "added",
		"count":    successCount,
		"total":    len(codes),
		"results":  results,
	})
}

// handleUnblockCountry removes a country from block list
func (s *Service) handleUnblockCountry(w http.ResponseWriter, r *http.Request) {
	countryCode := router.ExtractPathParam(r, "/api/fw/countries/")
	countryCode = strings.ToUpper(countryCode)
	if countryCode == "" {
		router.JSONError(w, "country code required", http.StatusBadRequest)
		return
	}

	result, err := s.db.Exec("DELETE FROM blocked_countries WHERE country_code = ?", countryCode)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	deleted, _ := result.RowsAffected()
	if deleted > 0 {
		s.db.Exec("DELETE FROM country_zones_cache WHERE country_code = ?", countryCode)
		s.ApplyRules()
	}

	router.JSON(w, map[string]interface{}{
		"status":      "removed",
		"countryCode": countryCode,
	})
}

// handleGetCountryStatus returns country blocking status
func (s *Service) handleGetCountryStatus(w http.ResponseWriter, r *http.Request) {
	var blockedCount, totalRanges int
	var lastUpdate sql.NullString

	s.db.QueryRow("SELECT COUNT(*) FROM blocked_countries WHERE enabled = 1").Scan(&blockedCount)
	s.db.QueryRow(`
		SELECT COALESCE(SUM(LENGTH(c.zones) - LENGTH(REPLACE(c.zones, char(10), '')) + 1), 0)
		FROM country_zones_cache c
		INNER JOIN blocked_countries b ON c.country_code = b.country_code
		WHERE b.enabled = 1
	`).Scan(&totalRanges)
	s.db.QueryRow("SELECT MAX(updated_at) FROM country_zones_cache").Scan(&lastUpdate)

	s.zoneUpdateMutex.RLock()
	status := CountryBlockingStatus{
		Enabled:           blockedCount > 0,
		AutoUpdateEnabled: s.zoneUpdateEnabled,
		AutoUpdateHour:    s.zoneUpdateHour,
		BlockedCount:      blockedCount,
		TotalRanges:       totalRanges,
		LastUpdate:        lastUpdate.String,
	}
	s.zoneUpdateMutex.RUnlock()

	router.JSON(w, status)
}

// handleUpdateCountryScheduler updates zone update scheduler
func (s *Service) handleUpdateCountryScheduler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Enabled bool `json:"enabled"`
		Hour    int  `json:"hour"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Hour < 0 || req.Hour > 23 {
		router.JSONError(w, "hour must be between 0 and 23", http.StatusBadRequest)
		return
	}

	s.zoneUpdateMutex.Lock()
	s.zoneUpdateEnabled = req.Enabled
	s.zoneUpdateHour = req.Hour
	s.zoneUpdateMutex.Unlock()

	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('zone_update_enabled', ?)", strconv.FormatBool(req.Enabled))
	s.db.Exec("INSERT OR REPLACE INTO settings (key, value) VALUES ('zone_update_hour', ?)", strconv.Itoa(req.Hour))

	log.Printf("Zone update scheduler updated: enabled=%v, hour=%d", req.Enabled, req.Hour)

	router.JSON(w, map[string]interface{}{
		"status":  "updated",
		"enabled": req.Enabled,
		"hour":    req.Hour,
	})
}

// handleRefreshCountryZones manually refreshes country zones
func (s *Service) handleRefreshCountryZones(w http.ResponseWriter, r *http.Request) {
	updated, errors := s.refreshAllCountryZones()

	if updated > 0 {
		s.ApplyRules()
	}

	router.JSON(w, map[string]interface{}{
		"status":  "refreshed",
		"updated": updated,
		"errors":  errors,
	})
}

// Helper functions

// getDistinctJails returns distinct jail names from a table
func (s *Service) getDistinctJails(table, whereClause string) []string {
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

// getDockerExposedPorts returns ports exposed by Docker containers
func (s *Service) getDockerExposedPorts() []AllowedPort {
	client := helper.NewDockerHTTPClientWithTimeout(5 * time.Second)

	req, err := http.NewRequest("GET", "http://docker/v1.44/containers/json", nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var rawContainers []struct {
		Names []string
		Ports []struct {
			IP          string
			PrivatePort int
			PublicPort  int
			Type        string
		}
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawContainers); err != nil {
		return nil
	}

	portMap := make(map[string]AllowedPort)

	for _, c := range rawContainers {
		containerName := ""
		if len(c.Names) > 0 {
			containerName = strings.TrimPrefix(c.Names[0], "/")
		}

		for _, p := range c.Ports {
			if p.PublicPort > 0 && (p.IP == "" || p.IP == "0.0.0.0" || p.IP == "::") {
				key := fmt.Sprintf("%d-%s", p.PublicPort, p.Type)
				if _, exists := portMap[key]; !exists {
					portMap[key] = AllowedPort{
						Port:      p.PublicPort,
						Protocol:  p.Type,
						Essential: true,
						Service:   fmt.Sprintf("Docker: %s", containerName),
					}
				}
			}
		}
	}

	ports := []AllowedPort{}
	for _, p := range portMap {
		ports = append(ports, p)
	}

	return ports
}
