package firewall

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"

	"api/internal/helper"
	"api/internal/router"
)

// handleGetBlocked returns blocked IPs with pagination
func (s *Service) handleGetBlocked(w http.ResponseWriter, r *http.Request) {
	p := router.ParsePagination(r, helper.DefaultPaginationLimit)
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
	p := router.ParsePagination(r, helper.DefaultPaginationLimit)
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
