package firewall

import (
	"fmt"
	"log"
	"strings"
	"time"
)

// blockIP blocks an IP address from a jail
func (s *Service) blockIP(ip, jailName, reason string, banTime int) {
	s.blockIPWithOptions(ip, jailName, reason, banTime, false, "", "jail:"+jailName)
}

// blockIPWithOptions blocks an IP with additional options
func (s *Service) blockIPWithOptions(ip, jailName, reason string, banTime int, isRange bool, escalatedFrom, source string) {
	var expiresAt interface{}
	if banTime > 0 {
		expiresAt = time.Now().Add(time.Duration(banTime) * time.Second)
	}

	_, err := s.db.Exec(`
		INSERT INTO blocked_ips (ip, jail_name, reason, expires_at, hit_count, manual, is_range, escalated_from, source)
		VALUES (?, ?, ?, ?, 1, 0, ?, ?, ?)
		ON CONFLICT(ip, jail_name) DO UPDATE SET
			hit_count = hit_count + 1,
			blocked_at = CURRENT_TIMESTAMP,
			expires_at = excluded.expires_at,
			reason = excluded.reason
	`, ip, jailName, reason, expiresAt, isRange, escalatedFrom, source)

	if err == nil {
		log.Printf("Blocked IP %s (jail: %s, reason: %s, isRange: %v)", ip, jailName, reason, isRange)
		s.ApplyRules()

		// Check for auto-escalation (only for individual IPs, not ranges)
		if !isRange {
			s.checkEscalation(ip, jailName, banTime)
		}
	}
}

// checkEscalation checks if we should escalate to blocking an entire /24 range
func (s *Service) checkEscalation(ip, jailName string, banTime int) {
	// Get jail's escalation settings
	var escalateEnabled bool
	var escalateThreshold, escalateWindow int
	err := s.db.QueryRow(`SELECT COALESCE(escalate_enabled, 0), COALESCE(escalate_threshold, 3), COALESCE(escalate_window, 3600)
		FROM jails WHERE name = ?`, jailName).Scan(&escalateEnabled, &escalateThreshold, &escalateWindow)
	if err != nil || !escalateEnabled {
		return
	}

	// Get the /24 subnet for this IP
	subnet := getSubnet24(ip)
	if subnet == "" {
		return
	}

	// Count distinct IPs from this subnet blocked within the escalation window
	var count int
	err = s.db.QueryRow(`
		SELECT COUNT(DISTINCT ip) FROM blocked_ips
		WHERE jail_name = ?
		AND is_range = 0
		AND ip LIKE ?
		AND blocked_at > datetime('now', '-' || ? || ' seconds')
	`, jailName, strings.TrimSuffix(subnet, ".0/24")+".%", escalateWindow).Scan(&count)
	if err != nil {
		log.Printf("Error checking escalation: %v", err)
		return
	}

	log.Printf("Escalation check for %s: %d IPs from %s (threshold: %d)", jailName, count, subnet, escalateThreshold)

	if count >= escalateThreshold {
		// Block the entire /24 range
		log.Printf("Auto-escalating: blocking %s (jail: %s, IPs: %d)", subnet, jailName, count)

		// Insert the range block
		_, err := s.db.Exec(`
			INSERT INTO blocked_ips (ip, jail_name, reason, expires_at, hit_count, manual, is_range, escalated_from, source)
			VALUES (?, ?, ?, ?, ?, 0, 1, ?, ?)
			ON CONFLICT(ip, jail_name) DO NOTHING
		`, subnet, jailName,
			fmt.Sprintf("Auto-escalated: %d IPs from this range blocked", count),
			func() interface{} {
				if banTime > 0 {
					return time.Now().Add(time.Duration(banTime) * time.Second)
				}
				return nil
			}(),
			count, jailName, "escalated")

		if err != nil {
			log.Printf("Error inserting escalated range: %v", err)
			return
		}

		// Remove individual IPs that are now covered by the range
		result, err := s.db.Exec(`
			DELETE FROM blocked_ips
			WHERE jail_name = ?
			AND is_range = 0
			AND ip LIKE ?
		`, jailName, strings.TrimSuffix(subnet, ".0/24")+".%")
		if err == nil {
			if deleted, _ := result.RowsAffected(); deleted > 0 {
				log.Printf("Removed %d individual IPs now covered by range %s", deleted, subnet)
			}
		}

		s.ApplyRules()
	}
}

// isIPBlocked checks if an IP is currently blocked
func (s *Service) isIPBlocked(ip string) bool {
	var count int
	// Check direct IP match
	err := s.db.QueryRow(`
		SELECT COUNT(*) FROM blocked_ips
		WHERE ip = ? AND (expires_at IS NULL OR expires_at > datetime('now'))
	`, ip).Scan(&count)
	if err == nil && count > 0 {
		return true
	}

	// Check if IP is in any blocked CIDR range
	rows, err := s.db.Query(`
		SELECT ip FROM blocked_ips
		WHERE is_range = 1 AND (expires_at IS NULL OR expires_at > datetime('now'))
	`)
	if err != nil {
		return false
	}
	defer rows.Close()

	for rows.Next() {
		var cidr string
		if err := rows.Scan(&cidr); err != nil {
			continue
		}
		if isIPInRange(ip, cidr) {
			return true
		}
	}
	return false
}

// recordAttempt logs a connection attempt
func (s *Service) recordAttempt(srcIP string, destPort int, protocol, jailName, action string) {
	s.db.Exec(`
		INSERT INTO attempts (source_ip, dest_port, protocol, jail_name, action)
		VALUES (?, ?, ?, ?, ?)
	`, srcIP, destPort, protocol, jailName, action)
}
