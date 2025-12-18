package firewall

import (
	"bufio"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// runVPNTrafficMonitor monitors VPN client outbound traffic
func (s *Service) runVPNTrafficMonitor() {
	logFile := "/var/log/kern.log"
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		logFile = "/var/log/syslog"
	}

	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		log.Printf("VPN traffic monitor: no log file found, skipping")
		return
	}

	log.Printf("Starting VPN traffic monitor: %s", logFile)

	ticker := time.NewTicker(time.Duration(s.config.TrafficMonitorInterval) * time.Second)
	defer ticker.Stop()

	var lastSize int64
	trafficRegex := regexp.MustCompile(`VPN_TRAFFIC:.*SRC=(\d+\.\d+\.\d+\.\d+).*DST=(\d+\.\d+\.\d+\.\d+).*PROTO=(\w+)(?:.*DPT=(\d+))?`)

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("VPN traffic monitor stopping (context cancelled)")
			return
		case <-ticker.C:
			lastSize = s.processVPNTrafficLog(logFile, trafficRegex, lastSize)
		}
	}
}

// processVPNTrafficLog processes the VPN traffic log file
func (s *Service) processVPNTrafficLog(logFile string, trafficRegex *regexp.Regexp, lastSize int64) int64 {
	file, err := os.Open(logFile)
	if err != nil {
		return lastSize
	}
	defer file.Close()

	stat, _ := file.Stat()
	currentSize := stat.Size()

	if currentSize < lastSize || lastSize == 0 {
		return currentSize
	}

	file.Seek(lastSize, 0)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.Contains(line, "VPN_TRAFFIC") {
			continue
		}

		matches := trafficRegex.FindStringSubmatch(line)
		if len(matches) < 4 {
			continue
		}

		srcIP := matches[1]
		dstIP := matches[2]
		proto := strings.ToLower(matches[3])
		dstPort := 0
		if len(matches) >= 5 && matches[4] != "" {
			dstPort, _ = strconv.Atoi(matches[4])
		}

		// Only VPN client traffic
		if !strings.HasPrefix(srcIP, s.config.WgIPPrefix) && !strings.HasPrefix(srcIP, s.config.HeadscaleIPPrefix) {
			continue
		}

		// Skip internal destinations
		if s.isPrivateIP(dstIP) {
			continue
		}

		domain := s.reverseDNS(dstIP)

		s.db.Exec(`
			INSERT INTO traffic_logs (client_ip, dest_ip, dest_port, protocol, domain)
			VALUES (?, ?, ?, ?, ?)
		`, srcIP, dstIP, dstPort, proto, domain)
	}

	// Cleanup old traffic logs
	s.db.Exec("DELETE FROM traffic_logs WHERE id NOT IN (SELECT id FROM traffic_logs ORDER BY timestamp DESC LIMIT ?)", s.config.MaxTrafficLogs)

	return currentSize
}

// runExpirationCleanup periodically cleans up expired bans and old data
func (s *Service) runExpirationCleanup() {
	ticker := time.NewTicker(time.Duration(s.config.CleanupInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("Expiration cleanup stopping (context cancelled)")
			return
		case <-ticker.C:
			s.cleanupExpiredData()
		}
	}
}

// cleanupExpiredData removes expired bans and old attempts
func (s *Service) cleanupExpiredData() {
	// Remove expired bans
	result, err := s.db.Exec("DELETE FROM blocked_ips WHERE expires_at IS NOT NULL AND expires_at < datetime('now')")
	if err == nil {
		if count, _ := result.RowsAffected(); count > 0 {
			log.Printf("Cleaned up %d expired bans", count)
			s.ApplyRules()
		}
	}

	// Cleanup old attempts
	s.db.Exec("DELETE FROM attempts WHERE id NOT IN (SELECT id FROM attempts ORDER BY timestamp DESC LIMIT ?)", s.config.MaxAttempts)
}

// Stop cancels all background goroutines
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}
