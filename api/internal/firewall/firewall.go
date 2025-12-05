package firewall

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/config"
	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"
)

// dnsEntry holds a cached DNS lookup with timestamp
type dnsEntry struct {
	domain    string
	timestamp time.Time
}

// Service handles firewall operations
type Service struct {
	db        *sql.DB
	dbMutex   sync.RWMutex
	config    Config
	dnsCache  map[string]dnsEntry
	dnsMutex  sync.RWMutex
	ctx       context.Context
	cancel    context.CancelFunc
}

// Config holds firewall configuration
type Config struct {
	EssentialPorts         []helper.EssentialPort `json:"-"`
	IgnoreNetworks         []string               `json:"ignoreNetworks"`
	MaxAttempts            int                    `json:"maxAttempts"`
	MaxTrafficLogs         int                    `json:"maxTrafficLogs"`
	DataDir                string                 `json:"-"`
	WgPort                 int                    `json:"-"`
	WgIPPrefix             string                 `json:"-"` // e.g., "100.65."
	HeadscaleIPPrefix      string                 `json:"-"` // e.g., "100.64."
	JailCheckInterval      int                    `json:"-"` // seconds
	TrafficMonitorInterval int                    `json:"-"` // seconds
	CleanupInterval        int                    `json:"-"` // minutes
	DNSLookupTimeout       int                    `json:"-"` // seconds
}

// Jail represents a blocking rule configuration
type Jail struct {
	ID              int64  `json:"id"`
	Name            string `json:"name"`
	Enabled         bool   `json:"enabled"`
	LogFile         string `json:"logFile"`
	FilterRegex     string `json:"filterRegex"`
	MaxRetry        int    `json:"maxRetry"`
	FindTime        int    `json:"findTime"`
	BanTime         int    `json:"banTime"`
	Port            string `json:"port"`
	Action          string `json:"action"`
	CurrentlyBanned int    `json:"currentlyBanned"`
	TotalBanned     int    `json:"totalBanned"`
}

// BlockedIP represents a blocked IP address
type BlockedIP struct {
	ID        int64     `json:"id"`
	IP        string    `json:"ip"`
	JailName  string    `json:"jailName"`
	Reason    string    `json:"reason"`
	BlockedAt time.Time `json:"blockedAt"`
	ExpiresAt time.Time `json:"expiresAt,omitempty"`
	HitCount  int       `json:"hitCount"`
	Manual    bool      `json:"manual"`
}

// Attempt represents a logged connection attempt
type Attempt struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	SourceIP  string    `json:"sourceIP"`
	DestPort  int       `json:"destPort"`
	Protocol  string    `json:"protocol"`
	JailName  string    `json:"jailName"`
	Action    string    `json:"action"`
}

// TrafficLog represents VPN client outbound traffic
type TrafficLog struct {
	ID        int64     `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	ClientIP  string    `json:"clientIP"`
	DestIP    string    `json:"destIP"`
	DestPort  int       `json:"destPort"`
	Protocol  string    `json:"protocol"`
	Domain    string    `json:"domain"`
}

// AllowedPort represents an allowed port
type AllowedPort struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Essential bool   `json:"essential"`
	Service   string `json:"service,omitempty"`
}

// New creates a new firewall service
func New(dataDir string) (*Service, error) {
	// Get shared database instance
	db := database.Get()
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// Get config from JSON
	fwCfg := config.GetFirewallConfig()

	// Create cancellable context for background tasks
	ctx, cancel := context.WithCancel(context.Background())

	svc := &Service{
		db:       db,
		dnsCache: make(map[string]dnsEntry),
		ctx:      ctx,
		cancel:   cancel,
		config: Config{
			EssentialPorts:         helper.BuildEssentialPorts(),
			IgnoreNetworks:         helper.ParseStringList(helper.GetEnv("IGNORE_NETWORKS")),
			MaxAttempts:            fwCfg.MaxAttempts,
			MaxTrafficLogs:         fwCfg.MaxTrafficLogs,
			DataDir:                dataDir,
			WgPort:                 helper.GetEnvInt("WG_PORT"),
			WgIPPrefix:             helper.ExtractIPPrefix(helper.GetEnv("WG_IP_RANGE")),
			HeadscaleIPPrefix:      helper.ExtractIPPrefix(helper.GetEnv("HEADSCALE_IP_RANGE")),
			JailCheckInterval:      fwCfg.JailCheckIntervalSec,
			TrafficMonitorInterval: fwCfg.TrafficMonitorIntervalSec,
			CleanupInterval:        fwCfg.CleanupIntervalMin,
			DNSLookupTimeout:       fwCfg.DNSLookupTimeoutSec,
		},
	}

	// Insert default jails if not exist
	if err := svc.ensureDefaultJails(); err != nil {
		log.Printf("Warning: Failed to ensure default jails: %v", err)
	}

	// Apply initial firewall rules
	if err := svc.ApplyRules(); err != nil {
		log.Printf("Warning: Failed to apply initial firewall rules: %v", err)
	}

	// Start background tasks
	go svc.runJailMonitors()
	go svc.runVPNTrafficMonitor()
	go svc.runExpirationCleanup()

	log.Printf("Firewall service initialized")
	return svc, nil
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetStatus":       s.handleStatus,
		"GetBlocked":      s.handleGetBlocked,
		"BlockIP":         s.handleBlockIP,
		"UnblockIP":       s.handleUnblockIP,
		"GetAttempts":     s.handleAttempts,
		"GetPorts":        s.handleGetPorts,
		"AddPort":         s.handleAddPort,
		"RemovePort":      s.handleRemovePort,
		"GetJails":        s.handleGetJails,
		"CreateJail":      s.handleCreateJail,
		"GetJail":         s.handleGetJail,
		"UpdateJail":      s.handleUpdateJail,
		"DeleteJail":      s.handleDeleteJail,
		"GetTraffic":      s.handleTraffic,
		"GetTrafficStats": s.handleTrafficStats,
		"GetTrafficLive":  s.handleTrafficLive,
		"GetConfig":       s.handleGetConfig,
		"UpdateConfig":    s.handleUpdateConfig,
		"ApplyRules":      s.handleApplyRules,
		"GetSSHPort":      s.handleGetSSHPort,
		"ChangeSSHPort":   s.handleChangeSSHPort,
		"Health":          s.handleHealth,
	}
}

// ensureDefaultJails inserts default jails and ports if they don't exist
func (s *Service) ensureDefaultJails() error {
	// Insert default jails
	defaultJails := []Jail{
		{Name: "portscan", Enabled: true, LogFile: "/var/log/kern.log",
			FilterRegex: `FIREWALL_DROP:.*SRC=(\d+\.\d+\.\d+\.\d+).*DPT=(\d+)`,
			MaxRetry: 10, FindTime: 300, BanTime: 2592000, Port: "all", Action: "drop"},
		{Name: "sshd", Enabled: true, LogFile: "/var/log/auth.log",
			FilterRegex: `Failed password.*from (\d+\.\d+\.\d+\.\d+)`,
			MaxRetry: 5, FindTime: 600, BanTime: 2592000, Port: "22", Action: "drop"},
	}

	for _, jail := range defaultJails {
		s.db.Exec(`INSERT OR IGNORE INTO jails (name, enabled, log_file, filter_regex, max_retry, find_time, ban_time, port, action)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			jail.Name, jail.Enabled, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.Port, jail.Action)
	}

	// Insert default ports
	var portCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM allowed_ports").Scan(&portCount); err != nil {
		log.Printf("Warning: failed to count ports: %v", err)
	}
	if portCount == 0 {
		for _, ep := range s.config.EssentialPorts {
			s.db.Exec("INSERT OR IGNORE INTO allowed_ports (port, protocol, essential, service) VALUES (?, ?, 1, ?)",
				ep.Port, ep.Protocol, ep.Service)
		}
		log.Printf("Initialized essential ports: %d ports", len(s.config.EssentialPorts))
	}

	return nil
}

// ApplyRules applies nftables firewall rules
func (s *Service) ApplyRules() error {
	s.dbMutex.RLock()
	defer s.dbMutex.RUnlock()

	// Get blocked IPs
	rows, err := s.db.Query("SELECT ip FROM blocked_ips WHERE expires_at IS NULL OR expires_at > datetime('now')")
	if err != nil {
		return err
	}
	var blockedIPs []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			log.Printf("Warning: failed to scan blocked IP: %v", err)
			continue
		}
		blockedIPs = append(blockedIPs, ip)
	}
	rows.Close()

	// Get allowed ports
	rows, err = s.db.Query("SELECT port FROM allowed_ports")
	if err != nil {
		return err
	}
	var allowedPorts []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			log.Printf("Warning: failed to scan allowed port: %v", err)
			continue
		}
		allowedPorts = append(allowedPorts, port)
	}
	rows.Close()

	// Build nftables script
	script := `#!/usr/sbin/nft -f

table inet firewall {
    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

`

	// Add blocked IPs
	for _, ip := range blockedIPs {
		script += fmt.Sprintf("        ip saddr %s drop\n", ip)
	}

	// Add allowed ports
	for _, port := range allowedPorts {
		script += fmt.Sprintf("        tcp dport %d accept\n", port)
		script += fmt.Sprintf("        udp dport %d accept\n", port)
	}

	script += `
        # Log dropped packets
        limit rate 5/minute log prefix "FIREWALL_DROP: " drop
    }

    chain forward {
        type filter hook forward priority 0; policy accept;

        # Log VPN client outbound traffic
        iifname "wg0" ct state new log prefix "VPN_TRAFFIC: " accept
        oifname "wg0" accept
        iifname "tailscale0" ct state new log prefix "VPN_TRAFFIC: " accept
        oifname "tailscale0" accept
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
`

	// Delete existing table and apply new rules
	exec.Command("nft", "delete", "table", "inet", "firewall").Run()

	tmpFile := "/tmp/firewall.nft"
	if err := os.WriteFile(tmpFile, []byte(script), 0600); err != nil {
		return err
	}

	cmd := exec.Command("nft", "-f", tmpFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft error: %v - %s", err, string(out))
	}

	log.Printf("Firewall rules applied: %d ports allowed, %d IPs blocked", len(allowedPorts), len(blockedIPs))
	return nil
}

// ============================================================================
// JAIL MONITORS
// ============================================================================

func (s *Service) runJailMonitors() {
	// Get all enabled jails
	rows, err := s.db.Query("SELECT id, name, log_file, filter_regex, max_retry, find_time, ban_time, last_log_pos FROM jails WHERE enabled = 1")
	if err != nil {
		log.Printf("Failed to load jails: %v", err)
		return
	}
	defer rows.Close()

	var jails []struct {
		ID          int64
		Name        string
		LogFile     string
		FilterRegex string
		MaxRetry    int
		FindTime    int
		BanTime     int
		LastLogPos  int64
	}

	for rows.Next() {
		var j struct {
			ID          int64
			Name        string
			LogFile     string
			FilterRegex string
			MaxRetry    int
			FindTime    int
			BanTime     int
			LastLogPos  int64
		}
		if err := rows.Scan(&j.ID, &j.Name, &j.LogFile, &j.FilterRegex, &j.MaxRetry, &j.FindTime, &j.BanTime, &j.LastLogPos); err != nil {
			log.Printf("Warning: failed to scan jail: %v", err)
			continue
		}
		jails = append(jails, j)
	}

	// Start a monitor for each jail
	for _, jail := range jails {
		go s.monitorJail(jail.ID, jail.Name, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.LastLogPos)
	}

	log.Printf("Started %d jail monitors", len(jails))
}

func (s *Service) monitorJail(jailID int64, name, logFile, filterRegex string, maxRetry, findTime, banTime int, lastLogPos int64) {
	if _, err := os.Stat(logFile); os.IsNotExist(err) {
		log.Printf("Jail %s: log file %s not found, skipping", name, logFile)
		return
	}

	log.Printf("Starting jail monitor: %s (file: %s, maxRetry: %d, findTime: %ds, banTime: %ds)",
		name, logFile, maxRetry, findTime, banTime)

	ticker := time.NewTicker(time.Duration(s.config.JailCheckInterval) * time.Second)
	defer ticker.Stop()

	regex := regexp.MustCompile(filterRegex)
	ipAttempts := make(map[string][]time.Time) // IP -> list of attempt timestamps

	// If lastLogPos is 0, start from current end of file
	if lastLogPos == 0 {
		if stat, err := os.Stat(logFile); err == nil {
			lastLogPos = stat.Size()
			s.db.Exec("UPDATE jails SET last_log_pos = ? WHERE id = ?", lastLogPos, jailID)
		}
	}

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("Jail monitor %s stopping (context cancelled)", name)
			return
		case <-ticker.C:
		file, err := os.Open(logFile)
		if err != nil {
			continue
		}

		stat, _ := file.Stat()
		currentSize := stat.Size()

		// File rotated?
		if currentSize < lastLogPos {
			lastLogPos = 0
		}

		// Seek to last position
		file.Seek(lastLogPos, 0)

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			matches := regex.FindStringSubmatch(line)
			if len(matches) < 2 {
				continue
			}

			srcIP := matches[1]

			// Skip ignored networks
			if s.isIgnoredIP(srcIP) {
				continue
			}

			// Skip already blocked IPs
			if s.isIPBlocked(srcIP) {
				continue
			}

			// For portscan jail, skip WireGuard port
			if name == "portscan" && len(matches) >= 3 {
				port, _ := strconv.Atoi(matches[2])
				if port == s.config.WgPort {
					continue
				}
			}

			// Record attempt
			now := time.Now()
			ipAttempts[srcIP] = append(ipAttempts[srcIP], now)

			// Log the attempt
			destPort := 0
			if len(matches) >= 3 {
				destPort, _ = strconv.Atoi(matches[2])
			}
			s.recordAttempt(srcIP, destPort, "tcp", name, "blocked")

			// Clean old attempts outside findTime window
			cutoff := now.Add(-time.Duration(findTime) * time.Second)
			var recent []time.Time
			for _, t := range ipAttempts[srcIP] {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			ipAttempts[srcIP] = recent

			// Check if should block
			if len(recent) >= maxRetry {
				s.blockIP(srcIP, name, fmt.Sprintf("Auto-blocked: %d attempts in %ds", len(recent), findTime), banTime)
				delete(ipAttempts, srcIP)
			}
		}

		lastLogPos = currentSize
		file.Close()

		// Save position periodically
		s.db.Exec("UPDATE jails SET last_log_pos = ? WHERE id = ?", lastLogPos, jailID)
		}
	}
}

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
		file, err := os.Open(logFile)
		if err != nil {
			continue
		}

		stat, _ := file.Stat()
		currentSize := stat.Size()

		if currentSize < lastSize || lastSize == 0 {
			lastSize = currentSize
			file.Close()
			continue
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

			// Resolve domain
			domain := s.reverseDNS(dstIP)

			// Record traffic
			s.db.Exec(`
				INSERT INTO traffic_logs (client_ip, dest_ip, dest_port, protocol, domain)
				VALUES (?, ?, ?, ?, ?)
			`, srcIP, dstIP, dstPort, proto, domain)
		}

		lastSize = currentSize
		file.Close()

		// Cleanup old traffic logs
		s.db.Exec("DELETE FROM traffic_logs WHERE id NOT IN (SELECT id FROM traffic_logs ORDER BY timestamp DESC LIMIT ?)", s.config.MaxTrafficLogs)
		}
	}
}

func (s *Service) runExpirationCleanup() {
	ticker := time.NewTicker(time.Duration(s.config.CleanupInterval) * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("Expiration cleanup stopping (context cancelled)")
			return
		case <-ticker.C:
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
	}
}

// Stop cancels all background goroutines
func (s *Service) Stop() {
	if s.cancel != nil {
		s.cancel()
	}
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

func (s *Service) isIgnoredIP(ip string) bool {
	for _, network := range s.config.IgnoreNetworks {
		// Extract prefix from network CIDR
		prefix := helper.ExtractIPPrefix(network)
		if prefix != "" && strings.HasPrefix(ip, prefix) {
			return true
		}
		// Handle /8 networks (e.g., 10.0.0.0/8, 127.0.0.1/8)
		if strings.HasSuffix(network, "/8") && strings.HasPrefix(ip, strings.Split(network, ".")[0]+".") {
			return true
		}
		// Handle /32 exact match
		if strings.HasSuffix(network, "/32") && strings.TrimSuffix(network, "/32") == ip {
			return true
		}
		// Handle /12 networks (e.g., 172.16.0.0/12)
		if strings.HasSuffix(network, "/12") && strings.HasPrefix(ip, "172.") {
			return true
		}
		// Handle /10 networks (e.g., 100.64.0.0/10 covers 100.64-127.x.x.x)
		if strings.HasSuffix(network, "/10") && strings.HasPrefix(network, "100.64") {
			// Check if IP is in 100.64.0.0/10 range (100.64.x.x - 100.127.x.x)
			if strings.HasPrefix(ip, "100.") {
				parts := strings.Split(ip, ".")
				if len(parts) >= 2 {
					second, _ := strconv.Atoi(parts[1])
					if second >= 64 && second <= 127 {
						return true
					}
				}
			}
		}
	}
	return false
}

func (s *Service) isPrivateIP(ip string) bool {
	return strings.HasPrefix(ip, "10.") || strings.HasPrefix(ip, "172.") ||
		strings.HasPrefix(ip, "192.168.") || strings.HasPrefix(ip, s.config.HeadscaleIPPrefix) || strings.HasPrefix(ip, s.config.WgIPPrefix)
}

func (s *Service) isIPBlocked(ip string) bool {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM blocked_ips WHERE ip = ? AND (expires_at IS NULL OR expires_at > datetime('now'))", ip).Scan(&count)
	return count > 0
}

// parseIP validates and returns a net.IP, or nil if invalid
func parseIP(ip string) net.IP {
	return net.ParseIP(ip)
}

func (s *Service) blockIP(ip, jailName, reason string, banTime int) {
	var expiresAt interface{}
	if banTime > 0 {
		expiresAt = time.Now().Add(time.Duration(banTime) * time.Second)
	}

	_, err := s.db.Exec(`
		INSERT INTO blocked_ips (ip, jail_name, reason, expires_at, hit_count, manual)
		VALUES (?, ?, ?, ?, 1, 0)
		ON CONFLICT(ip, jail_name) DO UPDATE SET
			hit_count = hit_count + 1,
			blocked_at = CURRENT_TIMESTAMP,
			expires_at = excluded.expires_at,
			reason = excluded.reason
	`, ip, jailName, reason, expiresAt)

	if err == nil {
		log.Printf("Blocked IP %s (jail: %s, reason: %s)", ip, jailName, reason)
		s.ApplyRules()
	}
}

func (s *Service) recordAttempt(srcIP string, destPort int, protocol, jailName, action string) {
	s.db.Exec(`
		INSERT INTO attempts (source_ip, dest_port, protocol, jail_name, action)
		VALUES (?, ?, ?, ?, ?)
	`, srcIP, destPort, protocol, jailName, action)
}

const dnsCacheTTL = 5 * time.Minute
const dnsCacheMaxSize = 10000

func (s *Service) reverseDNS(ip string) string {
	s.dnsMutex.RLock()
	if entry, exists := s.dnsCache[ip]; exists {
		// Check if entry is still valid (not expired)
		if time.Since(entry.timestamp) < dnsCacheTTL {
			s.dnsMutex.RUnlock()
			return entry.domain
		}
	}
	s.dnsMutex.RUnlock()

	domain := ""
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.DNSLookupTimeout)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "dig", "+short", "-x", ip)
	out, err := cmd.Output()
	if err == nil && len(out) > 0 {
		domain = strings.TrimSuffix(strings.TrimSpace(string(out)), ".")
	}

	s.dnsMutex.Lock()
	// Evict oldest entries if cache is too large
	if len(s.dnsCache) >= dnsCacheMaxSize {
		oldest := time.Now()
		var oldestKey string
		for k, v := range s.dnsCache {
			if v.timestamp.Before(oldest) {
				oldest = v.timestamp
				oldestKey = k
			}
		}
		if oldestKey != "" {
			delete(s.dnsCache, oldestKey)
		}
	}
	s.dnsCache[ip] = dnsEntry{domain: domain, timestamp: time.Now()}
	s.dnsMutex.Unlock()

	return domain
}

// ============================================================================
// HTTP HANDLERS
// ============================================================================

func (s *Service) handleStatus(w http.ResponseWriter, r *http.Request) {
	var blockedCount, attemptsCount, portsCount, jailsCount int
	s.db.QueryRow("SELECT COUNT(*) FROM blocked_ips WHERE expires_at IS NULL OR expires_at > datetime('now')").Scan(&blockedCount)
	s.db.QueryRow("SELECT COUNT(*) FROM attempts").Scan(&attemptsCount)
	s.db.QueryRow("SELECT COUNT(*) FROM allowed_ports").Scan(&portsCount)
	s.db.QueryRow("SELECT COUNT(*) FROM jails WHERE enabled = 1").Scan(&jailsCount)

	router.JSON(w, map[string]interface{}{
		"enabled":        true,
		"defaultPolicy":  "drop",
		"blockedIPCount": blockedCount,
		"recentAttempts": attemptsCount,
		"allowedPorts":   portsCount,
		"activeJails":    jailsCount,
	})
}

func (s *Service) handleGetBlocked(w http.ResponseWriter, r *http.Request) {
	limit := 25
	offset := 0
	search := r.URL.Query().Get("search")
	jailFilter := r.URL.Query().Get("jail")

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// Build WHERE clause
	where := "(expires_at IS NULL OR expires_at > datetime('now'))"
	args := []interface{}{}

	if jailFilter != "" {
		where += " AND jail_name = ?"
		args = append(args, jailFilter)
	}

	if search != "" {
		where += " AND (ip LIKE ? OR jail_name LIKE ? OR reason LIKE ?)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern)
	}

	// Get total count
	var total int
	countQuery := "SELECT COUNT(*) FROM blocked_ips WHERE " + where
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		log.Printf("Warning: failed to count blocked IPs: %v", err)
	}

	// Get unique jails for filter dropdown
	jailRows, err := s.db.Query("SELECT DISTINCT jail_name FROM blocked_ips WHERE expires_at IS NULL OR expires_at > datetime('now') ORDER BY jail_name")
	var jails []string
	if err != nil {
		log.Printf("Warning: failed to query jails: %v", err)
	} else {
		for jailRows.Next() {
			var j string
			if err := jailRows.Scan(&j); err != nil {
				log.Printf("Warning: failed to scan jail name: %v", err)
				continue
			}
			jails = append(jails, j)
		}
		jailRows.Close()
	}
	if jails == nil {
		jails = []string{}
	}

	// Get blocked IPs with pagination
	query := fmt.Sprintf(`SELECT id, ip, jail_name, reason, blocked_at, expires_at, hit_count, manual
		FROM blocked_ips WHERE %s ORDER BY blocked_at DESC LIMIT ? OFFSET ?`, where)
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var blocked []BlockedIP
	for rows.Next() {
		var b BlockedIP
		var expiresAt sql.NullTime
		if err := rows.Scan(&b.ID, &b.IP, &b.JailName, &b.Reason, &b.BlockedAt, &expiresAt, &b.HitCount, &b.Manual); err != nil {
			continue
		}
		if expiresAt.Valid {
			b.ExpiresAt = expiresAt.Time
		}
		blocked = append(blocked, b)
	}
	if blocked == nil {
		blocked = []BlockedIP{}
	}

	router.JSON(w, map[string]interface{}{
		"blocked": blocked,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"jails":   jails,
	})
}

func (s *Service) handleBlockIP(w http.ResponseWriter, r *http.Request) {
	var req struct {
		IP      string `json:"ip"`
		Reason  string `json:"reason"`
		BanTime int    `json:"banTime"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate IP address
	if ip := parseIP(req.IP); ip == nil {
		router.JSONError(w, "invalid IP address", http.StatusBadRequest)
		return
	}

	var expiresAt interface{}
	if req.BanTime > 0 {
		expiresAt = time.Now().Add(time.Duration(req.BanTime) * time.Second)
	}

	_, err := s.db.Exec(`INSERT INTO blocked_ips (ip, jail_name, reason, expires_at, manual) VALUES (?, 'manual', ?, ?, 1)`,
		req.IP, req.Reason, expiresAt)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	s.ApplyRules()
	router.JSON(w, map[string]string{"status": "blocked", "ip": req.IP})
}

func (s *Service) handleUnblockIP(w http.ResponseWriter, r *http.Request) {
	ip := router.ExtractPathParam(r, "/api/fw/blocked/")
	s.db.Exec("DELETE FROM blocked_ips WHERE ip = ?", ip)
	s.ApplyRules()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleAttempts(w http.ResponseWriter, r *http.Request) {
	limit := 25
	offset := 0
	search := r.URL.Query().Get("search")
	jailFilter := r.URL.Query().Get("jail")

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// Build WHERE clause
	where := "1=1"
	args := []interface{}{}

	if jailFilter != "" {
		where += " AND jail_name = ?"
		args = append(args, jailFilter)
	}

	if search != "" {
		where += " AND (source_ip LIKE ? OR jail_name LIKE ? OR protocol LIKE ? OR CAST(dest_port AS TEXT) LIKE ?)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern)
	}

	// Get total count
	var total int
	countQuery := "SELECT COUNT(*) FROM attempts WHERE " + where
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		log.Printf("Warning: failed to count attempts: %v", err)
	}

	// Get unique jails for filter dropdown
	jailRows, err := s.db.Query("SELECT DISTINCT jail_name FROM attempts ORDER BY jail_name")
	var jails []string
	if err != nil {
		log.Printf("Warning: failed to query attempt jails: %v", err)
	} else {
		for jailRows.Next() {
			var j string
			if err := jailRows.Scan(&j); err != nil {
				continue
			}
			jails = append(jails, j)
		}
		jailRows.Close()
	}
	if jails == nil {
		jails = []string{}
	}

	// Get attempts with pagination
	query := fmt.Sprintf(`SELECT id, timestamp, source_ip, dest_port, protocol, jail_name, action
		FROM attempts WHERE %s ORDER BY timestamp DESC LIMIT ? OFFSET ?`, where)
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var attempts []Attempt
	for rows.Next() {
		var a Attempt
		if err := rows.Scan(&a.ID, &a.Timestamp, &a.SourceIP, &a.DestPort, &a.Protocol, &a.JailName, &a.Action); err != nil {
			continue
		}
		attempts = append(attempts, a)
	}
	if attempts == nil {
		attempts = []Attempt{}
	}

	router.JSON(w, map[string]interface{}{
		"attempts": attempts,
		"total":    total,
		"limit":    limit,
		"offset":   offset,
		"jails":    jails,
	})
}

// getDockerExposedPorts returns ports exposed by Docker containers
func (s *Service) getDockerExposedPorts() []AllowedPort {
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
		Timeout: 5 * time.Second,
	}

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

	// Track unique ports (port+protocol)
	portMap := make(map[string]AllowedPort)

	for _, c := range rawContainers {
		containerName := ""
		if len(c.Names) > 0 {
			containerName = strings.TrimPrefix(c.Names[0], "/")
		}

		for _, p := range c.Ports {
			// Only include publicly exposed ports (0.0.0.0 or ::)
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

	// Convert map to slice
	var ports []AllowedPort
	for _, p := range portMap {
		ports = append(ports, p)
	}

	return ports
}

func (s *Service) handleGetPorts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT port, protocol, essential, COALESCE(service, '') FROM allowed_ports ORDER BY port")
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var ports []AllowedPort
	for rows.Next() {
		var p AllowedPort
		if err := rows.Scan(&p.Port, &p.Protocol, &p.Essential, &p.Service); err != nil {
			continue
		}
		ports = append(ports, p)
	}

	// Add Docker exposed ports as essential
	dockerPorts := s.getDockerExposedPorts()
	for _, dp := range dockerPorts {
		// Check if this port+protocol combo already exists
		found := false
		for i, existing := range ports {
			if existing.Port == dp.Port && existing.Protocol == dp.Protocol {
				// Merge service names
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

	if ports == nil {
		ports = []AllowedPort{}
	}
	router.JSON(w, ports)
}

func (s *Service) handleAddPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	// Check if this port is in the essential list
	isEssential := false
	for _, ep := range s.config.EssentialPorts {
		if req.Port == ep.Port && req.Protocol == ep.Protocol {
			isEssential = true
			if req.Service == "" {
				req.Service = ep.Service // Use predefined service name
			}
			break
		}
	}

	s.db.Exec("INSERT OR IGNORE INTO allowed_ports (port, protocol, essential, service) VALUES (?, ?, ?, ?)",
		req.Port, req.Protocol, isEssential, req.Service)
	s.ApplyRules()
	router.JSON(w, map[string]interface{}{"port": req.Port, "protocol": req.Protocol, "essential": isEssential, "service": req.Service})
}

func (s *Service) handleRemovePort(w http.ResponseWriter, r *http.Request) {
	portStr := router.ExtractPathParam(r, "/api/fw/ports/")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		router.JSONError(w, "invalid port", http.StatusBadRequest)
		return
	}

	var essential bool
	s.db.QueryRow("SELECT essential FROM allowed_ports WHERE port = ?", port).Scan(&essential)
	if essential {
		router.JSONError(w, "cannot remove essential port", http.StatusForbidden)
		return
	}

	s.db.Exec("DELETE FROM allowed_ports WHERE port = ?", port)
	s.ApplyRules()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleGetJails(w http.ResponseWriter, r *http.Request) {
	// Single query with LEFT JOIN to avoid N+1 queries
	rows, err := s.db.Query(`
		SELECT j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action,
			COUNT(CASE WHEN b.expires_at IS NULL OR b.expires_at > datetime('now') THEN 1 END) as currently_banned,
			COUNT(b.id) as total_banned
		FROM jails j
		LEFT JOIN blocked_ips b ON j.name = b.jail_name
		GROUP BY j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action`)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var jails []Jail
	for rows.Next() {
		var j Jail
		rows.Scan(&j.ID, &j.Name, &j.Enabled, &j.LogFile, &j.FilterRegex, &j.MaxRetry, &j.FindTime, &j.BanTime, &j.Port, &j.Action, &j.CurrentlyBanned, &j.TotalBanned)
		jails = append(jails, j)
	}
	if jails == nil {
		jails = []Jail{}
	}
	router.JSON(w, jails)
}

func (s *Service) handleCreateJail(w http.ResponseWriter, r *http.Request) {
	var jail Jail
	if err := json.NewDecoder(r.Body).Decode(&jail); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate regex pattern
	if jail.FilterRegex != "" {
		if _, err := regexp.Compile(jail.FilterRegex); err != nil {
			router.JSONError(w, "invalid regex pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	result, err := s.db.Exec(`INSERT INTO jails (name, enabled, log_file, filter_regex, max_retry, find_time, ban_time, port, action)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		jail.Name, jail.Enabled, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.Port, jail.Action)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	jail.ID, _ = result.LastInsertId()

	// Start monitor for new jail
	if jail.Enabled {
		go s.monitorJail(jail.ID, jail.Name, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, 0)
	}

	router.JSON(w, jail)
}

func (s *Service) handleGetJail(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/fw/jails/")
	var jail Jail
	// Single query with LEFT JOIN to get jail and counts
	err := s.db.QueryRow(`
		SELECT j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action,
			COUNT(CASE WHEN b.expires_at IS NULL OR b.expires_at > datetime('now') THEN 1 END) as currently_banned,
			COUNT(b.id) as total_banned
		FROM jails j
		LEFT JOIN blocked_ips b ON j.name = b.jail_name
		WHERE j.name = ?
		GROUP BY j.id, j.name, j.enabled, j.log_file, j.filter_regex, j.max_retry, j.find_time, j.ban_time, j.port, j.action`,
		name).Scan(&jail.ID, &jail.Name, &jail.Enabled, &jail.LogFile, &jail.FilterRegex,
		&jail.MaxRetry, &jail.FindTime, &jail.BanTime, &jail.Port, &jail.Action, &jail.CurrentlyBanned, &jail.TotalBanned)
	if err != nil {
		router.JSONError(w, "jail not found", http.StatusNotFound)
		return
	}
	router.JSON(w, jail)
}

func (s *Service) handleUpdateJail(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/fw/jails/")
	var jail Jail
	if err := json.NewDecoder(r.Body).Decode(&jail); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate regex pattern
	if jail.FilterRegex != "" {
		if _, err := regexp.Compile(jail.FilterRegex); err != nil {
			router.JSONError(w, "invalid regex pattern: "+err.Error(), http.StatusBadRequest)
			return
		}
	}

	_, err := s.db.Exec(`UPDATE jails SET enabled = ?, log_file = ?, filter_regex = ?, max_retry = ?,
		find_time = ?, ban_time = ?, port = ?, action = ? WHERE name = ?`,
		jail.Enabled, jail.LogFile, jail.FilterRegex, jail.MaxRetry, jail.FindTime, jail.BanTime, jail.Port, jail.Action, name)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, jail)
}

func (s *Service) handleDeleteJail(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/fw/jails/")
	s.db.Exec("DELETE FROM jails WHERE name = ?", name)
	s.db.Exec("DELETE FROM blocked_ips WHERE jail_name = ?", name)
	s.ApplyRules()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleTraffic(w http.ResponseWriter, r *http.Request) {
	limit := 25
	offset := 0
	search := r.URL.Query().Get("search")
	clientIP := r.URL.Query().Get("client")

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			limit = parsed
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			offset = parsed
		}
	}

	// Build WHERE clause
	where := "1=1"
	args := []interface{}{}

	if clientIP != "" {
		where += " AND client_ip = ?"
		args = append(args, clientIP)
	}

	if search != "" {
		where += " AND (client_ip LIKE ? OR dest_ip LIKE ? OR domain LIKE ? OR protocol LIKE ? OR CAST(dest_port AS TEXT) LIKE ?)"
		searchPattern := "%" + search + "%"
		args = append(args, searchPattern, searchPattern, searchPattern, searchPattern, searchPattern)
	}

	// Get total count with filters
	var total int
	countQuery := "SELECT COUNT(*) FROM traffic_logs WHERE " + where
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		log.Printf("Warning: failed to count traffic logs: %v", err)
	}

	// Get unique clients for filter dropdown
	clientRows, err := s.db.Query("SELECT DISTINCT client_ip FROM traffic_logs ORDER BY client_ip")
	if err != nil {
		log.Printf("Warning: failed to query traffic clients: %v", err)
	} else {
		defer clientRows.Close()
	}
	var clients []string
	if err == nil {
		for clientRows.Next() {
			var c string
			if err := clientRows.Scan(&c); err != nil {
				continue
			}
			clients = append(clients, c)
		}
	}
	if clients == nil {
		clients = []string{}
	}

	// Get logs with pagination
	query := fmt.Sprintf(`SELECT id, timestamp, client_ip, dest_ip, dest_port, protocol, domain
		FROM traffic_logs WHERE %s ORDER BY timestamp DESC LIMIT ? OFFSET ?`, where)
	args = append(args, limit, offset)

	rows, err := s.db.Query(query, args...)
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var logs []TrafficLog
	for rows.Next() {
		var t TrafficLog
		rows.Scan(&t.ID, &t.Timestamp, &t.ClientIP, &t.DestIP, &t.DestPort, &t.Protocol, &t.Domain)
		logs = append(logs, t)
	}
	if logs == nil {
		logs = []TrafficLog{}
	}

	router.JSON(w, map[string]interface{}{
		"logs":    logs,
		"total":   total,
		"limit":   limit,
		"offset":  offset,
		"clients": clients,
	})
}

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

	var stats []Stats
	for rows.Next() {
		var s Stats
		var clients string
		rows.Scan(&s.DestIP, &s.Domain, &s.Connections, &s.LastSeen, &clients)
		if clients != "" {
			s.Clients = strings.Split(clients, ",")
		}
		stats = append(stats, s)
	}
	if stats == nil {
		stats = []Stats{}
	}
	router.JSON(w, stats)
}

func (s *Service) handleTrafficLive(w http.ResponseWriter, r *http.Request) {
	var totalConns, uniqueDests, activeClients int
	s.db.QueryRow("SELECT COUNT(*) FROM traffic_logs WHERE timestamp > datetime('now', '-5 minutes')").Scan(&totalConns)
	s.db.QueryRow("SELECT COUNT(DISTINCT dest_ip) FROM traffic_logs WHERE timestamp > datetime('now', '-5 minutes')").Scan(&uniqueDests)
	s.db.QueryRow("SELECT COUNT(DISTINCT client_ip) FROM traffic_logs WHERE timestamp > datetime('now', '-5 minutes')").Scan(&activeClients)

	router.JSON(w, map[string]interface{}{
		"totalConnections":   totalConns,
		"uniqueDestinations": uniqueDests,
		"activeClients":      activeClients,
		"periodMinutes":      5,
	})
}

func (s *Service) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, s.config)
}

func (s *Service) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	if err := json.NewDecoder(r.Body).Decode(&s.config); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}
	router.JSON(w, s.config)
}

func (s *Service) handleApplyRules(w http.ResponseWriter, r *http.Request) {
	if err := s.ApplyRules(); err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	router.JSON(w, map[string]string{"status": "applied"})
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"status": "ok"})
}

func (s *Service) handleGetSSHPort(w http.ResponseWriter, r *http.Request) {
	port := helper.GetSSHPort()
	router.JSON(w, map[string]interface{}{
		"port": port,
	})
}

func (s *Service) handleChangeSSHPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port int `json:"port"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		router.JSONError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Validate port
	if req.Port < 1 || req.Port > 65535 {
		router.JSONError(w, "invalid port number (must be 1-65535)", http.StatusBadRequest)
		return
	}

	// Reserved ports check
	if req.Port < 1024 && req.Port != 22 {
		// Allow changing to standard SSH port, but warn about other privileged ports
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

	// Step 1: Add the new port to firewall allowed ports
	_, err := s.db.Exec("INSERT OR IGNORE INTO allowed_ports (port, protocol, essential, service) VALUES (?, 'tcp', 1, 'SSH')",
		req.Port)
	if err != nil {
		router.JSONError(w, "failed to add new port to firewall: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Apply firewall rules to allow the new port
	if err := s.ApplyRules(); err != nil {
		router.JSONError(w, "failed to apply firewall rules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("SSH port change: added port %d to firewall", req.Port)

	// Step 2: Update sshd_config
	_, err = helper.SetSSHPort(req.Port)
	if err != nil {
		// Rollback: remove the new port from firewall
		s.db.Exec("DELETE FROM allowed_ports WHERE port = ? AND service = 'SSH'", req.Port)
		s.ApplyRules()
		router.JSONError(w, "failed to update sshd_config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("SSH port change: updated sshd_config from port %d to %d", oldPort, req.Port)

	// Step 3: Restart SSH service
	// Use nsenter to run systemctl in the host's namespace (since we run with pid: host and privileged: true)
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "restart", "sshd")
	if out, err := cmd.CombinedOutput(); err != nil {
		// Try alternative service name (some systems use 'ssh' instead of 'sshd')
		cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "restart", "ssh")
		if out2, err2 := cmd.CombinedOutput(); err2 != nil {
			// Rollback: revert sshd_config
			helper.SetSSHPort(oldPort)
			// Rollback: remove new port from firewall
			s.db.Exec("DELETE FROM allowed_ports WHERE port = ? AND service = 'SSH'", req.Port)
			s.ApplyRules()
			router.JSONError(w, fmt.Sprintf("failed to restart SSH: %v - %s / %s", err, string(out), string(out2)), http.StatusInternalServerError)
			return
		}
	}

	log.Printf("SSH port change: restarted SSH service")

	// Step 4: Remove old port from firewall (only if different from new port)
	if oldPort != req.Port {
		s.db.Exec("DELETE FROM allowed_ports WHERE port = ? AND service = 'SSH'", oldPort)
		// Update essential ports list
		s.config.EssentialPorts = helper.BuildEssentialPorts()
		s.ApplyRules()
		log.Printf("SSH port change: removed old port %d from firewall", oldPort)
	}

	// Update the sshd jail to monitor the new port
	s.db.Exec("UPDATE jails SET port = ? WHERE name = 'sshd'", strconv.Itoa(req.Port))

	router.JSON(w, map[string]interface{}{
		"status":  "success",
		"oldPort": oldPort,
		"newPort": req.Port,
		"message": fmt.Sprintf("SSH port changed from %d to %d", oldPort, req.Port),
	})
}
