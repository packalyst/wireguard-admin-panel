package wireguard

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"

	"github.com/skip2/go-qrcode"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// validateIP checks if the given string is a valid IP address
func validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// validateCIDR checks if the given string is a valid CIDR notation
func validateCIDR(cidr string) error {
	_, _, err := net.ParseCIDR(cidr)
	if err != nil {
		return fmt.Errorf("invalid CIDR: %s", cidr)
	}
	return nil
}

// Service handles WireGuard operations
type Service struct {
	config    Config
	peerStore *PeerStore
}

// Package-level service instance for cross-service access
var serviceInstance *Service

// SetService stores the service instance for access by other packages
func SetService(s *Service) {
	serviceInstance = s
}

// GetService returns the stored service instance
func GetService() *Service {
	return serviceInstance
}

// SimplePeer is a minimal peer representation for other services
type SimplePeer struct {
	ID        string
	Name      string
	IPAddress string
}

// ListPeers returns all peers in a simple format for other services
func (s *Service) ListPeers() []SimplePeer {
	peers := s.peerStore.List()
	result := make([]SimplePeer, len(peers))
	for i, p := range peers {
		result[i] = SimplePeer{ID: p.ID, Name: p.Name, IPAddress: p.IPAddress}
	}
	return result
}

// ListPeersWithStatus returns all peers with enriched online status
func (s *Service) ListPeersWithStatus() []*Peer {
	peers := s.peerStore.List()
	s.enrichPeersWithStatus(peers)
	return peers
}


// Config holds WireGuard configuration
type Config struct {
	Interface        string
	ListenPort       int
	ServerPubKey     string
	ServerPriKey     string
	Endpoint         string
	IPRange          string
	ServerIP         string
	DNS              string
	DataDir          string
	HeadscaleIPRange string
}

// Peer represents a WireGuard peer
type Peer struct {
	ID            string    `json:"id"`
	Name          string    `json:"name"`
	PublicKey     string    `json:"publicKey"`
	PrivateKey    string    `json:"privateKey,omitempty"`
	PresharedKey  string    `json:"presharedKey,omitempty"`
	IPAddress     string    `json:"ipAddress"`
	CreatedAt     time.Time `json:"createdAt"`
	LastSeen      time.Time `json:"lastSeen,omitempty"`
	Enabled       bool      `json:"enabled"`
	Online        bool      `json:"online"`
	LastHandshake time.Time `json:"lastHandshake,omitempty"`
}

// PeerStore manages peers with database persistence
type PeerStore struct {
	sync.RWMutex
	cache   map[string]*Peer // in-memory cache for performance
	dataDir string           // for migration from legacy peers.json
}

// New creates a new WireGuard service
func New(dataDir string) (*Service, error) {
	port := helper.GetEnvInt("WG_PORT")
	serverIP := helper.GetEnv("SERVER_IP")
	wgServerIP := helper.GetEnv("WG_SERVER_IP")
	ipRange := helper.GetEnv("WG_IP_RANGE")
	dns := helper.GetEnv("WG_DNS")
	headscaleIPRange := helper.GetEnv("HEADSCALE_IP_RANGE")

	// Validate IP configurations
	if err := validateIP(serverIP); err != nil {
		return nil, fmt.Errorf("invalid SERVER_IP: %v", err)
	}
	if err := validateIP(wgServerIP); err != nil {
		return nil, fmt.Errorf("invalid WG_SERVER_IP: %v", err)
	}
	if err := validateIP(dns); err != nil {
		return nil, fmt.Errorf("invalid WG_DNS: %v", err)
	}
	if err := validateCIDR(ipRange); err != nil {
		return nil, fmt.Errorf("invalid WG_IP_RANGE: %v", err)
	}
	if headscaleIPRange != "" {
		if err := validateCIDR(headscaleIPRange); err != nil {
			return nil, fmt.Errorf("invalid HEADSCALE_IP_RANGE: %v", err)
		}
	}

	endpoint := fmt.Sprintf("%s:%d", serverIP, port)

	svc := &Service{
		config: Config{
			Interface:        helper.GetEnv("WG_INTERFACE"),
			ListenPort:       port,
			Endpoint:         endpoint,
			IPRange:          ipRange,
			ServerIP:         wgServerIP,
			DNS:              dns,
			DataDir:          dataDir,
			HeadscaleIPRange: headscaleIPRange,
		},
	}

	// Ensure data directory exists
	os.MkdirAll(dataDir, 0700)

	// Initialize server keys
	if err := svc.initServerKeys(); err != nil {
		return nil, fmt.Errorf("failed to initialize server keys: %v", err)
	}

	// Initialize peer store
	svc.peerStore = &PeerStore{
		cache:   make(map[string]*Peer),
		dataDir: dataDir,
	}
	// Migrate from legacy peers.json if exists
	if err := svc.peerStore.MigrateLegacyFile(); err != nil {
		log.Printf("Warning: failed to migrate legacy peers.json: %v", err)
	}
	// Load peers from database into cache
	svc.peerStore.Load()

	// Initialize WireGuard interface
	if err := svc.initWireGuard(); err != nil {
		return nil, fmt.Errorf("failed to initialize WireGuard: %v", err)
	}

	log.Printf("WireGuard service initialized, server public key: %s", svc.config.ServerPubKey)
	return svc, nil
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetPeers":      s.handleGetPeers,
		"CreatePeer":    s.handleCreatePeer,
		"GetPeer":       s.handleGetPeer,
		"UpdatePeer":    s.handleUpdatePeer,
		"DeletePeer":    s.handleDeletePeer,
		"EnablePeer":    s.handleEnablePeer,
		"DisablePeer":   s.handleDisablePeer,
		"GetPeerConfig": s.handleGetPeerConfig,
		"GetPeerQR":     s.handleGetPeerQR,
		"GetServer":     s.handleGetServer,
		"Health":        s.handleHealth,
	}
}

func (s *Service) initServerKeys() error {
	priKeyPath := filepath.Join(s.config.DataDir, "server_private.key")
	pubKeyPath := filepath.Join(s.config.DataDir, "server_public.key")

	if priKeyData, err := os.ReadFile(priKeyPath); err == nil {
		s.config.ServerPriKey = strings.TrimSpace(string(priKeyData))
		if pubKeyData, err := os.ReadFile(pubKeyPath); err == nil {
			s.config.ServerPubKey = strings.TrimSpace(string(pubKeyData))
			return nil
		}
	}

	priKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("failed to generate private key: %v", err)
	}

	s.config.ServerPriKey = priKey.String()
	s.config.ServerPubKey = priKey.PublicKey().String()

	if err := os.WriteFile(priKeyPath, []byte(s.config.ServerPriKey), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(pubKeyPath, []byte(s.config.ServerPubKey), 0644); err != nil {
		return err
	}

	log.Println("Generated new server keys")
	return nil
}

func (s *Service) initWireGuard() error {
	// Check if wireguard module is loaded (don't try modprobe - container doesn't have it)
	if _, err := os.Stat("/sys/module/wireguard"); os.IsNotExist(err) {
		log.Printf("Warning: WireGuard kernel module not loaded on host. Load it with: sudo modprobe wireguard")
	}

	cmd := exec.Command("ip", "link", "show", s.config.Interface)
	if err := cmd.Run(); err != nil {
		log.Printf("Creating WireGuard interface %s", s.config.Interface)
		if err := exec.Command("ip", "link", "add", "dev", s.config.Interface, "type", "wireguard").Run(); err != nil {
			return fmt.Errorf("failed to create interface: %v", err)
		}
	}

	if err := s.syncConfig(); err != nil {
		return err
	}

	if err := exec.Command("ip", "addr", "flush", "dev", s.config.Interface).Run(); err != nil {
		log.Printf("Warning: failed to flush addresses: %v", err)
	}
	// Extract netmask from IPRange env var (e.g., "100.65.0.0/16" -> "/16")
	_, ipNet, err := net.ParseCIDR(s.config.IPRange)
	if err != nil {
		return fmt.Errorf("invalid IP range %s: %v", s.config.IPRange, err)
	}
	ones, _ := ipNet.Mask.Size()
	serverIPWithMask := fmt.Sprintf("%s/%d", s.config.ServerIP, ones)
	if err := exec.Command("ip", "addr", "add", serverIPWithMask, "dev", s.config.Interface).Run(); err != nil {
		return fmt.Errorf("failed to set IP: %v", err)
	}

	if err := exec.Command("ip", "link", "set", "up", "dev", s.config.Interface).Run(); err != nil {
		return fmt.Errorf("failed to bring up interface: %v", err)
	}

	s.setupNAT()
	log.Printf("WireGuard interface %s initialized with IP %s", s.config.Interface, s.config.ServerIP)
	return nil
}

func (s *Service) setupNAT() error {
	// Enable IP forwarding by writing directly to sysctl (no shell needed)
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0644); err != nil {
		log.Printf("Warning: failed to enable IP forwarding: %v", err)
	}

	outIface := s.getDefaultInterface()
	if outIface == "" {
		outIface = "eth0"
	}

	// MASQUERADE
	checkCmd := exec.Command("iptables", "-t", "nat", "-C", "POSTROUTING", "-s", s.config.IPRange, "-o", outIface, "-j", "MASQUERADE")
	if checkCmd.Run() != nil {
		if err := exec.Command("iptables", "-t", "nat", "-A", "POSTROUTING", "-s", s.config.IPRange, "-o", outIface, "-j", "MASQUERADE").Run(); err != nil {
			log.Printf("Warning: failed to add NAT MASQUERADE rule: %v", err)
		} else {
			log.Printf("Added NAT MASQUERADE rule for %s via %s", s.config.IPRange, outIface)
		}
	}

	// FORWARD rules
	checkCmd = exec.Command("iptables", "-C", "FORWARD", "-i", s.config.Interface, "-j", "ACCEPT")
	if checkCmd.Run() != nil {
		if err := exec.Command("iptables", "-A", "FORWARD", "-i", s.config.Interface, "-j", "ACCEPT").Run(); err != nil {
			log.Printf("Warning: failed to add FORWARD rule (in): %v", err)
		}
	}

	checkCmd = exec.Command("iptables", "-C", "FORWARD", "-o", s.config.Interface, "-j", "ACCEPT")
	if checkCmd.Run() != nil {
		if err := exec.Command("iptables", "-A", "FORWARD", "-o", s.config.Interface, "-j", "ACCEPT").Run(); err != nil {
			log.Printf("Warning: failed to add FORWARD rule (out): %v", err)
		}
	}

	return nil
}

func (s *Service) getDefaultInterface() string {
	// Parse ip route output directly without shell pipeline
	out, err := exec.Command("ip", "route", "show", "default").Output()
	if err != nil {
		return ""
	}
	// Output format: "default via X.X.X.X dev ethX ..."
	fields := strings.Fields(string(out))
	for i, field := range fields {
		if field == "dev" && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	return ""
}

func (s *Service) syncConfig() error {
	confPath := filepath.Join(s.config.DataDir, s.config.Interface+".conf")
	enabledPeers := make(map[string]bool)

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
ListenPort = %d

`, s.config.ServerPriKey, s.config.ListenPort)

	s.peerStore.RLock()
	for _, peer := range s.peerStore.cache {
		if peer.Enabled {
			enabledPeers[peer.PublicKey] = true
			peerConf := fmt.Sprintf("[Peer]\nPublicKey = %s\n", peer.PublicKey)
			if peer.PresharedKey != "" {
				peerConf += fmt.Sprintf("PresharedKey = %s\n", peer.PresharedKey)
			}
			peerConf += fmt.Sprintf("AllowedIPs = %s/32\n\n", peer.IPAddress)
			conf += peerConf
		}
	}
	s.peerStore.RUnlock()

	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return err
	}

	// Remove disabled peers
	currentPeers := s.getCurrentPeers()
	for _, pubKey := range currentPeers {
		if !enabledPeers[pubKey] {
			exec.Command("wg", "set", s.config.Interface, "peer", pubKey, "remove").Run()
		}
	}

	return exec.Command("wg", "syncconf", s.config.Interface, confPath).Run()
}

func (s *Service) getCurrentPeers() []string {
	var peers []string
	out, err := exec.Command("wg", "show", s.config.Interface, "peers").Output()
	if err != nil {
		return peers
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			peers = append(peers, line)
		}
	}
	return peers
}

func (s *Service) getWgStatus() map[string]time.Time {
	status := make(map[string]time.Time)
	out, err := exec.Command("wg", "show", s.config.Interface, "dump").Output()
	if err != nil {
		return status
	}

	lines := strings.Split(string(out), "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) >= 5 {
			pubKey := fields[0]
			if ts, err := strconv.ParseInt(fields[4], 10, 64); err == nil && ts > 0 {
				status[pubKey] = time.Unix(ts, 0)
			}
		}
	}
	return status
}

func (s *Service) enrichPeersWithStatus(peers []*Peer) {
	status := s.getWgStatus()
	now := time.Now()

	for _, peer := range peers {
		if handshake, ok := status[peer.PublicKey]; ok {
			peer.LastHandshake = handshake
			peer.Online = now.Sub(handshake) < 3*time.Minute
		} else {
			peer.Online = false
			peer.LastHandshake = time.Time{}
		}
	}
}

// PeerStore methods

// MigrateLegacyFile migrates peers from legacy peers.json to database
func (ps *PeerStore) MigrateLegacyFile() error {
	legacyPath := filepath.Join(ps.dataDir, "peers.json")
	data, err := os.ReadFile(legacyPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // No legacy file, nothing to migrate
		}
		return err
	}

	var legacyPeers map[string]*Peer
	if err := json.Unmarshal(data, &legacyPeers); err != nil {
		return fmt.Errorf("failed to parse legacy peers.json: %v", err)
	}

	if len(legacyPeers) == 0 {
		// Empty file, just remove it
		os.Remove(legacyPath)
		return nil
	}

	log.Printf("Migrating %d peers from legacy peers.json to database", len(legacyPeers))

	db := database.Get()
	if db == nil {
		return fmt.Errorf("database not available")
	}

	for _, peer := range legacyPeers {
		// Encrypt sensitive keys
		var privateKeyEnc, presharedKeyEnc string
		var err error
		if peer.PrivateKey != "" {
			privateKeyEnc, err = helper.Encrypt(peer.PrivateKey)
			if err != nil {
				log.Printf("ERROR: Failed to encrypt private key for peer %s: %v", peer.Name, err)
				continue // Skip this peer, don't lose the key by saving empty
			}
		}
		if peer.PresharedKey != "" {
			presharedKeyEnc, err = helper.Encrypt(peer.PresharedKey)
			if err != nil {
				log.Printf("ERROR: Failed to encrypt preshared key for peer %s: %v", peer.Name, err)
				continue
			}
		}

		// Prepare raw_data without sensitive keys
		peerCopy := *peer
		peerCopy.PrivateKey = ""
		peerCopy.PresharedKey = ""
		rawData, _ := json.Marshal(peerCopy)

		enabledInt := 0
		if peer.Enabled {
			enabledInt = 1
		}

		// Insert or update in database
		_, err = db.Exec(`
			INSERT INTO vpn_clients (name, ip, type, external_id, raw_data, acl_policy, public_key, private_key_enc, preshared_key_enc, enabled)
			VALUES (?, ?, 'wireguard', ?, ?, 'selected', ?, ?, ?, ?)
			ON CONFLICT(ip) DO UPDATE SET
				name = excluded.name,
				external_id = excluded.external_id,
				raw_data = excluded.raw_data,
				public_key = excluded.public_key,
				private_key_enc = excluded.private_key_enc,
				preshared_key_enc = excluded.preshared_key_enc,
				enabled = excluded.enabled,
				updated_at = CURRENT_TIMESTAMP
		`, peer.Name, peer.IPAddress, peer.ID, string(rawData), peer.PublicKey, privateKeyEnc, presharedKeyEnc, enabledInt)
		if err != nil {
			log.Printf("Warning: failed to migrate peer %s: %v", peer.Name, err)
		}
	}

	// Rename legacy file to backup
	backupPath := legacyPath + ".migrated"
	if err := os.Rename(legacyPath, backupPath); err != nil {
		log.Printf("Warning: could not rename legacy peers.json: %v", err)
	} else {
		log.Printf("Legacy peers.json migrated and renamed to peers.json.migrated")
	}

	return nil
}

// Load loads peers from database into cache
func (ps *PeerStore) Load() error {
	ps.Lock()
	defer ps.Unlock()

	db := database.Get()
	if db == nil {
		return fmt.Errorf("database not available")
	}

	rows, err := db.Query(`
		SELECT external_id, name, ip, public_key, private_key_enc, preshared_key_enc, enabled, created_at
		FROM vpn_clients
		WHERE type = 'wireguard' AND external_id IS NOT NULL
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	ps.cache = make(map[string]*Peer)
	for rows.Next() {
		var id, name, ip string
		var publicKey, privateKeyEnc, presharedKeyEnc sql.NullString
		var enabled int
		var createdAt time.Time

		if err := rows.Scan(&id, &name, &ip, &publicKey, &privateKeyEnc, &presharedKeyEnc, &enabled, &createdAt); err != nil {
			log.Printf("Warning: failed to scan peer row: %v", err)
			continue
		}

		peer := &Peer{
			ID:        id,
			Name:      name,
			IPAddress: ip,
			PublicKey: publicKey.String,
			Enabled:   enabled == 1,
			CreatedAt: createdAt,
		}

		// Decrypt sensitive keys
		if privateKeyEnc.Valid && privateKeyEnc.String != "" {
			if decrypted, err := helper.Decrypt(privateKeyEnc.String); err == nil {
				peer.PrivateKey = decrypted
			}
		}
		if presharedKeyEnc.Valid && presharedKeyEnc.String != "" {
			if decrypted, err := helper.Decrypt(presharedKeyEnc.String); err == nil {
				peer.PresharedKey = decrypted
			}
		}

		ps.cache[id] = peer
	}

	log.Printf("Loaded %d WireGuard peers from database", len(ps.cache))
	return nil
}

// Add adds or updates a peer in database and cache
func (ps *PeerStore) Add(peer *Peer) {
	ps.Lock()
	defer ps.Unlock()

	db := database.Get()
	if db == nil {
		return
	}

	// Encrypt sensitive keys
	var privateKeyEnc, presharedKeyEnc string
	var err error
	if peer.PrivateKey != "" {
		privateKeyEnc, err = helper.Encrypt(peer.PrivateKey)
		if err != nil {
			log.Printf("ERROR: Failed to encrypt private key for peer %s: %v", peer.Name, err)
			return
		}
	}
	if peer.PresharedKey != "" {
		presharedKeyEnc, err = helper.Encrypt(peer.PresharedKey)
		if err != nil {
			log.Printf("ERROR: Failed to encrypt preshared key for peer %s: %v", peer.Name, err)
			return
		}
	}

	// Prepare raw_data without sensitive keys
	peerCopy := *peer
	peerCopy.PrivateKey = ""
	peerCopy.PresharedKey = ""
	rawData, _ := json.Marshal(peerCopy)

	enabledInt := 0
	if peer.Enabled {
		enabledInt = 1
	}

	// Upsert to database
	_, err = db.Exec(`
		INSERT INTO vpn_clients (name, ip, type, external_id, raw_data, acl_policy, public_key, private_key_enc, preshared_key_enc, enabled)
		VALUES (?, ?, 'wireguard', ?, ?, 'selected', ?, ?, ?, ?)
		ON CONFLICT(ip) DO UPDATE SET
			name = excluded.name,
			external_id = excluded.external_id,
			raw_data = excluded.raw_data,
			public_key = excluded.public_key,
			private_key_enc = excluded.private_key_enc,
			preshared_key_enc = excluded.preshared_key_enc,
			enabled = excluded.enabled,
			updated_at = CURRENT_TIMESTAMP
	`, peer.Name, peer.IPAddress, peer.ID, string(rawData), peer.PublicKey, privateKeyEnc, presharedKeyEnc, enabledInt)
	if err != nil {
		log.Printf("Warning: failed to save peer %s: %v", peer.Name, err)
		return
	}

	// Update cache with a copy
	peerForCache := *peer
	ps.cache[peer.ID] = &peerForCache
}

// Get returns a copy of a peer by ID
func (ps *PeerStore) Get(id string) *Peer {
	ps.RLock()
	defer ps.RUnlock()
	if p, ok := ps.cache[id]; ok {
		// Return a copy to prevent modification of cached data
		peerCopy := *p
		return &peerCopy
	}
	return nil
}

// Delete removes a peer from database and cache
func (ps *PeerStore) Delete(id string) {
	ps.Lock()
	peer := ps.cache[id]
	delete(ps.cache, id)
	ps.Unlock()

	if peer == nil {
		return
	}

	db := database.Get()
	if db == nil {
		return
	}

	_, err := db.Exec(`DELETE FROM vpn_clients WHERE ip = ? AND type = 'wireguard'`, peer.IPAddress)
	if err != nil {
		log.Printf("Warning: failed to delete peer %s from database: %v", id, err)
	}
}

// List returns copies of all peers
func (ps *PeerStore) List() []*Peer {
	ps.RLock()
	defer ps.RUnlock()
	list := make([]*Peer, 0, len(ps.cache))
	for _, p := range ps.cache {
		// Return copies to prevent modification of cached data
		peerCopy := *p
		list = append(list, &peerCopy)
	}
	// Sort by creation time
	for i := 0; i < len(list)-1; i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].CreatedAt.Before(list[i].CreatedAt) {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	return list
}

// AllocateIP allocates a new IP address for a peer
func (ps *PeerStore) AllocateIP(ipRange string) string {
	ps.RLock()
	defer ps.RUnlock()

	usedIPs := make(map[string]bool)
	for _, p := range ps.cache {
		usedIPs[p.IPAddress] = true
	}

	baseIP, maskBits := parseIPRange(ipRange)
	if baseIP == nil {
		baseIP = []byte{100, 65, 0, 0}
		maskBits = 16
	}

	numIPs := 1 << (32 - maskBits)

	for i := 2; i < numIPs; i++ {
		ip := make([]byte, 4)
		copy(ip, baseIP)
		ip[3] = byte((int(baseIP[3]) + i) & 0xFF)
		ip[2] = byte((int(baseIP[2]) + (int(baseIP[3])+i)/256) & 0xFF)
		ip[1] = byte((int(baseIP[1]) + (int(baseIP[2])+(int(baseIP[3])+i)/256)/256) & 0xFF)

		ipStr := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
		if !usedIPs[ipStr] {
			return ipStr
		}
	}
	return ""
}

func parseIPRange(cidr string) ([]byte, int) {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return nil, 0
	}
	ipParts := strings.Split(parts[0], ".")
	if len(ipParts) != 4 {
		return nil, 0
	}
	ip := make([]byte, 4)
	for i, p := range ipParts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 || v > 255 {
			return nil, 0
		}
		ip[i] = byte(v)
	}
	mask, err := strconv.Atoi(parts[1])
	if err != nil || mask < 0 || mask > 32 {
		return nil, 0
	}
	return ip, mask
}

func generateID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Service) generateClientConfig(peer *Peer, mode string) string {
	allowedIPs := "0.0.0.0/0, ::/0"
	dns := s.config.DNS

	if mode == "split" {
		allowedIPs = s.config.IPRange
		if s.config.HeadscaleIPRange != "" {
			allowedIPs += ", " + s.config.HeadscaleIPRange
		}
		dns = ""
	}

	conf := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
`, peer.PrivateKey, peer.IPAddress)

	if dns != "" {
		conf += fmt.Sprintf("DNS = %s\n", dns)
	}

	conf += fmt.Sprintf(`
[Peer]
PublicKey = %s
PresharedKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, s.config.ServerPubKey, peer.PresharedKey, s.config.Endpoint, allowedIPs)

	return conf
}

// HTTP Handlers
func (s *Service) handleGetPeers(w http.ResponseWriter, r *http.Request) {
	peers := s.peerStore.List()
	s.enrichPeersWithStatus(peers)
	// Strip sensitive keys from list response - private keys only returned during creation or config download
	for _, p := range peers {
		p.PrivateKey = ""
		p.PresharedKey = ""
	}
	router.JSON(w, peers)
}

func (s *Service) handleCreatePeer(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Name == "" {
		router.JSONError(w, "name is required", http.StatusBadRequest)
		return
	}

	priKey, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		router.JSONError(w, "failed to generate keys", http.StatusInternalServerError)
		return
	}

	psk, err := wgtypes.GenerateKey()
	if err != nil {
		router.JSONError(w, "failed to generate preshared key", http.StatusInternalServerError)
		return
	}

	peer := &Peer{
		ID:           generateID(),
		Name:         req.Name,
		PrivateKey:   priKey.String(),
		PublicKey:    priKey.PublicKey().String(),
		PresharedKey: psk.String(),
		IPAddress:    s.peerStore.AllocateIP(s.config.IPRange),
		CreatedAt:    time.Now(),
		Enabled:      true,
	}

	s.peerStore.Add(peer)
	s.syncConfig()

	w.WriteHeader(http.StatusCreated)
	router.JSON(w, peer)
}

func (s *Service) handleGetPeer(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}
	s.enrichPeersWithStatus([]*Peer{peer})
	router.JSON(w, peer)
}

func (s *Service) handleUpdatePeer(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	var req struct {
		Name    *string `json:"name"`
		Enabled *bool   `json:"enabled"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Name != nil {
		peer.Name = *req.Name
	}
	if req.Enabled != nil {
		peer.Enabled = *req.Enabled
	}

	s.peerStore.Add(peer)
	s.syncConfig()
	router.JSON(w, peer)
}

func (s *Service) handleDeletePeer(w http.ResponseWriter, r *http.Request) {
	id := router.ExtractPathParam(r, "/api/wg/peers/")
	s.peerStore.Delete(id)
	s.syncConfig()
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) handleEnablePeer(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/wg/peers/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	id := parts[0]

	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	peer.Enabled = true
	s.peerStore.Add(peer)
	s.syncConfig()
	// Return peer without sensitive keys
	peer.PrivateKey = ""
	peer.PresharedKey = ""
	router.JSON(w, peer)
}

func (s *Service) handleDisablePeer(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/wg/peers/")
	parts := strings.Split(path, "/")
	if len(parts) < 1 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	id := parts[0]

	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	peer.Enabled = false
	s.peerStore.Add(peer)
	s.syncConfig()
	// Return peer without sensitive keys
	peer.PrivateKey = ""
	peer.PresharedKey = ""
	router.JSON(w, peer)
}

func (s *Service) handleGetPeerConfig(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/wg/peers/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	id := parts[0]

	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "full"
	}

	conf := s.generateClientConfig(peer, mode)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s.conf\"", peer.Name))
	w.Write([]byte(conf))
}

func (s *Service) handleGetPeerQR(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/wg/peers/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
		router.JSONError(w, "invalid path", http.StatusBadRequest)
		return
	}
	id := parts[0]

	peer := s.peerStore.Get(id)
	if peer == nil {
		router.JSONError(w, "peer not found", http.StatusNotFound)
		return
	}

	mode := r.URL.Query().Get("mode")
	if mode == "" {
		mode = "full"
	}

	conf := s.generateClientConfig(peer, mode)
	png, err := qrcode.Encode(conf, qrcode.Medium, 256)
	if err != nil {
		router.JSONError(w, "failed to generate QR code", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "image/png")
	w.Write(png)
}

func (s *Service) handleGetServer(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]interface{}{
		"publicKey":        s.config.ServerPubKey,
		"endpoint":         s.config.Endpoint,
		"port":             s.config.ListenPort,
		"ipRange":          s.config.IPRange,
		"serverIP":         s.config.ServerIP,
		"interface":        s.config.Interface,
		"dns":              s.config.DNS,
		"headscaleIPRange": s.config.HeadscaleIPRange,
	})
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	router.JSON(w, map[string]string{"status": "ok"})
}
