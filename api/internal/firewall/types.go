package firewall

import (
	"context"
	"database/sql"
	"sync"

	"api/internal/helper"
)

// jailMonitor tracks a running jail monitor
type jailMonitor struct {
	cancel context.CancelFunc
	name   string
}

// Service handles firewall operations
type Service struct {
	db           *sql.DB
	dbMutex      sync.RWMutex
	config       Config
	dnsCache     *lruDNSCache
	ctx          context.Context
	cancel       context.CancelFunc
	jailMonitors map[int64]*jailMonitor
	jailMutex    sync.RWMutex
	// Country zone scheduler
	zoneUpdateEnabled bool
	zoneUpdateHour    int
	zoneUpdateMutex   sync.RWMutex
}

// Config holds firewall configuration
type Config struct {
	EssentialPorts         []helper.EssentialPort `json:"-"`
	IgnoreNetworks         []string               `json:"ignoreNetworks"`
	MaxAttempts            int                    `json:"maxAttempts"`
	MaxTrafficLogs         int                    `json:"maxTrafficLogs"`
	DataDir                string                 `json:"-"`
	WgPort                 int                    `json:"-"`
	WgIPPrefix             string                 `json:"-"`
	HeadscaleIPPrefix      string                 `json:"-"`
	JailCheckInterval      int                    `json:"-"`
	TrafficMonitorInterval int                    `json:"-"`
	CleanupInterval        int                    `json:"-"`
	DNSLookupTimeout       int                    `json:"-"`
}

// Jail represents a blocking rule configuration
type Jail struct {
	ID                int64  `json:"id"`
	Name              string `json:"name"`
	Enabled           bool   `json:"enabled"`
	LogFile           string `json:"logFile"`
	FilterRegex       string `json:"filterRegex"`
	MaxRetry          int    `json:"maxRetry"`
	FindTime          int    `json:"findTime"`
	BanTime           int    `json:"banTime"`
	Port              string `json:"port"`
	Action            string `json:"action"`
	CurrentlyBanned   int    `json:"currentlyBanned"`
	TotalBanned       int    `json:"totalBanned"`
	EscalateEnabled   bool   `json:"escalateEnabled"`
	EscalateThreshold int    `json:"escalateThreshold"`
	EscalateWindow    int    `json:"escalateWindow"`
}

// BlockedIP represents a blocked IP address
type BlockedIP struct {
	ID            int64  `json:"id"`
	IP            string `json:"ip"`
	JailName      string `json:"jailName"`
	Reason        string `json:"reason"`
	BlockedAt     string `json:"blockedAt"`
	ExpiresAt     string `json:"expiresAt,omitempty"`
	HitCount      int    `json:"hitCount"`
	Manual        bool   `json:"manual"`
	IsRange       bool   `json:"isRange"`
	EscalatedFrom string `json:"escalatedFrom,omitempty"`
	Source        string `json:"source"`
}

// Attempt represents a logged connection attempt
type Attempt struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	SourceIP  string `json:"sourceIP"`
	DestPort  int    `json:"destPort"`
	Protocol  string `json:"protocol"`
	JailName  string `json:"jailName"`
	Action    string `json:"action"`
}

// TrafficLog represents VPN client outbound traffic
type TrafficLog struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	ClientIP  string `json:"src_ip"`
	DestIP    string `json:"dest_ip"`
	DestPort  int    `json:"dest_port"`
	Protocol  string `json:"protocol"`
	Domain    string `json:"domain"`
}

// AllowedPort represents an allowed port
type AllowedPort struct {
	Port      int    `json:"port"`
	Protocol  string `json:"protocol"`
	Essential bool   `json:"essential"`
	Service   string `json:"service,omitempty"`
}

// BlocklistSource represents a blocklist source configuration
type BlocklistSource struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	URL      string   `json:"url,omitempty"`
	Ranges   []string `json:"ranges,omitempty"`
	MinScore int      `json:"minScore,omitempty"`
	Count    int      `json:"count,omitempty"`
}

// CountryConfig represents a country from the config file
type CountryConfig struct {
	Code string `json:"code"`
	Name string `json:"name"`
	Flag string `json:"flag"`
}

// BlockedCountry represents an active country block
type BlockedCountry struct {
	CountryCode string `json:"countryCode"`
	Name        string `json:"name"`
	Direction   string `json:"direction"`
	Enabled     bool   `json:"enabled"`
	RangeCount  int    `json:"rangeCount"`
	CreatedAt   string `json:"createdAt"`
}

// CountryBlockingStatus represents the status of country blocking
type CountryBlockingStatus struct {
	Enabled           bool   `json:"enabled"`
	AutoUpdateEnabled bool   `json:"autoUpdateEnabled"`
	AutoUpdateHour    int    `json:"autoUpdateHour"`
	BlockedCount      int    `json:"blockedCount"`
	TotalRanges       int    `json:"totalRanges"`
	LastUpdate        string `json:"lastUpdate"`
}
