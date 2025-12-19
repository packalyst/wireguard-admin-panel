package geolocation

import "time"

// GeoResult represents the result of an IP geolocation lookup
type GeoResult struct {
	IP          string `json:"ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	City        string `json:"city,omitempty"`
	Region      string `json:"region,omitempty"`
	Provider    string `json:"provider"`
}

// Provider interface for geolocation lookup providers
type Provider interface {
	Name() string
	Init() error
	Lookup(ip string) (*GeoResult, error)
	LookupBulk(ips []string) map[string]*GeoResult
	Close() error
	// Update methods
	NeedsUpdate() bool
	Update() error
	LastUpdated() time.Time
	IsAvailable() bool
}

// CIDRProvider interface for providers that supply country CIDR ranges
type CIDRProvider interface {
	Name() string
	GetCountryCIDRs(countryCode string) ([]string, error)
	GetAllBlockedCIDRs(outboundOnly bool) ([]string, error)
	GetCachedZones(countryCode string) (string, error)
	FetchCountryZones(countryCode string) (string, error)
	RefreshAllZones() (updated int, errors int)
	Close() error
	NeedsUpdate() bool
	Update() error
	LastUpdated() time.Time
}

// Config holds geolocation service configuration
type Config struct {
	DataDir             string
	LookupProvider      string // none, maxmind, ip2location
	BlockingEnabled     bool
	BlockingProvider    string // ipdeny
	AutoUpdate          bool
	UpdateHour          int
	UpdateServices      string // all, lookup, blocking
	MaxMindLicenseKey   string
	IP2LocationToken    string
	IP2LocationVariant  string // DB1, DB3
}

// Status represents the current status of the geolocation service
type Status struct {
	LookupProvider    string                    `json:"lookup_provider"`
	BlockingEnabled   bool                      `json:"blocking_enabled"`
	BlockingProvider  string                    `json:"blocking_provider"`
	AutoUpdate        bool                      `json:"auto_update"`
	UpdateHour        int                       `json:"update_hour"`
	UpdateServices    string                    `json:"update_services"`
	LastUpdateLookup  string                    `json:"last_update_lookup"`
	LastUpdateBlocking string                   `json:"last_update_blocking"`
	Providers         map[string]ProviderStatus `json:"providers"`
}

// ProviderStatus represents the status of a single provider
type ProviderStatus struct {
	Name       string `json:"name"`
	Available  bool   `json:"available"`
	Configured bool   `json:"configured"`
	FileSize   int64  `json:"file_size,omitempty"`
	FilePath   string `json:"file_path,omitempty"`
	LastUpdate string `json:"last_update,omitempty"`
	Error      string `json:"error,omitempty"`
}

// BlockedCountry represents a country that is blocked
type BlockedCountry struct {
	CountryCode string `json:"country_code"`
	Name        string `json:"name"`
	Direction   string `json:"direction"` // inbound, both
	Enabled     bool   `json:"enabled"`
	RangeCount  int    `json:"range_count"`
	CreatedAt   string `json:"created_at"`
}

// CountryConfig holds country metadata from config file
type CountryConfig struct {
	Name   string `json:"name"`
	Region string `json:"region"`
}

// Settings request/response types
type GeoSettings struct {
	LookupProvider     string `json:"lookup_provider"`
	BlockingEnabled    bool   `json:"blocking_enabled"`
	AutoUpdate         bool   `json:"auto_update"`
	UpdateHour         int    `json:"update_hour"`
	UpdateServices     string `json:"update_services"`
	MaxMindLicenseKey  string `json:"maxmind_license_key,omitempty"`
	IP2LocationToken   string `json:"ip2location_token,omitempty"`
	IP2LocationVariant string `json:"ip2location_variant"`
}

// LookupRequest for bulk IP lookups
type LookupRequest struct {
	IPs []string `json:"ips"`
}

// LookupResponse for bulk IP lookups
type LookupResponse struct {
	Results map[string]*GeoResult `json:"results"`
	Errors  map[string]string     `json:"errors,omitempty"`
}

// BlockCountryRequest for blocking a country
type BlockCountryRequest struct {
	CountryCode string `json:"country_code"`
	Direction   string `json:"direction"` // inbound, both
}

// CountryBlockingStatus represents overall status of country blocking
type CountryBlockingStatus struct {
	Enabled       bool   `json:"enabled"`
	BlockedCount  int    `json:"blocked_count"`
	TotalRanges   int    `json:"total_ranges"`
	LastUpdate    string `json:"last_update"`
	AutoUpdate    bool   `json:"auto_update"`
	UpdateHour    int    `json:"update_hour"`
}
