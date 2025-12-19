package geolocation

import (
	"fmt"
	"log"
	"os/exec"
	"strings"
)

const (
	nftTable         = "firewall"
	nftFamily        = "inet"
	nftSetInbound    = "blocked_countries"
	nftSetOutbound   = "blocked_countries_out"
	nftBatchSize     = 1000
)

// UpdateCountrySet adds or removes country zones from the nftables set
func (s *Service) UpdateCountrySet(zones string, add bool, outbound bool) error {
	var elements []string
	for _, zone := range strings.Split(zones, "\n") {
		zone = strings.TrimSpace(zone)
		if zone != "" && !strings.HasPrefix(zone, "#") {
			elements = append(elements, zone)
		}
	}

	if len(elements) == 0 {
		return nil
	}

	setName := nftSetInbound
	if outbound {
		setName = nftSetOutbound
	}

	action := "add"
	if !add {
		action = "delete"
	}

	// Process in batches
	for i := 0; i < len(elements); i += nftBatchSize {
		end := i + nftBatchSize
		if end > len(elements) {
			end = len(elements)
		}
		batch := elements[i:end]

		cmd := exec.Command("nft", action, "element", nftFamily, nftTable, setName,
			"{", strings.Join(batch, ", "), "}")
		if out, err := cmd.CombinedOutput(); err != nil {
			// Ignore "already exists" or "doesn't exist" errors
			if !strings.Contains(string(out), "exists") && !strings.Contains(string(out), "No such") {
				return fmt.Errorf("nft %s element error: %v - %s", action, err, string(out))
			}
		}
	}

	return nil
}

// UpdateCountryOutboundSet is a convenience wrapper for outbound set operations
func (s *Service) UpdateCountryOutboundSet(zones string, add bool) error {
	return s.UpdateCountrySet(zones, add, true)
}

// UpdateCountryInboundSet is a convenience wrapper for inbound set operations
func (s *Service) UpdateCountryInboundSet(zones string, add bool) error {
	return s.UpdateCountrySet(zones, add, false)
}

// ClearCountrySets clears all country blocking nftables sets
func (s *Service) ClearCountrySets() error {
	sets := []string{nftSetInbound, nftSetOutbound}

	for _, setName := range sets {
		// Flush the set
		cmd := exec.Command("nft", "flush", "set", nftFamily, nftTable, setName)
		if out, err := cmd.CombinedOutput(); err != nil {
			// Ignore if set doesn't exist
			if !strings.Contains(string(out), "No such") {
				log.Printf("Warning: failed to flush set %s: %v - %s", setName, err, string(out))
			}
		}
	}

	log.Printf("Cleared country blocking nftables sets")
	return nil
}

// ApplyCountryBlocking applies country blocking rules for a specific country
func (s *Service) ApplyCountryBlocking(countryCode string, direction string) error {
	if s.blockingProvider == nil {
		return fmt.Errorf("blocking provider not initialized")
	}

	zones, err := s.blockingProvider.GetCachedZones(countryCode)
	if err != nil {
		return fmt.Errorf("failed to get zones for %s: %v", countryCode, err)
	}

	// Add to inbound set (always)
	if err := s.UpdateCountryInboundSet(zones, true); err != nil {
		return fmt.Errorf("failed to add to inbound set: %v", err)
	}

	// Add to outbound set if direction is "both"
	if direction == "both" {
		if err := s.UpdateCountryOutboundSet(zones, true); err != nil {
			return fmt.Errorf("failed to add to outbound set: %v", err)
		}
	}

	return nil
}

// RemoveCountryBlocking removes country blocking rules for a specific country
func (s *Service) RemoveCountryBlocking(countryCode string, direction string) error {
	if s.blockingProvider == nil {
		return fmt.Errorf("blocking provider not initialized")
	}

	zones, err := s.blockingProvider.GetCachedZones(countryCode)
	if err != nil {
		// If no cached zones, nothing to remove
		return nil
	}

	// Remove from inbound set
	if err := s.UpdateCountryInboundSet(zones, false); err != nil {
		log.Printf("Warning: failed to remove from inbound set: %v", err)
	}

	// Remove from outbound set
	if err := s.UpdateCountryOutboundSet(zones, false); err != nil {
		log.Printf("Warning: failed to remove from outbound set: %v", err)
	}

	return nil
}

// ReapplyAllCountryBlocking reapplies all enabled country blocking rules
func (s *Service) ReapplyAllCountryBlocking() error {
	if !s.IsBlockingEnabled() || s.blockingProvider == nil {
		return nil
	}

	// Get all blocked countries
	countries, err := s.getBlockedCountries()
	if err != nil {
		return fmt.Errorf("failed to get blocked countries: %v", err)
	}

	for _, country := range countries {
		if !country.Enabled {
			continue
		}

		if err := s.ApplyCountryBlocking(country.CountryCode, country.Direction); err != nil {
			log.Printf("Warning: failed to apply blocking for %s: %v", country.CountryCode, err)
		}
	}

	return nil
}

// getBlockedCountries retrieves all blocked countries from the database
func (s *Service) getBlockedCountries() ([]BlockedCountry, error) {
	if s.db == nil {
		return nil, fmt.Errorf("database not available")
	}

	rows, err := s.db.Query(`
		SELECT b.country_code, b.name, b.direction, b.enabled,
			COALESCE(b.status, 'active') as status,
			COALESCE(LENGTH(c.zones) - LENGTH(REPLACE(c.zones, char(10), '')) + 1, 0) as range_count,
			b.created_at
		FROM blocked_countries b
		LEFT JOIN country_zones_cache c ON b.country_code = c.country_code
		ORDER BY b.created_at DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var countries []BlockedCountry
	for rows.Next() {
		var c BlockedCountry
		if err := rows.Scan(&c.CountryCode, &c.Name, &c.Direction, &c.Enabled, &c.Status, &c.RangeCount, &c.CreatedAt); err != nil {
			continue
		}
		countries = append(countries, c)
	}

	return countries, nil
}

// DisableBlocking disables country blocking and clears nftables sets
func (s *Service) DisableBlocking() error {
	// Clear nftables sets
	if err := s.ClearCountrySets(); err != nil {
		log.Printf("Warning: failed to clear country sets: %v", err)
	}

	// Update config
	s.mu.Lock()
	s.config.BlockingEnabled = false
	s.mu.Unlock()

	log.Printf("Country blocking disabled")
	return nil
}

// EnableBlocking enables country blocking and applies all rules
func (s *Service) EnableBlocking() error {
	// Update config
	s.mu.Lock()
	s.config.BlockingEnabled = true
	s.mu.Unlock()

	// Initialize blocking provider if needed
	if s.blockingProvider == nil {
		s.blockingProvider = NewIPDenyProvider(s.db)
	}

	// Reapply all country blocking rules
	if err := s.ReapplyAllCountryBlocking(); err != nil {
		return fmt.Errorf("failed to apply blocking rules: %v", err)
	}

	log.Printf("Country blocking enabled")
	return nil
}
