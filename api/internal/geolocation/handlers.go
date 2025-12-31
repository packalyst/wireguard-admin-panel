package geolocation

import (
	"database/sql"
	"log"
	"net/http"
	"strconv"
	"strings"

	"api/internal/router"
	"api/internal/settings"
)

// handleGetSettings returns current geolocation settings
func (s *Service) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Check if keys are configured (don't return actual values)
	maxmindConfigured := s.config.MaxMindLicenseKey != ""
	ip2locationConfigured := s.config.IP2LocationToken != ""

	response := map[string]interface{}{
		"lookup_provider":         s.config.LookupProvider,
		"blocking_enabled":        s.config.BlockingEnabled,
		"blocking_provider":       s.config.BlockingProvider,
		"auto_update":             s.config.AutoUpdate,
		"update_hour":             s.config.UpdateHour,
		"update_services":         s.config.UpdateServices,
		"ip2location_variant":     s.config.IP2LocationVariant,
		"maxmind_configured":      maxmindConfigured,
		"ip2location_configured":  ip2locationConfigured,
		"providers":               s.providersConfig.Providers,
	}

	router.JSON(w, response)
}

// handleUpdateSettings updates geolocation settings
func (s *Service) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req struct {
		LookupProvider     *string `json:"lookup_provider"`
		BlockingEnabled    *bool   `json:"blocking_enabled"`
		AutoUpdate         *bool   `json:"auto_update"`
		UpdateHour         *int    `json:"update_hour"`
		UpdateServices     *string `json:"update_services"`
		MaxMindLicenseKey  *string `json:"maxmind_license_key"`
		IP2LocationToken   *string `json:"ip2location_token"`
		IP2LocationVariant *string `json:"ip2location_variant"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	needsReload := false

	// Update settings
	if req.LookupProvider != nil {
		settings.SetSetting("geo_lookup_provider", *req.LookupProvider)
		needsReload = true
	}

	if req.BlockingEnabled != nil {
		settings.SetSetting("geo_blocking_enabled", strconv.FormatBool(*req.BlockingEnabled))
		if *req.BlockingEnabled {
			s.EnableBlocking()
		} else {
			s.DisableBlocking()
		}
	}

	if req.AutoUpdate != nil {
		settings.SetSetting("geo_auto_update", strconv.FormatBool(*req.AutoUpdate))
	}

	if req.UpdateHour != nil {
		settings.SetSetting("geo_update_hour", strconv.Itoa(*req.UpdateHour))
	}

	if req.UpdateServices != nil {
		settings.SetSetting("geo_update_services", *req.UpdateServices)
	}

	if req.MaxMindLicenseKey != nil && *req.MaxMindLicenseKey != "" {
		settings.SetSettingEncrypted("geo_maxmind_license_key", *req.MaxMindLicenseKey)
		needsReload = true
	}

	if req.IP2LocationToken != nil && *req.IP2LocationToken != "" {
		settings.SetSettingEncrypted("geo_ip2location_token", *req.IP2LocationToken)
		needsReload = true
	}

	if req.IP2LocationVariant != nil {
		settings.SetSetting("geo_ip2location_variant", *req.IP2LocationVariant)
		needsReload = true
	}

	// Reload config and providers if needed
	if needsReload {
		if err := s.ReloadConfig(); err != nil {
			log.Printf("Warning: failed to reload config: %v", err)
		}
	} else {
		s.loadConfig()
	}

	router.JSON(w, map[string]interface{}{
		"status":  "updated",
		"message": "Settings updated successfully",
	})
}

// handleLookupIP performs a single IP lookup
func (s *Service) handleLookupIP(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		router.JSONError(w, "ip parameter required", http.StatusBadRequest)
		return
	}

	result, err := s.LookupIP(ip)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, result)
}

// handleLookupBulk performs bulk IP lookups
func (s *Service) handleLookupBulk(w http.ResponseWriter, r *http.Request) {
	var req LookupRequest
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if len(req.IPs) == 0 {
		router.JSONError(w, "ips array required", http.StatusBadRequest)
		return
	}

	if len(req.IPs) > 1000 {
		router.JSONError(w, "maximum 1000 IPs per request", http.StatusBadRequest)
		return
	}

	results, errors := s.LookupBulk(req.IPs)

	router.JSON(w, LookupResponse{
		Results: results,
		Errors:  errors,
	})
}

// handleGetStatus returns geolocation service status
func (s *Service) handleGetStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	providers := make(map[string]ProviderStatus)

	// MaxMind status
	maxmindStatus := ProviderStatus{
		Name:       "maxmind",
		Configured: s.config.MaxMindLicenseKey != "",
	}
	if s.lookupProvider != nil && s.lookupProvider.Name() == "maxmind" {
		maxmindStatus.Available = s.lookupProvider.IsAvailable()
		maxmindStatus.LastUpdate = s.lookupProvider.LastUpdated().Format("2006-01-02 15:04:05")
		if mp, ok := s.lookupProvider.(*MaxMindProvider); ok {
			maxmindStatus.FileSize = mp.GetFileSize()
			maxmindStatus.FilePath = mp.GetFilePath()
		}
	}
	providers["maxmind"] = maxmindStatus

	// IP2Location status
	ip2locStatus := ProviderStatus{
		Name:       "ip2location",
		Configured: s.config.IP2LocationToken != "",
	}
	if s.lookupProvider != nil && s.lookupProvider.Name() == "ip2location" {
		ip2locStatus.Available = s.lookupProvider.IsAvailable()
		ip2locStatus.LastUpdate = s.lookupProvider.LastUpdated().Format("2006-01-02 15:04:05")
		if ip, ok := s.lookupProvider.(*IP2LocationProvider); ok {
			ip2locStatus.FileSize = ip.GetFileSize()
			ip2locStatus.FilePath = ip.GetFilePath()
		}
	}
	providers["ip2location"] = ip2locStatus

	// IPDeny status
	ipdenyStatus := ProviderStatus{
		Name:       "ipdeny",
		Available:  s.blockingProvider != nil,
		Configured: true, // Always available, no key needed
	}
	if s.blockingProvider != nil {
		ipdenyStatus.LastUpdate = s.blockingProvider.LastUpdated().Format("2006-01-02 15:04:05")
	}
	providers["ipdeny"] = ipdenyStatus

	// Get last update times
	lastUpdateLookup, _ := settings.GetSetting("geo_last_update_lookup")
	lastUpdateBlocking, _ := settings.GetSetting("geo_last_update_blocking")

	status := Status{
		LookupProvider:     s.config.LookupProvider,
		BlockingEnabled:    s.config.BlockingEnabled,
		BlockingProvider:   s.config.BlockingProvider,
		AutoUpdate:         s.config.AutoUpdate,
		UpdateHour:         s.config.UpdateHour,
		UpdateServices:     s.config.UpdateServices,
		LastUpdateLookup:   lastUpdateLookup,
		LastUpdateBlocking: lastUpdateBlocking,
		Providers:          providers,
	}

	router.JSON(w, status)
}

// handleTriggerUpdate manually triggers a database update
func (s *Service) handleTriggerUpdate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Services string `json:"services"` // all, lookup, blocking
	}
	// Optional JSON body - defaults to "all" if not provided or invalid
	_ = router.DecodeJSON(r, &req)

	if req.Services == "" {
		req.Services = "all"
	}

	results, err := s.TriggerUpdate(req.Services)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]interface{}{
		"status":  "triggered",
		"results": results,
	})
}

// handleGetCountries returns all available countries
func (s *Service) handleGetCountries(w http.ResponseWriter, r *http.Request) {
	countries := []map[string]interface{}{}
	for code, cfg := range s.countryConfigs {
		countries = append(countries, map[string]interface{}{
			"code":      code,
			"name":      cfg.Name,
			"continent": cfg.Continent,
		})
	}
	router.JSON(w, countries)
}

// handleGetBlockedCountries returns blocked countries
func (s *Service) handleGetBlockedCountries(w http.ResponseWriter, r *http.Request) {
	if !s.IsBlockingEnabled() {
		router.JSON(w, map[string]interface{}{
			"enabled":   false,
			"countries": []BlockedCountry{},
			"message":   "Country blocking is disabled. Enable it in Settings → Geolocation.",
		})
		return
	}

	countries, err := s.getBlockedCountries()
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, map[string]interface{}{
		"enabled":   true,
		"countries": countries,
	})
}

// handleBlockCountry blocks one or more countries
func (s *Service) handleBlockCountry(w http.ResponseWriter, r *http.Request) {
	if !s.IsBlockingEnabled() {
		router.JSONError(w, "Country blocking is disabled. Enable it in Settings → Geolocation.", http.StatusServiceUnavailable)
		return
	}

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
		"status":  "added",
		"count":   successCount,
		"total":   len(codes),
		"results": results,
	})
}

// blockSingleCountry blocks a single country and returns result info
func (s *Service) blockSingleCountry(countryCode, direction string) (name string, rangeCount int, warning string, err error) {
	countryCode = strings.ToUpper(countryCode)
	if len(countryCode) != 2 {
		return "", 0, "", nil
	}

	name = countryCode
	if cfg, exists := s.countryConfigs[countryCode]; exists {
		name = cfg.Name
	}

	if direction == "" {
		direction = "inbound"
	}

	// Check if zones already cached
	var cachedZones string
	var zonesExist bool
	if s.blockingProvider != nil {
		cachedZones, err = s.blockingProvider.GetCachedZones(countryCode)
		zonesExist = err == nil && cachedZones != ""
	}

	// Insert/update blocked country
	_, err = s.db.Exec(`
		INSERT INTO blocked_countries (country_code, name, direction, enabled)
		VALUES (?, ?, ?, 1)
		ON CONFLICT(country_code) DO UPDATE SET direction = ?, enabled = 1
	`, countryCode, name, direction, direction)
	if err != nil {
		return name, 0, "", err
	}

	if !zonesExist {
		// Fetch zones from ipdeny
		if s.blockingProvider != nil {
			zones, fetchErr := s.blockingProvider.FetchCountryZones(countryCode)
			if fetchErr != nil {
				log.Printf("Warning: failed to fetch zones for %s: %v", countryCode, fetchErr)
				return name, 0, "failed to fetch zones: " + fetchErr.Error(), nil
			}

			// Cache the zones
			if provider, ok := s.blockingProvider.(*IPDenyProvider); ok {
				provider.CacheZones(countryCode, zones)
			}

			rangeCount = strings.Count(zones, "\n") + 1

			// Apply to nftables
			if err := s.ApplyCountryBlocking(countryCode, direction); err != nil {
				log.Printf("Warning: failed to apply nftables rules for %s: %v", countryCode, err)
			}

			log.Printf("Country blocked: %s (%s), %d ranges (fetched)", countryCode, name, rangeCount)
		}
	} else {
		rangeCount = strings.Count(cachedZones, "\n") + 1

		// Update nftables based on direction
		if direction == "both" {
			if err := s.UpdateCountryOutboundSet(cachedZones, true); err != nil {
				log.Printf("Warning: failed to add to outbound set: %v", err)
			}
		} else {
			if err := s.UpdateCountryOutboundSet(cachedZones, false); err != nil {
				log.Printf("Warning: failed to remove from outbound set: %v", err)
			}
		}

		// Always ensure inbound is set
		if err := s.UpdateCountryInboundSet(cachedZones, true); err != nil {
			log.Printf("Warning: failed to add to inbound set: %v", err)
		}

		log.Printf("Country direction updated: %s (%s) -> %s (fast path)", countryCode, name, direction)
	}

	return name, rangeCount, "", nil
}

// handleUnblockCountry removes a country from block list
func (s *Service) handleUnblockCountry(w http.ResponseWriter, r *http.Request) {
	if !s.IsBlockingEnabled() {
		router.JSONError(w, "Country blocking is disabled", http.StatusServiceUnavailable)
		return
	}

	countryCode := router.ExtractPathParam(r, "/api/geo/blocked/")
	countryCode = strings.ToUpper(countryCode)
	if countryCode == "" {
		router.JSONError(w, "country code required", http.StatusBadRequest)
		return
	}

	// Get current status and direction
	var direction, currentStatus string
	err := s.db.QueryRow("SELECT direction, COALESCE(status, 'active') FROM blocked_countries WHERE country_code = ?", countryCode).Scan(&direction, &currentStatus)
	if err != nil {
		router.JSONError(w, "Country not found", http.StatusNotFound)
		return
	}

	// If already removing, just return current status
	if currentStatus == "removing" {
		router.JSON(w, map[string]interface{}{
			"status":      "removing",
			"countryCode": countryCode,
		})
		return
	}

	// Set status to 'removing' immediately
	_, err = s.db.Exec("UPDATE blocked_countries SET status = 'removing' WHERE country_code = ?", countryCode)
	if err != nil {
		router.JSONError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Process removal in background
	go func() {
		// Remove from nftables
		if err := s.RemoveCountryBlocking(countryCode, direction); err != nil {
			log.Printf("Warning: failed to remove nftables rules for %s: %v", countryCode, err)
		}

		// Delete from database
		result, err := s.db.Exec("DELETE FROM blocked_countries WHERE country_code = ?", countryCode)
		if err != nil {
			log.Printf("Error deleting blocked country %s: %v", countryCode, err)
			// Revert status on error
			s.db.Exec("UPDATE blocked_countries SET status = 'active' WHERE country_code = ?", countryCode)
			return
		}

		deleted, _ := result.RowsAffected()
		if deleted > 0 {
			// Also delete cached zones
			if provider, ok := s.blockingProvider.(*IPDenyProvider); ok {
				provider.DeleteCachedZones(countryCode)
			}
			log.Printf("Country %s unblocked successfully", countryCode)
		}
	}()

	router.JSON(w, map[string]interface{}{
		"status":      "removing",
		"countryCode": countryCode,
	})
}

// handleGetBlockingStatus returns country blocking status
func (s *Service) handleGetBlockingStatus(w http.ResponseWriter, r *http.Request) {
	var blockedCount, totalRanges int
	var lastUpdate sql.NullString

	if s.db != nil {
		s.db.QueryRow("SELECT COUNT(*) FROM blocked_countries WHERE enabled = 1").Scan(&blockedCount)
		s.db.QueryRow(`
			SELECT COALESCE(SUM(LENGTH(c.zones) - LENGTH(REPLACE(c.zones, char(10), '')) + 1), 0)
			FROM country_zones_cache c
			INNER JOIN blocked_countries b ON c.country_code = b.country_code
			WHERE b.enabled = 1
		`).Scan(&totalRanges)
		s.db.QueryRow("SELECT MAX(updated_at) FROM country_zones_cache").Scan(&lastUpdate)
	}

	s.mu.RLock()
	status := CountryBlockingStatus{
		Enabled:      s.config.BlockingEnabled,
		BlockedCount: blockedCount,
		TotalRanges:  totalRanges,
		LastUpdate:   lastUpdate.String,
		AutoUpdate:   s.config.AutoUpdate,
		UpdateHour:   s.config.UpdateHour,
	}
	s.mu.RUnlock()

	router.JSON(w, status)
}

// handleRefreshZones manually refreshes all country zones
func (s *Service) handleRefreshZones(w http.ResponseWriter, r *http.Request) {
	if !s.IsBlockingEnabled() {
		router.JSONError(w, "Country blocking is disabled", http.StatusServiceUnavailable)
		return
	}

	if s.blockingProvider == nil {
		router.JSONError(w, "Blocking provider not initialized", http.StatusInternalServerError)
		return
	}

	updated, errors := s.blockingProvider.RefreshAllZones()

	// Reapply nftables rules
	if updated > 0 {
		if err := s.ReapplyAllCountryBlocking(); err != nil {
			log.Printf("Warning: failed to reapply blocking rules: %v", err)
		}
	}

	router.JSON(w, map[string]interface{}{
		"status":  "refreshed",
		"updated": updated,
		"errors":  errors,
	})
}
