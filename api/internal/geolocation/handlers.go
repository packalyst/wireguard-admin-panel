package geolocation

import (
	"log"
	"net/http"
	"strconv"

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
		"lookup_provider":        s.config.LookupProvider,
		"blocking_enabled":       s.config.BlockingEnabled,
		"blocking_provider":      s.config.BlockingProvider,
		"auto_update":            s.config.AutoUpdate,
		"update_hour":            s.config.UpdateHour,
		"update_services":        s.config.UpdateServices,
		"ip2location_variant":    s.config.IP2LocationVariant,
		"maxmind_configured":     maxmindConfigured,
		"ip2location_configured": ip2locationConfigured,
		"providers":              s.providersConfig.Providers,
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

// handleGetCountries returns all available countries with blocked status
func (s *Service) handleGetCountries(w http.ResponseWriter, r *http.Request) {
	// Get blocked countries from firewall_entries
	blockedMap := make(map[string]bool)
	if s.db != nil {
		rows, err := s.db.Query(`SELECT value FROM firewall_entries
			WHERE entry_type = 'country' AND action = 'block' AND enabled = 1`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var code string
				if rows.Scan(&code) == nil {
					blockedMap[code] = true
				}
			}
		}
	}

	countries := []map[string]interface{}{}
	for code, cfg := range s.countryConfigs {
		countries = append(countries, map[string]interface{}{
			"code":      code,
			"name":      cfg.Name,
			"continent": cfg.Continent,
			"blocked":   blockedMap[code],
		})
	}
	router.JSON(w, countries)
}

// handleRefreshZones manually refreshes all country zones from ipdeny
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

	// Trigger nftables apply to use updated zones
	if updated > 0 && s.nft != nil {
		s.nft.RequestApply()
	}

	router.JSON(w, map[string]interface{}{
		"status":  "refreshed",
		"updated": updated,
		"errors":  errors,
	})
}
