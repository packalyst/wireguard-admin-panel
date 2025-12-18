package firewall

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Country configs loaded from config file
var countryConfigs map[string]CountryConfig

func init() {
	countryConfigs = make(map[string]CountryConfig)
}

// LoadCountryConfigs loads country configurations from JSON file
func LoadCountryConfigs() {
	configPath := "/app/configs/countries.json"
	data, err := os.ReadFile(configPath)
	if err != nil {
		log.Printf("Warning: failed to load country configs from %s: %v", configPath, err)
		return
	}

	if err := json.Unmarshal(data, &countryConfigs); err != nil {
		log.Printf("Warning: failed to parse country configs: %v", err)
		return
	}

	log.Printf("Loaded %d country configs from config", len(countryConfigs))
}

// GetCountryConfigs returns the loaded country configurations
func GetCountryConfigs() map[string]CountryConfig {
	return countryConfigs
}

// fetchCountryZones fetches IP zones for a country from ipdeny.com
func (s *Service) fetchCountryZones(countryCode string) (string, error) {
	countryCode = strings.ToLower(countryCode)
	url := fmt.Sprintf("https://www.ipdeny.com/ipblocks/data/countries/%s.zone", countryCode)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// Clean up the zones - remove comments and empty lines
	var cleanZones []string
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			cleanZones = append(cleanZones, line)
		}
	}

	return strings.Join(cleanZones, "\n"), nil
}

// refreshAllCountryZones refreshes zones for all blocked countries
func (s *Service) refreshAllCountryZones() (int, int) {
	rows, err := s.db.Query("SELECT country_code FROM blocked_countries WHERE enabled = 1")
	if err != nil {
		return 0, 1
	}
	defer rows.Close()

	var countryCodes []string
	for rows.Next() {
		var code string
		if err := rows.Scan(&code); err != nil {
			continue
		}
		countryCodes = append(countryCodes, code)
	}

	updated := 0
	errors := 0
	for _, code := range countryCodes {
		zones, err := s.fetchCountryZones(code)
		if err != nil {
			log.Printf("Error fetching zones for %s: %v", code, err)
			errors++
			continue
		}

		_, err = s.db.Exec(`
			INSERT INTO country_zones_cache (country_code, zones, updated_at)
			VALUES (?, ?, datetime('now'))
			ON CONFLICT(country_code) DO UPDATE SET zones = ?, updated_at = datetime('now')
		`, code, zones, zones)
		if err != nil {
			log.Printf("Error caching zones for %s: %v", code, err)
			errors++
			continue
		}

		updated++
		log.Printf("Refreshed zones for %s: %d ranges", code, strings.Count(zones, "\n")+1)
	}

	return updated, errors
}

// loadZoneSchedulerSettings loads scheduler settings from database
func (s *Service) loadZoneSchedulerSettings() {
	var enabledStr, hourStr string

	if err := s.db.QueryRow("SELECT value FROM settings WHERE key = 'zone_update_enabled'").Scan(&enabledStr); err == nil {
		s.zoneUpdateEnabled, _ = strconv.ParseBool(enabledStr)
	}

	if err := s.db.QueryRow("SELECT value FROM settings WHERE key = 'zone_update_hour'").Scan(&hourStr); err == nil {
		s.zoneUpdateHour, _ = strconv.Atoi(hourStr)
	} else {
		s.zoneUpdateHour = 3 // Default to 3 AM
	}

	log.Printf("Zone update scheduler settings: enabled=%v, hour=%d", s.zoneUpdateEnabled, s.zoneUpdateHour)
}

// updateCountryOutboundSet adds or removes country zones from the outbound set
func (s *Service) updateCountryOutboundSet(zones string, add bool) error {
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

	batchSize := 1000
	action := "add"
	if !add {
		action = "delete"
	}

	for i := 0; i < len(elements); i += batchSize {
		end := i + batchSize
		if end > len(elements) {
			end = len(elements)
		}
		batch := elements[i:end]

		cmd := exec.Command("nft", action, "element", "inet", "firewall", "blocked_countries_out", "{", strings.Join(batch, ", "), "}")
		if out, err := cmd.CombinedOutput(); err != nil {
			if !strings.Contains(string(out), "exists") && !strings.Contains(string(out), "No such") {
				return fmt.Errorf("nft %s element error: %v - %s", action, err, string(out))
			}
		}
	}

	return nil
}

// runZoneUpdateScheduler runs the daily zone update scheduler
func (s *Service) runZoneUpdateScheduler() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	lastRunDate := ""

	for {
		select {
		case <-s.ctx.Done():
			log.Printf("Zone update scheduler stopping")
			return
		case <-ticker.C:
			s.zoneUpdateMutex.RLock()
			enabled := s.zoneUpdateEnabled
			targetHour := s.zoneUpdateHour
			s.zoneUpdateMutex.RUnlock()

			if !enabled {
				continue
			}

			now := time.Now()
			currentDate := now.Format("2006-01-02")
			currentHour := now.Hour()

			if currentHour == targetHour && currentDate != lastRunDate {
				log.Printf("Running scheduled zone update at %s", now.Format(time.RFC3339))
				updated, errors := s.refreshAllCountryZones()
				if updated > 0 {
					s.ApplyRules()
				}
				log.Printf("Scheduled zone update complete: %d updated, %d errors", updated, errors)
				lastRunDate = currentDate
			}
		}
	}
}
