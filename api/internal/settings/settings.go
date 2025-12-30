package settings

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"api/internal/config"
	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

// Service handles settings management
type Service struct{}

// New creates a new settings service
func New() *Service {
	return &Service{}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetSettings":    s.handleGetSettings,
		"UpdateSettings": s.handleUpdateSettings,
		"TestAdGuard":    s.handleTestAdGuard,
	}
}

// SettingsResponse for GET /api/settings
type SettingsResponse struct {
	// Headscale
	HeadscaleAPIURL string `json:"headscale_api_url"` // Internal API URL (readonly, auto-detected)
	HeadscaleURL    string `json:"headscale_url"`     // Public URL for Tailscale clients
	HeadscaleAPIKey bool   `json:"headscale_api_key"` // true if set, don't expose actual key

	// AdGuard
	AdGuardUsername         string `json:"adguard_username"`
	AdGuardPassword         bool   `json:"adguard_password"`          // true if set
	AdGuardDashboardEnabled bool   `json:"adguard_dashboard_enabled"` // true = 0.0.0.0, false = 127.0.0.1
	AdGuardDashboardURL     string `json:"adguard_dashboard_url"`     // URL when dashboard enabled

	// Session
	SessionTimeout string `json:"session_timeout"`
}

// UpdateSettingsRequest for PUT /api/settings
type UpdateSettingsRequest struct {
	HeadscaleURL            *string `json:"headscale_url,omitempty"` // Public URL (editable)
	AdGuardUsername         *string `json:"adguard_username,omitempty"`
	AdGuardPassword         *string `json:"adguard_password,omitempty"`
	AdGuardDashboardEnabled *bool   `json:"adguard_dashboard_enabled,omitempty"`
	SessionTimeout          *string `json:"session_timeout,omitempty"`
}

// TestAdGuardRequest for POST /api/settings/test-adguard
type TestAdGuardRequest struct {
	URL      string  `json:"url"`
	Username string  `json:"username"`
	Password *string `json:"password"`
}

func (s *Service) handleGetSettings(w http.ResponseWriter, r *http.Request) {
	resp := SettingsResponse{}

	// Get Headscale settings
	if url, err := getSetting("headscale_api_url"); err == nil {
		resp.HeadscaleAPIURL = url
	}
	if url, err := getSetting("headscale_url"); err == nil {
		resp.HeadscaleURL = url
	}
	if _, err := getSettingEncrypted("headscale_api_key"); err == nil {
		resp.HeadscaleAPIKey = true
	}

	// Get AdGuard settings
	if username, err := getSetting("adguard_username"); err == nil {
		resp.AdGuardUsername = username
	}
	if _, err := getSettingEncrypted("adguard_password"); err == nil {
		resp.AdGuardPassword = true
	}
	// Read dashboard enabled from AdGuard config
	configPath := os.Getenv("ADGUARD_CONFIG")
	if configPath != "" {
		if data, err := os.ReadFile(configPath); err == nil {
			resp.AdGuardDashboardEnabled = strings.Contains(string(data), "address: 0.0.0.0:")
			if resp.AdGuardDashboardEnabled {
				serverIP := os.Getenv("SERVER_IP")
				adguardPort := os.Getenv("ADGUARD_PORT")
				if serverIP != "" && adguardPort != "" {
					resp.AdGuardDashboardURL = "http://" + serverIP + ":" + adguardPort
				}
			}
		}
	}

	// Get Session settings
	if timeout, err := getSetting("session_timeout"); err == nil {
		resp.SessionTimeout = timeout
	} else {
		resp.SessionTimeout = strconv.Itoa(config.GetSessionConfig().TimeoutHours)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Service) handleUpdateSettings(w http.ResponseWriter, r *http.Request) {
	var req UpdateSettingsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Update Headscale public URL (api_url is readonly, set during setup)
	if req.HeadscaleURL != nil {
		if err := setSetting("headscale_url", *req.HeadscaleURL); err != nil {
			http.Error(w, "Failed to save headscale_url: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Updated headscale_url")
	}

	// Update AdGuard settings
	adguardRestartRequired := false
	if req.AdGuardUsername != nil {
		if err := setSetting("adguard_username", *req.AdGuardUsername); err != nil {
			http.Error(w, "Failed to save adguard_username: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Updated adguard_username")
	}
	if req.AdGuardPassword != nil {
		if err := setSettingEncrypted("adguard_password", *req.AdGuardPassword); err != nil {
			http.Error(w, "Failed to save adguard_password: "+err.Error(), http.StatusInternalServerError)
			return
		}
		// Mark that adguard password has been configured
		_ = setSetting("adguard_pass_changed", "true")
		log.Printf("Updated adguard_password")
	}

	// Update AdGuard YAML config if needed
	configPath := helper.GetEnvOptional("ADGUARD_CONFIG", "")
	if configPath != "" {
		if req.AdGuardUsername != nil && req.AdGuardPassword != nil {
			if restart, err := updateAdGuardConfig(configPath, *req.AdGuardUsername, *req.AdGuardPassword); err != nil {
				log.Printf("Warning: Failed to update AdGuard config: %v", err)
			} else if restart {
				adguardRestartRequired = true
			}
		}
		if req.AdGuardDashboardEnabled != nil {
			if err := updateAdGuardDashboard(configPath, *req.AdGuardDashboardEnabled); err != nil {
				log.Printf("Warning: Failed to update AdGuard dashboard: %v", err)
			} else {
				adguardRestartRequired = true
			}
		}
	}

	// Update Session settings
	if req.SessionTimeout != nil {
		if err := setSetting("session_timeout", *req.SessionTimeout); err != nil {
			http.Error(w, "Failed to save session_timeout: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("Updated session_timeout to %s hours", *req.SessionTimeout)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":                 "ok",
		"adguardRestartRequired": adguardRestartRequired,
	})
}

func (s *Service) handleTestAdGuard(w http.ResponseWriter, r *http.Request) {
	var req TestAdGuardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.URL == "" {
		http.Error(w, "URL is required", http.StatusBadRequest)
		return
	}

	// Get password - either from request or from DB
	password := ""
	if req.Password != nil {
		password = *req.Password
	} else if stored, err := getSettingEncrypted("adguard_password"); err == nil {
		password = stored
	}

	// Test connection to AdGuard
	client := &http.Client{Timeout: 10 * time.Second}
	testReq, err := http.NewRequest("GET", req.URL+"/control/status", nil)
	if err != nil {
		http.Error(w, "Invalid URL: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Add basic auth if credentials provided
	if req.Username != "" && password != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(req.Username + ":" + password))
		testReq.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := client.Do(testReq)
	if err != nil {
		http.Error(w, "Connection failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}

	if resp.StatusCode >= 400 {
		http.Error(w, fmt.Sprintf("AdGuard returned error: %d", resp.StatusCode), http.StatusBadGateway)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

// Helper functions for settings

func getSetting(key string) (string, error) {
	db := database.Get()
	if db == nil {
		return "", fmt.Errorf("database not initialized")
	}

	var value string
	err := db.QueryRow("SELECT value FROM settings WHERE key = ? AND encrypted = 0", key).Scan(&value)
	return value, err
}

func setSetting(key, value string) error {
	db := database.Get()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := db.Exec(`
		INSERT INTO settings (key, value, encrypted, updated_at)
		VALUES (?, ?, 0, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = ?, encrypted = 0, updated_at = CURRENT_TIMESTAMP
	`, key, value, value)
	return err
}

func getSettingEncrypted(key string) (string, error) {
	db := database.Get()
	if db == nil {
		return "", fmt.Errorf("database not initialized")
	}

	var value string
	var encrypted bool
	err := db.QueryRow("SELECT value, encrypted FROM settings WHERE key = ?", key).Scan(&value, &encrypted)
	if err != nil {
		return "", err
	}

	if encrypted {
		return helper.Decrypt(value)
	}

	return value, nil
}

func setSettingEncrypted(key, value string) error {
	db := database.Get()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	encrypted, err := helper.Encrypt(value)
	if err != nil {
		return fmt.Errorf("failed to encrypt value: %v", err)
	}

	_, err = db.Exec(`
		INSERT INTO settings (key, value, encrypted, updated_at)
		VALUES (?, ?, 1, CURRENT_TIMESTAMP)
		ON CONFLICT(key) DO UPDATE SET value = ?, encrypted = 1, updated_at = CURRENT_TIMESTAMP
	`, key, encrypted, encrypted)
	return err
}

// GetSetting exports the getter for other packages
func GetSetting(key string) (string, error) {
	return getSetting(key)
}

// GetSettingEncrypted exports the encrypted getter for other packages
func GetSettingEncrypted(key string) (string, error) {
	return getSettingEncrypted(key)
}

// SetSetting exports the setter for other packages
func SetSetting(key, value string) error {
	return setSetting(key, value)
}

// SetSettingEncrypted exports the encrypted setter for other packages
func SetSettingEncrypted(key, value string) error {
	return setSettingEncrypted(key, value)
}

// DeleteSetting removes a setting from the database
func DeleteSetting(key string) error {
	db := database.Get()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	_, err := db.Exec("DELETE FROM settings WHERE key = ?", key)
	return err
}

// updateAdGuardConfig updates the username and password in AdGuardHome.yaml
// Returns true if restart is required (credentials changed)
func updateAdGuardConfig(configPath, username, password string) (bool, error) {
	// Read current config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false, err
	}

	content := string(data)

	// Hash the password using bcrypt
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return false, err
	}

	// Find and replace the users section
	// AdGuard YAML structure:
	// users:
	//   - name: username
	//     password: $2b$...

	newContent := updateYAMLUser(content, username, string(hashedPassword))

	if newContent == content {
		return false, nil // No changes needed
	}

	// Write back
	if err := os.WriteFile(configPath, []byte(newContent), 0644); err != nil {
		return false, err
	}

	log.Printf("Updated AdGuard config with new credentials for user: %s", username)
	return true, nil
}

// adguardConfig represents the relevant parts of AdGuardHome.yaml for user management
type adguardConfig struct {
	Users []struct {
		Name     string `yaml:"name"`
		Password string `yaml:"password"`
	} `yaml:"users"`
}

// updateYAMLUser updates the first user entry in the YAML content using proper YAML parsing
func updateYAMLUser(content, username, hashedPassword string) string {
	// Parse the YAML to get structure
	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(content), &cfg); err != nil {
		// Fallback to original content if parsing fails
		log.Printf("Warning: failed to parse YAML: %v", err)
		return content
	}

	// Update users section
	if users, ok := cfg["users"].([]interface{}); ok && len(users) > 0 {
		if user, ok := users[0].(map[string]interface{}); ok {
			user["name"] = username
			user["password"] = hashedPassword
		}
	}

	// Marshal back to YAML
	newContent, err := yaml.Marshal(cfg)
	if err != nil {
		log.Printf("Warning: failed to marshal YAML: %v", err)
		return content
	}

	return string(newContent)
}

// updateAdGuardDashboard updates the http.address in AdGuardHome.yaml
// enabled=true: 0.0.0.0:port (accessible externally)
// enabled=false: 127.0.0.1:port (local only)
func updateAdGuardDashboard(configPath string, enabled bool) error {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	var cfg map[string]interface{}
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse YAML: %v", err)
	}

	// Get current address to extract port
	port := "8083"
	if http, ok := cfg["http"].(map[string]interface{}); ok {
		if addr, ok := http["address"].(string); ok {
			// Extract port from "ip:port" format
			parts := strings.Split(addr, ":")
			if len(parts) >= 2 {
				port = parts[len(parts)-1]
			}
		}
		// Update address
		if enabled {
			http["address"] = "0.0.0.0:" + port
		} else {
			http["address"] = "127.0.0.1:" + port
		}
	}

	newData, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal YAML: %v", err)
	}

	return os.WriteFile(configPath, newData, 0644)
}
