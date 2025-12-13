package smtp

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"strconv"
	"strings"
	"time"

	"api/internal/auth"
	"api/internal/database"
	"api/internal/router"
)

// Service handles SMTP configuration and email sending
type Service struct {
	auth *auth.Service
}

// New creates a new SMTP service
func New() *Service {
	return &Service{
		auth: auth.GetService(),
	}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetSMTP":  s.handleGetSMTP,
		"SaveSMTP": s.handleSaveSMTP,
		"TestSMTP": s.handleTestSMTP,
	}
}

// SMTPConfig represents SMTP configuration
type SMTPConfig struct {
	Mode     string `json:"mode"`     // "builtin" or "external"
	Host     string `json:"host"`     // SMTP host (for external)
	Port     int    `json:"port"`     // SMTP port (for external)
	Username string `json:"username"` // SMTP username (for external)
	Password bool   `json:"password"` // true if password is set (never expose)
	From     string `json:"from"`     // From email address
	TLS      string `json:"tls"`      // "none", "starttls", "tls"
}

// SMTPSaveRequest represents SMTP save request
type SMTPSaveRequest struct {
	Mode     string  `json:"mode"`
	Host     string  `json:"host"`
	Port     int     `json:"port"`
	Username string  `json:"username"`
	Password *string `json:"password,omitempty"` // nil means don't change
	From     string  `json:"from"`
	TLS      string  `json:"tls"`
}

// SMTPTestRequest represents SMTP test request
type SMTPTestRequest struct {
	To string `json:"to"` // Email address to send test to
}

func (s *Service) handleGetSMTP(w http.ResponseWriter, r *http.Request) {
	config := SMTPConfig{
		Mode: "builtin", // default
		Port: 25,
		TLS:  "none",
	}

	// Get stored settings
	if mode, err := getSetting("smtp_mode"); err == nil {
		config.Mode = mode
	}
	if host, err := getSetting("smtp_host"); err == nil {
		config.Host = host
	}
	if portStr, err := getSetting("smtp_port"); err == nil {
		if port, err := strconv.Atoi(portStr); err == nil {
			config.Port = port
		}
	}
	if username, err := getSetting("smtp_username"); err == nil {
		config.Username = username
	}
	if _, err := getSettingEncrypted("smtp_password"); err == nil {
		config.Password = true
	}
	if from, err := getSetting("smtp_from"); err == nil {
		config.From = from
	} else {
		// Default from address using MAIL_DOMAIN
		mailDomain := os.Getenv("MAIL_DOMAIN")
		if mailDomain != "" {
			config.From = "noreply@" + mailDomain
		}
	}
	if tlsMode, err := getSetting("smtp_tls"); err == nil {
		config.TLS = tlsMode
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
}

func (s *Service) handleSaveSMTP(w http.ResponseWriter, r *http.Request) {
	var req SMTPSaveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate mode
	if req.Mode != "builtin" && req.Mode != "external" {
		http.Error(w, "Invalid mode, must be 'builtin' or 'external'", http.StatusBadRequest)
		return
	}

	// Save settings
	if err := setSetting("smtp_mode", req.Mode); err != nil {
		http.Error(w, "Failed to save smtp_mode: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if req.Mode == "external" {
		if req.Host == "" {
			http.Error(w, "Host is required for external SMTP", http.StatusBadRequest)
			return
		}
		if req.Port <= 0 || req.Port > 65535 {
			http.Error(w, "Invalid port number", http.StatusBadRequest)
			return
		}

		if err := setSetting("smtp_host", req.Host); err != nil {
			http.Error(w, "Failed to save smtp_host", http.StatusInternalServerError)
			return
		}
		if err := setSetting("smtp_port", strconv.Itoa(req.Port)); err != nil {
			http.Error(w, "Failed to save smtp_port", http.StatusInternalServerError)
			return
		}
		if err := setSetting("smtp_username", req.Username); err != nil {
			http.Error(w, "Failed to save smtp_username", http.StatusInternalServerError)
			return
		}
		if req.Password != nil && *req.Password != "" {
			if err := setSettingEncrypted("smtp_password", *req.Password); err != nil {
				http.Error(w, "Failed to save smtp_password", http.StatusInternalServerError)
				return
			}
		}
		if req.TLS != "none" && req.TLS != "starttls" && req.TLS != "tls" {
			req.TLS = "none"
		}
		if err := setSetting("smtp_tls", req.TLS); err != nil {
			http.Error(w, "Failed to save smtp_tls", http.StatusInternalServerError)
			return
		}
	}

	if req.From != "" {
		if err := setSetting("smtp_from", req.From); err != nil {
			http.Error(w, "Failed to save smtp_from", http.StatusInternalServerError)
			return
		}
	}

	log.Printf("SMTP settings updated: mode=%s", req.Mode)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "SMTP settings saved"})
}

func (s *Service) handleTestSMTP(w http.ResponseWriter, r *http.Request) {
	var req SMTPTestRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if req.To == "" || !strings.Contains(req.To, "@") {
		http.Error(w, "Valid email address required", http.StatusBadRequest)
		return
	}

	// Get current SMTP config
	mode, _ := getSetting("smtp_mode")
	if mode == "" {
		mode = "builtin"
	}

	from, _ := getSetting("smtp_from")
	if from == "" {
		mailDomain := os.Getenv("MAIL_DOMAIN")
		if mailDomain != "" {
			from = "noreply@" + mailDomain
		} else {
			from = "noreply@localhost"
		}
	}

	var smtpHost string
	var smtpPort int
	var username, password string
	var tlsMode string

	if mode == "builtin" {
		// Use internal Postfix container (exposed on localhost:25)
		smtpHost = "127.0.0.1"
		smtpPort = 25
		tlsMode = "none"
	} else {
		// External SMTP
		smtpHost, _ = getSetting("smtp_host")
		portStr, _ := getSetting("smtp_port")
		smtpPort, _ = strconv.Atoi(portStr)
		if smtpPort == 0 {
			smtpPort = 587
		}
		username, _ = getSetting("smtp_username")
		password, _ = getSettingEncrypted("smtp_password")
		tlsMode, _ = getSetting("smtp_tls")
	}

	// Build email
	subject := "VPN Admin Panel - Test Email"
	body := fmt.Sprintf("This is a test email from your VPN Admin Panel.\n\nSent at: %s\nMode: %s",
		time.Now().Format(time.RFC1123), mode)

	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n%s",
		from, req.To, subject, body))

	// Send email
	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)

	var auth smtp.Auth
	if username != "" && password != "" {
		auth = smtp.PlainAuth("", username, password, smtpHost)
	}

	var err error
	switch tlsMode {
	case "tls":
		err = sendMailTLS(addr, auth, from, []string{req.To}, msg)
	case "starttls":
		err = sendMailSTARTTLS(addr, auth, from, []string{req.To}, msg)
	default:
		// Use plain SMTP without TLS for local/builtin mode
		err = sendMailPlain(addr, auth, from, []string{req.To}, msg)
	}

	if err != nil {
		log.Printf("SMTP test failed: %v", err)
		http.Error(w, "Failed to send test email: "+err.Error(), http.StatusBadGateway)
		return
	}

	log.Printf("SMTP test email sent successfully to %s", req.To)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Test email sent successfully"})
}

// sendMailTLS sends email using implicit TLS (port 465)
func sendMailTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	host, _, _ := net.SplitHostPort(addr)

	tlsConfig := &tls.Config{
		ServerName: host,
	}

	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("TLS dial failed: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %v", err)
	}
	defer client.Close()

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %v", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("RCPT TO failed: %v", err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %v", err)
	}

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("Write failed: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("Close failed: %v", err)
	}

	return client.Quit()
}

// sendMailSTARTTLS sends email using STARTTLS (port 587)
func sendMailSTARTTLS(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	host, _, _ := net.SplitHostPort(addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("Dial failed: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %v", err)
	}
	defer client.Close()

	// STARTTLS
	tlsConfig := &tls.Config{
		ServerName: host,
	}
	if err := client.StartTLS(tlsConfig); err != nil {
		return fmt.Errorf("STARTTLS failed: %v", err)
	}

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %v", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("RCPT TO failed: %v", err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %v", err)
	}

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("Write failed: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("Close failed: %v", err)
	}

	return client.Quit()
}

// sendMailPlain sends email without TLS (for local/builtin SMTP)
func sendMailPlain(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	host, _, _ := net.SplitHostPort(addr)

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("Dial failed: %v", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("SMTP client creation failed: %v", err)
	}
	defer client.Close()

	// Skip STARTTLS - use plain connection

	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP auth failed: %v", err)
		}
	}

	if err := client.Mail(from); err != nil {
		return fmt.Errorf("MAIL FROM failed: %v", err)
	}

	for _, recipient := range to {
		if err := client.Rcpt(recipient); err != nil {
			return fmt.Errorf("RCPT TO failed: %v", err)
		}
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("DATA failed: %v", err)
	}

	_, err = w.Write(msg)
	if err != nil {
		return fmt.Errorf("Write failed: %v", err)
	}

	err = w.Close()
	if err != nil {
		return fmt.Errorf("Close failed: %v", err)
	}

	return client.Quit()
}

// SendEmail sends an email using the configured SMTP settings
func SendEmail(to, subject, body string) error {
	mode, _ := getSetting("smtp_mode")
	if mode == "" {
		mode = "builtin"
	}

	from, _ := getSetting("smtp_from")
	if from == "" {
		mailDomain := os.Getenv("MAIL_DOMAIN")
		if mailDomain != "" {
			from = "noreply@" + mailDomain
		} else {
			from = "noreply@localhost"
		}
	}

	var smtpHost string
	var smtpPort int
	var username, password string
	var tlsMode string

	if mode == "builtin" {
		smtpHost = "127.0.0.1"
		smtpPort = 25
		tlsMode = "none"
	} else {
		smtpHost, _ = getSetting("smtp_host")
		portStr, _ := getSetting("smtp_port")
		smtpPort, _ = strconv.Atoi(portStr)
		if smtpPort == 0 {
			smtpPort = 587
		}
		username, _ = getSetting("smtp_username")
		password, _ = getSettingEncrypted("smtp_password")
		tlsMode, _ = getSetting("smtp_tls")
	}

	msg := []byte(fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, to, subject, body))

	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)

	var auth smtp.Auth
	if username != "" && password != "" {
		auth = smtp.PlainAuth("", username, password, smtpHost)
	}

	switch tlsMode {
	case "tls":
		return sendMailTLS(addr, auth, from, []string{to}, msg)
	case "starttls":
		return sendMailSTARTTLS(addr, auth, from, []string{to}, msg)
	default:
		// Use plain SMTP without TLS for local/builtin mode
		return sendMailPlain(addr, auth, from, []string{to}, msg)
	}
}

// Helper functions for settings (same pattern as settings package)
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
		authSvc := auth.GetService()
		if authSvc == nil {
			return "", fmt.Errorf("auth service not available for decryption")
		}
		return authSvc.Decrypt(value)
	}

	return value, nil
}

func setSettingEncrypted(key, value string) error {
	db := database.Get()
	if db == nil {
		return fmt.Errorf("database not initialized")
	}

	authSvc := auth.GetService()
	if authSvc == nil {
		return fmt.Errorf("auth service not available for encryption")
	}

	encrypted, err := authSvc.Encrypt(value)
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
