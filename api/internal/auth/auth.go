package auth

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image/png"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"

	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidSession     = errors.New("invalid or expired session")
	ErrInvalidTOTP        = errors.New("invalid TOTP code")
	ErrTOTPRequired       = errors.New("TOTP verification required")
)

// Service handles authentication
type Service struct {
	db            *sql.DB
	encryptionKey []byte
}

// User represents a user account
type User struct {
	ID        int64     `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"createdAt"`
	LastLogin time.Time `json:"lastLogin,omitempty"`
}

// Session represents a login session
type Session struct {
	ID        string    `json:"id"`
	UserID    int64     `json:"userId"`
	CreatedAt time.Time `json:"createdAt"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// LoginRequest represents login credentials
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// LoginResponse represents successful login response
type LoginResponse struct {
	Token       string `json:"token,omitempty"`
	ExpiresAt   string `json:"expiresAt,omitempty"`
	User        User   `json:"user,omitempty"`
	Requires2FA bool   `json:"requires2fa,omitempty"`
	TempToken   string `json:"tempToken,omitempty"`
}

// ProfileResponse represents user profile data
type ProfileResponse struct {
	ID          int64  `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	TOTPEnabled bool   `json:"totpEnabled"`
	AvatarURL   string `json:"avatarUrl"`
	CreatedAt   string `json:"createdAt"`
	LastLogin   string `json:"lastLogin,omitempty"`
}

// ProfileUpdateRequest represents profile update data
type ProfileUpdateRequest struct {
	Email string `json:"email"`
}

// PasswordChangeRequest represents password change data
type PasswordChangeRequest struct {
	CurrentPassword string `json:"currentPassword"`
	NewPassword     string `json:"newPassword"`
}

// TOTPSetupResponse represents TOTP setup data
type TOTPSetupResponse struct {
	Secret    string `json:"secret"`
	QRCodeURL string `json:"qrCodeUrl"`
}

// TOTPVerifyRequest represents TOTP verification data
type TOTPVerifyRequest struct {
	Code string `json:"code"`
}

// TOTP2FALoginRequest represents 2FA login completion data
type TOTP2FALoginRequest struct {
	TempToken string `json:"tempToken"`
	Code      string `json:"code"`
}

// TOTPDisableRequest represents TOTP disable data
type TOTPDisableRequest struct {
	Password string `json:"password"`
}

// New creates a new auth service
func New() (*Service, error) {
	db := database.Get()
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	// Get encryption key from environment or generate one
	encKey := getEncryptionKey()

	svc := &Service{
		db:            db,
		encryptionKey: encKey,
	}

	log.Printf("Auth service initialized")
	return svc, nil
}

// getEncryptionKey gets or generates the encryption key
func getEncryptionKey() []byte {
	keyHex := os.Getenv("ENCRYPTION_SECRET")
	if keyHex == "" {
		// Generate a key from a default secret (in production, always set ENCRYPTION_SECRET)
		hash := sha256.Sum256([]byte("vpn-admin-default-key-change-me"))
		return hash[:]
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		log.Printf("Warning: Invalid ENCRYPTION_SECRET, using derived key")
		hash := sha256.Sum256([]byte(keyHex))
		return hash[:]
	}
	return key
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"Login":           s.handleLogin,
		"Logout":          s.handleLogout,
		"ValidateSession": s.handleValidate,
		"GetCurrentUser":  s.handleGetCurrentUser,
		"CreateUser":      s.handleCreateUser,
		"Health":          s.handleHealth,
		// Profile endpoints
		"GetProfile":    s.handleGetProfile,
		"UpdateProfile": s.handleUpdateProfile,
		// Password change
		"ChangePassword": s.handleChangePassword,
		// 2FA endpoints
		"Setup2FA":   s.handleSetup2FA,
		"Verify2FA":  s.handleVerify2FA,
		"Disable2FA": s.handleDisable2FA,
		"Login2FA":   s.handleLogin2FA,
	}
}

// validatePassword checks password strength
// Requires: 8+ chars, uppercase, lowercase, number, special char
func validatePassword(password string) error {
	if len(password) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	var hasUpper, hasLower, hasNumber, hasSpecial bool
	for _, c := range password {
		switch {
		case unicode.IsUpper(c):
			hasUpper = true
		case unicode.IsLower(c):
			hasLower = true
		case unicode.IsNumber(c):
			hasNumber = true
		case unicode.IsPunct(c) || unicode.IsSymbol(c):
			hasSpecial = true
		}
	}

	if !hasUpper {
		return errors.New("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return errors.New("password must contain at least one lowercase letter")
	}
	if !hasNumber {
		return errors.New("password must contain at least one number")
	}
	if !hasSpecial {
		return errors.New("password must contain at least one special character")
	}

	return nil
}

// CreateUser creates a new user account
func (s *Service) CreateUser(username, password string) (*User, error) {
	// Validate input
	username = strings.TrimSpace(strings.ToLower(username))
	if len(username) < 3 {
		return nil, errors.New("username must be at least 3 characters")
	}
	if err := validatePassword(password); err != nil {
		return nil, err
	}

	// Hash password
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %v", err)
	}

	// Insert user
	result, err := s.db.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username, string(hash),
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint") {
			return nil, ErrUserExists
		}
		return nil, fmt.Errorf("failed to create user: %v", err)
	}

	id, _ := result.LastInsertId()
	return &User{
		ID:        id,
		Username:  username,
		CreatedAt: time.Now(),
	}, nil
}

// Login validates credentials and creates a session (or temp session if 2FA enabled)
func (s *Service) Login(username, password string) (*LoginResponse, error) {
	username = strings.TrimSpace(strings.ToLower(username))

	// Get user with 2FA status
	var user User
	var passwordHash string
	var lastLogin sql.NullTime
	var totpEnabled bool
	err := s.db.QueryRow(
		"SELECT id, username, password_hash, created_at, last_login, COALESCE(totp_enabled, 0) FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &user.CreatedAt, &lastLogin, &totpEnabled)

	if err == sql.ErrNoRows {
		return nil, ErrInvalidCredentials
	}
	if err != nil {
		return nil, fmt.Errorf("failed to query user: %v", err)
	}
	if lastLogin.Valid {
		user.LastLogin = lastLogin.Time
	}

	// Verify password
	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(password)); err != nil {
		return nil, ErrInvalidCredentials
	}

	// If 2FA is enabled, create temporary session and require TOTP
	if totpEnabled {
		tempToken := generateSessionID()
		expiresAt := time.Now().Add(5 * time.Minute) // 5 minute temp token

		_, err = s.db.Exec(
			"INSERT INTO temp_sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
			tempToken, user.ID, expiresAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create temp session: %v", err)
		}

		return &LoginResponse{
			Requires2FA: true,
			TempToken:   tempToken,
		}, nil
	}

	// Create regular session
	sessionID := generateSessionID()
	expiresAt := time.Now().Add(24 * time.Hour) // 24 hour sessions

	_, err = s.db.Exec(
		"INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
		sessionID, user.ID, expiresAt,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}

	// Update last login
	s.db.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), user.ID)

	return &LoginResponse{
		Token:     sessionID,
		ExpiresAt: expiresAt.Format(time.RFC3339),
		User:      user,
	}, nil
}

// ValidateSession checks if a session token is valid
func (s *Service) ValidateSession(token string) (*User, error) {
	var session Session
	var user User
	var lastLogin sql.NullTime

	err := s.db.QueryRow(`
		SELECT s.id, s.user_id, s.expires_at, u.id, u.username, u.created_at, u.last_login
		FROM sessions s
		JOIN users u ON s.user_id = u.id
		WHERE s.id = ? AND s.expires_at > datetime('now')
	`, token).Scan(
		&session.ID, &session.UserID, &session.ExpiresAt,
		&user.ID, &user.Username, &user.CreatedAt, &lastLogin,
	)

	if err == sql.ErrNoRows {
		return nil, ErrInvalidSession
	}
	if err != nil {
		return nil, fmt.Errorf("failed to validate session: %v", err)
	}
	if lastLogin.Valid {
		user.LastLogin = lastLogin.Time
	}

	return &user, nil
}

// Logout invalidates a session
func (s *Service) Logout(token string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE id = ?", token)
	return err
}

// HasUsers checks if any users exist
func (s *Service) HasUsers() bool {
	var count int
	s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count > 0
}

// Encrypt encrypts a string value using AES-256-GCM
func (s *Service) Encrypt(plaintext string) (string, error) {
	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts an AES-256-GCM encrypted string
func (s *Service) Decrypt(ciphertext string) (string, error) {
	data, err := base64.StdEncoding.DecodeString(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(s.encryptionKey)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("ciphertext too short")
	}

	nonce, cipherData := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, cipherData, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// generateSessionID generates a random session ID
func generateSessionID() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.URLEncoding.EncodeToString(b)
}

// HTTP Handlers

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := s.Login(req.Username, req.Password)
	if err != nil {
		if err == ErrInvalidCredentials {
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Service) handleLogout(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusBadRequest)
		return
	}

	s.Logout(token)
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"message": "Logged out"})
}

func (s *Service) handleValidate(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"valid": true,
		"user":  user,
	})
}

func (s *Service) handleGetCurrentUser(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func (s *Service) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	user, err := s.CreateUser(req.Username, req.Password)
	if err != nil {
		if err == ErrUserExists {
			http.Error(w, "Username already exists", http.StatusConflict)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(user)
}

func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":   "ok",
		"hasUsers": s.HasUsers(),
	})
}

// handleGetProfile returns user profile data
func (s *Service) handleGetProfile(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	// Get additional profile data
	var email sql.NullString
	var totpEnabled bool
	var createdAt time.Time
	var lastLogin sql.NullTime

	err = s.db.QueryRow(
		"SELECT email, COALESCE(totp_enabled, 0), created_at, last_login FROM users WHERE id = ?",
		user.ID,
	).Scan(&email, &totpEnabled, &createdAt, &lastLogin)
	if err != nil {
		http.Error(w, "Failed to get profile", http.StatusInternalServerError)
		return
	}

	profile := ProfileResponse{
		ID:          user.ID,
		Username:    user.Username,
		Email:       email.String,
		TOTPEnabled: totpEnabled,
		AvatarURL:   helper.GravatarURL(email.String, 200),
		CreatedAt:   createdAt.Format(time.RFC3339),
	}
	if lastLogin.Valid {
		profile.LastLogin = lastLogin.Time.Format(time.RFC3339)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(profile)
}

// handleUpdateProfile updates user profile data
func (s *Service) handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	var req ProfileUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Basic email validation
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email != "" && !strings.Contains(req.Email, "@") {
		http.Error(w, "Invalid email address", http.StatusBadRequest)
		return
	}

	_, err = s.db.Exec("UPDATE users SET email = ? WHERE id = ?", req.Email, user.ID)
	if err != nil {
		http.Error(w, "Failed to update profile", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Profile updated"})
}

// handleChangePassword changes the user's password
func (s *Service) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	var req PasswordChangeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify current password
	var currentHash string
	err = s.db.QueryRow("SELECT password_hash FROM users WHERE id = ?", user.ID).Scan(&currentHash)
	if err != nil {
		http.Error(w, "Failed to verify password", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.CurrentPassword)); err != nil {
		http.Error(w, "Current password is incorrect", http.StatusUnauthorized)
		return
	}

	// Validate new password
	if err := validatePassword(req.NewPassword); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Hash new password
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Failed to hash password", http.StatusInternalServerError)
		return
	}

	_, err = s.db.Exec("UPDATE users SET password_hash = ? WHERE id = ?", string(newHash), user.ID)
	if err != nil {
		http.Error(w, "Failed to update password", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "Password changed successfully"})
}

// handleSetup2FA generates a TOTP secret and QR code
func (s *Service) handleSetup2FA(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	// Check if 2FA is already enabled
	var totpEnabled bool
	s.db.QueryRow("SELECT COALESCE(totp_enabled, 0) FROM users WHERE id = ?", user.ID).Scan(&totpEnabled)
	if totpEnabled {
		http.Error(w, "2FA is already enabled", http.StatusBadRequest)
		return
	}

	// Generate TOTP key
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "VPN Admin",
		AccountName: user.Username,
	})
	if err != nil {
		http.Error(w, "Failed to generate 2FA secret", http.StatusInternalServerError)
		return
	}

	// Generate QR code as base64 PNG
	qrImg, err := qrcode.New(key.URL(), qrcode.Medium)
	if err != nil {
		http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := png.Encode(&buf, qrImg.Image(256)); err != nil {
		http.Error(w, "Failed to encode QR code", http.StatusInternalServerError)
		return
	}
	qrBase64 := "data:image/png;base64," + base64.StdEncoding.EncodeToString(buf.Bytes())

	// Encrypt and store secret (not enabled yet)
	encryptedSecret, err := s.Encrypt(key.Secret())
	if err != nil {
		http.Error(w, "Failed to encrypt secret", http.StatusInternalServerError)
		return
	}

	_, err = s.db.Exec("UPDATE users SET totp_secret = ? WHERE id = ?", encryptedSecret, user.ID)
	if err != nil {
		http.Error(w, "Failed to save 2FA secret", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(TOTPSetupResponse{
		Secret:    key.Secret(),
		QRCodeURL: qrBase64,
	})
}

// handleVerify2FA verifies TOTP code and enables 2FA
func (s *Service) handleVerify2FA(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	var req TOTPVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Get stored secret
	var encryptedSecret sql.NullString
	err = s.db.QueryRow("SELECT totp_secret FROM users WHERE id = ?", user.ID).Scan(&encryptedSecret)
	if err != nil || !encryptedSecret.Valid {
		http.Error(w, "2FA not set up", http.StatusBadRequest)
		return
	}

	secret, err := s.Decrypt(encryptedSecret.String)
	if err != nil {
		http.Error(w, "Failed to decrypt secret", http.StatusInternalServerError)
		return
	}

	// Verify TOTP code
	if !totp.Validate(req.Code, secret) {
		http.Error(w, "Invalid verification code", http.StatusBadRequest)
		return
	}

	// Enable 2FA
	_, err = s.db.Exec("UPDATE users SET totp_enabled = 1 WHERE id = ?", user.ID)
	if err != nil {
		http.Error(w, "Failed to enable 2FA", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "2FA enabled successfully"})
}

// handleDisable2FA disables 2FA (requires password confirmation)
func (s *Service) handleDisable2FA(w http.ResponseWriter, r *http.Request) {
	token := helper.ExtractBearerToken(r)
	if token == "" {
		http.Error(w, "No token provided", http.StatusUnauthorized)
		return
	}

	user, err := s.ValidateSession(token)
	if err != nil {
		http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
		return
	}

	var req TOTPDisableRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Verify password
	var passwordHash string
	err = s.db.QueryRow("SELECT password_hash FROM users WHERE id = ?", user.ID).Scan(&passwordHash)
	if err != nil {
		http.Error(w, "Failed to verify password", http.StatusInternalServerError)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)); err != nil {
		http.Error(w, "Password is incorrect", http.StatusUnauthorized)
		return
	}

	// Disable 2FA
	_, err = s.db.Exec("UPDATE users SET totp_enabled = 0, totp_secret = NULL WHERE id = ?", user.ID)
	if err != nil {
		http.Error(w, "Failed to disable 2FA", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"message": "2FA disabled successfully"})
}

// handleLogin2FA completes login with TOTP code
func (s *Service) handleLogin2FA(w http.ResponseWriter, r *http.Request) {
	var req TOTP2FALoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Validate temp token
	var userID int64
	var expiresAt time.Time
	err := s.db.QueryRow(
		"SELECT user_id, expires_at FROM temp_sessions WHERE id = ? AND expires_at > datetime('now')",
		req.TempToken,
	).Scan(&userID, &expiresAt)

	if err == sql.ErrNoRows {
		http.Error(w, "Invalid or expired temporary token", http.StatusUnauthorized)
		return
	}
	if err != nil {
		http.Error(w, "Failed to validate token", http.StatusInternalServerError)
		return
	}

	// Get user and TOTP secret
	var user User
	var encryptedSecret sql.NullString
	var lastLogin sql.NullTime
	err = s.db.QueryRow(
		"SELECT id, username, totp_secret, created_at, last_login FROM users WHERE id = ?",
		userID,
	).Scan(&user.ID, &user.Username, &encryptedSecret, &user.CreatedAt, &lastLogin)

	if err != nil {
		http.Error(w, "User not found", http.StatusUnauthorized)
		return
	}
	if lastLogin.Valid {
		user.LastLogin = lastLogin.Time
	}

	if !encryptedSecret.Valid {
		http.Error(w, "2FA not configured", http.StatusBadRequest)
		return
	}

	secret, err := s.Decrypt(encryptedSecret.String)
	if err != nil {
		http.Error(w, "Failed to decrypt secret", http.StatusInternalServerError)
		return
	}

	// Verify TOTP code
	if !totp.Validate(req.Code, secret) {
		http.Error(w, "Invalid verification code", http.StatusUnauthorized)
		return
	}

	// Delete temp session
	s.db.Exec("DELETE FROM temp_sessions WHERE id = ?", req.TempToken)

	// Create regular session
	sessionID := generateSessionID()
	sessionExpires := time.Now().Add(24 * time.Hour)

	_, err = s.db.Exec(
		"INSERT INTO sessions (id, user_id, expires_at) VALUES (?, ?, ?)",
		sessionID, user.ID, sessionExpires,
	)
	if err != nil {
		http.Error(w, "Failed to create session", http.StatusInternalServerError)
		return
	}

	// Update last login
	s.db.Exec("UPDATE users SET last_login = ? WHERE id = ?", time.Now(), user.ID)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(LoginResponse{
		Token:     sessionID,
		ExpiresAt: sessionExpires.Format(time.RFC3339),
		User:      user,
	})
}

// GetService returns the auth service instance for use by other packages
var instance *Service

func GetService() *Service {
	return instance
}

func SetService(svc *Service) {
	instance = svc
}
