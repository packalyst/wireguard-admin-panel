package auth

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/router"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrUserNotFound       = errors.New("user not found")
	ErrUserExists         = errors.New("user already exists")
	ErrInvalidSession     = errors.New("invalid or expired session")
)

// Rate limiting for login attempts
const (
	maxLoginAttempts   = 5               // Max failed attempts before lockout
	loginLockoutWindow = 15 * time.Minute // Window for counting attempts
	loginLockoutTime   = 15 * time.Minute // How long to lock out after max attempts
)

type loginAttempt struct {
	count     int
	firstTry  time.Time
	lockedAt  time.Time
}

var (
	loginAttempts      = make(map[string]*loginAttempt)
	loginAttemptsMutex sync.RWMutex
	trustedProxyCIDRs  []*net.IPNet
)

func init() {
	// Load trusted proxies from environment
	// TRUSTED_PROXIES can be comma-separated list of IPs or CIDRs: "172.18.0.2,162.158.0.0/15"
	proxies := helper.GetEnvOptional("TRUSTED_PROXIES", "")
	if proxies != "" {
		for _, entry := range strings.Split(proxies, ",") {
			entry = strings.TrimSpace(entry)
			if entry == "" {
				continue
			}

			// Check if it's a CIDR or single IP
			if !strings.Contains(entry, "/") {
				// Single IP - convert to /32 CIDR
				entry = entry + "/32"
			}

			_, cidr, err := net.ParseCIDR(entry)
			if err != nil {
				log.Printf("Auth: invalid trusted proxy entry (skipped): %s - %v", entry, err)
				continue
			}
			trustedProxyCIDRs = append(trustedProxyCIDRs, cidr)
			log.Printf("Auth: trusted proxy added: %s", cidr.String())
		}
	}
}

// isTrustedProxy checks if an IP is in the trusted proxy list
func isTrustedProxy(ipStr string) bool {
	if len(trustedProxyCIDRs) == 0 {
		return true // No trusted proxies configured = trust all (backwards compatible)
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}

	for _, cidr := range trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}

// Service handles authentication
type Service struct {
	db *sql.DB
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
	Token     string `json:"token"`
	ExpiresAt string `json:"expiresAt"`
	User      User   `json:"user"`
}

// New creates a new auth service
func New() (*Service, error) {
	db := database.Get()
	if db == nil {
		return nil, fmt.Errorf("database not initialized")
	}

	svc := &Service{
		db: db,
	}

	log.Printf("Auth service initialized")
	return svc, nil
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

// Login validates credentials and creates a session
func (s *Service) Login(username, password string) (*LoginResponse, error) {
	username = strings.TrimSpace(strings.ToLower(username))

	// Get user
	var user User
	var passwordHash string
	var lastLogin sql.NullTime
	err := s.db.QueryRow(
		"SELECT id, username, password_hash, created_at, last_login FROM users WHERE username = ?",
		username,
	).Scan(&user.ID, &user.Username, &passwordHash, &user.CreatedAt, &lastLogin)

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

	// Create session
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
	_ = s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&count)
	return count > 0
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

// getClientIP extracts the real client IP from the request
func getClientIP(r *http.Request) string {
	// Extract remote IP (without port)
	remoteIP := r.RemoteAddr
	if idx := strings.LastIndex(remoteIP, ":"); idx != -1 {
		remoteIP = remoteIP[:idx]
	}

	// Only trust X-Forwarded-For and X-Real-IP from trusted proxies
	if isTrustedProxy(remoteIP) {
		// Check X-Forwarded-For header (set by reverse proxy)
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Take the first IP (original client)
			if idx := strings.Index(xff, ","); idx != -1 {
				return strings.TrimSpace(xff[:idx])
			}
			return strings.TrimSpace(xff)
		}
		// Check X-Real-IP header
		if xri := r.Header.Get("X-Real-IP"); xri != "" {
			return xri
		}
	}

	return remoteIP
}

// checkLoginRateLimit returns true if the IP is rate limited
func checkLoginRateLimit(ip string) (bool, time.Duration) {
	loginAttemptsMutex.RLock()
	attempt, exists := loginAttempts[ip]
	loginAttemptsMutex.RUnlock()

	if !exists {
		return false, 0
	}

	now := time.Now()

	// Check if currently locked out
	if !attempt.lockedAt.IsZero() {
		remaining := loginLockoutTime - now.Sub(attempt.lockedAt)
		if remaining > 0 {
			return true, remaining
		}
		// Lockout expired, reset
		loginAttemptsMutex.Lock()
		delete(loginAttempts, ip)
		loginAttemptsMutex.Unlock()
		return false, 0
	}

	// Check if window has expired (reset counter)
	if now.Sub(attempt.firstTry) > loginLockoutWindow {
		loginAttemptsMutex.Lock()
		delete(loginAttempts, ip)
		loginAttemptsMutex.Unlock()
		return false, 0
	}

	return false, 0
}

// recordFailedLogin records a failed login attempt and returns true if now locked out
func recordFailedLogin(ip string) bool {
	loginAttemptsMutex.Lock()
	defer loginAttemptsMutex.Unlock()

	now := time.Now()
	attempt, exists := loginAttempts[ip]

	if !exists {
		loginAttempts[ip] = &loginAttempt{
			count:    1,
			firstTry: now,
		}
		return false
	}

	// Reset if window expired
	if now.Sub(attempt.firstTry) > loginLockoutWindow {
		attempt.count = 1
		attempt.firstTry = now
		attempt.lockedAt = time.Time{}
		return false
	}

	attempt.count++
	if attempt.count >= maxLoginAttempts {
		attempt.lockedAt = now
		log.Printf("Login rate limit: IP %s locked out after %d failed attempts", ip, attempt.count)
		return true
	}

	return false
}

// clearLoginAttempts clears failed attempts for an IP after successful login
func clearLoginAttempts(ip string) {
	loginAttemptsMutex.Lock()
	delete(loginAttempts, ip)
	loginAttemptsMutex.Unlock()
}

func (s *Service) handleLogin(w http.ResponseWriter, r *http.Request) {
	clientIP := getClientIP(r)

	// Check rate limit
	if locked, remaining := checkLoginRateLimit(clientIP); locked {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", int(remaining.Seconds())))
		http.Error(w, fmt.Sprintf("Too many login attempts. Try again in %d minutes.", int(remaining.Minutes())+1), http.StatusTooManyRequests)
		return
	}

	var req LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	resp, err := s.Login(req.Username, req.Password)
	if err != nil {
		if err == ErrInvalidCredentials {
			// Record failed attempt
			if recordFailedLogin(clientIP) {
				w.Header().Set("Retry-After", fmt.Sprintf("%d", int(loginLockoutTime.Seconds())))
				http.Error(w, fmt.Sprintf("Too many login attempts. Try again in %d minutes.", int(loginLockoutTime.Minutes())), http.StatusTooManyRequests)
				return
			}
			http.Error(w, "Invalid username or password", http.StatusUnauthorized)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Clear failed attempts on successful login
	clearLoginAttempts(clientIP)

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


// GetService returns the auth service instance for use by other packages
var instance *Service

func GetService() *Service {
	return instance
}

func SetService(svc *Service) {
	instance = svc
}
