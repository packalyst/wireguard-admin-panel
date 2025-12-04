package auth

import (
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
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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
	}
}

// CreateUser creates a new user account
func (s *Service) CreateUser(username, password string) (*User, error) {
	// Validate input
	username = strings.TrimSpace(strings.ToLower(username))
	if len(username) < 3 {
		return nil, errors.New("username must be at least 3 characters")
	}
	if len(password) < 12 {
		return nil, errors.New("password must be at least 12 characters")
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


// GetService returns the auth service instance for use by other packages
var instance *Service

func GetService() *Service {
	return instance
}

func SetService(svc *Service) {
	instance = svc
}
