package auth

import (
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"api/internal/helper"
)

// Rate limiting for login attempts
const (
	maxLoginAttempts = 5 // Max failed attempts before lockout
)

// Use helper constants for lockout timing
var (
	loginLockoutWindow = helper.LoginLockoutWindow   // Window for counting attempts
	loginLockoutTime   = helper.LoginLockoutDuration // How long to lock out after max attempts
)

type loginAttempt struct {
	count    int
	firstTry time.Time
	lockedAt time.Time
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

// getClientIP extracts the real client IP, respecting trusted proxies
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
