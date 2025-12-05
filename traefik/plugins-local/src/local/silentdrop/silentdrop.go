// Package silentdrop provides a Traefik middleware that restricts access
// to VPN clients only, with configurable responses (silent drop or custom error page).
package silentdrop

import (
	"context"
	"net"
	"net/http"
	"strings"
)

const errorPageHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>403 - Access Denied</title>
  <style>
    *{margin:0;padding:0;box-sizing:border-box}
    body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:linear-gradient(135deg,#1a1a2e 0%,#16213e 100%);color:#fff;min-height:100vh;display:flex;align-items:center;justify-content:center;text-align:center;padding:20px}
    .container{max-width:500px}
    .code{font-size:120px;font-weight:700;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;line-height:1;margin-bottom:10px}
    .title{font-size:24px;font-weight:600;margin-bottom:15px;color:#e0e0e0}
    .message{font-size:16px;color:#a0a0a0;line-height:1.6}
  </style>
</head>
<body>
  <div class="container">
    <div class="code">403</div>
    <h1 class="title">Access Denied</h1>
    <p class="message">Connect to the VPN to access this resource.</p>
  </div>
</body>
</html>`

// Config holds the plugin configuration.
type Config struct {
	// SourceRange is a list of allowed IP ranges in CIDR notation
	SourceRange []string `json:"sourceRange,omitempty"`
	// Mode: "silent" (drop connection) or "error" (show error page)
	Mode string `json:"mode,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		SourceRange: []string{},
		Mode:        "silent",
	}
}

// SilentDrop is the middleware handler.
type SilentDrop struct {
	next     http.Handler
	name     string
	networks []*net.IPNet
	mode     string
}

// New creates a new SilentDrop middleware.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	networks := make([]*net.IPNet, 0, len(config.SourceRange))

	for _, cidr := range config.SourceRange {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}

		// Handle single IPs without CIDR notation
		if !strings.Contains(cidr, "/") {
			if strings.Contains(cidr, ":") {
				cidr += "/128" // IPv6
			} else {
				cidr += "/32" // IPv4
			}
		}

		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // Skip invalid CIDRs
		}
		networks = append(networks, network)
	}

	mode := config.Mode
	if mode == "" {
		mode = "silent"
	}

	return &SilentDrop{
		next:     next,
		name:     name,
		networks: networks,
		mode:     mode,
	}, nil
}

// ServeHTTP implements the http.Handler interface.
func (s *SilentDrop) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	// If no networks configured, allow all
	if len(s.networks) == 0 {
		s.next.ServeHTTP(rw, req)
		return
	}

	// Get client IP
	clientIP := s.getClientIP(req)
	if clientIP == nil {
		// Can't determine IP, block
		s.blockRequest(rw, req)
		return
	}

	// Check if IP is allowed
	if s.isAllowed(clientIP) {
		s.next.ServeHTTP(rw, req)
		return
	}

	// Not allowed - block based on mode
	s.blockRequest(rw, req)
}

// getClientIP extracts the client IP from the request.
func (s *SilentDrop) getClientIP(req *http.Request) net.IP {
	// Check X-Forwarded-For header first
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP (original client)
		parts := strings.Split(xff, ",")
		if len(parts) > 0 {
			ip := net.ParseIP(strings.TrimSpace(parts[0]))
			if ip != nil {
				return ip
			}
		}
	}

	// Check X-Real-IP header
	if xri := req.Header.Get("X-Real-IP"); xri != "" {
		ip := net.ParseIP(strings.TrimSpace(xri))
		if ip != nil {
			return ip
		}
	}

	// Fall back to RemoteAddr
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return net.ParseIP(req.RemoteAddr)
	}
	return net.ParseIP(host)
}

// isAllowed checks if the IP is in any of the allowed networks.
func (s *SilentDrop) isAllowed(ip net.IP) bool {
	for _, network := range s.networks {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// blockRequest handles blocking based on the configured mode.
func (s *SilentDrop) blockRequest(rw http.ResponseWriter, req *http.Request) {
	if s.mode == "silent" {
		s.dropConnection(rw)
		return
	}

	// Error mode - serve 403 page directly
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.WriteHeader(http.StatusForbidden)
	rw.Write([]byte(errorPageHTML))
}

// dropConnection silently closes the connection without sending a response.
func (s *SilentDrop) dropConnection(rw http.ResponseWriter) {
	// Try to hijack the connection and close it
	hj, ok := rw.(http.Hijacker)
	if ok {
		conn, _, err := hj.Hijack()
		if err == nil && conn != nil {
			conn.Close()
			return
		}
	}
	// Fallback: just don't respond (connection will timeout)
}
