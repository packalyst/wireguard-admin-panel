// Package silentdrop provides a Traefik middleware that restricts access
// to VPN clients only, with configurable responses (silent drop or custom error page).
package silentdrop

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
)

// Error page template - substitutes {CODE}, {TITLE}, {MESSAGE}
const errorPageTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" /><meta http-equiv="X-UA-Compatible" content="IE=edge" /><meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{TITLE} | {CODE}</title>
    <style type="text/css">body,html{width:100%;height:100%;background-color:#21232a}body{color:#fff;text-align:center;text-shadow:0 2px 4px rgba(0,0,0,.5);padding:0;min-height:100%;box-shadow:inset 0 0 100px rgba(0,0,0,.8);display:table;font-family:"Open Sans",Arial,sans-serif}h1{font-weight:500;line-height:1.1;font-size:36px}h1 small{font-size:68%;font-weight:400;line-height:1;color:#777}.lead{color:silver;font-size:21px;line-height:1.4}.cover{display:table-cell;vertical-align:middle;padding:0 20px}</style>
</head>
<body>
    <div class="cover"><h1>{TITLE} <small>{CODE}</small></h1><p class="lead">{MESSAGE}</p></div>
</body>
</html>`

// Error responses for different modes
var errorResponses = map[string]struct {
	code    int
	title   string
	message string
}{
	"403":   {403, "Access Denied", "The requested resource requires authentication."},
	"error": {403, "Access Denied", "The requested resource requires authentication."},
	"404":   {404, "Not Found", "The requested resource could not be found."},
	"503":   {503, "Service Unavailable", "The service is temporarily unavailable."},
	"401":   {401, "Unauthorized", "Authentication is required to access this resource."},
}

// Config holds the plugin configuration.
type Config struct {
	// SourceRange is a list of allowed IP ranges in CIDR notation
	SourceRange []string `json:"sourceRange,omitempty"`
	// Mode determines how blocked requests are handled:
	//   "silent" - drop connection without response (default)
	//   "403" or "error" - 403 Access Denied
	//   "404" - 404 Not Found (makes resource appear non-existent)
	//   "401" - 401 Unauthorized
	//   "503" - 503 Service Unavailable
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
	debug    bool
}

// log prints debug messages if debug mode is enabled
func (s *SilentDrop) log(format string, args ...interface{}) {
	if s.debug {
		fmt.Fprintf(os.Stderr, "[silentdrop] "+format+"\n", args...)
	}
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

	// Enable debug via environment variable
	debug := os.Getenv("SILENTDROP_DEBUG") == "true"

	sd := &SilentDrop{
		next:     next,
		name:     name,
		networks: networks,
		mode:     mode,
		debug:    debug,
	}

	if debug {
		sd.log("initialized with %d networks, mode=%s", len(networks), mode)
		for _, n := range networks {
			sd.log("  allowed network: %s", n.String())
		}
	}

	return sd, nil
}

// ServeHTTP implements the http.Handler interface.
func (s *SilentDrop) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	s.log("request: %s %s from RemoteAddr=%s", req.Method, req.URL.Path, req.RemoteAddr)
	s.log("  CF-Connecting-IP: %s", req.Header.Get("CF-Connecting-IP"))
	s.log("  X-Forwarded-For: %s", req.Header.Get("X-Forwarded-For"))
	s.log("  X-Real-IP: %s", req.Header.Get("X-Real-IP"))
	s.log("  TLS: %v", req.TLS != nil)

	// If no networks configured, allow all
	if len(s.networks) == 0 {
		s.log("  no networks configured, allowing")
		s.next.ServeHTTP(rw, req)
		return
	}

	// Get client IP
	clientIP := s.getClientIP(req)
	if clientIP == nil {
		s.log("  could not determine client IP, blocking")
		s.blockRequest(rw, req)
		return
	}

	s.log("  detected client IP: %s", clientIP.String())

	// Check if IP is allowed
	if s.isAllowed(clientIP) {
		s.log("  IP is in allowed range, allowing")
		s.next.ServeHTTP(rw, req)
		return
	}

	// Not allowed - block based on mode
	s.log("  IP is NOT in allowed range, blocking with mode=%s", s.mode)
	s.blockRequest(rw, req)
}

// getClientIP extracts the client IP from the request.
func (s *SilentDrop) getClientIP(req *http.Request) net.IP {
	// Check CF-Connecting-IP header first (Cloudflare's real client IP)
	if cfIP := req.Header.Get("CF-Connecting-IP"); cfIP != "" {
		ip := net.ParseIP(strings.TrimSpace(cfIP))
		if ip != nil {
			s.log("  using CF-Connecting-IP: %s", cfIP)
			return ip
		}
	}

	// Check X-Forwarded-For header
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
		s.log("  executing silent drop")
		s.dropConnection(rw, req)
		return
	}

	// Look up error response for mode, default to 403
	resp, ok := errorResponses[s.mode]
	if !ok {
		resp = errorResponses["403"]
	}

	// Generate error page from template
	html := errorPageTemplate
	html = strings.Replace(html, "{CODE}", fmt.Sprintf("%d", resp.code), -1)
	html = strings.Replace(html, "{TITLE}", resp.title, -1)
	html = strings.Replace(html, "{MESSAGE}", resp.message, -1)

	s.log("  returning %d %s", resp.code, resp.title)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")
	rw.Header().Set("Connection", "close")
	rw.Header().Set("Cache-Control", "no-store")
	rw.WriteHeader(resp.code)
	_, err := rw.Write([]byte(html))
	if err != nil {
		s.log("  error writing response: %v", err)
	}
}

// dropConnection silently closes the connection without sending a response.
func (s *SilentDrop) dropConnection(rw http.ResponseWriter, req *http.Request) {
	// Try to hijack the connection and close it
	hj, ok := rw.(http.Hijacker)
	if ok {
		conn, _, err := hj.Hijack()
		if err == nil && conn != nil {
			s.log("  hijacked connection, closing")
			// For TCP connections, set linger to 0 to send RST instead of FIN
			// This makes the close appear as a network error (connection reset)
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetLinger(0)
			}
			conn.Close()
			return
		}
		s.log("  hijack failed: %v", err)
	} else {
		s.log("  ResponseWriter does not support Hijacker")
	}

	// Fallback: Return empty response with connection close
	// This is the best we can do when hijack fails (e.g., with TLS)
	s.log("  using fallback: empty 444 response")
	rw.Header().Set("Connection", "close")
	rw.Header().Set("Content-Length", "0")
	// 444 is nginx's "No Response" - many clients treat it as connection closed
	// If this causes issues, we could also try just not writing anything
	rw.WriteHeader(444)
}
