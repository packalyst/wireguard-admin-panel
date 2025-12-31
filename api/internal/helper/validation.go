package helper

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	// Domain validation: alphanumeric, hyphens, dots, underscores
	// Allows: wiki.local, my-app.home, sub.domain.local
	domainRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-_\.]*[a-zA-Z0-9])?$`)

	// Simple hostname/label validation (single segment)
	hostnameRegex = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-_]*[a-zA-Z0-9])?$`)
)

// ValidationError represents a validation failure
type ValidationError struct {
	Field   string
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidateIP validates an IP address (IPv4 or IPv6)
func ValidateIP(ip string) error {
	if ip == "" {
		return &ValidationError{Field: "ip", Message: "IP address is required"}
	}

	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return &ValidationError{Field: "ip", Message: "invalid IP address format"}
	}

	return nil
}

// ValidateIPv4 validates specifically an IPv4 address
func ValidateIPv4(ip string) error {
	if ip == "" {
		return &ValidationError{Field: "ip", Message: "IP address is required"}
	}

	ip = strings.TrimSpace(ip)
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return &ValidationError{Field: "ip", Message: "invalid IP address format"}
	}

	// Check if it's IPv4 (To4() returns nil for IPv6)
	if parsed.To4() == nil {
		return &ValidationError{Field: "ip", Message: "must be an IPv4 address"}
	}

	return nil
}

// ValidatePort validates a port number (1-65535)
func ValidatePort(port int) error {
	if port < 1 || port > 65535 {
		return &ValidationError{Field: "port", Message: "port must be between 1 and 65535"}
	}
	return nil
}

// ValidatePortString validates a port from string input
func ValidatePortString(portStr string) (int, error) {
	if portStr == "" {
		return 0, &ValidationError{Field: "port", Message: "port is required"}
	}

	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil {
		return 0, &ValidationError{Field: "port", Message: "port must be a number"}
	}

	if err := ValidatePort(port); err != nil {
		return 0, err
	}

	return port, nil
}

// ValidateDomain validates a domain name
// Allows formats like: wiki.local, my-app.home, sub.domain.local
func ValidateDomain(domain string) error {
	if domain == "" {
		return &ValidationError{Field: "domain", Message: "domain is required"}
	}

	domain = strings.TrimSpace(domain)

	// Check length
	if len(domain) > 253 {
		return &ValidationError{Field: "domain", Message: "domain name too long (max 253 characters)"}
	}

	// Check overall pattern
	if !domainRegex.MatchString(domain) {
		return &ValidationError{Field: "domain", Message: "invalid domain format (use alphanumeric, hyphens, dots)"}
	}

	// Validate each label
	labels := strings.Split(domain, ".")
	for _, label := range labels {
		if len(label) == 0 {
			return &ValidationError{Field: "domain", Message: "domain cannot have empty labels (consecutive dots)"}
		}
		if len(label) > 63 {
			return &ValidationError{Field: "domain", Message: "domain label too long (max 63 characters per segment)"}
		}
		if !hostnameRegex.MatchString(label) {
			return &ValidationError{Field: "domain", Message: "invalid domain label format"}
		}
	}

	return nil
}

// ValidateHostname validates a simple hostname (single label, no dots)
func ValidateHostname(hostname string) error {
	if hostname == "" {
		return &ValidationError{Field: "hostname", Message: "hostname is required"}
	}

	hostname = strings.TrimSpace(hostname)

	if len(hostname) > 63 {
		return &ValidationError{Field: "hostname", Message: "hostname too long (max 63 characters)"}
	}

	if !hostnameRegex.MatchString(hostname) {
		return &ValidationError{Field: "hostname", Message: "invalid hostname format (use alphanumeric and hyphens)"}
	}

	return nil
}

// ValidatePortRange validates a port range
func ValidatePortRange(start, end int) error {
	if err := ValidatePort(start); err != nil {
		return &ValidationError{Field: "port_start", Message: "start port must be between 1 and 65535"}
	}
	if err := ValidatePort(end); err != nil {
		return &ValidationError{Field: "port_end", Message: "end port must be between 1 and 65535"}
	}
	if start > end {
		return &ValidationError{Field: "port_range", Message: "start port must be less than or equal to end port"}
	}
	return nil
}

// ValidateCIDR validates a CIDR notation (e.g., 192.168.1.0/24)
func ValidateCIDR(cidr string) error {
	if cidr == "" {
		return &ValidationError{Field: "cidr", Message: "CIDR is required"}
	}

	_, _, err := net.ParseCIDR(strings.TrimSpace(cidr))
	if err != nil {
		return &ValidationError{Field: "cidr", Message: "invalid CIDR format (e.g., 192.168.1.0/24)"}
	}

	return nil
}

// IsPrivateIP checks if an IP is in a private range
func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(strings.TrimSpace(ip))
	if parsed == nil {
		return false
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()
}

// SanitizeDomainName creates a safe identifier from a domain name
func SanitizeDomainName(domain string) string {
	// Replace dots and other special chars with hyphens
	safe := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			return r
		}
		return '-'
	}, domain)

	// Remove consecutive hyphens
	for strings.Contains(safe, "--") {
		safe = strings.ReplaceAll(safe, "--", "-")
	}

	// Trim hyphens from ends
	safe = strings.Trim(safe, "-")

	// Lowercase
	return strings.ToLower(safe)
}
