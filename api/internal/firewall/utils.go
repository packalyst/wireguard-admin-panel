package firewall

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// escapeLikePattern escapes SQL LIKE special characters to prevent wildcard injection
func escapeLikePattern(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "%", "\\%")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}

// parseIP parses an IP address string
func parseIP(ip string) net.IP {
	return net.ParseIP(ip)
}

// validateIPOrCIDR validates an IP address or CIDR range
func validateIPOrCIDR(input string) (string, bool, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", false, fmt.Errorf("empty input")
	}

	// Check if it's a CIDR range
	if strings.Contains(input, "/") {
		_, ipNet, err := net.ParseCIDR(input)
		if err != nil {
			return "", false, fmt.Errorf("invalid CIDR: %v", err)
		}
		return ipNet.String(), true, nil
	}

	// Check if it's a single IP
	ip := net.ParseIP(input)
	if ip == nil {
		return "", false, fmt.Errorf("invalid IP address")
	}

	// Normalize IPv4
	if ip4 := ip.To4(); ip4 != nil {
		return ip4.String(), false, nil
	}
	return ip.String(), false, nil
}

// getSubnet24 returns the /24 subnet for an IP
func getSubnet24(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if ip4 := parsed.To4(); ip4 != nil {
		return fmt.Sprintf("%d.%d.%d.0/24", ip4[0], ip4[1], ip4[2])
	}
	return ""
}

// isIPInRange checks if an IP is within a CIDR range
func isIPInRange(ip, cidr string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return ipNet.Contains(parsedIP)
}

// isPrivateRange checks if a CIDR is in private IP space
func isPrivateRange(cidr string) bool {
	ip, _, err := net.ParseCIDR(cidr)
	if err != nil {
		// Try as single IP
		ip = net.ParseIP(cidr)
		if ip == nil {
			return false
		}
	}

	privateRanges := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"127.0.0.0/8",
		"100.64.0.0/10", // CGNAT/Tailscale
	}

	for _, pr := range privateRanges {
		_, prNet, _ := net.ParseCIDR(pr)
		if prNet.Contains(ip) {
			return true
		}
	}
	return false
}

// isIgnoredIP checks if an IP should be ignored
func (s *Service) isIgnoredIP(ip string) bool {
	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return false
	}

	// Check if IP is in ignored networks from config
	for _, network := range s.config.IgnoreNetworks {
		if strings.Contains(network, "/") {
			_, ipNet, err := net.ParseCIDR(network)
			if err == nil && ipNet.Contains(parsedIP) {
				return true
			}
		} else {
			if network == ip {
				return true
			}
		}
	}

	// Check for VPN client IPs
	if s.config.WgIPPrefix != "" && strings.HasPrefix(ip, s.config.WgIPPrefix) {
		return true
	}
	if s.config.HeadscaleIPPrefix != "" && strings.HasPrefix(ip, s.config.HeadscaleIPPrefix) {
		return true
	}

	return false
}

// isPrivateIP checks if an IP is in private ranges
func (s *Service) isPrivateIP(ip string) bool {
	return isPrivateRange(ip)
}

// reverseDNS performs a reverse DNS lookup with caching
func (s *Service) reverseDNS(ip string) string {
	// Check cache first
	if domain, found := s.dnsCache.get(ip); found {
		return domain
	}

	// Do reverse lookup with timeout
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(s.config.DNSLookupTimeout)*time.Second)
	defer cancel()

	var domain string
	done := make(chan struct{})
	go func() {
		names, err := net.LookupAddr(ip)
		if err == nil && len(names) > 0 {
			domain = strings.TrimSuffix(names[0], ".")
		}
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		domain = ""
	}

	// Cache the result (even empty ones to avoid repeated lookups)
	s.dnsCache.set(ip, domain)
	return domain
}
