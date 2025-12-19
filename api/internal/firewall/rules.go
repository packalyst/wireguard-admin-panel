package firewall

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"

	"api/internal/geolocation"
)

// ApplyRules applies nftables firewall rules
func (s *Service) ApplyRules() error {
	s.dbMutex.RLock()
	defer s.dbMutex.RUnlock()

	// Get blocked IPs and ranges
	blockedIPs, blockedRanges, err := s.getBlockedIPsAndRanges()
	if err != nil {
		return err
	}

	// Get allowed ports
	allowedPorts, err := s.getAllowedPorts()
	if err != nil {
		return err
	}

	// Get country zones
	countryRangesInbound := s.getCountryRanges(false)
	countryRangesOutbound := s.getCountryRanges(true)

	// Build and apply nftables script
	script := s.buildNftablesScript(blockedIPs, blockedRanges, allowedPorts, countryRangesInbound, countryRangesOutbound)

	if err := s.applyNftablesScript(script); err != nil {
		return err
	}

	log.Printf("Firewall rules applied: %d ports, %d IPs blocked, %d ranges blocked, %d country ranges (in), %d country ranges (out)",
		len(allowedPorts), len(blockedIPs), len(blockedRanges), len(countryRangesInbound), len(countryRangesOutbound))
	return nil
}

// getBlockedIPsAndRanges retrieves blocked IPs and CIDR ranges from database
func (s *Service) getBlockedIPsAndRanges() ([]string, []string, error) {
	rows, err := s.db.Query("SELECT ip, is_range FROM blocked_ips WHERE expires_at IS NULL OR expires_at > datetime('now')")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	var blockedIPs []string
	var blockedRanges []string

	for rows.Next() {
		var ip string
		var isRange bool
		if err := rows.Scan(&ip, &isRange); err != nil {
			log.Printf("Warning: failed to scan blocked IP: %v", err)
			continue
		}
		if isRange || strings.Contains(ip, "/") {
			blockedRanges = append(blockedRanges, ip)
		} else {
			blockedIPs = append(blockedIPs, ip)
		}
	}

	return blockedIPs, blockedRanges, nil
}

// getAllowedPorts retrieves allowed ports from database
func (s *Service) getAllowedPorts() ([]int, error) {
	rows, err := s.db.Query("SELECT port FROM allowed_ports")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var allowedPorts []int
	for rows.Next() {
		var port int
		if err := rows.Scan(&port); err != nil {
			log.Printf("Warning: failed to scan allowed port: %v", err)
			continue
		}
		allowedPorts = append(allowedPorts, port)
	}

	return allowedPorts, nil
}

// getCountryRanges retrieves country IP ranges from geolocation service
func (s *Service) getCountryRanges(outboundOnly bool) []string {
	geoSvc := geolocation.GetService()
	if geoSvc == nil {
		return nil
	}
	return geoSvc.GetBlockedCountryCIDRs(outboundOnly)
}

// buildNftablesScript generates the nftables script
func (s *Service) buildNftablesScript(blockedIPs, blockedRanges []string, allowedPorts []int, countryRangesInbound, countryRangesOutbound []string) string {
	var sb strings.Builder

	sb.WriteString(`#!/usr/sbin/nft -f

table inet firewall {
    # Blocked single IPs set
    set blocked_ips {
        type ipv4_addr
`)

	if len(blockedIPs) > 0 {
		sb.WriteString("        elements = { ")
		sb.WriteString(strings.Join(blockedIPs, ", "))
		sb.WriteString(" }\n")
	}

	sb.WriteString(`    }

    # Blocked CIDR ranges set (with interval flag)
    set blocked_ranges {
        type ipv4_addr
        flags interval
`)

	if len(blockedRanges) > 0 {
		sb.WriteString("        elements = { ")
		sb.WriteString(strings.Join(blockedRanges, ", "))
		sb.WriteString(" }\n")
	}

	sb.WriteString(`    }

    # Allowed TCP ports set
    set allowed_tcp_ports {
        type inet_service
`)

	if len(allowedPorts) > 0 {
		sb.WriteString("        elements = { ")
		sb.WriteString(formatPorts(allowedPorts))
		sb.WriteString(" }\n")
	}

	sb.WriteString(`    }

    # Allowed UDP ports set
    set allowed_udp_ports {
        type inet_service
`)

	if len(allowedPorts) > 0 {
		sb.WriteString("        elements = { ")
		sb.WriteString(formatPorts(allowedPorts))
		sb.WriteString(" }\n")
	}

	sb.WriteString(`    }

    # Blocked country ranges set - inbound (with interval flag)
    set blocked_countries {
        type ipv4_addr
        flags interval
`)

	if len(countryRangesInbound) > 0 {
		sb.WriteString("        elements = { ")
		sb.WriteString(strings.Join(countryRangesInbound, ", "))
		sb.WriteString(" }\n")
	}

	sb.WriteString(`    }

    # Blocked country ranges set - outbound (with interval flag)
    set blocked_countries_out {
        type ipv4_addr
        flags interval
`)

	if len(countryRangesOutbound) > 0 {
		sb.WriteString("        elements = { ")
		sb.WriteString(strings.Join(countryRangesOutbound, ", "))
		sb.WriteString(" }\n")
	}

	sb.WriteString(`    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Allow established connections
        ct state established,related accept

        # Allow loopback
        iif lo accept

        # Allow ICMP
        ip protocol icmp accept
        ip6 nexthdr icmpv6 accept

        # Drop blocked IPs and ranges (O(1) set lookups)
        ip saddr @blocked_ips drop
        ip saddr @blocked_ranges drop

        # Drop blocked country ranges
        ip saddr @blocked_countries drop

        # Allow ports (single rule per protocol, O(1) set lookup)
        tcp dport @allowed_tcp_ports accept
        udp dport @allowed_udp_ports accept

        # Log dropped packets
        limit rate 5/minute log prefix "FIREWALL_DROP: " drop
    }

    chain forward {
        type filter hook forward priority -1; policy accept;

        # Allow established connections
        ct state established,related accept

        # Drop blocked IPs and ranges (applies to Docker containers too)
        ip saddr @blocked_ips drop
        ip saddr @blocked_ranges drop

        # Drop blocked country ranges (applies to Docker containers too)
        ip saddr @blocked_countries drop

        # Log VPN client outbound traffic
        iifname "wg0" ct state new log prefix "VPN_TRAFFIC: " accept
        oifname "wg0" accept
        iifname "tailscale0" ct state new log prefix "VPN_TRAFFIC: " accept
        oifname "tailscale0" accept
    }

    chain output {
        type filter hook output priority 0; policy accept;

        # Allow established connections
        ct state established,related accept

        # Block outbound to countries with direction='both'
        ip daddr @blocked_countries_out drop
    }
}
`)

	return sb.String()
}

// formatPorts formats a list of ports for nftables
func formatPorts(ports []int) string {
	strs := make([]string, len(ports))
	for i, p := range ports {
		strs[i] = fmt.Sprintf("%d", p)
	}
	return strings.Join(strs, ", ")
}

// applyNftablesScript writes and applies the nftables script
func (s *Service) applyNftablesScript(script string) error {
	// Delete existing table
	exec.Command("nft", "delete", "table", "inet", "firewall").Run()

	tmpFile := "/tmp/firewall.nft"
	if err := os.WriteFile(tmpFile, []byte(script), 0600); err != nil {
		return err
	}

	cmd := exec.Command("nft", "-f", tmpFile)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("nft error: %v - %s", err, string(out))
	}

	return nil
}
