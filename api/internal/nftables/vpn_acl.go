package nftables

import (
	"database/sql"
	"fmt"
	"strings"

	"api/internal/helper"
)

// VPNACLTable builds the inet vpn_acl table
type VPNACLTable struct {
	db *sql.DB
}

// NewVPNACLTable creates a new VPN ACL table builder
func NewVPNACLTable(db *sql.DB) *VPNACLTable {
	return &VPNACLTable{db: db}
}

func (t *VPNACLTable) Name() string     { return "wgadmin_vpn_acl" }
func (t *VPNACLTable) Family() string   { return "inet" }
func (t *VPNACLTable) Priority() int    { return 20 }

// Build generates the nftables script for VPN ACL
func (t *VPNACLTable) Build() (string, error) {
	wgIPRange := helper.GetEnvOptional("WG_IP_RANGE", "")
	hsIPRange := helper.GetEnvOptional("HEADSCALE_IP_RANGE", "")
	serverIP := helper.GetEnvOptional("SERVER_IP", "")

	// Load clients
	clients, err := t.loadClients()
	if err != nil {
		return "", err
	}

	// Load ACL rules
	rules, err := t.loadRules()
	if err != nil {
		return "", err
	}

	return t.buildScript(clients, rules, wgIPRange, hsIPRange, serverIP), nil
}

type vpnClient struct {
	ID     int64
	Name   string
	IP     string
	Type   string
	Policy string
}

type aclRule struct {
	SourceID int64
	TargetID int64
}

func (t *VPNACLTable) loadClients() (map[int64]vpnClient, error) {
	rows, err := t.db.Query(`SELECT id, name, ip, type, acl_policy FROM vpn_clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	clients := make(map[int64]vpnClient)
	for rows.Next() {
		var c vpnClient
		if err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.Type, &c.Policy); err != nil {
			continue
		}
		clients[c.ID] = c
	}
	return clients, nil
}

func (t *VPNACLTable) loadRules() ([]aclRule, error) {
	rows, err := t.db.Query(`SELECT source_client_id, target_client_id FROM vpn_acl_rules`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []aclRule
	for rows.Next() {
		var r aclRule
		if err := rows.Scan(&r.SourceID, &r.TargetID); err != nil {
			continue
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func (t *VPNACLTable) buildScript(clients map[int64]vpnClient, rules []aclRule, wgIPRange, hsIPRange, serverIP string) string {
	var sb strings.Builder

	// Validate IP ranges before use
	if !ValidateIPOrCIDR(wgIPRange) {
		wgIPRange = ""
	}
	if !ValidateIPOrCIDR(hsIPRange) {
		hsIPRange = ""
	}
	if serverIP != "" && !ValidateIPOrCIDR(serverIP) {
		serverIP = ""
	}

	sb.WriteString("# VPN ACL nftables rules\n")
	sb.WriteString("# AUTO-GENERATED - DO NOT EDIT\n")
	if serverIP != "" {
		sb.WriteString(fmt.Sprintf("# Server: %s\n\n", SanitizeComment(serverIP)))
	}

	// Delete existing table
	sb.WriteString("table inet vpn_acl\ndelete table inet vpn_acl\n\n")

	sb.WriteString("table inet vpn_acl {\n")
	sb.WriteString("    chain forward {\n")
	sb.WriteString("        type filter hook forward priority 0; policy accept;\n\n")
	sb.WriteString("        # Allow established/related\n")
	sb.WriteString("        ct state established,related accept\n\n")
	sb.WriteString("        # Allow ICMP\n")
	sb.WriteString("        ip protocol icmp accept\n\n")
	sb.WriteString("        # === VPN ACL Rules ===\n\n")

	allowedPairs := make(map[string]bool)

	// Handle allow_all policy clients first
	for _, c := range clients {
		// Skip clients with invalid IPs
		if !ValidateIPOrCIDR(c.IP) {
			continue
		}
		if c.Policy == helper.ACLPolicyAllowAll {
			safeName := SanitizeComment(c.Name)
			sb.WriteString(fmt.Sprintf("        # %s [allow_all]\n", safeName))
			if wgIPRange != "" {
				sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s accept\n", c.IP, wgIPRange))
			}
			if hsIPRange != "" {
				sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s accept\n", c.IP, hsIPRange))
			}
			sb.WriteString("\n")
		}
	}

	// Process explicit rules
	for _, rule := range rules {
		src, srcExists := clients[rule.SourceID]
		dst, dstExists := clients[rule.TargetID]
		if !srcExists || !dstExists {
			continue
		}

		// Skip clients with invalid IPs
		if !ValidateIPOrCIDR(src.IP) || !ValidateIPOrCIDR(dst.IP) {
			continue
		}

		// Skip if either has block_all
		if src.Policy == helper.ACLPolicyBlockAll || dst.Policy == helper.ACLPolicyBlockAll {
			continue
		}

		// Skip if source has allow_all (already covered)
		if src.Policy == helper.ACLPolicyAllowAll {
			continue
		}

		key := fmt.Sprintf("%s->%s", src.IP, dst.IP)
		if !allowedPairs[key] {
			sb.WriteString(fmt.Sprintf("        # %s -> %s\n", SanitizeComment(src.Name), SanitizeComment(dst.Name)))
			sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s accept\n\n", src.IP, dst.IP))
			allowedPairs[key] = true
		}
	}

	// Drop unallowed VPN-to-VPN traffic
	sb.WriteString("        # Drop unallowed VPN traffic\n")
	if wgIPRange != "" && hsIPRange != "" {
		sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s drop\n", wgIPRange, hsIPRange))
		sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s drop\n", hsIPRange, wgIPRange))
	}
	if wgIPRange != "" {
		sb.WriteString(fmt.Sprintf("        ip saddr %s ip daddr %s drop\n", wgIPRange, wgIPRange))
	}

	sb.WriteString("    }\n")
	sb.WriteString("}\n")

	return sb.String()
}
