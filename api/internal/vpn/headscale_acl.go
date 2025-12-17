package vpn

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"

	"api/internal/database"
	"api/internal/helper"
)

// getHeadscaleACLPath returns the configured Headscale ACL path
func getHeadscaleACLPath() string {
	return helper.GetHeadscaleACLPath()
}

// HeadscaleACL represents the Headscale ACL policy file structure
type HeadscaleACL struct {
	Hosts       map[string]string `json:"hosts"`
	Groups      map[string][]string `json:"groups,omitempty"`
	TagOwners   map[string][]string `json:"tagOwners,omitempty"`
	ACLs        []ACLEntry        `json:"acls"`
	AutoApprovers map[string][]string `json:"autoApprovers,omitempty"`
}

// ACLEntry represents a single ACL entry
type ACLEntry struct {
	Action string   `json:"action"`
	Src    []string `json:"src"`
	Dst    []string `json:"dst"`
}

// GenerateAndApplyHeadscaleACL generates Headscale ACL policy from the database and applies it
func GenerateAndApplyHeadscaleACL() error {
	acl, err := generateHeadscaleACL()
	if err != nil {
		return err
	}

	// Marshal to JSON with indentation
	data, err := json.MarshalIndent(acl, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal Headscale ACL: %v", err)
	}

	aclPath := getHeadscaleACLPath()

	// Ensure directory exists
	os.MkdirAll(filepath.Dir(aclPath), 0755)

	// Write ACL file
	if err := os.WriteFile(aclPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write Headscale ACL: %v", err)
	}

	// Reload Headscale policy
	// Note: Headscale reads the policy file on startup and when receiving SIGHUP
	cmd := exec.Command("pkill", "-HUP", "headscale")
	if err := cmd.Run(); err != nil {
		// Try docker approach if direct signal fails
		cmd = exec.Command("docker", "exec", "headscale", "kill", "-HUP", "1")
		if err := cmd.Run(); err != nil {
			log.Printf("Warning: Could not signal Headscale to reload policy: %v", err)
			// Not a fatal error - the policy will be applied on next restart
		}
	}

	log.Printf("Applied Headscale ACL policy")
	return nil
}

func generateHeadscaleACL() (*HeadscaleACL, error) {
	db := database.Get()
	wgIPRange := helper.GetEnv("WG_IP_RANGE")

	// Get all clients
	rows, err := db.Query(`SELECT id, name, ip, type, acl_policy, default_direction FROM vpn_clients`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type client struct {
		ID        int
		Name      string
		IP        string
		Type      string
		Policy    string
		Direction string
	}
	clients := make(map[int]client)

	for rows.Next() {
		var c client
		if err := rows.Scan(&c.ID, &c.Name, &c.IP, &c.Type, &c.Policy, &c.Direction); err != nil {
			continue
		}
		clients[c.ID] = c
	}

	// Get all ACL rules
	ruleRows, err := db.Query(`SELECT source_client_id, target_client_id, direction FROM vpn_acl_rules`)
	if err != nil {
		return nil, err
	}
	defer ruleRows.Close()

	type aclRule struct {
		SourceID  int
		TargetID  int
		Direction string
	}
	var rules []aclRule
	for ruleRows.Next() {
		var r aclRule
		if err := ruleRows.Scan(&r.SourceID, &r.TargetID, &r.Direction); err != nil {
			continue
		}
		rules = append(rules, r)
	}

	// Build Headscale ACL
	acl := &HeadscaleACL{
		Hosts: make(map[string]string),
		ACLs:  []ACLEntry{},
	}

	// Add all clients to hosts
	for _, c := range clients {
		// Sanitize name for use in ACL
		safeName := sanitizeHostName(c.Name)
		acl.Hosts[safeName] = c.IP
	}

	// Add WireGuard network as a host entry for routing
	if wgIPRange != "" {
		acl.Hosts["wireguard-network"] = wgIPRange
	}

	// Allow router to access everything (needed for subnet routing)
	routerName := helper.GetEnv("VPN_ROUTER_NAME")
	if routerName == "" {
		routerName = "vpn-router"
	}
	acl.ACLs = append(acl.ACLs, ACLEntry{
		Action: "accept",
		Src:    []string{routerName},
		Dst:    []string{"*:*"},
	})
	acl.ACLs = append(acl.ACLs, ACLEntry{
		Action: "accept",
		Src:    []string{"*"},
		Dst:    []string{routerName + ":*"},
	})

	// Track which pairs are already allowed
	allowedPairs := make(map[string]bool)

	// Process explicit rules
	for _, rule := range rules {
		src, srcExists := clients[rule.SourceID]
		dst, dstExists := clients[rule.TargetID]
		if !srcExists || !dstExists {
			continue
		}

		srcName := sanitizeHostName(src.Name)
		dstName := sanitizeHostName(dst.Name)

		switch rule.Direction {
		case helper.ACLDirectionBidirectional:
			key1 := fmt.Sprintf("%s->%s", srcName, dstName)
			key2 := fmt.Sprintf("%s->%s", dstName, srcName)
			if !allowedPairs[key1] {
				// Forward direction
				acl.ACLs = append(acl.ACLs, ACLEntry{
					Action: "accept",
					Src:    []string{srcName},
					Dst:    []string{dstName + ":*"},
				})
				// Reverse direction
				acl.ACLs = append(acl.ACLs, ACLEntry{
					Action: "accept",
					Src:    []string{dstName},
					Dst:    []string{srcName + ":*"},
				})
				allowedPairs[key1] = true
				allowedPairs[key2] = true
			}

		case helper.ACLDirectionOutboundOnly:
			key := fmt.Sprintf("%s->%s", srcName, dstName)
			if !allowedPairs[key] {
				acl.ACLs = append(acl.ACLs, ACLEntry{
					Action: "accept",
					Src:    []string{srcName},
					Dst:    []string{dstName + ":*"},
				})
				allowedPairs[key] = true
			}

		case helper.ACLDirectionInboundOnly:
			key := fmt.Sprintf("%s->%s", dstName, srcName)
			if !allowedPairs[key] {
				acl.ACLs = append(acl.ACLs, ACLEntry{
					Action: "accept",
					Src:    []string{dstName},
					Dst:    []string{srcName + ":*"},
				})
				allowedPairs[key] = true
			}
		}
	}

	// Handle "allow_all_future" policies
	for _, c := range clients {
		if c.Policy == helper.ACLPolicyAllowAllFuture {
			safeName := sanitizeHostName(c.Name)
			// Allow this client to reach everything
			acl.ACLs = append(acl.ACLs, ACLEntry{
				Action: "accept",
				Src:    []string{safeName},
				Dst:    []string{"*:*"},
			})
			// Allow everything to reach this client
			acl.ACLs = append(acl.ACLs, ACLEntry{
				Action: "accept",
				Src:    []string{"*"},
				Dst:    []string{safeName + ":*"},
			})
		}
	}

	// Allow access to wireguard-network via vpn-router for all Headscale clients with allowed rules
	// (This enables Headscale clients to reach WireGuard clients via the subnet router)
	for _, c := range clients {
		if c.Type == "headscale" && c.Policy != helper.ACLPolicyBlockAll {
			safeName := sanitizeHostName(c.Name)
			acl.ACLs = append(acl.ACLs, ACLEntry{
				Action: "accept",
				Src:    []string{safeName},
				Dst:    []string{"wireguard-network:*"},
			})
		}
	}

	return acl, nil
}

// sanitizeHostName converts a client name to a valid Headscale host name
func sanitizeHostName(name string) string {
	// Replace spaces and special characters with hyphens
	result := ""
	for _, c := range name {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' {
			result += string(c)
		} else if c == ' ' {
			result += "-"
		}
	}
	return result
}

// RemoveHeadscaleACL removes the Headscale ACL policy file
func RemoveHeadscaleACL() error {
	// Create a permissive default policy
	defaultACL := &HeadscaleACL{
		Hosts: map[string]string{},
		ACLs: []ACLEntry{
			{
				Action: "accept",
				Src:    []string{"*"},
				Dst:    []string{"*:*"},
			},
		},
	}

	data, err := json.MarshalIndent(defaultACL, "", "  ")
	if err != nil {
		return err
	}

	if err := os.WriteFile(getHeadscaleACLPath(), data, 0644); err != nil {
		return err
	}

	log.Printf("Reset Headscale ACL to default (allow all)")
	return nil
}
