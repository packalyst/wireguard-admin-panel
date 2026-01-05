package vpn

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"time"

	"api/internal/database"
	"api/internal/helper"
	"api/internal/settings"
)

// Mutex to prevent concurrent router setup/removal operations
var routerMu sync.Mutex

// RouterStatus represents the status of the VPN router
type RouterStatus struct {
	Enabled          bool      `json:"enabled"`
	Status           string    `json:"status"` // disabled, starting, running, error
	ContainerUp      bool      `json:"containerUp"`
	RouteEnabled     bool      `json:"routeEnabled"`
	HeadscaleUser    string    `json:"headscaleUser"`
	IP               string    `json:"ip,omitempty"`
	AdvertisedRoute  string    `json:"advertisedRoute,omitempty"`
	WgIPRange        string    `json:"wgIPRange"`
	HeadscaleIPRange string    `json:"headscaleIPRange"`
	LastCheck        time.Time `json:"lastCheck,omitempty"`
	Error            string    `json:"error,omitempty"`
}

// GetRouterStatus returns the current status of the VPN router
func GetRouterStatus() RouterStatus {
	status := RouterStatus{
		Status:           "disabled",
		LastCheck:        time.Now(),
		WgIPRange:        helper.GetEnv("WG_IP_RANGE"),
		HeadscaleIPRange: helper.GetEnv("HEADSCALE_IP_RANGE"),
	}

	db, err := database.GetDB()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	routerName := helper.GetRouterName()

	// Check if router is configured in database
	var enabled bool
	var dbStatus string
	var hsUser string
	err = db.QueryRow(`SELECT enabled, status, headscale_user FROM vpn_router_config WHERE id = 1`).Scan(&enabled, &dbStatus, &hsUser)
	if err != nil {
		// No config yet
		return status
	}

	status.Enabled = enabled
	status.HeadscaleUser = hsUser
	if !enabled {
		status.Status = "disabled"
		return status
	}

	// Check if container is running via Docker API
	resp, err := helper.DockerRequest("GET", "/containers/"+routerName+"/json", nil)
	if err != nil {
		status.Status = "error"
		status.Error = "Docker API error: " + err.Error()
		return status
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		status.Status = "error"
		status.Error = "Container not found"
		return status
	}

	var containerInfo struct {
		State struct {
			Running bool `json:"Running"`
		} `json:"State"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&containerInfo); err != nil {
		status.Status = "error"
		status.Error = "Failed to parse container info"
		return status
	}

	status.ContainerUp = containerInfo.State.Running

	if status.ContainerUp {
		// Check if route is enabled in Headscale and get IP/route info
		routeEnabled, routerIP, advertisedRoute := checkRouteEnabledWithInfo()
		status.RouteEnabled = routeEnabled
		status.IP = routerIP
		status.AdvertisedRoute = advertisedRoute
		if status.RouteEnabled {
			status.Status = "running"
		} else {
			status.Status = "starting"
		}
	} else {
		status.Status = "error"
		status.Error = "Container not running"
	}

	return status
}

func checkRouteEnabled() bool {
	enabled, _, _ := checkRouteEnabledWithInfo()
	return enabled
}

func checkRouteEnabledWithInfo() (enabled bool, routerIP string, advertisedRoute string) {
	routerName := helper.GetRouterName()
	wgIPRange := helper.GetEnv("WG_IP_RANGE")

	// Headscale 0.27+: Routes are now part of node data
	// Get all nodes with their route information
	// Note: Headscale API uses snake_case for JSON fields
	var nodeResult struct {
		Nodes []struct {
			ID              string   `json:"id"`
			Name            string   `json:"name"`
			GivenName       string   `json:"givenName"`
			IPAddresses     []string `json:"ipAddresses"`
			ApprovedRoutes  []string `json:"approved_routes"`
			AvailableRoutes []string `json:"available_routes"`
		} `json:"nodes"`
	}
	if err := helper.HeadscaleGetJSON("/node", &nodeResult); err != nil {
		return false, "", ""
	}

	for _, node := range nodeResult.Nodes {
		name := node.GivenName
		if name == "" {
			name = node.Name
		}
		if name == routerName {
			// Found the router node
			if len(node.IPAddresses) > 0 {
				routerIP = node.IPAddresses[0]
			}

			// Check if WG IP range is in available routes (advertised)
			for _, route := range node.AvailableRoutes {
				if route == wgIPRange {
					advertisedRoute = route
					// Check if it's approved (enabled)
					for _, approved := range node.ApprovedRoutes {
						if approved == wgIPRange {
							return true, routerIP, advertisedRoute
						}
					}
					// Route is advertised but not approved
					return false, routerIP, advertisedRoute
				}
			}
			break
		}
	}

	return false, routerIP, advertisedRoute
}

// SetupRouter initializes the VPN router
func SetupRouter() error {
	routerMu.Lock()
	defer routerMu.Unlock()

	db, err := database.GetDB()
	if err != nil {
		return err
	}
	routerName := helper.GetRouterName()
	routerImage := helper.GetRouterImage()
	routerDataPath := helper.GetRouterDataPath()

	// 1. Create/ensure router user in Headscale
	if err := createHeadscaleUser(routerName); err != nil {
		return fmt.Errorf("failed to create headscale user: %v", err)
	}

	// 2. Generate pre-auth key for the router
	authKey, err := createPreAuthKey(routerName)
	if err != nil {
		return fmt.Errorf("failed to create pre-auth key: %v", err)
	}

	// 3. Store auth key in database
	_, err = db.Exec(`
		INSERT INTO vpn_router_config (id, enabled, authkey, headscale_user, status)
		VALUES (1, 1, ?, ?, 'starting')
		ON CONFLICT(id) DO UPDATE SET enabled = 1, authkey = ?, status = 'starting', updated_at = CURRENT_TIMESTAMP
	`, authKey, routerName, authKey)
	if err != nil {
		return fmt.Errorf("failed to store router config: %v", err)
	}

	// 4. Start the router container using Docker API
	wgIPRange := helper.GetEnv("WG_IP_RANGE")

	// First, ensure any existing container is removed
	removeResp, _ := helper.DockerRequest("DELETE", "/containers/"+routerName+"?force=true", nil)
	if removeResp != nil {
		removeResp.Body.Close()
	}

	// Pull the image first
	// Parse image name and tag
	imageParts := strings.SplitN(routerImage, ":", 2)
	imageName := imageParts[0]
	imageTag := "latest"
	if len(imageParts) == 2 {
		imageTag = imageParts[1]
	}

	log.Printf("Pulling %s image...", routerImage)
	pullResp, err := helper.DockerRequest("POST", fmt.Sprintf("/images/create?fromImage=%s&tag=%s", imageName, imageTag), nil)
	if err != nil {
		return fmt.Errorf("failed to pull image: %v", err)
	}
	// Read and discard the pull output (it's streamed)
	io.Copy(io.Discard, pullResp.Body)
	pullResp.Body.Close()
	log.Printf("Image pulled successfully")

	// Get Headscale public URL for the login server (not the internal API URL)
	loginServer, err := settings.GetSetting("headscale_url")
	if err != nil || loginServer == "" {
		return fmt.Errorf("headscale_url not configured - set it in Settings")
	}
	loginServer = strings.TrimSuffix(loginServer, "/")

	// Create container configuration
	// Note: --login-server must be in TS_EXTRA_ARGS for the Tailscale container to use it
	containerConfig := map[string]interface{}{
		"Image":    routerImage,
		"Hostname": routerName,
		"Env": []string{
			"TS_AUTHKEY=" + authKey,
			"TS_EXTRA_ARGS=--login-server=" + loginServer + " --advertise-routes=" + wgIPRange + " --accept-routes --hostname=" + routerName,
			"TS_STATE_DIR=/var/lib/tailscale",
			"TS_USERSPACE=false",
		},
		"HostConfig": map[string]interface{}{
			"NetworkMode": "host",
			"CapAdd":      []string{"NET_ADMIN", "NET_RAW"},
			"Binds":       []string{routerDataPath + ":/var/lib/tailscale"},
			"RestartPolicy": map[string]interface{}{
				"Name": "unless-stopped",
			},
		},
	}

	configBytes, err := json.Marshal(containerConfig)
	if err != nil {
		return fmt.Errorf("failed to marshal container config: %v", err)
	}

	// Create container
	createResp, err := helper.DockerRequest("POST", "/containers/create?name="+routerName, configBytes)
	if err != nil {
		return fmt.Errorf("failed to create container: %v", err)
	}
	defer createResp.Body.Close()

	if createResp.StatusCode != 201 {
		body, _ := io.ReadAll(createResp.Body)
		return fmt.Errorf("failed to create container (status %d): %s", createResp.StatusCode, string(body))
	}

	var createResult struct {
		ID string `json:"Id"`
	}
	json.NewDecoder(createResp.Body).Decode(&createResult)

	// Start container
	startResp, err := helper.DockerRequest("POST", "/containers/"+routerName+"/start", nil)
	if err != nil {
		return fmt.Errorf("failed to start container: %v", err)
	}
	defer startResp.Body.Close()

	if startResp.StatusCode != 204 && startResp.StatusCode != 304 {
		body, _ := io.ReadAll(startResp.Body)
		return fmt.Errorf("failed to start container (status %d): %s", startResp.StatusCode, string(body))
	}

	log.Printf("VPN router container started: %s", createResult.ID[:12])

	// 6. Wait for container to register with Headscale
	go func() {
		for i := 0; i < 30; i++ { // Wait up to 30 seconds
			time.Sleep(time.Second)

			// Check if node appeared
			nodeID := findRouterNode()
			if nodeID != "" {
				// Enable the route
				if err := enableRouterRoute(nodeID); err != nil {
					log.Printf("Failed to enable router route: %v", err)
				} else {
					db.Exec(`UPDATE vpn_router_config SET status = 'running', route_id = ? WHERE id = 1`, nodeID)
					log.Printf("VPN router route enabled successfully")
				}
				return
			}
		}
		log.Printf("Warning: VPN router did not register within 30 seconds")
		db.Exec(`UPDATE vpn_router_config SET status = 'error' WHERE id = 1`)
	}()

	return nil
}

func createHeadscaleUser(name string) error {
	body := fmt.Sprintf(`{"name": "%s"}`, name)
	resp, err := helper.HeadscalePost("/user", body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		respBody, _ := io.ReadAll(resp.Body)
		// Check if user already exists (this is okay)
		if strings.Contains(string(respBody), "already exists") {
			return nil // User exists, that's fine
		}
		return fmt.Errorf("failed to create user: %s", string(respBody))
	}

	return nil
}

func createPreAuthKey(user string) (string, error) {
	// Create a pre-auth key that expires in 1 hour (one-time use)
	expiration := time.Now().Add(helper.PreAuthKeyExpiration).Format(time.RFC3339)
	body := fmt.Sprintf(`{"user": "%s", "reusable": false, "ephemeral": false, "expiration": "%s"}`, user, expiration)

	log.Printf("Creating pre-auth key for user %s, expiration: %s", user, expiration)

	resp, err := helper.HeadscalePost("/preauthkey", body)
	if err != nil {
		return "", fmt.Errorf("request failed: %v", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		return "", fmt.Errorf("failed to create pre-auth key (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result struct {
		PreAuthKey struct {
			Key string `json:"key"`
		} `json:"preAuthKey"`
	}
	if err := json.Unmarshal(respBody, &result); err != nil {
		return "", fmt.Errorf("parse response: %v, body: %s", err, string(respBody))
	}

	if result.PreAuthKey.Key == "" {
		return "", fmt.Errorf("empty key in response: %s", string(respBody))
	}

	return result.PreAuthKey.Key, nil
}

func findRouterNode() string {
	var result struct {
		Nodes []struct {
			ID        string `json:"id"`
			Name      string `json:"name"`
			GivenName string `json:"givenName"`
		} `json:"nodes"`
	}
	if err := helper.HeadscaleGetJSON("/node", &result); err != nil {
		return ""
	}

	routerName := helper.GetRouterName()
	for _, node := range result.Nodes {
		name := node.GivenName
		if name == "" {
			name = node.Name
		}
		if name == routerName {
			return node.ID
		}
	}

	return ""
}

func enableRouterRoute(nodeID string) error {
	// Headscale 0.27+: Use approve_routes endpoint instead of /routes/{id}/enable
	wgIPRange := helper.GetEnv("WG_IP_RANGE")

	// Get current node info to see existing approved routes
	// Note: Headscale API uses snake_case for JSON fields
	var nodeResult struct {
		Node struct {
			ApprovedRoutes  []string `json:"approved_routes"`
			AvailableRoutes []string `json:"available_routes"`
		} `json:"node"`
	}
	if err := helper.HeadscaleGetJSON("/node/"+nodeID, &nodeResult); err != nil {
		return err
	}

	// Check if the WG IP range is available (advertised by the node)
	routeAvailable := false
	for _, route := range nodeResult.Node.AvailableRoutes {
		if route == wgIPRange {
			routeAvailable = true
			break
		}
	}
	if !routeAvailable {
		return fmt.Errorf("route %s not advertised by node", wgIPRange)
	}

	// Check if already approved
	for _, route := range nodeResult.Node.ApprovedRoutes {
		if route == wgIPRange {
			log.Printf("Route %s already enabled for %s", wgIPRange, helper.GetRouterName())
			return nil
		}
	}

	// Add route to approved list
	approvedRoutes := append(nodeResult.Node.ApprovedRoutes, wgIPRange)

	// Call approve_routes endpoint
	body, _ := json.Marshal(map[string][]string{"routes": approvedRoutes})
	resp, err := helper.HeadscalePost("/node/"+nodeID+"/approve_routes", string(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("failed to approve route: status %d", resp.StatusCode)
	}

	log.Printf("Enabled route %s for %s", wgIPRange, helper.GetRouterName())
	return nil
}

// RestartRouter restarts the VPN router container
func RestartRouter() error {
	routerName := helper.GetRouterName()
	resp, err := helper.DockerRequest("POST", "/containers/"+routerName+"/restart?t=10", nil)
	if err != nil {
		return fmt.Errorf("failed to restart router: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 204 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to restart router (status %d): %s", resp.StatusCode, string(body))
	}
	return nil
}

// RemoveRouter removes the VPN router
func RemoveRouter() error {
	routerMu.Lock()
	defer routerMu.Unlock()

	db, err := database.GetDB()
	if err != nil {
		return err
	}
	routerName := helper.GetRouterName()

	// Stop and remove container via Docker API
	resp, _ := helper.DockerRequest("DELETE", "/containers/"+routerName+"?force=true", nil)
	if resp != nil {
		resp.Body.Close()
	}

	// Delete node from Headscale
	nodeID := findRouterNode()
	if nodeID != "" {
		deleteHeadscaleNode(nodeID)
	}

	// Delete user from Headscale
	deleteHeadscaleUser(routerName)

	// Clear all ACL rules and VPN clients in a transaction
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	if _, err := tx.Exec(`DELETE FROM vpn_acl_rules`); err != nil {
		return fmt.Errorf("failed to delete ACL rules: %v", err)
	}
	if _, err := tx.Exec(`DELETE FROM vpn_clients`); err != nil {
		return fmt.Errorf("failed to delete VPN clients: %v", err)
	}
	if _, err := tx.Exec(`UPDATE vpn_router_config SET enabled = 0, status = 'disabled' WHERE id = 1`); err != nil {
		return fmt.Errorf("failed to update router config: %v", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	log.Printf("Cleared all VPN ACL rules and clients")
	return nil
}

func deleteHeadscaleNode(nodeID string) {
	resp, err := helper.HeadscaleDelete("/node/" + nodeID)
	if err == nil {
		resp.Body.Close()
		log.Printf("Deleted Headscale node %s", nodeID)
	}
}

func deleteHeadscaleUser(name string) {
	resp, err := helper.HeadscaleDelete("/user/" + name)
	if err == nil {
		resp.Body.Close()
		log.Printf("Deleted Headscale user %s", name)
	}
}
