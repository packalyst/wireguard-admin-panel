package firewall

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os/exec"
	"strconv"
	"strings"

	"api/internal/helper"
	"api/internal/router"
)

// handleGetPorts returns allowed ports
func (s *Service) handleGetPorts(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.Query("SELECT port, protocol, essential, COALESCE(service, '') FROM allowed_ports ORDER BY port")
	if err != nil {
		router.JSONError(w, "database error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	ports := []AllowedPort{}
	for rows.Next() {
		var p AllowedPort
		if err := rows.Scan(&p.Port, &p.Protocol, &p.Essential, &p.Service); err != nil {
			continue
		}
		ports = append(ports, p)
	}

	// Add Docker exposed ports
	dockerPorts := s.getDockerExposedPorts()
	for _, dp := range dockerPorts {
		found := false
		for i, existing := range ports {
			if existing.Port == dp.Port && existing.Protocol == dp.Protocol {
				if existing.Service != "" && dp.Service != "" {
					ports[i].Service = existing.Service + ", " + dp.Service
				} else if dp.Service != "" {
					ports[i].Service = dp.Service
				}
				found = true
				break
			}
		}
		if !found {
			ports = append(ports, dp)
		}
	}

	router.JSON(w, ports)
}

// handleAddPort adds an allowed port
func (s *Service) handleAddPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
		Service  string `json:"service"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}

	isEssential := false
	for _, ep := range s.config.EssentialPorts {
		if req.Port == ep.Port && req.Protocol == ep.Protocol {
			isEssential = true
			if req.Service == "" {
				req.Service = ep.Service
			}
			break
		}
	}

	s.db.Exec("INSERT OR IGNORE INTO allowed_ports (port, protocol, essential, service) VALUES (?, ?, ?, ?)",
		req.Port, req.Protocol, isEssential, req.Service)
	s.ApplyRules()
	router.JSON(w, map[string]interface{}{"port": req.Port, "protocol": req.Protocol, "essential": isEssential, "service": req.Service})
}

// handleRemovePort removes an allowed port
func (s *Service) handleRemovePort(w http.ResponseWriter, r *http.Request) {
	portStr := router.ExtractPathParam(r, "/api/fw/ports/")
	port, err := strconv.Atoi(portStr)
	if err != nil {
		router.JSONError(w, "invalid port", http.StatusBadRequest)
		return
	}

	var essential bool
	_ = s.db.QueryRow("SELECT essential FROM allowed_ports WHERE port = ?", port).Scan(&essential)
	if essential {
		router.JSONError(w, "cannot remove essential port", http.StatusForbidden)
		return
	}

	s.db.Exec("DELETE FROM allowed_ports WHERE port = ?", port)
	s.ApplyRules()
	w.WriteHeader(http.StatusNoContent)
}

// handleGetSSHPort returns current SSH port
func (s *Service) handleGetSSHPort(w http.ResponseWriter, r *http.Request) {
	port := helper.GetSSHPort()
	router.JSON(w, map[string]interface{}{"port": port})
}

// handleChangeSSHPort changes the SSH port
func (s *Service) handleChangeSSHPort(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Port int `json:"port"`
	}
	if !router.DecodeJSONOrError(w, r, &req) {
		return
	}

	if req.Port < 1 || req.Port > 65535 {
		router.JSONError(w, "invalid port number (must be 1-65535)", http.StatusBadRequest)
		return
	}

	if req.Port < 1024 && req.Port != 22 {
		log.Printf("Warning: changing SSH to privileged port %d", req.Port)
	}

	oldPort := helper.GetSSHPort()
	if oldPort == req.Port {
		router.JSON(w, map[string]interface{}{
			"status":  "unchanged",
			"port":    req.Port,
			"message": "SSH is already on this port",
		})
		return
	}

	// Add new port to firewall
	_, err := s.db.Exec("INSERT OR IGNORE INTO allowed_ports (port, protocol, essential, service) VALUES (?, 'tcp', 1, 'SSH')", req.Port)
	if err != nil {
		router.JSONError(w, "failed to add new port to firewall: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err := s.ApplyRules(); err != nil {
		router.JSONError(w, "failed to apply firewall rules: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Update sshd_config
	_, err = helper.SetSSHPort(req.Port)
	if err != nil {
		s.db.Exec("DELETE FROM allowed_ports WHERE port = ? AND service = 'SSH'", req.Port)
		s.ApplyRules()
		router.JSONError(w, "failed to update sshd_config: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Restart SSH service
	cmd := exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "restart", "sshd")
	if _, err := cmd.CombinedOutput(); err != nil {
		cmd = exec.Command("nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "systemctl", "restart", "ssh")
		if _, err2 := cmd.CombinedOutput(); err2 != nil {
			helper.SetSSHPort(oldPort)
			s.db.Exec("DELETE FROM allowed_ports WHERE port = ? AND service = 'SSH'", req.Port)
			s.ApplyRules()
			router.JSONError(w, "failed to restart SSH", http.StatusInternalServerError)
			return
		}
	}

	// Remove old port from firewall
	if oldPort != req.Port {
		s.db.Exec("DELETE FROM allowed_ports WHERE port = ? AND service = 'SSH'", oldPort)
		s.config.EssentialPorts = helper.BuildEssentialPorts()
		s.ApplyRules()
	}

	// Update sshd jail
	s.db.Exec("UPDATE jails SET port = ? WHERE name = 'sshd'", strconv.Itoa(req.Port))

	router.JSON(w, map[string]interface{}{
		"status":  "success",
		"oldPort": oldPort,
		"newPort": req.Port,
		"message": fmt.Sprintf("SSH port changed from %d to %d", oldPort, req.Port),
	})
}

// getDockerExposedPorts returns ports exposed by Docker containers
func (s *Service) getDockerExposedPorts() []AllowedPort {
	client := helper.NewDockerHTTPClientWithTimeout(helper.DockerQuickTimeout)

	req, err := http.NewRequest("GET", "http://docker/v1.44/containers/json", nil)
	if err != nil {
		return nil
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var rawContainers []struct {
		Names []string
		Ports []struct {
			IP          string
			PrivatePort int
			PublicPort  int
			Type        string
		}
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawContainers); err != nil {
		return nil
	}

	portMap := make(map[string]AllowedPort)

	for _, c := range rawContainers {
		containerName := ""
		if len(c.Names) > 0 {
			containerName = strings.TrimPrefix(c.Names[0], "/")
		}

		for _, p := range c.Ports {
			if p.PublicPort > 0 && (p.IP == "" || p.IP == "0.0.0.0" || p.IP == "::") {
				key := fmt.Sprintf("%d-%s", p.PublicPort, p.Type)
				if _, exists := portMap[key]; !exists {
					portMap[key] = AllowedPort{
						Port:      p.PublicPort,
						Protocol:  p.Type,
						Essential: true,
						Service:   fmt.Sprintf("Docker: %s", containerName),
					}
				}
			}
		}
	}

	ports := []AllowedPort{}
	for _, p := range portMap {
		ports = append(ports, p)
	}

	return ports
}
