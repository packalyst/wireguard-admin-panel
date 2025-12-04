package docker

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"api/internal/router"
)

// validContainerName matches valid Docker container names (alphanumeric, underscore, dash, dot)
var validContainerName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// Service handles Docker operations via Unix socket
type Service struct {
	socketPath string
	client     *http.Client
}

// Container represents a Docker container
type Container struct {
	ID      string            `json:"id"`
	Name    string            `json:"name"`
	Image   string            `json:"image"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Created int64             `json:"created"`
	Ports   []Port            `json:"ports"`
	Labels  map[string]string `json:"labels,omitempty"`
}

// Port represents a container port mapping
type Port struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort int    `json:"privatePort"`
	PublicPort  int    `json:"publicPort,omitempty"`
	Type        string `json:"type"`
}

// ContainerStats represents container resource usage
type ContainerStats struct {
	CPUPercent float64 `json:"cpuPercent"`
	MemUsage   uint64  `json:"memUsage"`
	MemLimit   uint64  `json:"memLimit"`
	MemPercent float64 `json:"memPercent"`
	NetRx      uint64  `json:"netRx"`
	NetTx      uint64  `json:"netTx"`
}

// New creates a new Docker service
func New() *Service {
	// Create HTTP client that uses Unix socket
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", "/var/run/docker.sock")
			},
		},
		Timeout: 30 * time.Second,
	}

	return &Service{
		socketPath: "/var/run/docker.sock",
		client:     client,
	}
}

// Handlers returns the handler map for the router
func (s *Service) Handlers() router.ServiceHandlers {
	return router.ServiceHandlers{
		"GetContainers": s.handleGetContainers,
		"GetContainer":  s.handleGetContainer,
		"GetLogs":       s.handleGetLogs,
		"Restart":       s.handleRestart,
		"Stop":          s.handleStop,
		"Start":         s.handleStart,
		"Health":        s.handleHealth,
	}
}

// doRequest performs a request to Docker API
func (s *Service) doRequest(method, path string) (*http.Response, error) {
	req, err := http.NewRequest(method, "http://docker"+path, nil)
	if err != nil {
		return nil, err
	}
	return s.client.Do(req)
}

// handleGetContainers returns list of containers
func (s *Service) handleGetContainers(w http.ResponseWriter, r *http.Request) {
	resp, err := s.doRequest("GET", "/v1.44/containers/json?all=true")
	if err != nil {
		router.JSONError(w, "Failed to connect to Docker: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	var rawContainers []struct {
		ID      string `json:"Id"`
		Names   []string
		Image   string
		State   string
		Status  string
		Created int64
		Ports   []struct {
			IP          string
			PrivatePort int
			PublicPort  int
			Type        string
		}
		Labels map[string]string
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawContainers); err != nil {
		router.JSONError(w, "Failed to parse response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Return all containers
	containers := make([]Container, 0)

	for _, c := range rawContainers {
		name := ""
		if len(c.Names) > 0 {
			name = strings.TrimPrefix(c.Names[0], "/")
		}

		ports := make([]Port, len(c.Ports))
		for i, p := range c.Ports {
			ports[i] = Port{
				IP:          p.IP,
				PrivatePort: p.PrivatePort,
				PublicPort:  p.PublicPort,
				Type:        p.Type,
			}
		}

		containers = append(containers, Container{
			ID:      c.ID[:12],
			Name:    name,
			Image:   c.Image,
			State:   c.State,
			Status:  c.Status,
			Created: c.Created,
			Ports:   ports,
		})
	}

	router.JSON(w, map[string]interface{}{
		"containers": containers,
	})
}

// handleGetContainer returns details for a specific container
func (s *Service) handleGetContainer(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/docker/containers/")
	if name == "" {
		router.JSONError(w, "Container name required", http.StatusBadRequest)
		return
	}
	if !validContainerName.MatchString(name) {
		router.JSONError(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	resp, err := s.doRequest("GET", "/v1.44/containers/"+name+"/json")
	if err != nil {
		router.JSONError(w, "Failed to get container: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		router.JSONError(w, "Container not found", http.StatusNotFound)
		return
	}

	var container map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&container); err != nil {
		router.JSONError(w, "Failed to parse response: "+err.Error(), http.StatusInternalServerError)
		return
	}

	router.JSON(w, container)
}

// handleGetLogs returns container logs
func (s *Service) handleGetLogs(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/docker/containers/")
	// Remove /logs suffix
	name = strings.TrimSuffix(name, "/logs")
	if name == "" {
		router.JSONError(w, "Container name required", http.StatusBadRequest)
		return
	}
	if !validContainerName.MatchString(name) {
		router.JSONError(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	// Get query params
	tail := r.URL.Query().Get("tail")
	if tail == "" {
		tail = "100"
	}

	resp, err := s.doRequest("GET", fmt.Sprintf("/v1.44/containers/%s/logs?stdout=true&stderr=true&tail=%s&timestamps=true", name, tail))
	if err != nil {
		router.JSONError(w, "Failed to get logs: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		router.JSONError(w, "Container not found", http.StatusNotFound)
		return
	}

	// Parse Docker log format (8-byte header + message)
	var logs []map[string]string
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) < 8 {
			continue
		}
		// Skip 8-byte header
		message := string(line[8:])
		if message == "" {
			continue
		}

		// Parse timestamp if present
		parts := strings.SplitN(message, " ", 2)
		if len(parts) == 2 {
			logs = append(logs, map[string]string{
				"timestamp": parts[0],
				"message":   parts[1],
			})
		} else {
			logs = append(logs, map[string]string{
				"message": message,
			})
		}
	}

	router.JSON(w, map[string]interface{}{
		"logs": logs,
	})
}

// handleRestart restarts a container
func (s *Service) handleRestart(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/docker/containers/")
	name = strings.TrimSuffix(name, "/restart")
	if name == "" {
		router.JSONError(w, "Container name required", http.StatusBadRequest)
		return
	}
	if !validContainerName.MatchString(name) {
		router.JSONError(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	log.Printf("Restarting container: %s", name)

	resp, err := s.doRequest("POST", "/v1.44/containers/"+name+"/restart?t=10")
	if err != nil {
		router.JSONError(w, "Failed to restart container: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		router.JSONError(w, "Container not found", http.StatusNotFound)
		return
	}

	if resp.StatusCode != 204 {
		router.JSONError(w, "Failed to restart container", resp.StatusCode)
		return
	}

	log.Printf("Container %s restarted successfully", name)
	router.JSON(w, map[string]string{"status": "restarted", "container": name})
}

// handleStop stops a container
func (s *Service) handleStop(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/docker/containers/")
	name = strings.TrimSuffix(name, "/stop")
	if name == "" {
		router.JSONError(w, "Container name required", http.StatusBadRequest)
		return
	}
	if !validContainerName.MatchString(name) {
		router.JSONError(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	log.Printf("Stopping container: %s", name)

	resp, err := s.doRequest("POST", "/v1.44/containers/"+name+"/stop?t=10")
	if err != nil {
		router.JSONError(w, "Failed to stop container: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		router.JSONError(w, "Container not found", http.StatusNotFound)
		return
	}

	if resp.StatusCode == 304 {
		router.JSON(w, map[string]string{"status": "already_stopped", "container": name})
		return
	}

	if resp.StatusCode != 204 {
		router.JSONError(w, "Failed to stop container", resp.StatusCode)
		return
	}

	log.Printf("Container %s stopped successfully", name)
	router.JSON(w, map[string]string{"status": "stopped", "container": name})
}

// handleStart starts a container
func (s *Service) handleStart(w http.ResponseWriter, r *http.Request) {
	name := router.ExtractPathParam(r, "/api/docker/containers/")
	name = strings.TrimSuffix(name, "/start")
	if name == "" {
		router.JSONError(w, "Container name required", http.StatusBadRequest)
		return
	}
	if !validContainerName.MatchString(name) {
		router.JSONError(w, "Invalid container name", http.StatusBadRequest)
		return
	}

	log.Printf("Starting container: %s", name)

	resp, err := s.doRequest("POST", "/v1.44/containers/"+name+"/start")
	if err != nil {
		router.JSONError(w, "Failed to start container: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		router.JSONError(w, "Container not found", http.StatusNotFound)
		return
	}

	if resp.StatusCode == 304 {
		router.JSON(w, map[string]string{"status": "already_running", "container": name})
		return
	}

	if resp.StatusCode != 204 {
		router.JSONError(w, "Failed to start container", resp.StatusCode)
		return
	}

	log.Printf("Container %s started successfully", name)
	router.JSON(w, map[string]string{"status": "started", "container": name})
}

// handleHealth returns health status
func (s *Service) handleHealth(w http.ResponseWriter, r *http.Request) {
	// Try to ping Docker
	resp, err := s.doRequest("GET", "/v1.44/_ping")
	if err != nil {
		router.JSON(w, map[string]string{"status": "error", "error": err.Error()})
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		router.JSON(w, map[string]string{"status": "error", "error": "Docker not responding"})
		return
	}

	router.JSON(w, map[string]string{"status": "ok"})
}
