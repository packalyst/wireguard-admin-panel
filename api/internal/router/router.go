package router

import (
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"api/internal/config"
	"api/internal/helper"
)

// AuthValidator is a function that validates a session token
type AuthValidator func(token string) bool

// authValidator is the registered auth validator
var authValidator AuthValidator

// HandlerFunc is the standard handler function type
type HandlerFunc func(w http.ResponseWriter, r *http.Request)

// ServiceHandlers maps handler names to functions for a service
type ServiceHandlers map[string]HandlerFunc

// Router manages HTTP routing based on configuration
type Router struct {
	mux      *http.ServeMux
	config   *config.Config
	handlers map[string]ServiceHandlers
}

// New creates a new router with the given configuration
func New(cfg *config.Config) *Router {
	return &Router{
		mux:      http.NewServeMux(),
		config:   cfg,
		handlers: make(map[string]ServiceHandlers),
	}
}

// RegisterService registers handlers for a service
func (r *Router) RegisterService(serviceName string, handlers ServiceHandlers) {
	r.handlers[serviceName] = handlers
}

// Build builds the router based on configuration and registered handlers
func (r *Router) Build() http.Handler {
	// Group endpoints by actual pattern (after truncating path params)
	actualPatterns := make(map[string][]routeHandler)

	for serviceName, svcConfig := range r.config.Services {
		if !svcConfig.Enabled {
			log.Printf("Service %s is disabled, skipping", serviceName)
			continue
		}

		handlers, ok := r.handlers[serviceName]
		if !ok {
			log.Printf("Warning: No handlers registered for service %s", serviceName)
			continue
		}

		for _, endpoint := range svcConfig.Endpoints {
			handler, ok := handlers[endpoint.Handler]
			if !ok {
				log.Printf("Warning: Handler %s not found for %s%s", endpoint.Handler, svcConfig.Prefix, endpoint.Path)
				continue
			}

			fullPattern := svcConfig.Prefix + endpoint.Path
			// Get actual pattern for mux registration
			actualPattern := fullPattern
			if strings.Contains(fullPattern, "{") {
				actualPattern = fullPattern[:strings.Index(fullPattern, "{")]
			}

			actualPatterns[actualPattern] = append(actualPatterns[actualPattern], routeHandler{
				fullPattern: fullPattern,
				methods:     endpoint.Methods,
				handler:     handler,
			})
			log.Printf("Registered: %s %v -> %s", fullPattern, endpoint.Methods, endpoint.Handler)
		}
	}

	// Register combined handlers for each actual pattern
	for actualPattern, handlers := range actualPatterns {
		r.registerCombinedEndpointV2(actualPattern, handlers)
	}

	// Add API info endpoint
	r.mux.HandleFunc("/api", r.handleAPIInfo)
	r.mux.HandleFunc("/api/", r.handleAPIInfo)
	r.mux.HandleFunc("/health", r.handleHealth)

	return r.applyMiddleware(r.mux)
}

// routeHandler holds method-handler pairs with full pattern
type routeHandler struct {
	fullPattern string
	methods     []string
	handler     HandlerFunc
}

// registerCombinedEndpointV2 registers multiple handlers for a single actual path pattern
func (r *Router) registerCombinedEndpointV2(actualPattern string, handlers []routeHandler) {
	r.mux.HandleFunc(actualPattern, func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Find matching handler based on path and method
		path := req.URL.Path
		for _, rh := range handlers {
			// Check if path matches the full pattern
			if r.pathMatches(path, rh.fullPattern) && r.methodAllowed(req.Method, rh.methods) {
				rh.handler(w, req)
				return
			}
		}

		// Try method matching without strict path match for parameterized routes
		for _, rh := range handlers {
			if r.methodAllowed(req.Method, rh.methods) {
				rh.handler(w, req)
				return
			}
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	})
}

// pathMatches checks if a request path matches a pattern (with {param} support)
func (r *Router) pathMatches(reqPath, pattern string) bool {
	// Exact match
	if reqPath == pattern {
		return true
	}

	// Pattern with parameters
	if !strings.Contains(pattern, "{") {
		return reqPath == pattern
	}

	// Split into parts
	reqParts := strings.Split(strings.Trim(reqPath, "/"), "/")
	patParts := strings.Split(strings.Trim(pattern, "/"), "/")

	if len(reqParts) != len(patParts) {
		return false
	}

	for i, pat := range patParts {
		if strings.HasPrefix(pat, "{") && strings.HasSuffix(pat, "}") {
			continue // Parameter matches anything
		}
		if pat != reqParts[i] {
			return false
		}
	}

	return true
}

// methodAllowed checks if the request method is in the allowed list
func (r *Router) methodAllowed(method string, allowed []string) bool {
	if method == "OPTIONS" {
		return true
	}
	for _, m := range allowed {
		if m == method {
			return true
		}
	}
	return false
}

// SetAuthValidator sets the auth validator function
func SetAuthValidator(validator AuthValidator) {
	authValidator = validator
}

// applyMiddleware wraps the handler with configured middleware
func (r *Router) applyMiddleware(handler http.Handler) http.Handler {
	h := handler

	// Apply auth middleware (must be before logging to reject early)
	h = r.authMiddleware(h)

	// Apply logging middleware
	if r.config.Middleware.Logging.Enabled {
		h = r.loggingMiddleware(h)
	}

	// Apply CORS middleware
	if r.config.Middleware.CORS.Enabled {
		h = r.corsMiddleware(h)
	}

	return h
}

// authMiddleware checks for valid session token on protected routes
func (r *Router) authMiddleware(next http.Handler) http.Handler {
	// Public path prefixes (any path starting with these is public)
	publicPrefixes := []string{
		"/api/setup/",
		"/api/auth/login",
		"/api/auth/health",
	}

	// Exact public paths
	publicExact := []string{
		"/health",
		"/api",
		"/api/",
	}

	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path := req.URL.Path

		// Allow OPTIONS requests (CORS preflight)
		if req.Method == "OPTIONS" {
			next.ServeHTTP(w, req)
			return
		}

		// Check exact matches
		for _, exact := range publicExact {
			if path == exact {
				next.ServeHTTP(w, req)
				return
			}
		}

		// Check prefix matches
		for _, prefix := range publicPrefixes {
			if strings.HasPrefix(path, prefix) {
				next.ServeHTTP(w, req)
				return
			}
		}

		// Skip auth if no validator is set (e.g., during initial setup)
		if authValidator == nil {
			next.ServeHTTP(w, req)
			return
		}

		// Extract token from Authorization header or cookie
		token := helper.ExtractBearerToken(req)
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Validate token
		if !authValidator(token) {
			http.Error(w, "Invalid or expired session", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, req)
	})
}

// corsMiddleware adds CORS headers
func (r *Router) corsMiddleware(next http.Handler) http.Handler {
	cors := r.config.Middleware.CORS
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		origin := "*"
		if len(cors.AllowOrigins) > 0 && cors.AllowOrigins[0] != "*" {
			origin = cors.AllowOrigins[0]
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", strings.Join(cors.AllowMethods, ", "))
		w.Header().Set("Access-Control-Allow-Headers", strings.Join(cors.AllowHeaders, ", "))

		if req.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, req)
	})
}

// loggingMiddleware logs requests
func (r *Router) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		start := time.Now()
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(wrapped, req)

		if r.config.Middleware.Logging.Format == "json" {
			log.Printf(`{"method":"%s","path":"%s","status":%d,"duration":"%s"}`,
				req.Method, req.URL.Path, wrapped.statusCode, time.Since(start))
		} else {
			log.Printf("%s %s %d %s", req.Method, req.URL.Path, wrapped.statusCode, time.Since(start))
		}
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleAPIInfo returns information about available endpoints
func (r *Router) handleAPIInfo(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	info := map[string]interface{}{
		"version":  r.config.Version,
		"services": make(map[string]interface{}),
	}

	for name, svc := range r.config.Services {
		if !svc.Enabled {
			continue
		}

		endpoints := make([]map[string]interface{}, 0, len(svc.Endpoints))
		for _, ep := range svc.Endpoints {
			endpoints = append(endpoints, map[string]interface{}{
				"path":        svc.Prefix + ep.Path,
				"methods":     ep.Methods,
				"description": ep.Description,
			})
		}

		info["services"].(map[string]interface{})[name] = map[string]interface{}{
			"prefix":    svc.Prefix,
			"endpoints": endpoints,
		}
	}

	if err := json.NewEncoder(w).Encode(info); err != nil {
		log.Printf("Error encoding info response: %v", err)
	}
}

// handleHealth returns health status
func (r *Router) handleHealth(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]string{"status": "ok"}); err != nil {
		log.Printf("Error encoding health response: %v", err)
	}
}

// ExtractPathParam extracts a path parameter from the URL
func ExtractPathParam(r *http.Request, prefix string) string {
	path := strings.TrimPrefix(r.URL.Path, prefix)
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// JSON sends a JSON response
func JSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
	}
}

// JSONError sends a JSON error response
func JSONError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(map[string]string{"error": message}); err != nil {
		log.Printf("Error encoding JSON error response: %v", err)
	}
}

// PaginationParams holds parsed pagination parameters
type PaginationParams struct {
	Limit  int
	Offset int
}

// ParsePagination extracts limit and offset from URL query parameters
// with sensible defaults and validation
func ParsePagination(r *http.Request, defaultLimit int) PaginationParams {
	p := PaginationParams{
		Limit:  defaultLimit,
		Offset: 0,
	}

	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 {
			p.Limit = parsed
		}
	}

	if o := r.URL.Query().Get("offset"); o != "" {
		if parsed, err := strconv.Atoi(o); err == nil && parsed >= 0 {
			p.Offset = parsed
		}
	}

	return p
}
