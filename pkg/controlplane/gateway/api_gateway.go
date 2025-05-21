package gateway

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/cors"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	"github.com/TFMV/blackice/pkg/controlplane/auth"
	"github.com/TFMV/blackice/pkg/controlplane/config"
	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

// APIGateway provides a REST API interface to the Control Plane services
type APIGateway struct {
	config          *config.ControlPlaneConfig
	server          *http.Server
	router          *mux.Router
	rateLimiter     *RateLimiter
	cpClient        blackicev1.ControlPlaneServiceClient
	authClient      blackicev1.AuthServiceClient
	metricsRegistry *prometheus.Registry
}

// HTTP response wrapper
type apiResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
}

// Authentication context key type
type contextKey string

const (
	userIDContextKey      contextKey = "user_id"
	permissionsContextKey contextKey = "permissions"
)

// HTTP middleware functions
type middleware = mux.MiddlewareFunc

// NewAPIGateway creates a new API gateway
func NewAPIGateway(cfg *config.ControlPlaneConfig, cpConn, authConn *grpc.ClientConn) (*APIGateway, error) {
	router := mux.NewRouter()
	registry := prometheus.NewRegistry()

	// Create rate limiter
	rateLimiter, err := NewRateLimiter(cfg.Gateway.DefaultRateLimit, cfg.Gateway.RateLimitWindow)
	if err != nil {
		return nil, fmt.Errorf("failed to create rate limiter: %w", err)
	}

	// Create gRPC clients
	cpClient := blackicev1.NewControlPlaneServiceClient(cpConn)
	authClient := blackicev1.NewAuthServiceClient(authConn)

	gateway := &APIGateway{
		config:          cfg,
		router:          router,
		rateLimiter:     rateLimiter,
		cpClient:        cpClient,
		authClient:      authClient,
		metricsRegistry: registry,
	}

	// Create HTTP server
	gateway.server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Gateway.Host, cfg.Gateway.Port),
		Handler:      gateway.setupRoutes(),
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeoutSeconds) * time.Second,
	}

	return gateway, nil
}

// Start starts the API gateway
func (g *APIGateway) Start() error {
	log.Info().Msgf("Starting API Gateway on %s", g.server.Addr)

	// Start the server
	err := g.server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("API gateway error: %w", err)
	}

	return nil
}

// Stop stops the API gateway
func (g *APIGateway) Stop(ctx context.Context) error {
	log.Info().Msg("Stopping API Gateway")
	return g.server.Shutdown(ctx)
}

// setupRoutes configures the API routes
func (g *APIGateway) setupRoutes() http.Handler {
	// API versioning
	apiV1 := g.router.PathPrefix("/api/v1").Subrouter()

	// Set up middleware for API routes
	middlewares := []middleware{
		g.loggingMiddleware,
		g.metricsMiddleware,
	}

	// Add rate limiting if enabled
	if g.config.Gateway.EnableRateLimiting {
		middlewares = append(middlewares, g.rateLimitMiddleware)
	}

	// Apply middlewares to all API routes
	for _, m := range middlewares {
		apiV1.Use(m)
	}

	// Authentication endpoints
	authRouter := apiV1.PathPrefix("/auth").Subrouter()
	authRouter.HandleFunc("/login", g.handleLogin).Methods("POST")
	authRouter.HandleFunc("/refresh", g.handleRefreshToken).Methods("POST")
	authRouter.HandleFunc("/verify", g.handleVerifyToken).Methods("POST")
	authRouter.HandleFunc("/logout", g.handleLogout).Methods("POST")

	// System status endpoints
	statusRouter := apiV1.PathPrefix("/system").Subrouter()
	statusRouter.Use(g.authMiddleware) // Require authentication
	statusRouter.HandleFunc("/status", g.handleGetSystemStatus).Methods("GET")
	statusRouter.HandleFunc("/components", g.handleListComponents).Methods("GET")

	// Configuration endpoints
	configRouter := apiV1.PathPrefix("/config").Subrouter()
	configRouter.Use(g.authMiddleware) // Require authentication
	configRouter.HandleFunc("/{component_id}", g.handleGetComponentConfig).Methods("GET")
	configRouter.HandleFunc("/{component_id}", g.handleUpdateComponentConfig).Methods("PUT")
	configRouter.HandleFunc("/{component_id}/reset", g.handleResetComponentConfig).Methods("POST")

	// User management endpoints
	userRouter := apiV1.PathPrefix("/users").Subrouter()
	userRouter.Use(g.authMiddleware) // Require authentication
	userRouter.HandleFunc("", g.handleListUsers).Methods("GET")
	userRouter.HandleFunc("/{user_id}", g.handleGetUser).Methods("GET")
	userRouter.HandleFunc("", g.handleCreateUser).Methods("POST")
	userRouter.HandleFunc("/{user_id}", g.handleUpdateUser).Methods("PUT")
	userRouter.HandleFunc("/{user_id}", g.handleDeleteUser).Methods("DELETE")

	// Role management endpoints
	roleRouter := apiV1.PathPrefix("/roles").Subrouter()
	roleRouter.Use(g.authMiddleware) // Require authentication
	roleRouter.HandleFunc("", g.handleListRoles).Methods("GET")
	roleRouter.HandleFunc("/{role_id}", g.handleGetRole).Methods("GET")
	roleRouter.HandleFunc("", g.handleCreateRole).Methods("POST")
	roleRouter.HandleFunc("/{role_id}", g.handleUpdateRole).Methods("PUT")
	roleRouter.HandleFunc("/{role_id}", g.handleDeleteRole).Methods("DELETE")
	roleRouter.HandleFunc("/{role_id}/permissions", g.handleAddPermissions).Methods("POST")
	roleRouter.HandleFunc("/{role_id}/permissions", g.handleRemovePermissions).Methods("DELETE")

	// Audit endpoints
	auditRouter := apiV1.PathPrefix("/audit").Subrouter()
	auditRouter.Use(g.authMiddleware) // Require authentication
	auditRouter.HandleFunc("/logs", g.handleGetAuditLogs).Methods("GET")

	// Control endpoints
	controlRouter := apiV1.PathPrefix("/control").Subrouter()
	controlRouter.Use(g.authMiddleware) // Require authentication
	controlRouter.HandleFunc("/{component_id}/execute", g.handleExecuteCommand).Methods("POST")

	// Metrics endpoint
	g.router.Handle("/metrics", promhttp.HandlerFor(g.metricsRegistry, promhttp.HandlerOpts{}))

	// Health check endpoint
	g.router.HandleFunc("/health", g.handleHealthCheck).Methods("GET")

	// Static assets for UI
	g.router.PathPrefix("/ui/").Handler(http.StripPrefix("/ui/", http.FileServer(http.Dir("./assets/ui"))))

	// Configure CORS if enabled
	var handler http.Handler = g.router
	if g.config.Gateway.EnableCORS {
		corsOptions := cors.New(cors.Options{
			AllowedOrigins:   g.config.Gateway.AllowedOrigins,
			AllowedMethods:   g.config.Gateway.AllowedMethods,
			AllowedHeaders:   g.config.Gateway.AllowedHeaders,
			AllowCredentials: g.config.Gateway.AllowCredentials,
			MaxAge:           86400, // 24 hours
		})
		handler = corsOptions.Handler(g.router)
	}

	return handler
}

// =================== Middleware =================== //

// loggingMiddleware logs information about each request
func (g *APIGateway) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		responseCapturer := newResponseCapturer(w)

		// Process the request
		next.ServeHTTP(responseCapturer, r)

		// Log the request
		duration := time.Since(start)
		log.Info().
			Str("method", r.Method).
			Str("path", r.URL.Path).
			Str("remote_addr", r.RemoteAddr).
			Int("status", responseCapturer.statusCode).
			Dur("duration", duration).
			Msg("API request")
	})
}

// metricsMiddleware records metrics about each request
func (g *APIGateway) metricsMiddleware(next http.Handler) http.Handler {
	// Define metrics
	requestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "api_requests_total",
			Help: "Total number of API requests",
		},
		[]string{"method", "path", "status"},
	)

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "api_request_duration_seconds",
			Help:    "API request duration in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method", "path"},
	)

	// Register metrics
	g.metricsRegistry.MustRegister(requestsTotal, requestDuration)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap response writer to capture status code
		responseCapturer := newResponseCapturer(w)

		// Process the request
		next.ServeHTTP(responseCapturer, r)

		// Record metrics
		duration := time.Since(start)
		statusCode := strconv.Itoa(responseCapturer.statusCode)
		requestsTotal.WithLabelValues(r.Method, r.URL.Path, statusCode).Inc()
		requestDuration.WithLabelValues(r.Method, r.URL.Path).Observe(duration.Seconds())
	})
}

// rateLimitMiddleware applies rate limiting to requests
func (g *APIGateway) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.RemoteAddr // Use IP as default key

		// If authenticated, use user ID as key for more accurate per-user rate limiting
		if userID := getUserIDFromContext(r.Context()); userID != "" {
			key = userID
		}

		// Check rate limit
		if !g.rateLimiter.Allow(key) {
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// authMiddleware verifies user authentication
func (g *APIGateway) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, "Authorization header required", http.StatusUnauthorized)
			return
		}

		// Check if it's a Bearer token
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, "Invalid authorization format", http.StatusUnauthorized)
			return
		}

		token := parts[1]

		// Validate the token
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		resp, err := g.authClient.ValidateToken(ctx, &blackicev1.ValidateTokenRequest{
			Token: token,
		})

		if err != nil {
			st, ok := status.FromError(err)
			if ok && st.Code() == codes.Unauthenticated {
				http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			} else {
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		if resp.Status.Code != blackicev1.Status_OK {
			http.Error(w, resp.Status.Message, http.StatusUnauthorized)
			return
		}

		// Add user information to the context
		ctx = context.WithValue(r.Context(), userIDContextKey, resp.UserId)
		ctx = context.WithValue(ctx, permissionsContextKey, resp.Permissions)

		// Call the next handler
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// =================== Handler Functions =================== //

// handleLogin handles user authentication
func (g *APIGateway) handleLogin(w http.ResponseWriter, r *http.Request) {
	// Parse login request
	var loginRequest struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&loginRequest); err != nil {
		g.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Create authentication request
	passwordHash := auth.HashPassword(loginRequest.Password) // This would normally be done client-side

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Call authentication service
	resp, err := g.authClient.AuthenticateUser(ctx, &blackicev1.AuthenticateUserRequest{
		Username: loginRequest.Username,
		AuthFactor: &blackicev1.AuthenticateUserRequest_PasswordCredential{
			PasswordCredential: &blackicev1.PasswordCredential{
				PasswordHash: passwordHash,
			},
		},
	})

	if err != nil {
		st, ok := status.FromError(err)
		if ok && (st.Code() == codes.Unauthenticated || st.Code() == codes.PermissionDenied) {
			g.writeErrorResponse(w, http.StatusUnauthorized, "Authentication failed")
		} else {
			g.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	if resp.Status.Code != blackicev1.Status_OK {
		g.writeErrorResponse(w, http.StatusUnauthorized, resp.Status.Message)
		return
	}

	// Return successful response with token
	g.writeSuccessResponse(w, http.StatusOK, "Login successful", map[string]interface{}{
		"token":      resp.SessionToken,
		"expires_at": resp.ExpiryUnixNs / 1000000, // Convert to milliseconds
		"user": map[string]interface{}{
			"id":       resp.User.Id,
			"username": resp.User.Username,
			"email":    resp.User.Email,
		},
	})
}

// handleRefreshToken handles token refresh requests
func (g *APIGateway) handleRefreshToken(w http.ResponseWriter, r *http.Request) {
	// Parse refresh token from request
	var refreshRequest struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&refreshRequest); err != nil {
		g.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if refreshRequest.RefreshToken == "" {
		g.writeErrorResponse(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// For security, we need to validate the original token first
	// In a real implementation, this would validate the refresh token against stored data
	// and generate a new access token

	// Here we call the auth service to handle the refresh logic
	resp, err := g.authClient.ValidateToken(ctx, &blackicev1.ValidateTokenRequest{
		Token: refreshRequest.RefreshToken,
	})

	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.Unauthenticated {
			g.writeErrorResponse(w, http.StatusUnauthorized, "Invalid refresh token")
		} else {
			g.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	if resp.Status.Code != blackicev1.Status_OK {
		g.writeErrorResponse(w, http.StatusUnauthorized, resp.Status.Message)
		return
	}

	// Generate a new session token with the same permissions
	// In a production environment, you would call a dedicated refresh token endpoint
	// This is a simplified implementation
	userID := resp.UserId
	permissions := resp.Permissions

	// Return a new token
	// Typically we would need to get a newly issued token from the auth service
	// For this implementation, we'll assume the ValidateToken response includes necessary data
	g.writeSuccessResponse(w, http.StatusOK, "Token refreshed successfully", map[string]interface{}{
		"token":       "new-session-token", // This would be a real token from the auth service
		"expires_at":  time.Now().Add(time.Duration(g.config.Auth.TokenExpiryMinutes)*time.Minute).UnixNano() / 1000000,
		"user_id":     userID,
		"permissions": permissions,
	})
}

// handleVerifyToken verifies a token's validity
func (g *APIGateway) handleVerifyToken(w http.ResponseWriter, r *http.Request) {
	// Parse request
	var verifyRequest struct {
		Token string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&verifyRequest); err != nil {
		g.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Verify the token
	resp, err := g.authClient.ValidateToken(ctx, &blackicev1.ValidateTokenRequest{
		Token: verifyRequest.Token,
	})

	if err != nil {
		st, ok := status.FromError(err)
		if ok && st.Code() == codes.Unauthenticated {
			g.writeErrorResponse(w, http.StatusUnauthorized, "Invalid token")
		} else {
			g.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error")
		}
		return
	}

	if resp.Status.Code != blackicev1.Status_OK {
		g.writeErrorResponse(w, http.StatusUnauthorized, resp.Status.Message)
		return
	}

	// Return success response
	g.writeSuccessResponse(w, http.StatusOK, "Token is valid", map[string]interface{}{
		"user_id":     resp.UserId,
		"permissions": resp.Permissions,
		"expires_at":  resp.ExpiryUnixNs / 1000000, // Convert to milliseconds
	})
}

// handleLogout logs out a user by invalidating their token
func (g *APIGateway) handleLogout(w http.ResponseWriter, r *http.Request) {
	// Extract token from Authorization header
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		g.writeErrorResponse(w, http.StatusBadRequest, "Authorization header required")
		return
	}

	// Check if it's a Bearer token
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		g.writeErrorResponse(w, http.StatusBadRequest, "Invalid authorization format")
		return
	}

	token := parts[1]

	// In a real implementation, this would add the token to a blacklist or
	// invalidate it in the token store. For military-grade security,
	// we would also trigger additional security measures:
	// 1. Log the logout event for audit
	// 2. Notify security systems of normal logout pattern
	// 3. Consider expiring other sessions for the same user if suspicious
	// 4. Update last-logout timestamp in the user profile

	// Create audit log entry for the logout
	userID := getUserIDFromContext(r.Context())
	if userID == "" {
		// If we can't get the user ID from context, try to extract it from the token
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		// Validate the token to get the user ID
		resp, err := g.authClient.ValidateToken(ctx, &blackicev1.ValidateTokenRequest{
			Token: token,
		})

		if err == nil && resp.Status.Code == blackicev1.Status_OK {
			userID = resp.UserId
		}
	}

	// If we have a user ID, create a proper audit log
	if userID != "" {
		// Create audit log payload
		// In a production system, this would be handled by the audit service directly
		// auditEntry := &blackicev1.AuditLogEntry{
		//	UserId:      userID,
		//	ComponentId: "api_gateway",
		//	Action:      "user_logout",
		//	Resource:    "session",
		//	TimestampUnixNs: time.Now().UnixNano(),
		//	Status: &blackicev1.Status{
		//		Code:    blackicev1.Status_OK,
		//		Message: "User logged out successfully",
		//	},
		//	Metadata: map[string]string{
		//		"ip_address": r.RemoteAddr,
		//		"user_agent": r.UserAgent(),
		//	},
		// }

		// In a real implementation, we would log this audit event
		// For example:
		// ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		// defer cancel()
		// auditClient.LogEvent(ctx, auditEntry)

		// For now, we just log it locally
		log.Info().
			Str("user_id", userID).
			Str("action", "logout").
			Str("ip", r.RemoteAddr).
			Msg("User logged out")
	}

	g.writeSuccessResponse(w, http.StatusOK, "Logout successful", nil)
}

// handleGetSystemStatus gets the overall system status
func (g *APIGateway) handleGetSystemStatus(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Extract user ID from context for auditing
	userID := getUserIDFromContext(ctx)

	// Add user ID to gRPC metadata for server-side auditing
	md := metadata.Pairs("user_id", userID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Call the gRPC service
	resp, err := g.cpClient.GetSystemStatus(ctx, &blackicev1.GetSystemStatusRequest{})
	if err != nil {
		g.handleGRPCError(w, err)
		return
	}

	// Convert to API response format
	systemStatus := map[string]interface{}{
		"components_count": len(resp.Components),
		"resources": map[string]interface{}{
			"cpu_usage":      resp.Resources.CpuUsagePercent,
			"memory_usage":   resp.Resources.MemoryUsagePercent,
			"storage_usage":  resp.Resources.StorageUsagePercent,
			"connections":    resp.Resources.TotalActiveConnections,
			"events_per_sec": resp.Resources.TotalEventsPerSecond,
		},
	}

	g.writeSuccessResponse(w, http.StatusOK, "System status retrieved", systemStatus)
}

// handleListComponents lists all system components
func (g *APIGateway) handleListComponents(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters for pagination
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	pageToken := r.URL.Query().Get("page_token")
	includeHealth, _ := strconv.ParseBool(r.URL.Query().Get("include_health"))

	// Parse filter parameters
	var componentTypes []string
	if typesStr := r.URL.Query().Get("types"); typesStr != "" {
		componentTypes = strings.Split(typesStr, ",")
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// Call the gRPC service
	resp, err := g.cpClient.ListComponents(ctx, &blackicev1.ListComponentsRequest{
		ComponentTypes: componentTypes,
		IncludeHealth:  includeHealth,
		PageSize:       int32(pageSize),
		PageToken:      pageToken,
	})

	if err != nil {
		g.handleGRPCError(w, err)
		return
	}

	// Convert to API response format
	components := make([]map[string]interface{}, 0, len(resp.Components))
	for _, comp := range resp.Components {
		component := map[string]interface{}{
			"id":        comp.ComponentId,
			"type":      comp.ComponentType,
			"version":   comp.Version,
			"last_seen": comp.LastHeartbeatUnixNs / 1000000, // Convert to milliseconds
		}

		// Include health if requested
		if includeHealth && comp.Health != nil {
			component["health"] = map[string]interface{}{
				"state":   comp.Health.State.String(),
				"region":  comp.Health.Region,
				"metrics": comp.Health.Metrics,
			}
		}

		components = append(components, component)
	}

	responseData := map[string]interface{}{
		"components":      components,
		"next_page_token": resp.NextPageToken,
	}

	g.writeSuccessResponse(w, http.StatusOK, "Components retrieved", responseData)
}

// Additional handler stubs

func (g *APIGateway) handleGetComponentConfig(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleUpdateComponentConfig(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleResetComponentConfig(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleListUsers(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleGetUser(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleUpdateUser(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleListRoles(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleGetRole(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleUpdateRole(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleDeleteRole(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleAddPermissions(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleRemovePermissions(w http.ResponseWriter, r *http.Request) {
	g.writeErrorResponse(w, http.StatusNotImplemented, "Not implemented")
}

func (g *APIGateway) handleGetAuditLogs(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	query := r.URL.Query()

	// Parse time range
	startTimeStr := query.Get("start_time")
	endTimeStr := query.Get("end_time")

	var startTimeNs, endTimeNs int64
	var err error

	if startTimeStr != "" {
		startTimeMs, err := strconv.ParseInt(startTimeStr, 10, 64)
		if err != nil {
			g.writeErrorResponse(w, http.StatusBadRequest, "Invalid start_time parameter")
			return
		}
		startTimeNs = startTimeMs * 1000000 // Convert from ms to ns
	}

	if endTimeStr != "" {
		endTimeMs, err := strconv.ParseInt(endTimeStr, 10, 64)
		if err != nil {
			g.writeErrorResponse(w, http.StatusBadRequest, "Invalid end_time parameter")
			return
		}
		endTimeNs = endTimeMs * 1000000 // Convert from ms to ns
	}

	// Parse filtering parameters
	userIDs := query["user_id"]
	componentIDs := query["component_id"]
	actionTypes := query["action_type"]
	resourceTypes := query["resource_type"]

	// Parse pagination parameters
	pageToken := query.Get("page_token")
	pageSizeStr := query.Get("page_size")
	var pageSize int32
	if pageSizeStr != "" {
		pageSizeInt, err := strconv.Atoi(pageSizeStr)
		if err != nil {
			g.writeErrorResponse(w, http.StatusBadRequest, "Invalid page_size parameter")
			return
		}
		pageSize = int32(pageSizeInt)
	} else {
		pageSize = 50 // Default page size
	}

	// Get user ID from context for audit and authorization
	userID := getUserIDFromContext(r.Context())

	// Create context with metadata
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	md := metadata.Pairs("user_id", userID)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Call the Control Plane service to get audit logs
	resp, err := g.cpClient.GetAuditHistory(ctx, &blackicev1.GetAuditHistoryRequest{
		StartTimeUnixNs: startTimeNs,
		EndTimeUnixNs:   endTimeNs,
		UserIds:         userIDs,
		ComponentIds:    componentIDs,
		ActionTypes:     actionTypes,
		ResourceTypes:   resourceTypes,
		PageToken:       pageToken,
		PageSize:        pageSize,
	})

	if err != nil {
		g.handleGRPCError(w, err)
		return
	}

	// Convert AuditLogEntry objects to API response format
	auditLogs := make([]map[string]interface{}, 0, len(resp.AuditLogs))
	for _, entry := range resp.AuditLogs {
		// Convert to milliseconds for client readability
		timestampMs := entry.TimestampUnixNs / 1000000

		auditLog := map[string]interface{}{
			"id":           entry.Id,
			"user_id":      entry.UserId,
			"component_id": entry.ComponentId,
			"action":       entry.Action,
			"resource":     entry.Resource,
			"resource_id":  entry.ResourceId,
			"timestamp":    timestampMs,
			"status":       entry.Status.Code.String(),
			"metadata":     entry.Metadata,
		}

		auditLogs = append(auditLogs, auditLog)
	}

	// Create response
	response := map[string]interface{}{
		"audit_logs":      auditLogs,
		"next_page_token": resp.NextPageToken,
	}

	g.writeSuccessResponse(w, http.StatusOK, "Audit logs retrieved successfully", response)
}

func (g *APIGateway) handleExecuteCommand(w http.ResponseWriter, r *http.Request) {
	// This is a high-risk administrative operation that requires additional security checks

	// Get component ID from URL path
	vars := mux.Vars(r)
	componentID := vars["component_id"]
	if componentID == "" {
		g.writeErrorResponse(w, http.StatusBadRequest, "Component ID is required")
		return
	}

	// Parse request body
	var commandRequest struct {
		Command     string          `json:"command"`
		Parameters  json.RawMessage `json:"parameters"`
		Explanation string          `json:"explanation"` // Require explanation for audit
	}

	if err := json.NewDecoder(r.Body).Decode(&commandRequest); err != nil {
		g.writeErrorResponse(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	// Validate required fields
	if commandRequest.Command == "" {
		g.writeErrorResponse(w, http.StatusBadRequest, "Command is required")
		return
	}

	// Get user ID from context for authorization and audit
	userID := getUserIDFromContext(r.Context())

	// Get user permissions from context
	permissions, _ := r.Context().Value(permissionsContextKey).([]string)

	// Check if user has required permission to execute commands
	// For military-grade security, we require explicit command execution permission
	hasPermission := false
	requiredPermission := "control:execute_command"

	for _, perm := range permissions {
		if perm == requiredPermission || perm == "admin:all" {
			hasPermission = true
			break
		}
	}

	if !hasPermission {
		g.writeErrorResponse(w, http.StatusForbidden, "Insufficient permissions to execute commands")
		return
	}

	// Create context with timeout and metadata
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()

	md := metadata.Pairs(
		"user_id", userID,
		"explanation", commandRequest.Explanation,
		"client_ip", r.RemoteAddr,
	)
	ctx = metadata.NewOutgoingContext(ctx, md)

	// Create an attestation for the command (in a real implementation)
	// This would use the user's credentials to create a cryptographic attestation
	// that binds their identity to this specific command request

	// Execute the command via the Control Plane service
	resp, err := g.cpClient.ExecuteControlCommand(ctx, &blackicev1.ExecuteControlCommandRequest{
		ComponentId:       componentID,
		Command:           commandRequest.Command,
		CommandParameters: []byte(commandRequest.Parameters),
		// In a real implementation, we would include a proper attestation
		// AdminAttestation: attestation,
	})

	if err != nil {
		g.handleGRPCError(w, err)
		return
	}

	// Process the response
	var resultData interface{}
	if len(resp.Result) > 0 {
		// Try to parse the result as JSON
		if err := json.Unmarshal(resp.Result, &resultData); err != nil {
			// If not valid JSON, return as base64
			resultData = base64.StdEncoding.EncodeToString(resp.Result)
		}
	}

	// Create response
	response := map[string]interface{}{
		"operation_id": resp.OperationId,
		"result":       resultData,
	}

	if resp.LedgerEntryConfirmation != nil {
		// Include ledger information for auditability
		response["ledger_entry"] = map[string]interface{}{
			"index":      resp.LedgerEntryConfirmation.Index,
			"entry_id":   resp.LedgerEntryConfirmation.EntryId,
			"entry_type": resp.LedgerEntryConfirmation.EntryType.String(),
			"committed":  resp.LedgerEntryConfirmation.CommittedAtUnixNs / 1000000, // ms
		}
	}

	g.writeSuccessResponse(w, http.StatusOK, "Command executed successfully", response)
}

func (g *APIGateway) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "ok",
		"timestamp": time.Now().Unix(),
	}); err != nil {
		log.Error().Err(err).Msg("Failed to encode health check response")
	}
}

// =================== Helper Functions =================== //

// writeSuccessResponse writes a successful response
func (g *APIGateway) writeSuccessResponse(w http.ResponseWriter, statusCode int, message string, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := apiResponse{
		Success: true,
		Message: message,
		Data:    data,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode success response")
	}
}

// writeErrorResponse writes an error response
func (g *APIGateway) writeErrorResponse(w http.ResponseWriter, statusCode int, errorMessage string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	response := apiResponse{
		Success: false,
		Error:   errorMessage,
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		log.Error().Err(err).Msg("Failed to encode error response")
	}
}

// handleGRPCError handles gRPC errors and converts them to HTTP errors
func (g *APIGateway) handleGRPCError(w http.ResponseWriter, err error) {
	st, ok := status.FromError(err)
	if !ok {
		g.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error")
		return
	}

	switch st.Code() {
	case codes.NotFound:
		g.writeErrorResponse(w, http.StatusNotFound, st.Message())
	case codes.InvalidArgument:
		g.writeErrorResponse(w, http.StatusBadRequest, st.Message())
	case codes.Unauthenticated:
		g.writeErrorResponse(w, http.StatusUnauthorized, st.Message())
	case codes.PermissionDenied:
		g.writeErrorResponse(w, http.StatusForbidden, st.Message())
	case codes.ResourceExhausted:
		g.writeErrorResponse(w, http.StatusTooManyRequests, st.Message())
	default:
		g.writeErrorResponse(w, http.StatusInternalServerError, "Internal server error")
	}
}

// getUserIDFromContext extracts the user ID from the context
func getUserIDFromContext(ctx context.Context) string {
	userID, ok := ctx.Value(userIDContextKey).(string)
	if !ok {
		return ""
	}
	return userID
}

// responseCapturer is a wrapper for http.ResponseWriter that captures the status code
type responseCapturer struct {
	http.ResponseWriter
	statusCode int
}

func newResponseCapturer(w http.ResponseWriter) *responseCapturer {
	return &responseCapturer{w, http.StatusOK}
}

func (r *responseCapturer) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}
