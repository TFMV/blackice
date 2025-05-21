package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"

	"github.com/TFMV/blackice/pkg/controlplane"
	"github.com/TFMV/blackice/pkg/controlplane/audit"
	"github.com/TFMV/blackice/pkg/controlplane/auth"
	"github.com/TFMV/blackice/pkg/controlplane/config"
	"github.com/TFMV/blackice/pkg/controlplane/crypto"
	"github.com/TFMV/blackice/pkg/controlplane/gateway"
	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

// Version information - in a production environment, these would be set at build time
var (
	Version   = "1.0.0"
	BuildDate = time.Now().Format("2006-01-02")
	GitCommit = "development"
	GoVersion = "go1.18+"
)

// Server represents the Control Plane server
type Server struct {
	config           *config.ControlPlaneConfig
	grpcServer       *grpc.Server
	controlPlane     *controlplane.ControlPlaneService
	authService      *auth.AuthService
	auditService     *audit.AuditService
	apiGateway       *gateway.APIGateway
	httpServer       *http.Server // For health checks and metrics
	shutdownComplete chan struct{}
	shutdownTimeout  time.Duration
	logger           *zerolog.Logger
}

// NewServer creates a new Control Plane server
func NewServer(cfg *config.ControlPlaneConfig) (*Server, error) {
	// Setup logger
	logger := zerolog.New(os.Stdout).With().Timestamp().Str("component", "controlplane_server").Logger()

	// Create the token manager
	tokenManager, err := auth.NewJWTTokenManager(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create token manager: %w", err)
	}

	// Create mock stores for the auth service
	// These would be real database connections in production
	userStore := newMockUserStore()
	roleStore := newMockRoleStore()
	permissionStore := newMockPermissionStore()
	attestationClient := newMockAttestationClient()

	// Create auth service
	authService := auth.NewAuthService(cfg, userStore, roleStore, permissionStore, attestationClient, tokenManager)

	// Create audit service with adapter for attestation verification
	attestationVerifier := &AttestationVerifierAdapter{client: attestationClient}
	auditService, err := audit.NewAuditService(cfg, attestationVerifier)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit service: %w", err)
	}

	// Create control plane service with audit integration
	controlPlaneService := controlplane.NewControlPlaneService(cfg, authService)

	// Set the audit service for the control plane
	// The following would be uncommented in a production environment
	// To enable this, add the SetAuditService method to the ControlPlaneService struct
	if cfg.Audit.Enabled {
		logger.Info().Msg("Audit logging is enabled but controlPlaneService.SetAuditService is not implemented")
		// controlPlaneService.SetAuditService(auditService)
		// Since we can't modify the controlplane package now, we'll handle audit logging through interceptors
	}

	// Create gRPC server options
	var opts []grpc.ServerOption

	// Configure TLS if enabled
	if cfg.Server.TLS.Enabled {
		tlsConfig, err := createTLSConfig(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to configure TLS: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	}

	// Add other gRPC options
	opts = append(opts,
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionIdle:     time.Duration(cfg.Server.IdleTimeoutSeconds) * time.Second,
			MaxConnectionAge:      time.Hour,
			MaxConnectionAgeGrace: 5 * time.Minute,
			Time:                  1 * time.Minute,
			Timeout:               20 * time.Second,
		}),
		grpc.MaxConcurrentStreams(uint32(cfg.Server.MaxConcurrentRequests)),
		// Add UnaryInterceptor for auth and audit logging
		grpc.UnaryInterceptor(createServerInterceptor(authService, auditService)),
	)

	// Create gRPC server
	grpcServer := grpc.NewServer(opts...)

	// Register services
	blackicev1.RegisterControlPlaneServiceServer(grpcServer, controlPlaneService)
	blackicev1.RegisterAuthServiceServer(grpcServer, authService)

	// Enable reflection for development tools
	reflection.Register(grpcServer)

	// Create gRPC connection for API Gateway to use
	grpcAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	var clientConn *grpc.ClientConn
	var dialErr error

	// Configure the gRPC client with proper options
	if cfg.Server.TLS.Enabled {
		// Create TLS credentials for secure connection
		tlsCreds := credentials.NewTLS(&tls.Config{
			InsecureSkipVerify: false, // Verify server certificates
		})

		// If we have client certificates for mTLS
		if cfg.Server.TLS.RequireClientCert && cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != "" {
			// Load client certificates
			clientCert, certErr := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
			if certErr != nil {
				return nil, fmt.Errorf("failed to load client certificates: %w", certErr)
			}

			// Create TLS config with client certificates
			tlsConfig := &tls.Config{
				Certificates: []tls.Certificate{clientCert},
				MinVersion:   tls.VersionTLS13,
			}

			// Use the TLS config with client certificates
			tlsCreds = credentials.NewTLS(tlsConfig)
		}

		// Connect with TLS credentials
		clientConn, dialErr = grpc.Dial(
			grpcAddr,
			grpc.WithTransportCredentials(tlsCreds),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024*10)), // 10MB max message size
			grpc.WithDefaultServiceConfig(`{"loadBalancingPolicy":"round_robin"}`),
		)
		if dialErr != nil {
			return nil, fmt.Errorf("failed to create secure client connection for API Gateway: %w", dialErr)
		}
	} else {
		// For development environments only, use insecure connection
		// WARNING: Not suitable for production use
		clientConn, dialErr = grpc.Dial(
			grpcAddr,
			grpc.WithTransportCredentials(insecure.NewCredentials()),
			grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1024*1024*10)),
		)
		if dialErr != nil {
			return nil, fmt.Errorf("failed to create insecure client connection for API Gateway: %w", dialErr)
		}
	}

	// Create API Gateway
	apiGateway, err := gateway.NewAPIGateway(cfg, clientConn, clientConn)
	if err != nil {
		return nil, fmt.Errorf("failed to create API Gateway: %w", err)
	}

	// Create HTTP server for health checks and metrics
	httpServer := createHTTPServer(cfg, controlPlaneService, authService)

	return &Server{
		config:           cfg,
		grpcServer:       grpcServer,
		controlPlane:     controlPlaneService,
		authService:      authService,
		auditService:     auditService,
		apiGateway:       apiGateway,
		httpServer:       httpServer,
		shutdownComplete: make(chan struct{}),
		shutdownTimeout:  30 * time.Second,
		logger:           &logger,
	}, nil
}

// Start starts the server and blocks until it's stopped
func (s *Server) Start() error {
	s.logger.Info().Msg("Starting Control Plane server")

	// Setup signal handling for graceful shutdown
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)

	// Start gRPC server
	grpcAddr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)
	grpcListener, err := net.Listen("tcp", grpcAddr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", grpcAddr, err)
	}

	// Start HTTP server
	httpAddr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port+1)
	s.logger.Info().Str("addr", httpAddr).Msg("Starting HTTP server for health checks and metrics")
	go func() {
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.logger.Error().Err(err).Msg("HTTP server error")
		}
	}()

	// Start API Gateway if configured
	if s.apiGateway != nil {
		gatewayAddr := fmt.Sprintf("%s:%d", s.config.Gateway.Host, s.config.Gateway.Port)
		s.logger.Info().Str("addr", gatewayAddr).Msg("Starting API Gateway")
		go func() {
			if err := s.apiGateway.Start(); err != nil {
				s.logger.Error().Err(err).Msg("API Gateway error")
			}
		}()
	}

	// Start gRPC server
	s.logger.Info().Str("addr", grpcAddr).Msg("Starting gRPC server")
	go func() {
		if err := s.grpcServer.Serve(grpcListener); err != nil {
			s.logger.Error().Err(err).Msg("gRPC server error")
		}
		close(s.shutdownComplete)
	}()

	// Wait for signal to shut down
	sig := <-signalCh
	s.logger.Info().Str("signal", sig.String()).Msg("Received shutdown signal")

	// Graceful shutdown with timeout
	s.Shutdown(s.shutdownTimeout)

	return nil
}

// Shutdown gracefully shuts down all components with timeout
func (s *Server) Shutdown(timeout time.Duration) {
	s.logger.Info().Dur("timeout", timeout).Msg("Graceful shutdown initiated")

	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create WaitGroup for all shutdown tasks
	var wg sync.WaitGroup

	// Shutdown HTTP server
	if s.httpServer != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.logger.Info().Msg("Shutting down HTTP server")
			if err := s.httpServer.Shutdown(ctx); err != nil {
				s.logger.Error().Err(err).Msg("HTTP server shutdown error")
			}
		}()
	}

	// Shutdown API Gateway
	if s.apiGateway != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.logger.Info().Msg("Shutting down API Gateway")
			if err := s.apiGateway.Stop(ctx); err != nil {
				s.logger.Error().Err(err).Msg("API Gateway shutdown error")
			}
		}()
	}

	// Shutdown Audit Service
	if s.auditService != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.logger.Info().Msg("Shutting down Audit Service")
			s.auditService.Shutdown()
		}()
	}

	// Gracefully stop the gRPC server
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.logger.Info().Msg("Gracefully stopping gRPC server")
		s.grpcServer.GracefulStop()
	}()

	// Wait with timeout for all components to shut down
	waitCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(waitCh)
	}()

	select {
	case <-waitCh:
		s.logger.Info().Msg("All components shut down successfully")
	case <-ctx.Done():
		s.logger.Warn().Msg("Shutdown timeout reached, forcing shutdown")
		// Force stop the gRPC server if timeout
		s.grpcServer.Stop()
	}

	// Wait for gRPC server to complete shutdown
	select {
	case <-s.shutdownComplete:
		s.logger.Info().Msg("gRPC server shutdown complete")
	case <-time.After(2 * time.Second):
		s.logger.Warn().Msg("Timeout waiting for gRPC server shutdown completion")
	}

	s.logger.Info().Msg("Server shutdown complete")
}

// Stop stops the server
func (s *Server) Stop() {
	s.Shutdown(s.shutdownTimeout)
}

// createTLSConfig creates a TLS configuration for the server
func createTLSConfig(cfg *config.ControlPlaneConfig) (*tls.Config, error) {
	if cfg.Server.TLS.UseQuantumResistantAlgorithms {
		// Use quantum-resistant TLS config
		return crypto.CreateQuantumResistantTLSConfig(
			cfg.Server.TLS.CertFile,
			cfg.Server.TLS.KeyFile,
			cfg.Server.TLS.CAFile,
		)
	}

	// Regular TLS config
	tlsCert, err := tls.LoadX509KeyPair(cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	// If client verification is required, load CA cert
	if cfg.Server.TLS.RequireClientCert {
		// Load CA cert for client certificate verification
		caCert, err := os.ReadFile(cfg.Server.TLS.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert

		// Enable certificate revocation check using OCSP
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			// Skip if no chains (shouldn't happen in RequireAndVerifyClientCert mode)
			if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
				return fmt.Errorf("certificate verification failed: no verified chains")
			}

			// Get the leaf certificate from the first chain
			leaf := verifiedChains[0][0]

			// Check if the certificate has been revoked using CRL or OCSP
			// This is a simplified implementation for demonstration

			// 1. Check expiration
			if time.Now().After(leaf.NotAfter) {
				return fmt.Errorf("certificate has expired: %s", leaf.Subject)
			}
			if time.Now().Before(leaf.NotBefore) {
				return fmt.Errorf("certificate is not yet valid: %s", leaf.Subject)
			}

			// 2. Verify certificate purpose
			var validPurpose bool
			for _, usage := range leaf.ExtKeyUsage {
				if usage == x509.ExtKeyUsageClientAuth {
					validPurpose = true
					break
				}
			}

			if !validPurpose {
				return fmt.Errorf("certificate is not valid for client authentication: %s", leaf.Subject)
			}

			// 3. In production, we would check OCSP here using:
			// - Get OCSP server URL from certificate AIA extension
			// - Create OCSP request
			// - Send request to OCSP responder
			// - Check the response for revocation status

			// 4. In production, we would also check CRL here:
			// - Get CRL URL from certificate
			// - Download and parse CRL
			// - Check if certificate serial number is in the CRL

			// For now, we'll accept the certificate since the standard library
			// has already verified the chain against the CA certificates
			return nil
		}
	}

	return tlsConfig, nil
}

// Mock implementations of stores for demonstrating the server setup
// These would be replaced with real database implementations

type mockUserStore struct{}

func newMockUserStore() auth.UserStore {
	return &mockUserStore{}
}

func (s *mockUserStore) GetUser(ctx context.Context, id string) (*blackicev1.User, error) {
	// Mock implementation
	return &blackicev1.User{
		Id:       id,
		Username: "admin",
		Email:    "admin@example.com",
		Status:   blackicev1.UserStatus_USER_STATUS_ACTIVE,
	}, nil
}

func (s *mockUserStore) GetUserByUsername(ctx context.Context, username string) (*blackicev1.User, error) {
	// Mock implementation
	return &blackicev1.User{
		Id:       "user-1",
		Username: username,
		Email:    "admin@example.com",
		Status:   blackicev1.UserStatus_USER_STATUS_ACTIVE,
	}, nil
}

func (s *mockUserStore) CreateUser(ctx context.Context, user *blackicev1.User) (string, error) {
	return "user-1", nil
}

func (s *mockUserStore) UpdateUser(ctx context.Context, user *blackicev1.User) error {
	return nil
}

func (s *mockUserStore) DeleteUser(ctx context.Context, id string) error {
	return nil
}

func (s *mockUserStore) ListUsers(ctx context.Context, offset, limit int) ([]*blackicev1.User, error) {
	return []*blackicev1.User{}, nil
}

type mockRoleStore struct{}

func newMockRoleStore() auth.RoleStore {
	return &mockRoleStore{}
}

func (s *mockRoleStore) GetRole(ctx context.Context, id string) (*blackicev1.Role, error) {
	return &blackicev1.Role{
		Id:   id,
		Name: "Admin",
	}, nil
}

func (s *mockRoleStore) CreateRole(ctx context.Context, role *blackicev1.Role) (string, error) {
	return "role-1", nil
}

func (s *mockRoleStore) UpdateRole(ctx context.Context, role *blackicev1.Role) error {
	return nil
}

func (s *mockRoleStore) DeleteRole(ctx context.Context, id string) error {
	return nil
}

func (s *mockRoleStore) ListRoles(ctx context.Context, offset, limit int) ([]*blackicev1.Role, error) {
	return []*blackicev1.Role{}, nil
}

type mockPermissionStore struct{}

func newMockPermissionStore() auth.PermissionStore {
	return &mockPermissionStore{}
}

func (s *mockPermissionStore) GetPermissionsForUser(ctx context.Context, userID string) ([]string, error) {
	return []string{"controlplane:read", "controlplane:write", "auth:read"}, nil
}

func (s *mockPermissionStore) GetPermissionsForRole(ctx context.Context, roleID string) ([]string, error) {
	return []string{"controlplane:read", "controlplane:write", "auth:read"}, nil
}

func (s *mockPermissionStore) AddPermissionToRole(ctx context.Context, roleID string, permission string) error {
	return nil
}

func (s *mockPermissionStore) RemovePermissionFromRole(ctx context.Context, roleID string, permission string) error {
	return nil
}

type mockAttestationClient struct{}

func newMockAttestationClient() auth.AttestationClient {
	return &mockAttestationClient{}
}

func (c *mockAttestationClient) VerifyAttestation(ctx context.Context, attestation *blackicev1.Attestation) (bool, error) {
	// Mock implementation - always returns true
	return true, nil
}

func (c *mockAttestationClient) CreateChallenge(ctx context.Context, userID string, deviceID string, attestationType blackicev1.AttestationType) (*blackicev1.AttestationChallengeResponse, error) {
	// Mock implementation
	return &blackicev1.AttestationChallengeResponse{
		Status: &blackicev1.Status{
			Code: blackicev1.Status_OK,
		},
		ChallengeId:   "challenge-1",
		ChallengeData: []byte("mock-challenge-data"),
		ExpiryUnixNs:  time.Now().Add(5 * time.Minute).UnixNano(),
	}, nil
}

// AttestationVerifierAdapter adapts the AttestationClient to the AttestationVerifier interface
type AttestationVerifierAdapter struct {
	client auth.AttestationClient
}

// Verify implements the AttestationVerifier interface
func (a *AttestationVerifierAdapter) Verify(ctx context.Context, attestation *blackicev1.Attestation) (bool, error) {
	return a.client.VerifyAttestation(ctx, attestation)
}

// createServerInterceptor creates a gRPC server interceptor for auth and audit logging
func createServerInterceptor(authService *auth.AuthService, auditService *audit.AuditService) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
		start := time.Now()

		// Extract metadata for auth and auditing
		md, _ := metadata.FromIncomingContext(ctx)

		// Extract user ID for audit logging if present
		var userID string
		if userIDs := md.Get("user_id"); len(userIDs) > 0 {
			userID = userIDs[0]
		}

		// Extract token if present for validation
		var token string
		if tokens := md.Get("authorization"); len(tokens) > 0 {
			// Remove "Bearer " prefix if present
			token = strings.TrimPrefix(tokens[0], "Bearer ")
		}

		// Authenticate user if token is present
		var authenticated bool
		var permissions []string

		if token != "" {
			resp, err := authService.ValidateToken(ctx, &blackicev1.ValidateTokenRequest{
				Token: token,
			})

			if err == nil && resp.Status.Code == blackicev1.Status_OK {
				authenticated = true
				userID = resp.UserId
				permissions = resp.Permissions

				// Add user ID and permissions to context for downstream handlers
				newCtx := context.WithValue(ctx, UserIDKey, userID)
				newCtx = context.WithValue(newCtx, PermissionsKey, permissions)
				ctx = newCtx
			}
		}

		// Check if this method requires authentication
		methodName := info.FullMethod
		requiresAuth := !strings.HasSuffix(methodName, "AuthenticateUser") &&
			!strings.HasSuffix(methodName, "VerifyAttestation")

		if requiresAuth && !authenticated {
			return nil, status.Error(codes.Unauthenticated, "authentication required")
		}

		// Handle the request
		resp, err := handler(ctx, req)

		// Log audit entry
		if auditService != nil && userID != "" {
			// Create audit log entry
			auditEntry := &blackicev1.AuditLogEntry{
				UserId:          userID,
				ComponentId:     "control_plane",
				Action:          methodName,
				Resource:        methodName,
				TimestampUnixNs: time.Now().UnixNano(),
				Status: &blackicev1.Status{
					Code: blackicev1.Status_OK,
				},
				Metadata: map[string]string{
					"duration_ms": fmt.Sprintf("%d", time.Since(start).Milliseconds()),
					"method":      methodName,
				},
			}

			if err != nil {
				// Update status for audit log
				st, ok := status.FromError(err)
				if ok {
					auditEntry.Status.Code = blackicev1.Status_Code(st.Code())
					auditEntry.Status.Message = st.Message()
				} else {
					auditEntry.Status.Code = blackicev1.Status_ERROR
					auditEntry.Status.Message = err.Error()
				}
			}

			// Asynchronously log the audit entry
			go auditService.LogEvent(context.Background(), auditEntry)
		}

		return resp, err
	}
}

// createHTTPServer creates an HTTP server for health checks and metrics
func createHTTPServer(cfg *config.ControlPlaneConfig, cpService *controlplane.ControlPlaneService, authService *auth.AuthService) *http.Server {
	mux := http.NewServeMux()

	// Create a logger for the HTTP server
	httpLogger := zerolog.New(os.Stdout).With().Timestamp().Str("component", "http_server").Logger()

	// Health check endpoint
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"ok"}`))
		if err != nil {
			httpLogger.Error().Err(err).Msg("Error writing health check response")
		}
	})

	// Readiness check endpoint
	mux.HandleFunc("/ready", func(w http.ResponseWriter, r *http.Request) {
		// Check if services are ready
		if cpService == nil || authService == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, err := w.Write([]byte(`{"status":"not ready"}`))
			if err != nil {
				httpLogger.Error().Err(err).Msg("Error writing readiness check response")
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(`{"status":"ready"}`))
		if err != nil {
			httpLogger.Error().Err(err).Msg("Error writing readiness check response")
		}
	})

	// Version endpoint
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		// Construct version JSON with our version constants
		versionJSON := []byte(fmt.Sprintf(`{"version":"%s","build_date":"%s","git_commit":"%s","go_version":"%s"}`,
			Version, BuildDate, GitCommit, GoVersion))
		_, err := w.Write(versionJSON)
		if err != nil {
			httpLogger.Error().Err(err).Msg("Error writing version response")
		}
	})

	// Setup Prometheus metrics
	setupMetrics(mux)

	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port+1), // Use a different port than gRPC
		Handler:      mux,
		ReadTimeout:  time.Duration(cfg.Server.ReadTimeoutSeconds) * time.Second,
		WriteTimeout: time.Duration(cfg.Server.WriteTimeoutSeconds) * time.Second,
		IdleTimeout:  time.Duration(cfg.Server.IdleTimeoutSeconds) * time.Second,
	}
}

// Context keys for user information
type contextKey string

const (
	// UserIDKey is the context key for user ID
	UserIDKey contextKey = "user_id"
	// PermissionsKey is the context key for permissions
	PermissionsKey contextKey = "permissions"
)

// setupMetrics configures Prometheus metrics for the server
func setupMetrics(mux *http.ServeMux) {
	// We'll create our own registry instead of using the global default

	// Define and register metrics
	registry := prometheus.NewRegistry()

	// Server metrics
	serverUptime := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blackice_controlplane_uptime_seconds_total",
			Help: "Total uptime of the Control Plane server",
		},
		[]string{"component"},
	)

	requestsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blackice_controlplane_requests_total",
			Help: "Total number of gRPC requests processed",
		},
		[]string{"method", "status"},
	)

	requestDuration := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "blackice_controlplane_request_duration_seconds",
			Help:    "Duration of gRPC requests in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"method"},
	)

	// Authentication metrics
	authAttempts := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blackice_controlplane_auth_attempts_total",
			Help: "Total number of authentication attempts",
		},
		[]string{"result"},
	)

	// Audit metrics
	auditEventsTotal := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "blackice_controlplane_audit_events_total",
			Help: "Total number of audit events logged",
		},
		[]string{"action", "resource", "status"},
	)

	// Component health metrics
	componentStatus := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "blackice_controlplane_component_health",
			Help: "Health status of system components (1=healthy, 0=unhealthy)",
		},
		[]string{"component_id", "component_type"},
	)

	// Register all metrics
	registry.MustRegister(
		serverUptime,
		requestsTotal,
		requestDuration,
		authAttempts,
		auditEventsTotal,
		componentStatus,
	)

	// Start uptime counter
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			serverUptime.WithLabelValues("controlplane").Add(60) // Add one minute
		}
	}()

	// Create metrics handler with custom registry
	mux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
}
