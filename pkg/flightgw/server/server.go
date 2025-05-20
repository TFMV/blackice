package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/apache/arrow-go/v18/arrow/flight"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/TFMV/blackice/pkg/flightgw/config"
	"github.com/TFMV/blackice/pkg/flightgw/crypto"
	"github.com/TFMV/blackice/pkg/flightgw/trust"
)

// SecureFlightServer is a secure implementation of the Arrow Flight server
type SecureFlightServer struct {
	cfg                 *config.Config
	hmacVerifier        *crypto.HMACVerifier
	trustScorer         *trust.TrustScorer
	registry            *trust.Registry
	attestationVerifier *crypto.AttestationVerifier
	merkleVerifier      *crypto.MerkleVerifier
	upstreamClient      flight.Client
	grpcServer          *grpc.Server
	securityContext     *SecurityContext
	initialized         bool
	listener            net.Listener
	healthServer        *http.Server
	adminServer         *http.Server
	healthStatus        *HealthStatus
	circuitBreaker      *CircuitBreaker
	policyManager       *PolicyManager
}

// HealthStatus contains the health status of the server and its dependencies
type HealthStatus struct {
	mu            sync.RWMutex
	status        string // "healthy", "degraded", "unhealthy"
	statusCode    int
	upstreamOK    bool
	securityOK    bool
	lastCheck     time.Time
	startTime     time.Time
	versionInfo   string
	detailedState map[string]interface{}
}

// SecurityContext holds security components for handlers
type SecurityContext struct {
	HMACVerifier        *crypto.HMACVerifier
	AttestationVerifier *crypto.AttestationVerifier
	MerkleVerifier      *crypto.MerkleVerifier
	TrustScorer         *trust.TrustScorer
	Registry            *trust.Registry
}

// NewSecureFlightServer creates a new secure Flight server
func NewSecureFlightServer(cfg *config.Config) (*SecureFlightServer, error) {
	server := &SecureFlightServer{
		cfg: cfg,
		healthStatus: &HealthStatus{
			status:        "starting",
			statusCode:    http.StatusServiceUnavailable,
			upstreamOK:    false,
			securityOK:    false,
			lastCheck:     time.Now(),
			startTime:     time.Now(),
			versionInfo:   "1.0.0", // Replace with actual version from build
			detailedState: make(map[string]interface{}),
		},
		// Initialize the circuit breaker with a threshold of 5 failures and a 30 second reset timeout
		circuitBreaker: NewCircuitBreaker(5, 30*time.Second),
		// Initialize the policy manager
		policyManager: NewPolicyManager("config/policies.json"),
	}

	// Load existing policies
	if err := server.policyManager.LoadPolicies(); err != nil {
		log.Warn().Err(err).Msg("Failed to load policies, continuing with defaults")
	}

	// Add policy manager info to health status
	server.healthStatus.detailedState["policy_manager"] = map[string]interface{}{
		"initialized": true,
		"config_path": "config/policies.json",
	}

	// Initialize trust scorer
	server.trustScorer = trust.NewTrustScorer(
		cfg.Security.MinTrustScore,
		cfg.Security.TrustScoreThreshold,
	)

	// Initialize registry
	server.registry = trust.NewRegistry(server.trustScorer)

	// Initialize HMAC verifier if enabled
	if cfg.Security.EnableHMAC {
		var err error
		server.hmacVerifier, err = crypto.NewHMACVerifier(
			cfg.Security.HMACAlgorithm,
			cfg.Security.HMACSecretPath,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize HMAC verifier: %w", err)
		}
		log.Info().Msg("HMAC verification enabled")
	} else {
		log.Info().Msg("HMAC verification disabled")
	}

	// Initialize attestation verifier if enabled
	if cfg.Security.EnableAttestations {
		var err error
		server.attestationVerifier, err = crypto.NewAttestationVerifier()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize attestation verifier: %w", err)
		}
		log.Info().Msg("Attestation verification enabled")
	} else {
		log.Info().Msg("Attestation verification disabled")
	}

	// Initialize Merkle verifier if enabled
	if cfg.Security.EnableMerkleVerify {
		var err error
		server.merkleVerifier, err = crypto.NewMerkleVerifier()
		if err != nil {
			return nil, fmt.Errorf("failed to initialize Merkle verifier: %w", err)
		}
		log.Info().Msg("Merkle verification enabled")
	} else {
		log.Info().Msg("Merkle verification disabled")
	}

	// Initialize security context for handlers
	server.securityContext = &SecurityContext{
		HMACVerifier:        server.hmacVerifier,
		AttestationVerifier: server.attestationVerifier,
		MerkleVerifier:      server.merkleVerifier,
		TrustScorer:         server.trustScorer,
		Registry:            server.registry,
	}

	// Security is OK if we've initialized all required components
	server.healthStatus.securityOK = true
	server.healthStatus.detailedState["security"] = map[string]interface{}{
		"hmac_enabled":        cfg.Security.EnableHMAC,
		"attestation_enabled": cfg.Security.EnableAttestations,
		"merkle_enabled":      cfg.Security.EnableMerkleVerify,
		"pq_enabled":          cfg.Security.EnablePQTLS,
		"min_trust_score":     cfg.Security.MinTrustScore,
		"trust_threshold":     cfg.Security.TrustScoreThreshold,
	}

	// Add circuit breaker info to health status
	server.healthStatus.detailedState["circuit_breaker"] = map[string]interface{}{
		"state":       "CLOSED",
		"threshold":   5,
		"reset_after": "30s",
	}

	// Create the upstream client
	if err := server.setupUpstreamClient(); err != nil {
		return nil, fmt.Errorf("failed to set up upstream client: %w", err)
	}

	server.initialized = true
	server.healthStatus.status = "initialized"
	server.healthStatus.statusCode = http.StatusOK
	return server, nil
}

// setupUpstreamClient sets up the Flight client to the upstream service
func (s *SecureFlightServer) setupUpstreamClient() error {
	clientCfg := s.cfg.Client
	var opts []grpc.DialOption

	// Validate configuration
	if clientCfg.UpstreamHost == "" {
		log.Info().Msg("No upstream host configured, skipping client setup")
		s.healthStatus.mu.Lock()
		s.healthStatus.upstreamOK = false
		s.healthStatus.detailedState["upstream"] = map[string]interface{}{
			"connected": false,
			"reason":    "No upstream host configured",
		}
		s.healthStatus.mu.Unlock()
		return nil
	}

	// Set up TLS if configured
	if clientCfg.TLSCertPath != "" && clientCfg.TLSKeyPath != "" {
		// Use PQ TLS configuration which will incorporate post-quantum algorithms if enabled
		tlsConfig, err := crypto.CreatePQClientTLSConfig(
			clientCfg.TLSCertPath,
			clientCfg.TLSKeyPath,
			clientCfg.TLSCACertPath,
			clientCfg.DisableTLSVerify,
			s.cfg.Security,
		)
		if err != nil {
			s.healthStatus.mu.Lock()
			s.healthStatus.upstreamOK = false
			s.healthStatus.detailedState["upstream"] = map[string]interface{}{
				"connected": false,
				"reason":    fmt.Sprintf("TLS config error: %v", err),
			}
			s.healthStatus.mu.Unlock()
			return fmt.Errorf("failed to create client TLS config: %w", err)
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
		log.Warn().Msg("Using insecure connection to upstream Flight service")
	}

	// Create the connection to the upstream Flight service
	upstreamAddr := fmt.Sprintf("%s:%d", clientCfg.UpstreamHost, clientCfg.UpstreamPort)

	// Create the Flight client with the circuit breaker pattern
	var flightClient flight.Client
	err := s.circuitBreaker.Execute(func() error {
		var err error
		// Use NewClientWithMiddleware instead of NewFlightClient
		flightClient, err = flight.NewClientWithMiddleware(
			upstreamAddr,
			nil, // auth handler
			nil, // middleware
			opts...,
		)
		return err
	})

	if err != nil {
		s.healthStatus.mu.Lock()
		s.healthStatus.upstreamOK = false
		s.healthStatus.status = "degraded"
		s.healthStatus.detailedState["upstream"] = map[string]interface{}{
			"connected": false,
			"reason":    fmt.Sprintf("Connection error: %v", err),
			"address":   upstreamAddr,
		}
		// Update circuit breaker info in health status
		s.healthStatus.detailedState["circuit_breaker"] = map[string]interface{}{
			"state":       fmt.Sprintf("%v", s.circuitBreaker.GetState()),
			"threshold":   5,
			"reset_after": "30s",
		}
		s.healthStatus.mu.Unlock()
		return fmt.Errorf("failed to create Flight client: %w", err)
	}

	// Set the upstream client
	s.upstreamClient = flightClient

	// Update health status
	s.healthStatus.mu.Lock()
	s.healthStatus.upstreamOK = true
	s.healthStatus.detailedState["upstream"] = map[string]interface{}{
		"connected": true,
		"address":   upstreamAddr,
		"tls":       clientCfg.TLSCertPath != "",
		"pq_tls":    s.cfg.Security.EnablePQTLS,
	}
	// Update circuit breaker info in health status
	s.healthStatus.detailedState["circuit_breaker"] = map[string]interface{}{
		"state":       fmt.Sprintf("%v", s.circuitBreaker.GetState()),
		"threshold":   5,
		"reset_after": "30s",
	}
	// If both upstream and security are OK, set status to healthy
	if s.healthStatus.upstreamOK && s.healthStatus.securityOK {
		s.healthStatus.status = "healthy"
		s.healthStatus.statusCode = http.StatusOK
	}
	s.healthStatus.mu.Unlock()

	log.Info().
		Str("upstream", upstreamAddr).
		Bool("pq_enabled", s.cfg.Security.EnablePQTLS).
		Msg("Connected to upstream Flight service")
	return nil
}

// Start starts the Flight server
func (s *SecureFlightServer) Start() error {
	if !s.initialized {
		return fmt.Errorf("server not initialized")
	}

	// Setup TLS if configured
	var grpcOpts []grpc.ServerOption
	if s.cfg.Server.TLSCertPath != "" && s.cfg.Server.TLSKeyPath != "" {
		log.Info().Msg("Setting up server TLS")
		tlsConfig, err := crypto.CreatePQServerTLSConfig(
			s.cfg.Server.TLSCertPath,
			s.cfg.Server.TLSKeyPath,
			s.cfg.Server.TLSCACertPath,
			s.cfg.Security,
		)
		if err != nil {
			return fmt.Errorf("failed to create server TLS config: %w", err)
		}
		grpcOpts = append(grpcOpts, grpc.Creds(credentials.NewTLS(tlsConfig)))
	} else {
		log.Warn().Msg("TLS not configured, using insecure connection")
		grpcOpts = append(grpcOpts, grpc.Creds(insecure.NewCredentials()))
	}

	// Create Flight service
	flightService := &FlightServiceImpl{
		BaseFlightServer: &flight.BaseFlightServer{},
		server:           s,
	}

	// Create gRPC server with Flight service
	s.grpcServer = grpc.NewServer(grpcOpts...)

	// Register the Flight service
	flight.RegisterFlightServiceServer(s.grpcServer, flightService)

	// Listen on configured address
	addr := fmt.Sprintf("%s:%d", s.cfg.Server.Host, s.cfg.Server.Port)
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	s.listener = lis

	// Start the health monitoring API
	if err := s.StartHealthEndpoint(); err != nil {
		log.Error().Err(err).Msg("Failed to start health endpoint")
	}

	// Start the admin API
	if err := s.StartAdminAPI(); err != nil {
		log.Error().Err(err).Msg("Failed to start admin API")
	}

	// Start the Flight server
	log.Info().Str("addr", addr).Msg("Starting Flight server")
	go func() {
		if err := s.grpcServer.Serve(lis); err != nil {
			log.Error().Err(err).Msg("Flight server stopped with error")
		}
	}()

	return nil
}

// Stop stops the Flight server
func (s *SecureFlightServer) Stop() {
	// Stop main gRPC server
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	// Stop health check server if running
	if s.healthServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.healthServer.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Error shutting down health server")
		}
	}

	// Stop admin API server if running
	if s.adminServer != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.adminServer.Shutdown(ctx); err != nil {
			log.Error().Err(err).Msg("Error shutting down admin server")
		}
	}

	log.Info().Msg("Secure Flight Gateway stopped")
}

// CreateServerTLSConfig creates a TLS configuration for the server
func CreateServerTLSConfig(certPath, keyPath, caPath string, enableMTLS bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	if enableMTLS && caPath != "" {
		// Load CA certificate for client authentication
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("failed to append CA certificate")
		}

		tlsConfig.ClientCAs = caCertPool
		tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		log.Info().Msg("mTLS enabled for server")
	}

	return tlsConfig, nil
}

// CreateClientTLSConfig creates a TLS configuration for the client
func CreateClientTLSConfig(certPath, keyPath, caPath string, skipVerify bool) (*tls.Config, error) {
	var certificates []tls.Certificate

	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
		}
		certificates = append(certificates, cert)
	}

	tlsConfig := &tls.Config{
		Certificates:       certificates,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: skipVerify,
	}

	if caPath != "" {
		// Load CA certificate for server verification
		caCert, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA certificate: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
			return nil, fmt.Errorf("failed to append CA certificate")
		}

		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// StartHealthEndpoint starts an HTTP server to serve health check requests
func (s *SecureFlightServer) StartHealthEndpoint() error {
	if s.healthServer != nil {
		return fmt.Errorf("health check endpoint already running")
	}

	// Create HTTP mux for health endpoint
	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.handleHealthCheck)
	mux.HandleFunc("/ready", s.handleReadyCheck)
	mux.HandleFunc("/metrics", s.handleMetrics)

	// Start the health check server in the background
	addr := s.cfg.Proxy.MetricsAddr
	if addr == "" {
		addr = ":9090" // default to port 9090
	}
	s.healthServer = &http.Server{Addr: addr, Handler: mux}
	go func() {
		log.Info().Str("addr", addr).Msg("Starting health check endpoint")
		if err := s.healthServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Health check server failed")
		}
	}()

	return nil
}

// handleHealthCheck returns a basic health check response
func (s *SecureFlightServer) handleHealthCheck(w http.ResponseWriter, r *http.Request) {
	s.healthStatus.mu.RLock()
	status := s.healthStatus.status
	statusCode := s.healthStatus.statusCode
	s.healthStatus.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := map[string]interface{}{
		"status":    status,
		"version":   s.healthStatus.versionInfo,
		"uptime":    time.Since(s.healthStatus.startTime).String(),
		"timestamp": time.Now().Format(time.RFC3339),
		"service":   "flight-gateway",
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Error().Err(err).Msg("Failed to encode health check response as JSON")
	}
}

// handleReadyCheck determines if the service is ready to accept requests
func (s *SecureFlightServer) handleReadyCheck(w http.ResponseWriter, r *http.Request) {
	s.healthStatus.mu.RLock()
	upstreamOK := s.healthStatus.upstreamOK
	securityOK := s.healthStatus.securityOK
	status := s.healthStatus.status
	statusCode := s.healthStatus.statusCode
	s.healthStatus.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	resp := map[string]interface{}{
		"status":      status,
		"ready":       status == "healthy",
		"upstream_ok": upstreamOK,
		"security_ok": securityOK,
		"timestamp":   time.Now().Format(time.RFC3339),
		"service":     "flight-gateway",
	}

	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Error().Err(err).Msg("Failed to encode ready check response as JSON")
	}
}

// handleMetrics provides a basic set of metrics about the server
func (s *SecureFlightServer) handleMetrics(w http.ResponseWriter, r *http.Request) {
	s.healthStatus.mu.RLock()
	detailedState := s.healthStatus.detailedState
	status := s.healthStatus.status
	s.healthStatus.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	metrics := map[string]interface{}{
		"status":     status,
		"uptime_sec": time.Since(s.healthStatus.startTime).Seconds(),
		"details":    detailedState,
		"timestamp":  time.Now().Format(time.RFC3339),
	}

	if err := json.NewEncoder(w).Encode(metrics); err != nil {
		log.Error().Err(err).Msg("Failed to encode metrics as JSON")
	}
}

// executeWithCircuitBreaker runs the given function with circuit breaker protection
func (s *SecureFlightServer) executeWithCircuitBreaker(action func() error) error {
	return s.circuitBreaker.Execute(action)
}

// getUpstreamInfo executes GetFlightInfo on the upstream client with circuit breaker protection
func (s *SecureFlightServer) getUpstreamInfo(ctx context.Context, desc *flight.FlightDescriptor) (*flight.FlightInfo, error) {
	var info *flight.FlightInfo
	var err error

	err = s.executeWithCircuitBreaker(func() error {
		info, err = s.upstreamClient.GetFlightInfo(ctx, desc)
		return err
	})

	return info, err
}

// getUpstreamSchema executes GetSchema on the upstream client with circuit breaker protection
func (s *SecureFlightServer) getUpstreamSchema(ctx context.Context, desc *flight.FlightDescriptor) (*flight.SchemaResult, error) {
	var schema *flight.SchemaResult
	var err error

	err = s.executeWithCircuitBreaker(func() error {
		schema, err = s.upstreamClient.GetSchema(ctx, desc)
		return err
	})

	return schema, err
}

// doUpstreamGet executes DoGet on the upstream client with circuit breaker protection
func (s *SecureFlightServer) doUpstreamGet(ctx context.Context, ticket *flight.Ticket) (flight.FlightService_DoGetClient, error) {
	var reader flight.FlightService_DoGetClient
	var err error

	err = s.executeWithCircuitBreaker(func() error {
		reader, err = s.upstreamClient.DoGet(ctx, ticket)
		return err
	})

	return reader, err
}

// doUpstreamPut executes DoPut on the upstream client with circuit breaker protection
func (s *SecureFlightServer) doUpstreamPut(ctx context.Context) (flight.FlightService_DoPutClient, error) {
	var writer flight.FlightService_DoPutClient
	var err error

	err = s.executeWithCircuitBreaker(func() error {
		writer, err = s.upstreamClient.DoPut(ctx)
		return err
	})

	return writer, err
}
