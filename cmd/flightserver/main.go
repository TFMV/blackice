package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/TFMV/blackice/pkg/flightgw/config"
	"github.com/TFMV/blackice/pkg/flightgw/integration"
	"github.com/TFMV/blackice/pkg/flightgw/server"
)

var (
	// Server configuration flags
	mode          = flag.String("mode", "integrated", "Server mode: gateway, datastore, integrated")
	gatewayAddr   = flag.String("gateway-addr", "localhost:8089", "Gateway server address")
	datastoreAddr = flag.String("datastore-addr", "localhost:8090", "Data store server address")

	// Security flags
	enableTLS      = flag.Bool("tls", false, "Enable TLS")
	tlsCertPath    = flag.String("tls-cert", "", "Path to TLS certificate file")
	tlsKeyPath     = flag.String("tls-key", "", "Path to TLS key file")
	enableHMAC     = flag.Bool("hmac", false, "Enable HMAC verification")
	hmacSecretPath = flag.String("hmac-secret", "", "Path to HMAC secret file")

	// Performance and operational flags
	maxMemoryMB = flag.Int("max-memory", 1024, "Maximum memory usage in MB")
	cacheTTL    = flag.Duration("cache-ttl", 10*time.Minute, "Cache TTL duration")
	enableCache = flag.Bool("cache", true, "Enable local caching")
	verbose     = flag.Bool("v", false, "Enable verbose logging")
)

func main() {
	// Parse command line flags
	flag.Parse()

	// Configure logging
	if *verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339})

	// Display startup banner
	fmt.Printf(`
░█▀▀█ █── █▀▀█ █▀▀ █─█ ▀█▀ █▀▀ █▀▀ 
░█▀▀▄ █── █▄▄█ █── █▀▄ ─█─ █── █▀▀ 
░█▄▄█ ▀▀▀ ▀──▀ ▀▀▀ ▀─▀ ▄█▄ ▀▀▀ ▀▀▀
Flight Gateway & Data Store
--------------------------
`)

	var flightServer interface {
		Start() error
		Stop()
	}

	// Create appropriate server based on mode
	switch *mode {
	case "gateway":
		log.Info().Str("addr", *gatewayAddr).Msg("Starting in Gateway mode")
		gatewayServer, err := createGatewayServer()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create gateway server")
		}
		flightServer = gatewayServer

	case "datastore":
		log.Info().Str("addr", *datastoreAddr).Msg("Starting in DataStore mode")
		dataStoreServer, err := createDataStoreServer()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create data store server")
		}
		flightServer = dataStoreServer

	case "integrated":
		log.Info().
			Str("gateway", *gatewayAddr).
			Str("datastore", *datastoreAddr).
			Msg("Starting in Integrated mode")
		integratedServer, err := createIntegratedServer()
		if err != nil {
			log.Fatal().Err(err).Msg("Failed to create integrated server")
		}
		flightServer = integratedServer

	default:
		log.Fatal().Str("mode", *mode).Msg("Unknown server mode")
	}

	// Start the server
	if err := flightServer.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}

	// Wait for termination signal
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for OS signal
	sig := <-signalCh
	log.Info().Str("signal", sig.String()).Msg("Received termination signal")

	// Clean shutdown
	log.Info().Msg("Stopping server...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Signal shutdown
	go func() {
		flightServer.Stop()
		cancel()
	}()

	// Wait for shutdown to complete or timeout
	<-ctx.Done()
	if ctx.Err() == context.DeadlineExceeded {
		log.Warn().Msg("Shutdown timed out")
	} else {
		log.Info().Msg("Server stopped gracefully")
	}
}

// createGatewayServer creates a standalone gateway server
func createGatewayServer() (*server.SecureFlightServer, error) {
	// Load or create configuration
	cfg := &config.Config{}

	// Set gateway address
	cfg.Server.Host = "0.0.0.0"
	cfg.Server.Port = getPortFromAddr(*gatewayAddr)

	// Configure TLS if enabled
	if *enableTLS {
		cfg.Server.TLSCertPath = *tlsCertPath
		cfg.Server.TLSKeyPath = *tlsKeyPath
	}

	// Configure HMAC if enabled
	if *enableHMAC {
		cfg.Security.EnableHMAC = true
		cfg.Security.HMACSecretPath = *hmacSecretPath
	}

	// Create the gateway server
	return server.NewSecureFlightServer(cfg)
}

// createDataStoreServer creates a standalone data store server
func createDataStoreServer() (*server.FlightDataServer, error) {
	// Create data store configuration
	config := server.FlightDataServerConfig{
		Addr:           *datastoreAddr,
		Allocator:      memory.NewGoAllocator(),
		TTL:            *cacheTTL,
		MaxMemoryBytes: int64(*maxMemoryMB) * 1024 * 1024,
		EnableGC:       true,
		GCInterval:     5 * time.Minute,
	}

	// Configure HMAC if enabled
	if *enableHMAC {
		config.EnableHMAC = true
		config.HMACSecretPath = *hmacSecretPath
	}

	// Configure circuit breaker
	config.CircuitBreakerConfig = map[string]interface{}{
		"failure_threshold": 5,
		"reset_timeout":     30 * time.Second,
	}

	// Create the data store server
	return server.NewFlightDataServer(config)
}

// createIntegratedServer creates an integrated server with both gateway and data store
func createIntegratedServer() (*integration.IntegratedFlightServer, error) {
	// Load or create gateway configuration
	gatewayCfg := &config.Config{}

	// Set gateway address
	gatewayCfg.Server.Host = "0.0.0.0"
	gatewayCfg.Server.Port = getPortFromAddr(*gatewayAddr)

	// Configure TLS if enabled
	if *enableTLS {
		gatewayCfg.Server.TLSCertPath = *tlsCertPath
		gatewayCfg.Server.TLSKeyPath = *tlsKeyPath
	}

	// Configure HMAC if enabled
	if *enableHMAC {
		gatewayCfg.Security.EnableHMAC = true
		gatewayCfg.Security.HMACSecretPath = *hmacSecretPath
	}

	// Create data store configuration
	dataStoreCfg := server.FlightDataServerConfig{
		Addr:           *datastoreAddr,
		Allocator:      memory.NewGoAllocator(),
		TTL:            *cacheTTL,
		MaxMemoryBytes: int64(*maxMemoryMB) * 1024 * 1024,
		EnableGC:       true,
		GCInterval:     5 * time.Minute,
	}

	// Configure HMAC if enabled
	if *enableHMAC {
		dataStoreCfg.EnableHMAC = true
		dataStoreCfg.HMACSecretPath = *hmacSecretPath
	}

	// Configure circuit breaker
	dataStoreCfg.CircuitBreakerConfig = map[string]interface{}{
		"failure_threshold": 5,
		"reset_timeout":     30 * time.Second,
	}

	// Create integrated server configuration
	config := &integration.IntegratedServerConfig{
		GatewayConfig:           gatewayCfg,
		DataStoreConfig:         dataStoreCfg,
		EnableLocalCache:        *enableCache,
		CacheTTL:                *cacheTTL,
		RegistryRefreshInterval: 30 * time.Second,
		CachePatterns:           []string{"telemetry.", "metrics.", "events."},
	}

	// Create the integrated server
	return integration.NewIntegratedFlightServer(config)
}

// getPortFromAddr extracts the port number from an address string
func getPortFromAddr(addr string) int {
	var host string
	var port int

	_, err := fmt.Sscanf(addr, "%s:%d", &host, &port)
	if err != nil {
		// Default port if parsing fails
		return 8080
	}

	return port
}
