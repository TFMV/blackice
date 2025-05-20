package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/apache/arrow-go/v18/arrow/memory"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"

	"github.com/TFMV/blackice/pkg/flightgw/server"
)

var (
	addr           = flag.String("addr", "localhost:8991", "Address for the Flight Data Server to listen on")
	hmacSecretPath = flag.String("hmac-secret", "", "Path to HMAC secret file (enables HMAC verification if set)")
	tlsCertPath    = flag.String("tls-cert", "", "Path to TLS certificate file (enables TLS if set)")
	tlsKeyPath     = flag.String("tls-key", "", "Path to TLS key file (required if tls-cert is set)")
	maxMemoryMB    = flag.Int("max-memory", 1024, "Maximum memory usage in MB")
	batchTTL       = flag.Duration("batch-ttl", 1*time.Hour, "Time-to-live for stored batches")
	gcInterval     = flag.Duration("gc-interval", 5*time.Minute, "Interval for garbage collection runs")
	verbose        = flag.Bool("v", false, "Enable verbose logging")
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

	// Check TLS configuration
	if (*tlsCertPath != "" && *tlsKeyPath == "") || (*tlsCertPath == "" && *tlsKeyPath != "") {
		log.Fatal().Msg("Both --tls-cert and --tls-key must be provided to enable TLS")
	}

	// Create server configuration
	config := server.FlightDataServerConfig{
		Addr:           *addr,
		Allocator:      memory.NewGoAllocator(),
		TTL:            *batchTTL,
		MaxMemoryBytes: int64(*maxMemoryMB) * 1024 * 1024,
		EnableGC:       true,
		GCInterval:     *gcInterval,
	}

	// Configure HMAC if enabled
	if *hmacSecretPath != "" {
		config.EnableHMAC = true
		config.HMACSecretPath = *hmacSecretPath
	}

	// Configure circuit breaker
	config.CircuitBreakerConfig = map[string]interface{}{
		"failure_threshold": 5,
		"reset_timeout":     30 * time.Second,
	}

	// Create the server
	flightServer, err := server.NewFlightDataServer(config)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create Flight Data Server")
	}

	// Start the server
	if err := flightServer.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start Flight Data Server")
	}

	log.Info().Str("addr", *addr).Msg("Flight Data Server started successfully")

	// Wait for termination signal
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM)

	// Wait for OS signal
	sig := <-signalCh
	log.Info().Str("signal", sig.String()).Msg("Received termination signal")

	// Clean shutdown
	log.Info().Msg("Stopping Flight Data Server...")
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
		log.Info().Msg("Flight Data Server stopped gracefully")
	}
}
