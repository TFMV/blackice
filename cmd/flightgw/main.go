package main

import (
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/rs/zerolog/log"

	"github.com/TFMV/blackice/pkg/flightgw/config"
	"github.com/TFMV/blackice/pkg/flightgw/server"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "", "Path to config file")
	flag.Parse()

	// Load configuration
	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to load configuration")
	}

	// Set up logging using the config package
	if err := config.SetupLogging(&cfg.Logging); err != nil {
		log.Fatal().Err(err).Msg("Failed to set up logging")
	}

	// Create and start the secure Flight server
	secureServer, err := server.NewSecureFlightServer(cfg)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create secure Flight server")
	}

	if err := secureServer.Start(); err != nil {
		log.Fatal().Err(err).Msg("Failed to start secure Flight server")
	}

	log.Info().Msg("Secure Flight Gateway started successfully")

	// Wait for shutdown signal
	shutdown := make(chan os.Signal, 1)
	signal.Notify(shutdown, syscall.SIGINT, syscall.SIGTERM)
	<-shutdown

	log.Info().Msg("Shutdown signal received, stopping server...")
	secureServer.Stop()
	log.Info().Msg("Server stopped, goodbye!")
}
