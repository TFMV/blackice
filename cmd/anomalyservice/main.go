// main is the entry point for the anomaly detection service
package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/TFMV/blackice/pkg/flightgw/anomaly"
	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

var (
	port               = flag.Int("port", 8089, "The server port")
	logLevel           = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	enableStdDetectors = flag.Bool("enable-std-detectors", true, "Enable standard anomaly detectors")
)

func main() {
	flag.Parse()

	// Configure logging
	setupLogging()
	log.Info().Msg("Starting BlackIce Anomaly Detection Service")

	// Create a listener on the specified port
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatal().Err(err).Int("port", *port).Msg("Failed to listen")
	}

	// Create a gRPC server
	server := grpc.NewServer()

	// Create and register the anomaly service
	service := anomaly.NewService()
	blackicev1.RegisterAnomalyServiceServer(server, service)

	// Enable reflection for debugging
	reflection.Register(server)

	// Register standard detectors if enabled
	if *enableStdDetectors {
		if err := anomaly.RegisterStandardDetectors(service); err != nil {
			log.Error().Err(err).Msg("Failed to register standard detectors")
		} else {
			log.Info().Msg("Standard detectors registered successfully")
		}
	}

	// Start the server in a goroutine
	go func() {
		log.Info().Int("port", *port).Msg("Anomaly detection service is listening")
		if err := server.Serve(lis); err != nil {
			log.Fatal().Err(err).Msg("Failed to serve")
		}
	}()

	// Wait for interrupt signal to gracefully shut down the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Info().Msg("Shutting down anomaly detection service")
	server.GracefulStop()
	log.Info().Msg("Anomaly detection service stopped")
}

// setupLogging configures the logger
func setupLogging() {
	// Parse log level
	level, err := zerolog.ParseLevel(*logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Configure logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Log configuration
	log.Info().
		Str("log_level", level.String()).
		Bool("std_detectors", *enableStdDetectors).
		Msg("Logger configured")
}
