package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/TFMV/blackice/pkg/controlplane/config"
	"github.com/TFMV/blackice/pkg/controlplane/server"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", "", "Path to configuration file")
	genConfig := flag.Bool("generate-config", false, "Generate default configuration file")
	outputPath := flag.String("output", "controlplane_config.json", "Output path for generated config")
	flag.Parse()

	// Generate default config if requested
	if *genConfig {
		cfg := config.DefaultConfig()
		err := config.SaveConfigToFile(cfg, *outputPath)
		if err != nil {
			fmt.Printf("Failed to generate config file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Generated default configuration at %s\n", *outputPath)
		return
	}

	// Load config
	var cfg *config.ControlPlaneConfig
	var err error

	if *configPath != "" {
		// Load from specified path
		cfg, err = config.LoadConfig(*configPath)
		if err != nil {
			fmt.Printf("Failed to load config from %s: %v\n", *configPath, err)
			os.Exit(1)
		}
	} else {
		// Use default config
		cfg = config.DefaultConfig()
		fmt.Println("Using default configuration (no config file specified)")
	}

	// Create and start server
	srv, err := server.NewServer(cfg)
	if err != nil {
		fmt.Printf("Failed to create server: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("Starting BlackIce Control Plane...")
	if err := srv.Start(); err != nil {
		fmt.Printf("Server error: %v\n", err)
		os.Exit(1)
	}
}
