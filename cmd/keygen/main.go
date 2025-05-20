package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/TFMV/blackice/pkg/flightgw/crypto"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

func main() {
	// Parse command line arguments
	algorithm := flag.String("algorithm", "HYBRID-DILITHIUM-ED25519", "Algorithm to use for key generation")
	outputDir := flag.String("output-dir", "keys", "Directory where keys will be saved")
	privateKeyFile := flag.String("private-key", "private_key.pem", "Name of the private key file")
	publicKeyFile := flag.String("public-key", "public_key.pem", "Name of the public key file")
	force := flag.Bool("force", false, "Overwrite existing files")
	verbose := flag.Bool("verbose", false, "Enable verbose logging")
	listAlgorithms := flag.Bool("list", false, "List available algorithms")

	flag.Parse()

	// Set up logging
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	if *verbose {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	// List available algorithms
	if *listAlgorithms {
		printAvailableAlgorithms()
		return
	}

	// Create options for key generation
	opts := crypto.GenerateKeysOptions{
		Algorithm:      crypto.Algorithm(*algorithm),
		OutputDir:      *outputDir,
		PrivateKeyFile: *privateKeyFile,
		PublicKeyFile:  *publicKeyFile,
		ForceOverwrite: *force,
		RandomSource:   nil, // Use default
	}

	// Generate keys
	log.Info().
		Str("algorithm", string(opts.Algorithm)).
		Str("output_dir", opts.OutputDir).
		Msg("Generating post-quantum keys...")

	if err := crypto.GenerateKeys(opts); err != nil {
		log.Fatal().Err(err).Msg("Failed to generate keys")
	}

	log.Info().
		Str("private_key", fmt.Sprintf("%s/%s", opts.OutputDir, opts.PrivateKeyFile)).
		Str("public_key", fmt.Sprintf("%s/%s", opts.OutputDir, opts.PublicKeyFile)).
		Msg("Keys generated successfully")
}

// printAvailableAlgorithms prints the available algorithms
func printAvailableAlgorithms() {
	// Create providers
	classicProvider := crypto.NewClassicProvider()
	pqProvider := crypto.NewPQProvider()
	hybridProvider := crypto.NewHybridProvider()

	// Get algorithms for each provider
	var allAlgorithms []string

	// Classical signature algorithms
	for _, alg := range classicProvider.GetSupportedAlgorithms(crypto.AlgorithmTypeSignature) {
		allAlgorithms = append(allAlgorithms, fmt.Sprintf("%s (Classic Signature)", alg))
	}

	// Post-quantum signature algorithms
	for _, alg := range pqProvider.GetSupportedAlgorithms(crypto.AlgorithmTypeSignature) {
		allAlgorithms = append(allAlgorithms, fmt.Sprintf("%s (Post-Quantum Signature)", alg))
	}

	// Hybrid signature algorithms
	for _, alg := range hybridProvider.GetSupportedAlgorithms(crypto.AlgorithmTypeSignature) {
		allAlgorithms = append(allAlgorithms, fmt.Sprintf("%s (Hybrid Signature)", alg))
	}

	// Classical KEM algorithms
	for _, alg := range classicProvider.GetSupportedAlgorithms(crypto.AlgorithmTypeKEM) {
		allAlgorithms = append(allAlgorithms, fmt.Sprintf("%s (Classic KEM)", alg))
	}

	// Post-quantum KEM algorithms
	for _, alg := range pqProvider.GetSupportedAlgorithms(crypto.AlgorithmTypeKEM) {
		allAlgorithms = append(allAlgorithms, fmt.Sprintf("%s (Post-Quantum KEM)", alg))
	}

	// Hybrid KEM algorithms
	for _, alg := range hybridProvider.GetSupportedAlgorithms(crypto.AlgorithmTypeKEM) {
		allAlgorithms = append(allAlgorithms, fmt.Sprintf("%s (Hybrid KEM)", alg))
	}

	fmt.Println("Available algorithms:")
	fmt.Println(strings.Join(allAlgorithms, "\n"))
	fmt.Println("\nUse the algorithm name (e.g., DILITHIUM3) as the -algorithm parameter.")
}
