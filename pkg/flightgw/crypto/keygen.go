package crypto

import (
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// GenerateKeysOptions contains options for generating keys
type GenerateKeysOptions struct {
	Algorithm      Algorithm // The algorithm to use
	OutputDir      string    // Directory where keys will be saved
	PrivateKeyFile string    // Name of the private key file
	PublicKeyFile  string    // Name of the public key file
	ForceOverwrite bool      // Whether to overwrite existing files
	RandomSource   io.Reader // Source of randomness
}

// The default options for key generation
var DefaultGenerateKeysOptions = GenerateKeysOptions{
	Algorithm:      Algorithm(AlgorithmHybridDilithiumED25519),
	OutputDir:      "keys",
	PrivateKeyFile: "private_key.pem",
	PublicKeyFile:  "public_key.pem",
	ForceOverwrite: false,
	RandomSource:   nil, // Use crypto/rand by default
}

// GenerateKeys generates a key pair and saves it to files
func GenerateKeys(options GenerateKeysOptions) error {
	// Ensure the output directory exists
	if err := os.MkdirAll(options.OutputDir, 0700); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Check if files already exist
	privateKeyPath := filepath.Join(options.OutputDir, options.PrivateKeyFile)
	publicKeyPath := filepath.Join(options.OutputDir, options.PublicKeyFile)

	if !options.ForceOverwrite {
		if _, err := os.Stat(privateKeyPath); err == nil {
			return fmt.Errorf("private key file already exists: %s", privateKeyPath)
		}
		if _, err := os.Stat(publicKeyPath); err == nil {
			return fmt.Errorf("public key file already exists: %s", publicKeyPath)
		}
	}

	// Determine the provider to use
	var provider CryptoProvider
	var err error

	// For hybrid algorithms, use the hybrid provider
	if options.Algorithm == Algorithm(AlgorithmHybridDilithiumED25519) ||
		options.Algorithm == Algorithm(AlgorithmHybridKyberECDH) {
		provider = NewHybridProvider()
	} else if options.Algorithm == Algorithm(AlgorithmDilithium3) ||
		options.Algorithm == Algorithm(AlgorithmKyber768) {
		provider = NewPQProvider()
	} else {
		provider = NewClassicProvider()
	}

	// Generate the key pair
	privateKeyBytes, publicKeyBytes, err := provider.GenerateKeyPair(options.Algorithm, options.RandomSource)
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Encode the private key as PEM if it's not already
	var privateKeyPEM []byte
	if len(privateKeyBytes) > 0 && privateKeyBytes[0] != '-' { // Check if it's not already PEM
		pemBlock := &pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		}
		privateKeyPEM = pem.EncodeToMemory(pemBlock)
	} else {
		privateKeyPEM = privateKeyBytes
	}

	// Encode the public key as PEM if it's not already
	var publicKeyPEM []byte
	if len(publicKeyBytes) > 0 && publicKeyBytes[0] != '-' { // Check if it's not already PEM
		pemBlock := &pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		}
		publicKeyPEM = pem.EncodeToMemory(pemBlock)
	} else {
		publicKeyPEM = publicKeyBytes
	}

	// Save the private key to a file
	if err := os.WriteFile(privateKeyPath, privateKeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Save the public key to a file
	if err := os.WriteFile(publicKeyPath, publicKeyPEM, 0644); err != nil {
		return fmt.Errorf("failed to write public key: %w", err)
	}

	return nil
}
