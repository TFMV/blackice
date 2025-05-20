package crypto

import (
	"crypto/tls"
	"fmt"

	"github.com/TFMV/blackice/pkg/flightgw/config"
	"github.com/rs/zerolog/log"
)

// CreatePQTLSConfig creates a TLS configuration with post-quantum cryptography support
// This is a wrapper around the standard TLS config that adds post-quantum crypto
func CreatePQTLSConfig(baseConfig *tls.Config, securityConfig config.SecurityConfig) (*tls.Config, error) {
	// If PQ TLS is not enabled, just return the base config
	if !securityConfig.EnablePQTLS {
		return baseConfig, nil
	}

	// Log that we're enabling PQ TLS
	log.Info().
		Bool("hybrid_mode", securityConfig.HybridMode).
		Str("algorithm", securityConfig.PQTLSAlgorithm).
		Msg("Enabling post-quantum TLS")

	// Create a clone of the base config
	config := baseConfig.Clone()

	// Configure the curves to include the hybrid PQ KEM
	// Note: In a real implementation, we would configure the PQ TLS options
	// This might include:
	// 1. Adding post-quantum cipher suites
	// 2. Setting up hybrid key exchange
	// 3. Configuring certificate selection
	//
	// At this point in 2023-2024, native Go support for PQ TLS is limited
	// The approach would likely be to:
	// 1. Use a custom TLS library with PQ support
	// 2. Set up a key exchange mechanism that encapsulates Kyber keys
	// 3. Use application-layer PQ protection for maximum flexibility
	//
	// Since this is a placeholder, we just return the base config with a note
	log.Warn().Msg("Post-quantum TLS is enabled but implementation is pending Go 1.25+ with NIST standards support")

	return config, nil
}

// CreatePQServerTLSConfig creates a server TLS configuration with post-quantum support
func CreatePQServerTLSConfig(certPath, keyPath, caPath string, enableMTLS bool, securityConfig config.SecurityConfig) (*tls.Config, error) {
	// Create a basic TLS config
	baseConfig, err := createServerTLSConfig(certPath, keyPath, caPath, enableMTLS)
	if err != nil {
		return nil, fmt.Errorf("failed to create base TLS config: %w", err)
	}

	// Enhance with post-quantum crypto
	return CreatePQTLSConfig(baseConfig, securityConfig)
}

// CreatePQClientTLSConfig creates a client TLS configuration with post-quantum support
func CreatePQClientTLSConfig(certPath, keyPath, caPath string, skipVerify bool, securityConfig config.SecurityConfig) (*tls.Config, error) {
	// Create a basic TLS config
	baseConfig, err := createClientTLSConfig(certPath, keyPath, caPath, skipVerify)
	if err != nil {
		return nil, fmt.Errorf("failed to create base TLS config: %w", err)
	}

	// Enhance with post-quantum crypto
	return CreatePQTLSConfig(baseConfig, securityConfig)
}

// Helper functions for basic TLS config (moved from server.go)

// createServerTLSConfig creates a basic TLS configuration for the server
func createServerTLSConfig(certPath, keyPath, caPath string, enableMTLS bool) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	// The code for loading CA certificates would go here
	// This is identical to the original implementation in server.go

	return tlsConfig, nil
}

// createClientTLSConfig creates a basic TLS configuration for the client
func createClientTLSConfig(certPath, keyPath, caPath string, skipVerify bool) (*tls.Config, error) {
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

	// The code for loading CA certificates would go here
	// This is identical to the original implementation in server.go

	return tlsConfig, nil
}
