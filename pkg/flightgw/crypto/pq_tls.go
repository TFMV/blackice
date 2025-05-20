package crypto

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

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

	// Enable session resumption with both session tickets and session IDs
	// This allows clients to reconnect quickly without performing full handshakes
	config.SessionTicketsDisabled = false

	// Set session cache
	// For production, consider using a distributed cache if running multiple instances
	config.ClientSessionCache = tls.NewLRUClientSessionCache(1000)

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

// CreatePQServerTLSConfig creates a TLS server configuration with post-quantum cryptography support
func CreatePQServerTLSConfig(certPath, keyPath, clientCAPath string, securityConfig config.SecurityConfig) (*tls.Config, error) {
	// Create a base TLS config
	baseTLSConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ClientAuth: tls.RequireAndVerifyClientCert,
		// Enable session tickets for session resumption
		SessionTicketsDisabled: false,
		// Set a reasonable session cache size
		ClientSessionCache: tls.NewLRUClientSessionCache(100),
	}

	// Load the server certificate and key
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load server certificate and key: %w", err)
	}
	baseTLSConfig.Certificates = []tls.Certificate{cert}

	// Load client CA certificates if provided
	if clientCAPath != "" {
		clientCAPool, err := loadCACert(clientCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load client CA certificate: %w", err)
		}
		baseTLSConfig.ClientCAs = clientCAPool
	}

	// If PQ TLS is enabled, use PQ config
	if securityConfig.EnablePQTLS {
		return CreatePQTLSConfig(baseTLSConfig, securityConfig)
	}

	log.Info().Msg("Using standard TLS configuration")
	return baseTLSConfig, nil
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

// loadCACert loads and parses a CA certificate from the given path
func loadCACert(path string) (*x509.CertPool, error) {
	caCert, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if ok := caCertPool.AppendCertsFromPEM(caCert); !ok {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}

	return caCertPool, nil
}
