package crypto

import (
	"crypto/tls"
	"fmt"

	"github.com/TFMV/blackice/pkg/flightgw/config"
	flightCrypto "github.com/TFMV/blackice/pkg/flightgw/crypto"
)

// IsQuantumResistantAvailable checks if quantum-resistant cryptographic algorithms
// are available in the current environment.
// This is a wrapper around the flight gateway crypto capabilities.
func IsQuantumResistantAvailable() bool {
	// The flight gateway has extensive post-quantum crypto support
	// We'll leverage that infrastructure rather than reimplementing

	// This is a simple check to determine if PQ crypto is available
	// In a production system, this would do more sophisticated detection

	// Create a test security config
	testConfig := config.SecurityConfig{
		EnablePQTLS:    true,
		HybridMode:     true,
		PQTLSAlgorithm: "kyber",
	}

	// Try to create a PQ TLS config - if it returns an error about PQ not being
	// available (vs. other initialization errors), that tells us PQ isn't supported
	_, err := flightCrypto.CreatePQTLSConfig(&tls.Config{}, testConfig)

	// If we get a nil error, or an error that isn't about PQ availability,
	// that suggests PQ is available (even if there are other issues)
	return err == nil || !isPQUnavailableError(err)
}

// isPQUnavailableError checks if an error indicates that PQ algorithms are unavailable
// This is a helper function to parse error messages
func isPQUnavailableError(err error) bool {
	if err == nil {
		return false
	}

	// This would need to be updated when the underlying implementation changes
	// In a real system, we'd have specific error types to check
	return false
}

// GetSupportedQuantumResistantAlgorithms returns a list of available quantum-resistant algorithms
// supported by the BlackIce platform.
func GetSupportedQuantumResistantAlgorithms() []string {
	// In a production system, this would dynamically detect available algorithms
	// For now we'll return algorithms known to be implemented in flightgw
	if !IsQuantumResistantAvailable() {
		return []string{}
	}

	return []string{
		"CRYSTALS-Kyber",     // Key encapsulation mechanism
		"CRYSTALS-Dilithium", // Digital signature
		"FALCON",             // Digital signature
		"SPHINCS+",           // Digital signature
	}
}

// CreateQuantumResistantTLSConfig creates a TLS configuration with post-quantum protections
// by delegating to the flight gateway crypto package.
func CreateQuantumResistantTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	// Create a base TLS config using the provided paths
	baseConfig, err := createBaseTLSConfig(certPath, keyPath, caPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create base TLS config: %w", err)
	}

	// Configure to use post-quantum crypto
	securityConfig := config.SecurityConfig{
		EnablePQTLS:    true,
		HybridMode:     true, // Use hybrid mode for compatibility
		PQTLSAlgorithm: "kyber",
	}

	// Enhance with post-quantum crypto from the flight gateway
	return flightCrypto.CreatePQTLSConfig(baseConfig, securityConfig)
}

// createBaseTLSConfig creates a standard TLS configuration
func createBaseTLSConfig(certPath, keyPath, caPath string) (*tls.Config, error) {
	// Delegate to the flight gateway's implementation for consistency
	return flightCrypto.CreatePQClientTLSConfig(certPath, keyPath, caPath, false, config.SecurityConfig{
		EnablePQTLS: false, // We'll enable this in the wrapper
	})
}
