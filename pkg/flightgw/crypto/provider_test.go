package crypto

import (
	"testing"
)

func TestProviderRegistry(t *testing.T) {
	// Create a registry
	registry := NewProviderRegistry()

	// Register providers
	classicProvider := NewClassicProvider()
	pqProvider := NewPQProvider()
	hybridProvider := NewHybridProvider()

	registry.RegisterProvider(classicProvider)
	registry.RegisterProvider(pqProvider)
	registry.RegisterProvider(hybridProvider)

	// Verify registration
	provider, err := registry.GetProvider("classic")
	if err != nil {
		t.Fatalf("Failed to get classic provider: %v", err)
	}
	if provider.GetName() != "classic" {
		t.Fatalf("Unexpected provider name: %s", provider.GetName())
	}

	provider, err = registry.GetProvider("post-quantum")
	if err != nil {
		t.Fatalf("Failed to get post-quantum provider: %v", err)
	}
	if provider.GetName() != "post-quantum" {
		t.Fatalf("Unexpected provider name: %s", provider.GetName())
	}

	provider, err = registry.GetProvider("hybrid")
	if err != nil {
		t.Fatalf("Failed to get hybrid provider: %v", err)
	}
	if provider.GetName() != "hybrid" {
		t.Fatalf("Unexpected provider name: %s", provider.GetName())
	}

	// Test default provider
	defaultProvider, err := registry.GetDefaultProvider()
	if err != nil {
		t.Fatalf("Failed to get default provider: %v", err)
	}
	if defaultProvider.GetName() != "classic" {
		t.Fatalf("Unexpected default provider name: %s", defaultProvider.GetName())
	}

	// Test setting default provider
	err = registry.SetDefaultProvider("hybrid")
	if err != nil {
		t.Fatalf("Failed to set default provider: %v", err)
	}

	defaultProvider, err = registry.GetDefaultProvider()
	if err != nil {
		t.Fatalf("Failed to get default provider after change: %v", err)
	}
	if defaultProvider.GetName() != "hybrid" {
		t.Fatalf("Default provider was not changed. Expected 'hybrid', got '%s'", defaultProvider.GetName())
	}

	// Test error cases
	_, err = registry.GetProvider("non-existent")
	if err != ErrProviderNotFound {
		t.Fatalf("Expected ErrProviderNotFound, got: %v", err)
	}

	err = registry.SetDefaultProvider("non-existent")
	if err != ErrProviderNotFound {
		t.Fatalf("Expected ErrProviderNotFound, got: %v", err)
	}
}

func TestGetSupportedAlgorithms(t *testing.T) {
	// Test classic provider
	classicProvider := NewClassicProvider()
	sigAlgos := classicProvider.GetSupportedAlgorithms(AlgorithmTypeSignature)
	if len(sigAlgos) != 4 {
		t.Fatalf("Expected 4 signature algorithms from classic provider, got %d", len(sigAlgos))
	}

	// Test post-quantum provider
	pqProvider := NewPQProvider()
	pqSigAlgos := pqProvider.GetSupportedAlgorithms(AlgorithmTypeSignature)
	if len(pqSigAlgos) != 1 || pqSigAlgos[0] != Algorithm(AlgorithmDilithium3) {
		t.Fatalf("Expected 1 signature algorithm (Dilithium3) from PQ provider, got %v", pqSigAlgos)
	}

	pqKemAlgos := pqProvider.GetSupportedAlgorithms(AlgorithmTypeKEM)
	if len(pqKemAlgos) != 1 || pqKemAlgos[0] != Algorithm(AlgorithmKyber768) {
		t.Fatalf("Expected 1 KEM algorithm (Kyber768) from PQ provider, got %v", pqKemAlgos)
	}

	// Test hybrid provider
	hybridProvider := NewHybridProvider()
	hybridSigAlgos := hybridProvider.GetSupportedAlgorithms(AlgorithmTypeSignature)
	if len(hybridSigAlgos) != 1 || hybridSigAlgos[0] != Algorithm(AlgorithmHybridDilithiumED25519) {
		t.Fatalf("Expected 1 signature algorithm (HybridDilithiumED25519) from hybrid provider, got %v", hybridSigAlgos)
	}

	// Test with unsupported algorithm type
	unsupportedAlgos := classicProvider.GetSupportedAlgorithms("unsupported")
	if len(unsupportedAlgos) != 0 {
		t.Fatalf("Expected 0 algorithms for unsupported type, got %d", len(unsupportedAlgos))
	}
}
