package crypto

import (
	"testing"
)

func TestDilithiumSignVerify(t *testing.T) {
	// Create a provider
	provider := NewPQProvider()

	// Generate key pair
	privateKey, publicKey, err := provider.GenerateKeyPair(Algorithm(AlgorithmDilithium3), nil)
	if err != nil {
		t.Fatalf("Failed to generate Dilithium key pair: %v", err)
	}

	// Test data
	testData := []byte("Test message to sign with Dilithium")

	// Sign the data
	signature, err := provider.Sign(privateKey, Algorithm(AlgorithmDilithium3), testData)
	if err != nil {
		t.Fatalf("Failed to sign with Dilithium: %v", err)
	}

	// Verify the signature
	valid, err := provider.Verify(publicKey, Algorithm(AlgorithmDilithium3), testData, signature)
	if err != nil {
		t.Fatalf("Failed to verify Dilithium signature: %v", err)
	}

	if !valid {
		t.Fatalf("Dilithium signature verification failed")
	}
}

func TestKyberEncapsulationDecapsulation(t *testing.T) {
	// Create a provider
	provider := NewPQProvider()

	// Generate key pair
	privateKey, publicKey, err := provider.GenerateKeyPair(Algorithm(AlgorithmKyber768), nil)
	if err != nil {
		t.Fatalf("Failed to generate Kyber key pair: %v", err)
	}

	// Encapsulate key
	ciphertext, sharedSecret1, err := provider.EncapsulateKey(publicKey, Algorithm(AlgorithmKyber768))
	if err != nil {
		t.Fatalf("Failed to encapsulate key: %v", err)
	}

	// Decapsulate key
	sharedSecret2, err := provider.DecapsulateKey(privateKey, Algorithm(AlgorithmKyber768), ciphertext)
	if err != nil {
		t.Fatalf("Failed to decapsulate key: %v", err)
	}

	// Verify shared secrets match
	if len(sharedSecret1) != len(sharedSecret2) {
		t.Fatalf("Shared secret lengths don't match: %d vs %d", len(sharedSecret1), len(sharedSecret2))
	}

	for i := range sharedSecret1 {
		if sharedSecret1[i] != sharedSecret2[i] {
			t.Fatalf("Shared secrets don't match at byte %d: %d vs %d", i, sharedSecret1[i], sharedSecret2[i])
		}
	}
}

func TestHybridSignVerify(t *testing.T) {
	// Create a provider
	provider := NewHybridProvider()

	// Generate key pair
	privateKey, publicKey, err := provider.GenerateKeyPair(Algorithm(AlgorithmHybridDilithiumED25519), nil)
	if err != nil {
		t.Fatalf("Failed to generate hybrid key pair: %v", err)
	}

	// Test data
	testData := []byte("Test message to sign with hybrid approach")

	// Sign the data
	signature, err := provider.Sign(privateKey, Algorithm(AlgorithmHybridDilithiumED25519), testData)
	if err != nil {
		t.Fatalf("Failed to sign with hybrid approach: %v", err)
	}

	// Verify the signature
	valid, err := provider.Verify(publicKey, Algorithm(AlgorithmHybridDilithiumED25519), testData, signature)
	if err != nil {
		t.Fatalf("Failed to verify hybrid signature: %v", err)
	}

	if !valid {
		t.Fatalf("Hybrid signature verification failed")
	}
}

func BenchmarkDilithiumSignature(b *testing.B) {
	// Create a provider
	provider := NewPQProvider()

	// Generate key pair
	privateKey, _, err := provider.GenerateKeyPair(Algorithm(AlgorithmDilithium3), nil)
	if err != nil {
		b.Fatalf("Failed to generate Dilithium key pair: %v", err)
	}

	// Test data
	testData := []byte("Test message to sign with Dilithium for benchmark")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.Sign(privateKey, Algorithm(AlgorithmDilithium3), testData)
		if err != nil {
			b.Fatalf("Failed to sign with Dilithium: %v", err)
		}
	}
}

func BenchmarkDilithiumVerification(b *testing.B) {
	// Create a provider
	provider := NewPQProvider()

	// Generate key pair
	privateKey, publicKey, err := provider.GenerateKeyPair(Algorithm(AlgorithmDilithium3), nil)
	if err != nil {
		b.Fatalf("Failed to generate Dilithium key pair: %v", err)
	}

	// Test data
	testData := []byte("Test message to sign with Dilithium for benchmark")

	// Sign the data
	signature, err := provider.Sign(privateKey, Algorithm(AlgorithmDilithium3), testData)
	if err != nil {
		b.Fatalf("Failed to sign with Dilithium: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.Verify(publicKey, Algorithm(AlgorithmDilithium3), testData, signature)
		if err != nil {
			b.Fatalf("Failed to verify Dilithium signature: %v", err)
		}
	}
}

func BenchmarkKyberEncapsulation(b *testing.B) {
	// Create a provider
	provider := NewPQProvider()

	// Generate key pair
	_, publicKey, err := provider.GenerateKeyPair(Algorithm(AlgorithmKyber768), nil)
	if err != nil {
		b.Fatalf("Failed to generate Kyber key pair: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := provider.EncapsulateKey(publicKey, Algorithm(AlgorithmKyber768))
		if err != nil {
			b.Fatalf("Failed to encapsulate key: %v", err)
		}
	}
}

func BenchmarkKyberDecapsulation(b *testing.B) {
	// Create a provider
	provider := NewPQProvider()

	// Generate key pair
	privateKey, publicKey, err := provider.GenerateKeyPair(Algorithm(AlgorithmKyber768), nil)
	if err != nil {
		b.Fatalf("Failed to generate Kyber key pair: %v", err)
	}

	// Encapsulate key
	ciphertext, _, err := provider.EncapsulateKey(publicKey, Algorithm(AlgorithmKyber768))
	if err != nil {
		b.Fatalf("Failed to encapsulate key: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.DecapsulateKey(privateKey, Algorithm(AlgorithmKyber768), ciphertext)
		if err != nil {
			b.Fatalf("Failed to decapsulate key: %v", err)
		}
	}
}
