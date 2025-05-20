package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestHybridProviderSignVerify(t *testing.T) {
	provider := NewHybridProvider()
	algorithm := Algorithm(AlgorithmHybridDilithiumED25519)

	// Generate key pair
	privateKey, publicKey, err := provider.GenerateKeyPair(algorithm, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate hybrid key pair: %v", err)
	}

	// Verify keys are not empty
	if len(privateKey) == 0 {
		t.Fatal("Empty private key generated")
	}
	if len(publicKey) == 0 {
		t.Fatal("Empty public key generated")
	}

	// Test data
	testData := []byte("Test message for hybrid signature")

	// Sign
	signature, err := provider.Sign(privateKey, algorithm, testData)
	if err != nil {
		t.Fatalf("Failed to sign with hybrid approach: %v", err)
	}

	// Verify signature is not empty
	if len(signature) == 0 {
		t.Fatal("Empty signature generated")
	}

	// Verify
	valid, err := provider.Verify(publicKey, algorithm, testData, signature)
	if err != nil {
		t.Fatalf("Error during hybrid verification: %v", err)
	}
	if !valid {
		t.Fatal("Hybrid signature verification failed")
	}

	// Verify with modified data should fail
	modifiedData := append([]byte{}, testData...)
	modifiedData[0] ^= 0xFF // Flip bits in first byte
	valid, err = provider.Verify(publicKey, algorithm, modifiedData, signature)
	if err != nil {
		t.Logf("Expected error during hybrid verification with modified data: %v", err)
	}
	if valid {
		t.Fatal("Hybrid signature verification should have failed with modified data")
	}

	// Test with tampered signature
	tamperedSig := append([]byte{}, signature...)
	if len(tamperedSig) > 10 {
		tamperedSig[10] ^= 0xFF // Tamper with a byte in the signature
		valid, err = provider.Verify(publicKey, algorithm, testData, tamperedSig)
		if err != nil {
			t.Logf("Expected error during verification with tampered signature: %v", err)
		}
		if valid {
			t.Fatal("Verification should have failed with tampered signature")
		}
	}
}

func TestHybridProviderKEM(t *testing.T) {
	provider := NewHybridProvider()
	algorithm := Algorithm(AlgorithmHybridKyberECDH)

	// Generate key pair
	privateKey, publicKey, err := provider.GenerateKeyPair(algorithm, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate hybrid KEM key pair: %v", err)
	}

	// Encapsulate key
	ciphertext, sharedSecret1, err := provider.EncapsulateKey(publicKey, algorithm)
	if err != nil {
		t.Fatalf("Failed to encapsulate key: %v", err)
	}

	// Verify ciphertext and shared secret are not empty
	if len(ciphertext) == 0 {
		t.Fatal("Empty ciphertext generated")
	}
	if len(sharedSecret1) == 0 {
		t.Fatal("Empty shared secret generated")
	}

	// Decapsulate key
	sharedSecret2, err := provider.DecapsulateKey(privateKey, algorithm, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decapsulate key: %v", err)
	}

	// Verify shared secrets match
	if !bytes.Equal(sharedSecret1, sharedSecret2) {
		t.Fatal("Shared secrets don't match")
	}

	// Test with tampered ciphertext
	if len(ciphertext) > 0 {
		tamperedCiphertext := make([]byte, len(ciphertext))
		copy(tamperedCiphertext, ciphertext)
		// Tamper with the ciphertext to ensure it's different
		tamperedCiphertext[0] ^= 0xFF

		// Attempt to decapsulate with tampered ciphertext
		tamperedSecret, err := provider.DecapsulateKey(privateKey, algorithm, tamperedCiphertext)

		// We expect either an error OR a different shared secret
		if err == nil && bytes.Equal(tamperedSecret, sharedSecret1) {
			t.Fatal("Decapsulation should have failed with tampered ciphertext or produced a different shared secret")
		}
	}
}

func TestHybridProviderEncryptionDecryption(t *testing.T) {
	provider := NewHybridProvider()

	// Hybrid provider doesn't support direct encryption/decryption
	// so we expect errors when attempting to use these methods

	testData := []byte("Test data for encryption")
	dummyKey := []byte("dummy key")

	_, err := provider.Encrypt(dummyKey, Algorithm(AlgorithmAESGCM), testData)
	if err == nil {
		t.Fatal("Expected error for unsupported Encrypt operation, got none")
	}

	_, err = provider.Decrypt(dummyKey, Algorithm(AlgorithmAESGCM), testData)
	if err == nil {
		t.Fatal("Expected error for unsupported Decrypt operation, got none")
	}
}

func TestHybridProviderUnsupportedAlgorithms(t *testing.T) {
	provider := NewHybridProvider()

	// Test with unsupported signature algorithm
	_, err := provider.Sign([]byte("key"), Algorithm("UNSUPPORTED"), []byte("data"))
	if err == nil {
		t.Fatal("Expected error for unsupported signature algorithm, got none")
	}

	// Test with unsupported verification algorithm
	_, err = provider.Verify([]byte("key"), Algorithm("UNSUPPORTED"), []byte("data"), []byte("sig"))
	if err == nil {
		t.Fatal("Expected error for unsupported verification algorithm, got none")
	}

	// Test with unsupported KEM algorithm
	_, _, err = provider.EncapsulateKey([]byte("key"), Algorithm("UNSUPPORTED"))
	if err == nil {
		t.Fatal("Expected error for unsupported KEM algorithm, got none")
	}

	// Test with unsupported KEM algorithm for decapsulation
	_, err = provider.DecapsulateKey([]byte("key"), Algorithm("UNSUPPORTED"), []byte("ct"))
	if err == nil {
		t.Fatal("Expected error for unsupported KEM decapsulation algorithm, got none")
	}

	// Test with unsupported key generation algorithm
	_, _, err = provider.GenerateKeyPair(Algorithm("UNSUPPORTED"), rand.Reader)
	if err == nil {
		t.Fatal("Expected error for unsupported key generation algorithm, got none")
	}
}

func BenchmarkHybridSign(b *testing.B) {
	provider := NewHybridProvider()
	algorithm := Algorithm(AlgorithmHybridDilithiumED25519)

	// Generate key pair
	privateKey, _, err := provider.GenerateKeyPair(algorithm, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate hybrid key pair: %v", err)
	}

	testData := []byte("Benchmark test data for hybrid signing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.Sign(privateKey, algorithm, testData)
		if err != nil {
			b.Fatalf("Failed to sign: %v", err)
		}
	}
}

func BenchmarkHybridVerify(b *testing.B) {
	provider := NewHybridProvider()
	algorithm := Algorithm(AlgorithmHybridDilithiumED25519)

	// Generate key pair
	privateKey, publicKey, err := provider.GenerateKeyPair(algorithm, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate hybrid key pair: %v", err)
	}

	testData := []byte("Benchmark test data for hybrid verification")

	// Sign once
	signature, err := provider.Sign(privateKey, algorithm, testData)
	if err != nil {
		b.Fatalf("Failed to sign: %v", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := provider.Verify(publicKey, algorithm, testData, signature)
		if err != nil {
			b.Fatalf("Failed to verify: %v", err)
		}
	}
}

func BenchmarkHybridKEM(b *testing.B) {
	provider := NewHybridProvider()
	algorithm := Algorithm(AlgorithmHybridKyberECDH)

	// Generate key pair
	_, publicKey, err := provider.GenerateKeyPair(algorithm, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate hybrid KEM key pair: %v", err)
	}

	b.Run("Encapsulate", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, _, err := provider.EncapsulateKey(publicKey, algorithm)
			if err != nil {
				b.Fatalf("Failed to encapsulate: %v", err)
			}
		}
	})

	// For decapsulation benchmark, we need to generate a ciphertext first
	privateKey, publicKey, err := provider.GenerateKeyPair(algorithm, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate hybrid KEM key pair: %v", err)
	}

	ciphertext, _, err := provider.EncapsulateKey(publicKey, algorithm)
	if err != nil {
		b.Fatalf("Failed to encapsulate: %v", err)
	}

	b.Run("Decapsulate", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			_, err := provider.DecapsulateKey(privateKey, algorithm, ciphertext)
			if err != nil {
				b.Fatalf("Failed to decapsulate: %v", err)
			}
		}
	})
}
