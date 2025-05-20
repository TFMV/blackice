package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestClassicProviderSignVerify(t *testing.T) {
	provider := NewClassicProvider()
	testCases := []struct {
		name      string
		algorithm Algorithm
	}{
		{"RSA-PKCS1", Algorithm(AlgorithmRSAPKCS1SHA256)},
		{"RSA-PSS", Algorithm(AlgorithmRSAPSSSHA256)},
		{"ECDSA", Algorithm(AlgorithmECDSAP256SHA256)},
		{"ED25519", Algorithm(AlgorithmED25519)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate key pair
			privateKey, publicKey, err := provider.GenerateKeyPair(tc.algorithm, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate key pair for %s: %v", tc.name, err)
			}

			// Test data
			testData := []byte("Test message for " + tc.name)

			// Sign
			signature, err := provider.Sign(privateKey, tc.algorithm, testData)
			if err != nil {
				t.Fatalf("Failed to sign with %s: %v", tc.name, err)
			}

			// Verify
			valid, err := provider.Verify(publicKey, tc.algorithm, testData, signature)
			if err != nil {
				t.Fatalf("Error during verification with %s: %v", tc.name, err)
			}
			if !valid {
				t.Fatalf("Signature verification failed for %s", tc.name)
			}

			// Verify with modified data should fail
			modifiedData := append([]byte{}, testData...)
			modifiedData[0] ^= 0xFF // Flip bits in first byte
			valid, err = provider.Verify(publicKey, tc.algorithm, modifiedData, signature)
			if err != nil {
				t.Logf("Expected error during verification with modified data: %v", err)
			}
			if valid {
				t.Fatalf("Signature verification should have failed with modified data for %s", tc.name)
			}
		})
	}
}

func TestClassicProviderHash(t *testing.T) {
	provider := NewClassicProvider()
	testCases := []struct {
		name      string
		algorithm Algorithm
		expected  int // Expected hash output length in bytes
	}{
		{"SHA-256", Algorithm("SHA-256"), 32},
		{"SHA-512", Algorithm("SHA-512"), 64},
	}

	testData := []byte("Test data for hashing")

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Get hash algorithm
			hashAlgo, err := provider.GetHash(tc.algorithm)
			if err != nil {
				t.Fatalf("Failed to get hash algorithm for %s: %v", tc.name, err)
			}

			// Hash the data
			hash, err := provider.Hash(tc.algorithm, testData)
			if err != nil {
				t.Fatalf("Failed to hash data with %s: %v", tc.name, err)
			}

			// Verify hash length
			if len(hash) != tc.expected {
				t.Fatalf("Unexpected hash length for %s: expected %d, got %d", tc.name, tc.expected, len(hash))
			}

			// Verify hash is correct by computing it directly
			h := hashAlgo.New()
			h.Write(testData)
			expectedHash := h.Sum(nil)
			if !bytes.Equal(hash, expectedHash) {
				t.Fatalf("Hash doesn't match expected value for %s", tc.name)
			}
		})
	}

	// Test with unsupported algorithm
	_, err := provider.Hash(Algorithm("UNSUPPORTED-HASH"), testData)
	if err == nil {
		t.Fatalf("Expected error for unsupported hash algorithm, got none")
	}
}

func TestClassicProviderEncryptDecrypt(t *testing.T) {
	provider := NewClassicProvider()

	// Currently only AES-GCM is implemented for direct encryption
	algorithm := Algorithm(AlgorithmAESGCM)

	// Generate a 32-byte AES key
	key := make([]byte, 32)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to generate random AES key: %v", err)
	}

	// Test data
	plaintext := []byte("This is a secret message for AES-GCM encryption")

	// Encrypt
	ciphertext, err := provider.Encrypt(key, algorithm, plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt with AES-GCM: %v", err)
	}

	// Decrypt
	decrypted, err := provider.Decrypt(key, algorithm, ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt with AES-GCM: %v", err)
	}

	// Verify decrypted matches original
	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("Decrypted data doesn't match original plaintext")
	}

	// Test with invalid key length
	invalidKey := make([]byte, 17) // Not a valid AES key length
	_, err = provider.Encrypt(invalidKey, algorithm, plaintext)
	if err == nil {
		t.Fatalf("Expected error for invalid key length, got none")
	}

	// Test with tampered ciphertext
	tamperedCiphertext := append([]byte{}, ciphertext...)
	tamperedCiphertext[len(tamperedCiphertext)-1] ^= 0xFF // Tamper with the last byte
	_, err = provider.Decrypt(key, algorithm, tamperedCiphertext)
	if err == nil {
		t.Fatalf("Expected error for tampered ciphertext, got none")
	}
}

func TestClassicProviderGenerateKeyPair(t *testing.T) {
	provider := NewClassicProvider()
	testCases := []struct {
		name      string
		algorithm Algorithm
	}{
		{"RSA-PKCS1", Algorithm(AlgorithmRSAPKCS1SHA256)},
		{"RSA-PSS", Algorithm(AlgorithmRSAPSSSHA256)},
		{"ECDSA", Algorithm(AlgorithmECDSAP256SHA256)},
		{"ED25519", Algorithm(AlgorithmED25519)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Generate key pair
			privateKey, publicKey, err := provider.GenerateKeyPair(tc.algorithm, rand.Reader)
			if err != nil {
				t.Fatalf("Failed to generate key pair for %s: %v", tc.name, err)
			}

			// Verify keys are not empty
			if len(privateKey) == 0 {
				t.Fatalf("Empty private key generated for %s", tc.name)
			}
			if len(publicKey) == 0 {
				t.Fatalf("Empty public key generated for %s", tc.name)
			}

			// Test with basic sign/verify to ensure the keys work
			testData := []byte("Test message for key generation test")
			signature, err := provider.Sign(privateKey, tc.algorithm, testData)
			if err != nil {
				t.Fatalf("Failed to sign with generated key for %s: %v", tc.name, err)
			}

			valid, err := provider.Verify(publicKey, tc.algorithm, testData, signature)
			if err != nil {
				t.Fatalf("Error during verification with generated key for %s: %v", tc.name, err)
			}
			if !valid {
				t.Fatalf("Signature verification failed with generated key for %s", tc.name)
			}
		})
	}

	// Test with unsupported algorithm
	_, _, err := provider.GenerateKeyPair(Algorithm("UNSUPPORTED-ALGO"), rand.Reader)
	if err == nil {
		t.Fatalf("Expected error for unsupported algorithm, got none")
	}
}

func BenchmarkClassicSign(b *testing.B) {
	provider := NewClassicProvider()
	algorithms := []Algorithm{
		Algorithm(AlgorithmRSAPKCS1SHA256),
		Algorithm(AlgorithmRSAPSSSHA256),
		Algorithm(AlgorithmECDSAP256SHA256),
		Algorithm(AlgorithmED25519),
	}

	testData := []byte("Benchmark test data for signing")

	for _, algorithm := range algorithms {
		b.Run(string(algorithm), func(b *testing.B) {
			privateKey, _, err := provider.GenerateKeyPair(algorithm, rand.Reader)
			if err != nil {
				b.Fatalf("Failed to generate key pair: %v", err)
			}

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_, err := provider.Sign(privateKey, algorithm, testData)
				if err != nil {
					b.Fatalf("Failed to sign: %v", err)
				}
			}
		})
	}
}

func BenchmarkClassicVerify(b *testing.B) {
	provider := NewClassicProvider()
	algorithms := []Algorithm{
		Algorithm(AlgorithmRSAPKCS1SHA256),
		Algorithm(AlgorithmRSAPSSSHA256),
		Algorithm(AlgorithmECDSAP256SHA256),
		Algorithm(AlgorithmED25519),
	}

	testData := []byte("Benchmark test data for verification")

	for _, algorithm := range algorithms {
		b.Run(string(algorithm), func(b *testing.B) {
			privateKey, publicKey, err := provider.GenerateKeyPair(algorithm, rand.Reader)
			if err != nil {
				b.Fatalf("Failed to generate key pair: %v", err)
			}

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
		})
	}
}
