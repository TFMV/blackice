package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateKeys(t *testing.T) {
	// Create a temporary directory for test keys
	tempDir, err := os.MkdirTemp("", "keygen_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	testCases := []struct {
		name      string
		algorithm Algorithm
	}{
		{"RSA", Algorithm(AlgorithmRSAPKCS1SHA256)},
		{"ECDSA", Algorithm(AlgorithmECDSAP256SHA256)},
		{"ED25519", Algorithm(AlgorithmED25519)},
		{"Dilithium", Algorithm(AlgorithmDilithium3)},
		{"Kyber", Algorithm(AlgorithmKyber768)},
		{"Hybrid-Signature", Algorithm(AlgorithmHybridDilithiumED25519)},
		{"Hybrid-KEM", Algorithm(AlgorithmHybridKyberECDH)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a subdirectory for this test case
			testDir := filepath.Join(tempDir, tc.name)

			options := GenerateKeysOptions{
				Algorithm:      tc.algorithm,
				OutputDir:      testDir,
				PrivateKeyFile: "test_private.pem",
				PublicKeyFile:  "test_public.pem",
				ForceOverwrite: false,
				RandomSource:   rand.Reader,
			}

			// Generate keys
			err := GenerateKeys(options)
			if err != nil {
				t.Fatalf("Failed to generate keys for %s: %v", tc.name, err)
			}

			// Check if files exist
			privateKeyPath := filepath.Join(testDir, "test_private.pem")
			publicKeyPath := filepath.Join(testDir, "test_public.pem")

			if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
				t.Fatalf("Private key file doesn't exist for %s", tc.name)
			}

			if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
				t.Fatalf("Public key file doesn't exist for %s", tc.name)
			}

			// Read key files
			privateKeyData, err := os.ReadFile(privateKeyPath)
			if err != nil {
				t.Fatalf("Failed to read private key file for %s: %v", tc.name, err)
			}

			publicKeyData, err := os.ReadFile(publicKeyPath)
			if err != nil {
				t.Fatalf("Failed to read public key file for %s: %v", tc.name, err)
			}

			// Verify keys are in PEM format
			privatePem, _ := pem.Decode(privateKeyData)
			if privatePem == nil {
				t.Fatalf("Failed to decode private key PEM for %s", tc.name)
			}

			publicPem, _ := pem.Decode(publicKeyData)
			if publicPem == nil {
				t.Fatalf("Failed to decode public key PEM for %s", tc.name)
			}

			// Test if keys actually work (with a simple sign/verify operation)
			var provider CryptoProvider

			switch tc.algorithm {
			case Algorithm(AlgorithmHybridDilithiumED25519), Algorithm(AlgorithmHybridKyberECDH):
				provider = NewHybridProvider()
			case Algorithm(AlgorithmDilithium3), Algorithm(AlgorithmKyber768):
				provider = NewPQProvider()
			default:
				provider = NewClassicProvider()
			}

			// Only test sign/verify for signature algorithms
			if tc.algorithm == Algorithm(AlgorithmRSAPKCS1SHA256) ||
				tc.algorithm == Algorithm(AlgorithmECDSAP256SHA256) ||
				tc.algorithm == Algorithm(AlgorithmED25519) {

				testData := []byte("Test message for key verification")

				// Use the full PEM encoded keys for classical algorithms
				signature, err := provider.Sign(privateKeyData, tc.algorithm, testData)
				if err != nil {
					t.Fatalf("Failed to sign with generated key for %s: %v", tc.name, err)
				}

				valid, err := provider.Verify(publicKeyData, tc.algorithm, testData, signature)
				if err != nil {
					t.Fatalf("Error during verification with generated key for %s: %v", tc.name, err)
				}

				if !valid {
					t.Fatalf("Signature verification failed with generated key for %s", tc.name)
				}
			} else if tc.algorithm == Algorithm(AlgorithmDilithium3) {
				// For Dilithium, we need to use the raw key data, not the PEM wrapper
				testData := []byte("Test message for Dilithium key verification")

				// Extract the raw key data from PEM
				privateKeyRaw := privatePem.Bytes
				publicKeyRaw := publicPem.Bytes

				signature, err := provider.Sign(privateKeyRaw, tc.algorithm, testData)
				if err != nil {
					t.Fatalf("Failed to sign with generated key for %s: %v", tc.name, err)
				}

				valid, err := provider.Verify(publicKeyRaw, tc.algorithm, testData, signature)
				if err != nil {
					t.Fatalf("Error during verification with generated key for %s: %v", tc.name, err)
				}

				if !valid {
					t.Fatalf("Signature verification failed with generated key for %s", tc.name)
				}
			} else if tc.algorithm == Algorithm(AlgorithmHybridDilithiumED25519) {
				// For hybrid signatures, we need to use the raw key data, not the PEM wrapper
				testData := []byte("Test message for hybrid signature key verification")

				// Extract the raw key data from PEM
				privateKeyRaw := privatePem.Bytes
				publicKeyRaw := publicPem.Bytes

				signature, err := provider.Sign(privateKeyRaw, tc.algorithm, testData)
				if err != nil {
					t.Fatalf("Failed to sign with generated key for %s: %v", tc.name, err)
				}

				valid, err := provider.Verify(publicKeyRaw, tc.algorithm, testData, signature)
				if err != nil {
					t.Fatalf("Error during verification with generated key for %s: %v", tc.name, err)
				}

				if !valid {
					t.Fatalf("Signature verification failed with generated key for %s", tc.name)
				}
			}
			// Note: AlgorithmKyber768 and AlgorithmHybridKyberECDH don't need sign/verify tests
		})
	}
}

func TestGenerateKeysOverwrite(t *testing.T) {
	// Create a temporary directory for test keys
	tempDir, err := os.MkdirTemp("", "keygen_overwrite_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create initial key
	options := GenerateKeysOptions{
		Algorithm:      Algorithm(AlgorithmED25519),
		OutputDir:      tempDir,
		PrivateKeyFile: "overwrite_private.pem",
		PublicKeyFile:  "overwrite_public.pem",
		ForceOverwrite: false,
		RandomSource:   rand.Reader,
	}

	err = GenerateKeys(options)
	if err != nil {
		t.Fatalf("Failed to generate initial keys: %v", err)
	}

	// Read the initial keys
	privateKeyPath := filepath.Join(tempDir, "overwrite_private.pem")
	publicKeyPath := filepath.Join(tempDir, "overwrite_public.pem")

	initialPrivateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to read initial private key: %v", err)
	}

	initialPublicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read initial public key: %v", err)
	}

	// Try to generate keys again without ForceOverwrite (should fail)
	err = GenerateKeys(options)
	if err == nil {
		t.Fatal("Key generation should have failed without ForceOverwrite")
	}

	// Verify files haven't changed
	currentPrivateKey, err := os.ReadFile(privateKeyPath)
	if err != nil {
		t.Fatalf("Failed to read current private key: %v", err)
	}

	currentPublicKey, err := os.ReadFile(publicKeyPath)
	if err != nil {
		t.Fatalf("Failed to read current public key: %v", err)
	}

	if !bytes.Equal(initialPrivateKey, currentPrivateKey) {
		t.Fatal("Private key was changed despite failure")
	}

	if !bytes.Equal(initialPublicKey, currentPublicKey) {
		t.Fatal("Public key was changed despite failure")
	}

	// Now generate with ForceOverwrite=true (should succeed)
	options.ForceOverwrite = true
	err = GenerateKeys(options)
	if err != nil {
		t.Fatalf("Failed to generate keys with ForceOverwrite: %v", err)
	}

	// Files should exist but potentially have different content
	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Fatal("Private key file doesn't exist after forced overwrite")
	}

	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		t.Fatal("Public key file doesn't exist after forced overwrite")
	}
}

func TestGenerateKeysDefaultOptions(t *testing.T) {
	// Create a temporary directory for test keys
	tempDir, err := os.MkdirTemp("", "keygen_default_test")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Create a copy of the default options but change the output directory
	options := DefaultGenerateKeysOptions
	options.OutputDir = tempDir

	// Generate keys with default options
	err = GenerateKeys(options)
	if err != nil {
		t.Fatalf("Failed to generate keys with default options: %v", err)
	}

	// Check if files exist with default names
	privateKeyPath := filepath.Join(tempDir, DefaultGenerateKeysOptions.PrivateKeyFile)
	publicKeyPath := filepath.Join(tempDir, DefaultGenerateKeysOptions.PublicKeyFile)

	if _, err := os.Stat(privateKeyPath); os.IsNotExist(err) {
		t.Fatal("Private key file doesn't exist with default name")
	}

	if _, err := os.Stat(publicKeyPath); os.IsNotExist(err) {
		t.Fatal("Public key file doesn't exist with default name")
	}
}
