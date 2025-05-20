package crypto

import (
	"encoding/hex"
	"os"
	"testing"
)

func TestHMACVerifier(t *testing.T) {
	// Create a temporary file with a test secret
	tempFile, err := os.CreateTemp("", "hmac-secret")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	// Write a test secret to the file
	testSecret := []byte("test-hmac-secret-key-for-verification")
	if _, err := tempFile.Write(testSecret); err != nil {
		t.Fatalf("Failed to write to temp file: %v", err)
	}
	if err := tempFile.Close(); err != nil {
		t.Fatalf("Failed to close temp file: %v", err)
	}

	testCases := []struct {
		name      string
		algorithm string
	}{
		{"SHA256", "SHA256"},
		{"SHA384", "SHA384"},
		{"SHA512", "SHA512"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create verifier
			verifier, err := NewHMACVerifier(tc.algorithm, tempFile.Name())
			if err != nil {
				t.Fatalf("Failed to create HMAC verifier: %v", err)
			}

			if verifier == nil {
				t.Fatal("Verifier is nil")
			}

			if !verifier.initialized {
				t.Fatal("Verifier is not initialized")
			}

			// Test message
			testMessage := []byte("This is a test message for HMAC verification")

			// Generate HMAC
			signature, err := verifier.GenerateHMAC(testMessage)
			if err != nil {
				t.Fatalf("Failed to generate HMAC: %v", err)
			}

			// Verify the signature
			valid, err := verifier.VerifyHMAC(signature, testMessage)
			if err != nil {
				t.Fatalf("Error during HMAC verification: %v", err)
			}

			if !valid {
				t.Fatal("HMAC verification failed")
			}

			// Test with modified message
			modifiedMessage := append([]byte{}, testMessage...)
			modifiedMessage[0] ^= 0xFF // Flip bits in first byte

			valid, err = verifier.VerifyHMAC(signature, modifiedMessage)
			if err != nil {
				t.Logf("Error during HMAC verification with modified message: %v", err)
			}

			if valid {
				t.Fatal("HMAC verification should have failed with modified message")
			}

			// Test hex encoding
			hexSignature, err := verifier.GenerateHMACHex(testMessage)
			if err != nil {
				t.Fatalf("Failed to generate hex HMAC: %v", err)
			}

			// Verify the hex signature can be decoded to the binary signature
			binarySignature, err := hex.DecodeString(hexSignature)
			if err != nil {
				t.Fatalf("Failed to decode hex signature: %v", err)
			}

			// Verify decoded binary signature matches original
			if len(binarySignature) != len(signature) {
				t.Fatal("Decoded signature length doesn't match original")
			}

			for i := range signature {
				if signature[i] != binarySignature[i] {
					t.Fatalf("Decoded signature doesn't match original at byte %d", i)
				}
			}

			// Verify using hex verification method
			valid, err = verifier.VerifyHMACHex(hexSignature, testMessage)
			if err != nil {
				t.Fatalf("Error during hex HMAC verification: %v", err)
			}

			if !valid {
				t.Fatal("Hex HMAC verification failed")
			}
		})
	}
}

func TestHMACVerifierErrors(t *testing.T) {
	// Test with unsupported algorithm
	_, err := NewHMACVerifier("UNSUPPORTED", "")
	if err == nil {
		t.Fatal("Expected error for unsupported algorithm, got none")
	}

	// Test with non-existent secret file
	_, err = NewHMACVerifier("SHA256", "/path/to/nonexistent/file")
	if err == nil {
		t.Fatal("Expected error for non-existent secret file, got none")
	}

	// Test with empty secret path (should succeed but warn)
	verifier, err := NewHMACVerifier("SHA256", "")
	if err != nil {
		t.Fatalf("Failed to create verifier with empty secret path: %v", err)
	}

	// Generate and verify with empty secret
	testMessage := []byte("Test message with empty secret")
	signature, err := verifier.GenerateHMAC(testMessage)
	if err != nil {
		t.Fatalf("Failed to generate HMAC with empty secret: %v", err)
	}

	valid, err := verifier.VerifyHMAC(signature, testMessage)
	if err != nil {
		t.Fatalf("Error during HMAC verification with empty secret: %v", err)
	}

	if !valid {
		t.Fatal("HMAC verification with empty secret failed")
	}

	// Test hex verification with invalid hex string
	_, err = verifier.VerifyHMACHex("invalid-hex", testMessage)
	if err == nil {
		t.Fatal("Expected error for invalid hex signature, got none")
	}
}
