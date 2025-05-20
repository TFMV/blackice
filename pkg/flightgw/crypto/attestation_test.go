package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

func TestAttestationVerifierCreation(t *testing.T) {
	verifier, err := NewAttestationVerifier()
	if err != nil {
		t.Fatalf("Failed to create attestation verifier: %v", err)
	}

	if verifier == nil {
		t.Fatal("Attestation verifier is nil")
	}

	if !verifier.initialized {
		t.Fatal("Attestation verifier is not initialized")
	}

	if verifier.providers == nil {
		t.Fatal("Provider registry is nil")
	}
}

// Helper function to encode ED25519 private key in PEM format
func encodePKCS8PrivateKey(privateKey ed25519.PrivateKey) ([]byte, error) {
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// Helper function to encode ED25519 public key in PEM format
func encodePKIXPublicKey(publicKey ed25519.PublicKey) ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return pem.EncodeToMemory(pemBlock), nil
}

// Helper function to calculate data hash for manual attestation verification
func calculateDataHash(data []byte) []byte {
	hash := sha256.Sum256(data)
	return hash[:]
}

func TestCreateVerifyAttestationManual(t *testing.T) {
	// Create a manual attestation that precisely matches the verification expectations

	// Generate an ED25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	// Encode the public key in PEM format (for verification)
	pemPubKey, err := encodePKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to encode public key: %v", err)
	}

	// Test data
	testData := []byte("Test message for manual ED25519 attestation")
	identity := "test-identity-ed25519-manual"

	// Calculate the data hash
	dataHash := calculateDataHash(testData)

	// Create a signature using the raw ED25519 key
	// ED25519 signs the data hash, not the raw data (to match our implementation)
	signature := ed25519.Sign(privKey, dataHash)

	// Create the attestation manually
	attestation := &blackicev1.Attestation{
		SignatureAlgorithm: SignatureAlgorithmED25519,
		SignerId:           identity,
		TimestampUnixNs:    time.Now().UnixNano(),
		DataHash:           dataHash,
		HashAlgorithm:      "SHA256",
		Signature:          signature,
	}

	// Verify the attestation using the verifier
	verifier, err := NewAttestationVerifier()
	if err != nil {
		t.Fatalf("Failed to create attestation verifier: %v", err)
	}

	valid, err := verifier.VerifyAttestation(attestation, pemPubKey, testData)
	if err != nil {
		t.Fatalf("Error during attestation verification: %v", err)
	}

	if !valid {
		t.Fatal("Attestation verification failed")
	}

	// Verify with tampered data should fail
	tamperedData := append([]byte{}, testData...)
	tamperedData[0] ^= 0xFF // Tamper with first byte

	valid, err = verifier.VerifyAttestation(attestation, pemPubKey, tamperedData)
	if err == nil {
		t.Log("Expected error for tampered data, but got none")
	}

	if valid {
		t.Fatal("Attestation verification should have failed with tampered data")
	}
}

func TestCreateVerifyAttestation(t *testing.T) {
	verifier, err := NewAttestationVerifier()
	if err != nil {
		t.Fatalf("Failed to create attestation verifier: %v", err)
	}

	// Generate an ED25519 key pair
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate ED25519 key pair: %v", err)
	}

	// Encode the keys in PEM format
	pemPrivKey, err := encodePKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("Failed to encode private key: %v", err)
	}

	pemPubKey, err := encodePKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to encode public key: %v", err)
	}

	// Test data to be attested
	testData := []byte("Test message for ED25519 attestation")
	identity := "test-identity-ed25519"

	// Create attestation with PEM encoded key
	attestation, err := verifier.CreateAttestation(pemPrivKey, SignatureAlgorithmED25519, testData, identity)
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	// Verify attestation attributes
	if attestation.SignatureAlgorithm != SignatureAlgorithmED25519 {
		t.Fatalf("Unexpected signature algorithm: %s", attestation.SignatureAlgorithm)
	}

	if attestation.SignerId != identity {
		t.Fatalf("Unexpected signer ID: %s", attestation.SignerId)
	}

	if attestation.TimestampUnixNs == 0 {
		t.Fatal("Timestamp is zero")
	}

	if len(attestation.Signature) == 0 {
		t.Fatal("Empty signature in attestation")
	}

	if len(attestation.DataHash) == 0 {
		t.Fatal("Empty data hash in attestation")
	}

	// Manually calculate the data hash to verify against attestation
	dataHash := calculateDataHash(testData)
	if !bytes.Equal(dataHash, attestation.DataHash) {
		t.Fatal("Data hash in attestation doesn't match expected hash")
	}

	// VerifyDataHash should work
	hashValid, err := verifier.VerifyDataHash(attestation, testData)
	if err != nil {
		t.Fatalf("Error during data hash verification: %v", err)
	}
	if !hashValid {
		t.Fatal("Data hash verification failed")
	}

	// Verify the attestation against the original data
	valid, err := verifier.VerifyAttestation(attestation, pemPubKey, testData)
	if err != nil {
		t.Fatalf("Error during attestation verification: %v", err)
	}

	if !valid {
		t.Fatal("Attestation verification failed")
	}

	// Verify with tampered data should fail
	tamperedData := append([]byte{}, testData...)
	tamperedData[0] ^= 0xFF // Tamper with first byte

	valid, err = verifier.VerifyAttestation(attestation, pemPubKey, tamperedData)
	if err == nil {
		t.Log("Expected error for tampered data, but got none")
	}

	if valid {
		t.Fatal("Attestation verification should have failed with tampered data")
	}
}

func TestVerifyAttestationErrors(t *testing.T) {
	verifier, err := NewAttestationVerifier()
	if err != nil {
		t.Fatalf("Failed to create attestation verifier: %v", err)
	}

	// Generate key for tests
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Encode the keys in PEM format
	pemPrivKey, err := encodePKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("Failed to encode private key: %v", err)
	}

	pemPubKey, err := encodePKIXPublicKey(pubKey)
	if err != nil {
		t.Fatalf("Failed to encode public key: %v", err)
	}

	testData := []byte("Test message for attestation error cases")

	// Test with nil attestation
	valid, err := verifier.VerifyAttestation(nil, pemPubKey, testData)
	if err == nil {
		t.Fatal("Expected error for nil attestation, got none")
	}
	if valid {
		t.Fatal("Verification should have failed with nil attestation")
	}

	// Test with empty public key
	attestation, err := verifier.CreateAttestation(pemPrivKey, SignatureAlgorithmED25519, testData, "test-id")
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	valid, err = verifier.VerifyAttestation(attestation, []byte{}, testData)
	if err == nil {
		t.Fatal("Expected error for empty public key, got none")
	}
	if valid {
		t.Fatal("Verification should have failed with empty public key")
	}

	// Test with future timestamp
	futureAttestation := &blackicev1.Attestation{
		SignatureAlgorithm: SignatureAlgorithmED25519,
		SignerId:           "test-id",
		TimestampUnixNs:    time.Now().Add(10 * time.Hour).UnixNano(), // 10 hours in the future
		DataHash:           attestation.DataHash,
		HashAlgorithm:      "SHA256",
		Signature:          attestation.Signature,
	}

	valid, err = verifier.VerifyAttestation(futureAttestation, pemPubKey, testData)
	if err == nil {
		t.Fatal("Expected error for future timestamp, got none")
	}
	if valid {
		t.Fatal("Verification should have failed with future timestamp")
	}

	// Test with expired timestamp
	expiredAttestation := &blackicev1.Attestation{
		SignatureAlgorithm: SignatureAlgorithmED25519,
		SignerId:           "test-id",
		TimestampUnixNs:    time.Now().Add(-30 * 24 * time.Hour).UnixNano(), // 30 days in the past
		DataHash:           attestation.DataHash,
		HashAlgorithm:      "SHA256",
		Signature:          attestation.Signature,
	}

	valid, err = verifier.VerifyAttestation(expiredAttestation, pemPubKey, testData)
	if err == nil {
		t.Fatal("Expected error for expired timestamp, got none")
	}
	if valid {
		t.Fatal("Verification should have failed with expired timestamp")
	}

	// Test with unsupported algorithm
	unsupportedAlgAttestation := &blackicev1.Attestation{
		SignatureAlgorithm: "UNSUPPORTED-ALGORITHM",
		SignerId:           "test-id",
		TimestampUnixNs:    time.Now().UnixNano(),
		DataHash:           attestation.DataHash,
		HashAlgorithm:      "SHA256",
		Signature:          attestation.Signature,
	}

	valid, err = verifier.VerifyAttestation(unsupportedAlgAttestation, pemPubKey, testData)
	if err == nil {
		t.Fatal("Expected error for unsupported algorithm, got none")
	}
	if valid {
		t.Fatal("Verification should have failed with unsupported algorithm")
	}
}

func TestVerifyDataHash(t *testing.T) {
	verifier, err := NewAttestationVerifier()
	if err != nil {
		t.Fatalf("Failed to create attestation verifier: %v", err)
	}

	testData := []byte("Test data for hash verification")
	identity := "test-hash-verifier"

	// Generate key pair
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate key pair: %v", err)
	}

	// Encode the private key in PEM format
	pemPrivKey, err := encodePKCS8PrivateKey(privKey)
	if err != nil {
		t.Fatalf("Failed to encode private key: %v", err)
	}

	// Create attestation
	attestation, err := verifier.CreateAttestation(pemPrivKey, SignatureAlgorithmED25519, testData, identity)
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	// Verify data hash
	hashValid, err := verifier.VerifyDataHash(attestation, testData)
	if err != nil {
		t.Fatalf("Error during data hash verification: %v", err)
	}

	if !hashValid {
		t.Fatal("Data hash verification failed")
	}

	// Test with modified data
	modifiedData := append([]byte{}, testData...)
	modifiedData[0] ^= 0xFF // Modify first byte

	hashValid, err = verifier.VerifyDataHash(attestation, modifiedData)
	if err != nil {
		t.Logf("Expected error during data hash verification with modified data: %v", err)
	}

	if hashValid {
		t.Fatal("Data hash verification should have failed with modified data")
	}

	// Test with unsupported hash algorithm
	unsupportedHashAttestation := &blackicev1.Attestation{
		SignatureAlgorithm: SignatureAlgorithmED25519,
		SignerId:           identity,
		TimestampUnixNs:    time.Now().UnixNano(),
		DataHash:           attestation.DataHash,
		HashAlgorithm:      "UNSUPPORTED-HASH",
		Signature:          attestation.Signature,
	}

	hashValid, err = verifier.VerifyDataHash(unsupportedHashAttestation, testData)
	if err == nil {
		t.Fatal("Expected error for unsupported hash algorithm, got none")
	}

	if hashValid {
		t.Fatal("Data hash verification should have failed with unsupported hash algorithm")
	}
}
