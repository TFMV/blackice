package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/rs/zerolog/log"
	"google.golang.org/protobuf/proto"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

// Define supported signature algorithms to match what's in the proto
const (
	SignatureAlgorithmRSAPKCS1SHA256  = "RSA-PKCS1-SHA256"
	SignatureAlgorithmRSAPSSSHA256    = "RSA-PSS-SHA256"
	SignatureAlgorithmECDSAP256SHA256 = "ECDSA-P256-SHA256"
	SignatureAlgorithmED25519         = "ED25519"
	SignatureAlgorithmDilithium       = "DILITHIUM3"
)

// AttestationVerifier verifies attestations
type AttestationVerifier struct {
	initialized bool
}

// NewAttestationVerifier creates a new AttestationVerifier
func NewAttestationVerifier() (*AttestationVerifier, error) {
	return &AttestationVerifier{
		initialized: true,
	}, nil
}

// VerifyAttestation verifies an attestation against a public key
func (v *AttestationVerifier) VerifyAttestation(
	attestation *blackicev1.Attestation,
	publicKey []byte,
	data []byte,
) (bool, error) {
	if !v.initialized {
		return false, fmt.Errorf("attestation verifier not properly initialized")
	}

	if attestation == nil {
		return false, fmt.Errorf("attestation is nil")
	}

	if len(publicKey) == 0 {
		return false, fmt.Errorf("public key is empty")
	}

	// Check attestation timestamp
	if attestation.GetTimestampUnixNs() == 0 {
		return false, fmt.Errorf("attestation has no timestamp")
	}

	attestationTime := time.Unix(0, attestation.GetTimestampUnixNs())
	now := time.Now()

	// Check if attestation is too old
	maxAge := 24 * time.Hour
	if now.Sub(attestationTime) > maxAge {
		return false, fmt.Errorf("attestation is too old")
	}

	// Check if attestation is from the future (clock skew)
	if attestationTime.After(now.Add(5 * time.Minute)) {
		return false, fmt.Errorf("attestation timestamp is in the future")
	}

	// Verify signature
	switch attestation.GetSignatureAlgorithm() {
	case SignatureAlgorithmRSAPKCS1SHA256:
		return verifyRSAPKCS1Signature(publicKey, attestation.GetSignature(), data, crypto.SHA256)
	case SignatureAlgorithmRSAPSSSHA256:
		return verifyRSAPSSSignature(publicKey, attestation.GetSignature(), data, crypto.SHA256)
	case SignatureAlgorithmECDSAP256SHA256:
		return verifyECDSASignature(publicKey, attestation.GetSignature(), data, crypto.SHA256)
	case SignatureAlgorithmED25519:
		return verifyEd25519Signature(publicKey, attestation.GetSignature(), data)
	case SignatureAlgorithmDilithium:
		// Post-quantum signature verification would go here
		// We'd need to implement Dilithium verification
		return false, fmt.Errorf("dilithium signature verification not yet implemented")
	default:
		return false, fmt.Errorf("unsupported signature algorithm: %s", attestation.GetSignatureAlgorithm())
	}
}

// CreateAttestation creates a new attestation for a payload
func (v *AttestationVerifier) CreateAttestation(
	privateKeyPEM []byte,
	algorithm string,
	data []byte,
	identity string,
) (*blackicev1.Attestation, error) {
	if !v.initialized {
		return nil, fmt.Errorf("attestation verifier not properly initialized")
	}

	// Parse private key
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	var (
		privateKey interface{}
		err        error
	)

	// Try to parse as PKCS8, PKCS1, or EC
	if privateKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
		if privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
			if privateKey, err = x509.ParseECPrivateKey(block.Bytes); err != nil {
				return nil, fmt.Errorf("failed to parse private key: %w", err)
			}
		}
	}

	// Calculate hash of data
	hasher := sha256.New()
	hasher.Write(data)
	dataHash := hasher.Sum(nil)

	// Create attestation
	attestation := &blackicev1.Attestation{
		SignatureAlgorithm: algorithm,
		SignerId:           identity,
		TimestampUnixNs:    time.Now().UnixNano(),
		DataHash:           dataHash,
		HashAlgorithm:      "SHA256",
	}

	// Calculate signature
	var signature []byte
	switch algorithm {
	case SignatureAlgorithmRSAPKCS1SHA256:
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		signature, err = rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, dataHash)
		if err != nil {
			return nil, fmt.Errorf("error signing with RSA-PKCS1: %w", err)
		}

	case SignatureAlgorithmRSAPSSSHA256:
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		signature, err = rsa.SignPSS(nil, rsaKey, crypto.SHA256, dataHash, nil)
		if err != nil {
			return nil, fmt.Errorf("error signing with RSA-PSS: %w", err)
		}

	case SignatureAlgorithmECDSAP256SHA256:
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an ECDSA private key")
		}
		signature, err = ecdsa.SignASN1(nil, ecdsaKey, dataHash)
		if err != nil {
			return nil, fmt.Errorf("error signing with ECDSA: %w", err)
		}

	case SignatureAlgorithmED25519:
		ed25519Key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an Ed25519 private key")
		}
		signature = ed25519.Sign(ed25519Key, data)

	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}

	attestation.Signature = signature
	return attestation, nil
}

// ExtractAttestationData extracts the data to be verified from a protobuf message
// This function handles the extraction before attestation verification
func (v *AttestationVerifier) ExtractAttestationData(
	msg proto.Message,
	attestationField string,
) ([]byte, *blackicev1.Attestation, error) {
	// Currently, we don't have a generic way to extract attestation fields from proto messages
	// In a real implementation, we'd use reflection to extract the attestation field and remove
	// it before computing the digest of the message for verification

	// Create a copy of the message with the attestation field removed
	// This is a simple placeholder for the real implementation
	msgData, err := proto.Marshal(msg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal message: %w", err)
	}

	// This is just a placeholder - normally we'd extract the attestation field properly
	attestation := &blackicev1.Attestation{
		SignatureAlgorithm: SignatureAlgorithmRSAPKCS1SHA256,
		SignerId:           "placeholder",
		TimestampUnixNs:    time.Now().UnixNano(),
		Signature:          []byte("placeholder"),
	}

	return msgData, attestation, nil
}

// VerifyDataHash verifies the data hash in an attestation
func (v *AttestationVerifier) VerifyDataHash(attestation *blackicev1.Attestation, data []byte) (bool, error) {
	if attestation == nil {
		return false, fmt.Errorf("attestation is nil")
	}

	if len(attestation.DataHash) == 0 {
		return false, fmt.Errorf("attestation has no data hash")
	}

	var hasher crypto.Hash
	switch attestation.HashAlgorithm {
	case "SHA256":
		hasher = crypto.SHA256
	case "SHA512":
		hasher = crypto.SHA512
	case "SHA3-256":
		// We'd need to implement SHA3 specially
		return false, fmt.Errorf("SHA3 not yet implemented")
	default:
		return false, fmt.Errorf("unsupported hash algorithm: %s", attestation.HashAlgorithm)
	}

	// Compute hash of data
	var computedHash []byte
	if hasher == crypto.SHA256 {
		h := sha256.Sum256(data)
		computedHash = h[:]
	} else if hasher == crypto.SHA512 {
		h := sha512.Sum512(data)
		computedHash = h[:]
	}

	// Compare hashes
	return hex.EncodeToString(computedHash) == hex.EncodeToString(attestation.DataHash), nil
}

// verifyRSAPKCS1Signature verifies an RSA PKCS1v15 signature
func verifyRSAPKCS1Signature(publicKeyPEM, signature, data []byte, hash crypto.Hash) (bool, error) {
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("key is not an RSA public key")
	}

	var hashed []byte
	switch hash {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		hashed = h[:]
	case crypto.SHA512:
		h := sha512.Sum512(data)
		hashed = h[:]
	default:
		return false, fmt.Errorf("unsupported hash function: %v", hash)
	}

	err = rsa.VerifyPKCS1v15(rsaKey, hash, hashed, signature)
	if err != nil {
		log.Debug().Err(err).Msg("RSA PKCS1v15 signature verification failed")
		return false, nil
	}

	return true, nil
}

// verifyRSAPSSSignature verifies an RSA PSS signature
func verifyRSAPSSSignature(publicKeyPEM, signature, data []byte, hash crypto.Hash) (bool, error) {
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("key is not an RSA public key")
	}

	var hashed []byte
	switch hash {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		hashed = h[:]
	case crypto.SHA512:
		h := sha512.Sum512(data)
		hashed = h[:]
	default:
		return false, fmt.Errorf("unsupported hash function: %v", hash)
	}

	err = rsa.VerifyPSS(rsaKey, hash, hashed, signature, nil)
	if err != nil {
		log.Debug().Err(err).Msg("RSA PSS signature verification failed")
		return false, nil
	}

	return true, nil
}

// verifyECDSASignature verifies an ECDSA signature
func verifyECDSASignature(publicKeyPEM, signature, data []byte, hash crypto.Hash) (bool, error) {
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("key is not an ECDSA public key")
	}

	var hashed []byte
	switch hash {
	case crypto.SHA256:
		h := sha256.Sum256(data)
		hashed = h[:]
	case crypto.SHA512:
		h := sha512.Sum512(data)
		hashed = h[:]
	default:
		return false, fmt.Errorf("unsupported hash function: %v", hash)
	}

	valid := ecdsa.VerifyASN1(ecdsaKey, hashed, signature)
	return valid, nil
}

// verifyEd25519Signature verifies an Ed25519 signature
func verifyEd25519Signature(publicKeyPEM, signature, data []byte) (bool, error) {
	publicKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return false, fmt.Errorf("key is not an Ed25519 public key")
	}

	valid := ed25519.Verify(ed25519Key, data, signature)
	return valid, nil
}

// parsePublicKey parses a PEM encoded public key
func parsePublicKey(keyPEM []byte) (interface{}, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		// Check if it's a certificate
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public key: %w", err)
		}
		publicKey = cert.PublicKey
	}

	return publicKey, nil
}
