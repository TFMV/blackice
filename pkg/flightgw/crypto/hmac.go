package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"hash"
	"os"
	"strings"

	"github.com/rs/zerolog/log"
)

// HMACVerifier is responsible for verifying HMAC signatures
type HMACVerifier struct {
	secret      []byte
	algorithm   string
	initialized bool
}

// NewHMACVerifier creates a new HMACVerifier
func NewHMACVerifier(algorithm string, secretPath string) (*HMACVerifier, error) {
	var secret []byte
	var err error

	if secretPath != "" {
		secret, err = os.ReadFile(secretPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read HMAC secret from %s: %w", secretPath, err)
		}
	} else {
		log.Warn().Msg("No HMAC secret path provided, using an empty secret")
		secret = []byte{}
	}

	// Validate algorithm
	algorithm = strings.ToUpper(algorithm)
	switch algorithm {
	case "SHA256", "SHA384", "SHA512":
		// Supported algorithms
	default:
		return nil, fmt.Errorf("unsupported HMAC algorithm: %s", algorithm)
	}

	return &HMACVerifier{
		secret:      secret,
		algorithm:   algorithm,
		initialized: true,
	}, nil
}

// VerifyHMAC verifies the HMAC signature for a payload
func (v *HMACVerifier) VerifyHMAC(signature []byte, payload []byte) (bool, error) {
	if !v.initialized {
		return false, fmt.Errorf("HMAC verifier not properly initialized")
	}

	// Create new HMAC hasher
	var hasher hash.Hash
	switch v.algorithm {
	case "SHA256":
		hasher = hmac.New(sha256.New, v.secret)
	case "SHA384":
		hasher = hmac.New(sha512.New384, v.secret)
	case "SHA512":
		hasher = hmac.New(sha512.New, v.secret)
	default:
		return false, fmt.Errorf("unsupported HMAC algorithm: %s", v.algorithm)
	}

	// Compute HMAC
	hasher.Write(payload)
	expectedSignature := hasher.Sum(nil)

	// Compare signatures in constant time to prevent timing attacks
	return hmac.Equal(signature, expectedSignature), nil
}

// GenerateHMAC generates an HMAC signature for a payload
func (v *HMACVerifier) GenerateHMAC(payload []byte) ([]byte, error) {
	if !v.initialized {
		return nil, fmt.Errorf("HMAC verifier not properly initialized")
	}

	// Create new HMAC hasher
	var hasher hash.Hash
	switch v.algorithm {
	case "SHA256":
		hasher = hmac.New(sha256.New, v.secret)
	case "SHA384":
		hasher = hmac.New(sha512.New384, v.secret)
	case "SHA512":
		hasher = hmac.New(sha512.New, v.secret)
	default:
		return nil, fmt.Errorf("unsupported HMAC algorithm: %s", v.algorithm)
	}

	// Compute HMAC
	hasher.Write(payload)
	signature := hasher.Sum(nil)

	return signature, nil
}

// GenerateHMACHex generates an HMAC signature for a payload and returns it as a hex string
func (v *HMACVerifier) GenerateHMACHex(payload []byte) (string, error) {
	signature, err := v.GenerateHMAC(payload)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(signature), nil
}

// VerifyHMACHex verifies an HMAC signature provided as a hex string
func (v *HMACVerifier) VerifyHMACHex(signatureHex string, payload []byte) (bool, error) {
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		return false, fmt.Errorf("failed to decode hex signature: %w", err)
	}
	return v.VerifyHMAC(signature, payload)
}
