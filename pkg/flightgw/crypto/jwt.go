// Package crypto provides military-grade cryptographic functionality for BlackIce
package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

// JWTValidator provides military-grade JWT token validation
type JWTValidator struct {
	secretKey []byte
}

// NewJWTValidator creates a new JWT validator using the secret key from the specified file
func NewJWTValidator(secretKeyPath string) (*JWTValidator, error) {
	// Read the secret key from the file
	secretBytes, err := os.ReadFile(secretKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read JWT secret key file: %w", err)
	}

	// Trim any whitespace
	secretKey := []byte(strings.TrimSpace(string(secretBytes)))

	if len(secretKey) < 32 {
		return nil, fmt.Errorf("JWT secret key is too short (min 32 bytes required)")
	}

	return &JWTValidator{
		secretKey: secretKey,
	}, nil
}

// ValidateToken validates a JWT token and returns the claims if valid
func (v *JWTValidator) ValidateToken(tokenString string) (map[string]interface{}, error) {
	// Split the token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	// Extract the header, payload, and signature
	headerB64, payloadB64, sigB64 := parts[0], parts[1], parts[2]

	// Verify the signature
	// The signature is calculated over the base64-encoded header and payload
	data := headerB64 + "." + payloadB64

	// Decode the signature from base64
	signature, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}

	// Calculate the expected signature
	h := hmac.New(sha256.New, v.secretKey)
	h.Write([]byte(data))
	expectedSignature := h.Sum(nil)

	// Compare signatures using constant-time comparison to prevent timing attacks
	if !hmac.Equal(signature, expectedSignature) {
		return nil, fmt.Errorf("invalid signature")
	}

	// Decode the payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return nil, fmt.Errorf("invalid payload encoding: %w", err)
	}

	// Parse the claims
	var claims map[string]interface{}
	if err := json.Unmarshal(payloadJSON, &claims); err != nil {
		return nil, fmt.Errorf("invalid claim format: %w", err)
	}

	// Verify standard claims
	now := time.Now().Unix()

	// Check expiration time
	if exp, ok := claims["exp"].(float64); ok {
		if now > int64(exp) {
			return nil, fmt.Errorf("token expired")
		}
	}

	// Check not before time
	if nbf, ok := claims["nbf"].(float64); ok {
		if now < int64(nbf) {
			return nil, fmt.Errorf("token not yet valid")
		}
	}

	// Check issued at time
	if iat, ok := claims["iat"].(float64); ok {
		if now < int64(iat) {
			return nil, fmt.Errorf("token issued in the future")
		}
	}

	log.Debug().Str("sub", fmt.Sprintf("%v", claims["sub"])).Msg("JWT token validated successfully")

	return claims, nil
}

// GenerateToken creates a new JWT token with the specified claims
// This is primarily for testing and should not be used in production
// as proper token issuance should be handled by an auth service
func (v *JWTValidator) GenerateToken(claims map[string]interface{}) (string, error) {
	// Set standard claims if not present
	now := time.Now().Unix()

	if _, ok := claims["iat"]; !ok {
		claims["iat"] = now
	}

	if _, ok := claims["nbf"]; !ok {
		claims["nbf"] = now
	}

	if _, ok := claims["exp"]; !ok {
		// Default expiration: 1 hour
		claims["exp"] = now + 3600
	}

	// Create the JWT header
	header := map[string]string{
		"alg": "HS256",
		"typ": "JWT",
	}

	// Encode the header to JSON and then to base64
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to encode header: %w", err)
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encode the payload to JSON and then to base64
	payloadJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("failed to encode claims: %w", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Calculate the signature
	data := headerB64 + "." + payloadB64
	h := hmac.New(sha256.New, v.secretKey)
	h.Write([]byte(data))
	signature := h.Sum(nil)
	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	// Combine all parts to form the JWT token
	token := headerB64 + "." + payloadB64 + "." + signatureB64

	return token, nil
}
