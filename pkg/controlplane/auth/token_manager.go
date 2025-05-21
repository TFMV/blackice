package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/TFMV/blackice/pkg/controlplane/config"
)

// JWTTokenManager implements the TokenManager interface using JWT tokens
type JWTTokenManager struct {
	config         *config.ControlPlaneConfig
	privateKey     *rsa.PrivateKey
	publicKey      *rsa.PublicKey
	tokenBlacklist map[string]time.Time // Map of token ID to expiry time
	blacklistMutex sync.RWMutex
}

// JWT header
type jwtHeader struct {
	Alg string `json:"alg"` // Algorithm used for signing (e.g., "RS256")
	Typ string `json:"typ"` // Token type (e.g., "JWT")
}

// JWT payload
type jwtPayload struct {
	Sub         string   `json:"sub"`         // Subject (user ID)
	Iss         string   `json:"iss"`         // Issuer
	Iat         int64    `json:"iat"`         // Issued at (Unix timestamp)
	Exp         int64    `json:"exp"`         // Expiry (Unix timestamp)
	Jti         string   `json:"jti"`         // JWT ID (unique identifier for this token)
	Permissions []string `json:"permissions"` // User permissions
}

// Create a new JWT Token Manager
func NewJWTTokenManager(cfg *config.ControlPlaneConfig) (*JWTTokenManager, error) {
	// TODO: In a real implementation, we would load RSA keys from secure storage
	// For simplicity, we'll generate a new key pair here
	// This would not be done in production as keys would be lost on restart
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	return &JWTTokenManager{
		config:         cfg,
		privateKey:     privateKey,
		publicKey:      &privateKey.PublicKey,
		tokenBlacklist: make(map[string]time.Time),
	}, nil
}

// GenerateToken creates a new JWT token for the specified user with the given permissions
func (tm *JWTTokenManager) GenerateToken(userID string, permissions []string, duration time.Duration) (string, error) {
	// Create JWT token
	now := time.Now()
	exp := now.Add(duration)

	// Create a unique token ID
	tokenID := generateTokenID()

	// Create the payload
	payload := jwtPayload{
		Sub:         userID,
		Iss:         tm.config.Auth.TokenIssuer,
		Iat:         now.Unix(),
		Exp:         exp.Unix(),
		Jti:         tokenID,
		Permissions: permissions,
	}

	// Create the header
	header := jwtHeader{
		Alg: "RS256",
		Typ: "JWT",
	}

	// Encode header and payload to JSON
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	// Base64 encode the header and payload
	headerBase64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadBase64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create the signature input: <header-base64>.<payload-base64>
	signInput := headerBase64 + "." + payloadBase64

	// Calculate the hash of the signature input
	hash := sha256.Sum256([]byte(signInput))

	// Sign the hash with the private key
	signature, err := rsa.SignPKCS1v15(rand.Reader, tm.privateKey, 0, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	// Base64 encode the signature
	signatureBase64 := base64.RawURLEncoding.EncodeToString(signature)

	// Combine all parts to form the final JWT token
	tokenString := signInput + "." + signatureBase64

	return tokenString, nil
}

// ValidateToken validates a JWT token and returns the user ID and permissions
func (tm *JWTTokenManager) ValidateToken(tokenString string) (string, []string, error) {
	// Split the token into its three parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return "", nil, ErrInvalidToken
	}

	headerBase64, payloadBase64, signatureBase64 := parts[0], parts[1], parts[2]

	// Verify the signature
	signInput := headerBase64 + "." + payloadBase64
	hash := sha256.Sum256([]byte(signInput))

	// Decode the signature from base64
	signature, err := base64.RawURLEncoding.DecodeString(signatureBase64)
	if err != nil {
		return "", nil, ErrInvalidToken
	}

	// Verify the signature using the public key
	err = rsa.VerifyPKCS1v15(tm.publicKey, 0, hash[:], signature)
	if err != nil {
		return "", nil, ErrInvalidToken
	}

	// Decode the payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return "", nil, ErrInvalidToken
	}

	// Parse the payload JSON
	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", nil, ErrInvalidToken
	}

	// Check if the token is in the blacklist
	tm.blacklistMutex.RLock()
	_, blacklisted := tm.tokenBlacklist[payload.Jti]
	tm.blacklistMutex.RUnlock()
	if blacklisted {
		return "", nil, ErrInvalidToken
	}

	// Check if the token has expired
	now := time.Now().Unix()
	if payload.Exp < now {
		return "", nil, ErrTokenExpired
	}

	// Token is valid, return the user ID and permissions
	return payload.Sub, payload.Permissions, nil
}

// RevokeToken adds a token to the blacklist
func (tm *JWTTokenManager) RevokeToken(tokenString string) error {
	// Parse the token to get its ID and expiry
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return ErrInvalidToken
	}

	payloadBase64 := parts[1]

	// Decode the payload
	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadBase64)
	if err != nil {
		return ErrInvalidToken
	}

	// Parse the payload JSON
	var payload jwtPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return ErrInvalidToken
	}

	// Add the token to the blacklist
	expiry := time.Unix(payload.Exp, 0)
	tm.blacklistMutex.Lock()
	tm.tokenBlacklist[payload.Jti] = expiry
	tm.blacklistMutex.Unlock()

	// Schedule clean-up of expired tokens in the blacklist
	go tm.cleanupBlacklist()

	return nil
}

// cleanupBlacklist removes expired tokens from the blacklist
func (tm *JWTTokenManager) cleanupBlacklist() {
	tm.blacklistMutex.Lock()
	defer tm.blacklistMutex.Unlock()

	now := time.Now()
	for id, expiry := range tm.tokenBlacklist {
		if now.After(expiry) {
			delete(tm.tokenBlacklist, id)
		}
	}
}

// generateTokenID creates a unique ID for a token
func generateTokenID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}

	return base64.RawURLEncoding.EncodeToString(b)
}
