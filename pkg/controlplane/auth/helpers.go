package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/pbkdf2"
)

// HashPassword hashes a password using PBKDF2 with a random salt
// This is a proper implementation rather than the placeholder in the API gateway
func HashPassword(password string) string {
	// Generate a random salt
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	if err != nil {
		// If we can't get random data, use a derivable but not completely predictable salt
		// This is not ideal but better than no salt
		defaultSalt := fmt.Sprintf("salt-%s-%d", password, len(password))
		salt = []byte(defaultSalt)[:16]
	}

	// Use PBKDF2 with SHA-256 and 10000 iterations (adjust based on security needs)
	iterations := 10000
	keyLen := 32
	dk := pbkdf2.Key([]byte(password), salt, iterations, keyLen, sha256.New)

	// Format as "algorithm:iterations:salt:hash"
	return fmt.Sprintf("pbkdf2:sha256:%d:%s:%s",
		iterations,
		base64.StdEncoding.EncodeToString(salt),
		hex.EncodeToString(dk))
}

// VerifyPassword verifies a password against a stored hash
func VerifyPassword(storedHash string, password string) bool {
	// Parse the stored hash
	parts := strings.Split(storedHash, ":")
	if len(parts) != 5 || parts[0] != "pbkdf2" || parts[1] != "sha256" {
		return false // Invalid format
	}

	// Parse iterations
	iterations := 10000 // Default
	if _, err := fmt.Sscanf(parts[2], "%d", &iterations); err != nil {
		// Log the error but continue with default iterations
		// This preserves backward compatibility with existing hashes
		log.Warn().Err(err).Str("iterations_str", parts[2]).Msg("Failed to parse iterations from hash, using default")
	}

	// Decode salt
	salt, err := base64.StdEncoding.DecodeString(parts[3])
	if err != nil {
		return false
	}

	// Decode stored key
	storedKey, err := hex.DecodeString(parts[4])
	if err != nil {
		return false
	}

	// Hash the provided password with the same parameters
	keyLen := len(storedKey)
	dk := pbkdf2.Key([]byte(password), salt, iterations, keyLen, sha256.New)

	// Compare in constant time to prevent timing attacks
	return subtle.ConstantTimeCompare(storedKey, dk) == 1
}

// GenerateRandomToken generates a secure random token of specified length in bytes
func GenerateRandomToken(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// GenerateUniqueID generates a unique ID
// This is a convenience function to avoid duplicating code across auth service files
func GenerateUniqueID() string {
	return generateUniqueID() // Uses the existing function from auth_service.go
}
