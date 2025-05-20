package crypto

import (
	"crypto"
	"fmt"
	"io"
)

// Algorithm represents a cryptographic algorithm type
type Algorithm string

// Algorithm types
const (
	AlgorithmTypeSignature  = "signature"
	AlgorithmTypeKEM        = "kem"
	AlgorithmTypeEncryption = "encryption"
	AlgorithmTypeHash       = "hash"
)

// Algorithm names
const (
	// Classical algorithms
	AlgorithmRSAPKCS1SHA256  = "RSA-PKCS1-SHA256"
	AlgorithmRSAPSSSHA256    = "RSA-PSS-SHA256"
	AlgorithmECDSAP256SHA256 = "ECDSA-P256-SHA256"
	AlgorithmED25519         = "ED25519"
	AlgorithmAESGCM          = "AES-GCM"

	// Post-quantum algorithms
	AlgorithmDilithium3 = "DILITHIUM3"
	AlgorithmKyber768   = "KYBER768"
	AlgorithmFalcon512  = "FALCON512"

	// Hybrid algorithms
	AlgorithmHybridKyberECDH        = "HYBRID-KYBER768-ECDH"
	AlgorithmHybridDilithiumED25519 = "HYBRID-DILITHIUM-ED25519"
)

// VersionedAlgorithm represents an algorithm with a specific version
type VersionedAlgorithm struct {
	Algorithm Algorithm
	Version   string
}

// CryptoProvider defines the interface for cryptographic operations
type CryptoProvider interface {
	// GetName returns the name of the provider
	GetName() string

	// GetSupportedAlgorithms returns the algorithms supported by this provider
	GetSupportedAlgorithms(algorithmType string) []Algorithm

	// Sign creates a signature for the given data
	Sign(privateKey []byte, algorithm Algorithm, data []byte) ([]byte, error)

	// Verify verifies a signature
	Verify(publicKey []byte, algorithm Algorithm, data []byte, signature []byte) (bool, error)

	// Encrypt encrypts data
	Encrypt(publicKey []byte, algorithm Algorithm, plaintext []byte) ([]byte, error)

	// Decrypt decrypts data
	Decrypt(privateKey []byte, algorithm Algorithm, ciphertext []byte) ([]byte, error)

	// EncapsulateKey performs key encapsulation (for KEMs)
	EncapsulateKey(publicKey []byte, algorithm Algorithm) (ciphertext []byte, sharedSecret []byte, err error)

	// DecapsulateKey performs key decapsulation (for KEMs)
	DecapsulateKey(privateKey []byte, algorithm Algorithm, ciphertext []byte) (sharedSecret []byte, err error)

	// GenerateKeyPair generates a new key pair
	GenerateKeyPair(algorithm Algorithm, seed io.Reader) (privateKey []byte, publicKey []byte, err error)

	// Hash computes a hash of the given data
	Hash(algorithm Algorithm, data []byte) ([]byte, error)

	// GetHash returns the crypto.Hash for the given algorithm
	GetHash(algorithm Algorithm) (crypto.Hash, error)
}

// ProviderRegistry manages cryptographic providers
type ProviderRegistry struct {
	providers map[string]CryptoProvider
	default_  string
}

// NewProviderRegistry creates a new provider registry
func NewProviderRegistry() *ProviderRegistry {
	return &ProviderRegistry{
		providers: make(map[string]CryptoProvider),
	}
}

// RegisterProvider registers a provider
func (r *ProviderRegistry) RegisterProvider(provider CryptoProvider) {
	r.providers[provider.GetName()] = provider
	// If this is the first provider, make it the default
	if r.default_ == "" {
		r.default_ = provider.GetName()
	}
}

// SetDefaultProvider sets the default provider
func (r *ProviderRegistry) SetDefaultProvider(name string) error {
	if _, ok := r.providers[name]; !ok {
		return ErrProviderNotFound
	}
	r.default_ = name
	return nil
}

// GetProvider returns a provider by name
func (r *ProviderRegistry) GetProvider(name string) (CryptoProvider, error) {
	if provider, ok := r.providers[name]; ok {
		return provider, nil
	}
	return nil, ErrProviderNotFound
}

// GetDefaultProvider returns the default provider
func (r *ProviderRegistry) GetDefaultProvider() (CryptoProvider, error) {
	if r.default_ == "" {
		return nil, ErrNoDefaultProvider
	}
	return r.providers[r.default_], nil
}

// Standard error types
var (
	ErrProviderNotFound     = fmt.Errorf("crypto provider not found")
	ErrNoDefaultProvider    = fmt.Errorf("no default crypto provider set")
	ErrUnsupportedAlgorithm = fmt.Errorf("unsupported algorithm")
)
