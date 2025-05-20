package crypto

import (
	"crypto"
	"fmt"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// HybridProvider implements CryptoProvider for hybrid algorithms
// It combines classical and post-quantum algorithms for defense in depth
type HybridProvider struct {
	classicProvider *ClassicProvider
	pqProvider      *PQProvider
}

// NewHybridProvider creates a new HybridProvider
func NewHybridProvider() *HybridProvider {
	return &HybridProvider{
		classicProvider: NewClassicProvider(),
		pqProvider:      NewPQProvider(),
	}
}

// GetName returns the name of the provider
func (p *HybridProvider) GetName() string {
	return "hybrid"
}

// GetSupportedAlgorithms returns the algorithms supported by this provider
func (p *HybridProvider) GetSupportedAlgorithms(algorithmType string) []Algorithm {
	switch algorithmType {
	case AlgorithmTypeSignature:
		return []Algorithm{
			Algorithm(AlgorithmHybridDilithiumED25519),
		}
	case AlgorithmTypeKEM:
		return []Algorithm{
			Algorithm(AlgorithmHybridKyberECDH),
		}
	default:
		return []Algorithm{}
	}
}

// Sign creates a signature for the given data
func (p *HybridProvider) Sign(privateKeyData []byte, algorithm Algorithm, data []byte) ([]byte, error) {
	switch algorithm {
	case Algorithm(AlgorithmHybridDilithiumED25519):
		// Split the private key data - format is [dilithium_key_length][dilithium_key][ed25519_key]
		// This is a simplified approach - in a real implementation, we would have a more robust method
		// to encode and manage hybrid keys

		// For demonstration, assume first 2560 bytes are Dilithium key (mode3)
		dilithiumKeySize := mode3.PrivateKeySize // Approximately for mode3
		if len(privateKeyData) < dilithiumKeySize {
			return nil, fmt.Errorf("private key too short for hybrid: %d bytes", len(privateKeyData))
		}

		dilithiumKey := privateKeyData[:dilithiumKeySize]
		ed25519Key := privateKeyData[dilithiumKeySize:]

		// Sign with both algorithms
		dilithiumSig, err := p.pqProvider.Sign(dilithiumKey, Algorithm(AlgorithmDilithium3), data)
		if err != nil {
			return nil, fmt.Errorf("dilithium signing failed: %w", err)
		}

		ed25519Sig, err := p.classicProvider.Sign(ed25519Key, Algorithm(AlgorithmED25519), data)
		if err != nil {
			return nil, fmt.Errorf("ed25519 signing failed: %w", err)
		}

		// Combine signatures: [dilithium_sig_len(4 bytes)][dilithium_sig][ed25519_sig]
		dilithiumSigLen := len(dilithiumSig)
		combinedSig := make([]byte, 4+dilithiumSigLen+len(ed25519Sig))

		// Add the length of the Dilithium signature (big-endian)
		combinedSig[0] = byte(dilithiumSigLen >> 24)
		combinedSig[1] = byte(dilithiumSigLen >> 16)
		combinedSig[2] = byte(dilithiumSigLen >> 8)
		combinedSig[3] = byte(dilithiumSigLen)

		// Add the signatures
		copy(combinedSig[4:], dilithiumSig)
		copy(combinedSig[4+dilithiumSigLen:], ed25519Sig)

		return combinedSig, nil

	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
}

// Verify verifies a signature
func (p *HybridProvider) Verify(publicKeyData []byte, algorithm Algorithm, data []byte, signature []byte) (bool, error) {
	switch algorithm {
	case Algorithm(AlgorithmHybridDilithiumED25519):
		// Import dilithium mode3 for proper size constants
		// rather than using hardcoded values
		dilithiumKeySize := mode3.PublicKeySize

		// Split the public key data
		if len(publicKeyData) < dilithiumKeySize {
			return false, fmt.Errorf("public key too short for hybrid: %d bytes", len(publicKeyData))
		}

		dilithiumKey := publicKeyData[:dilithiumKeySize]
		ed25519Key := publicKeyData[dilithiumKeySize:]

		// Parse the signature format [dilithium_sig_len(4 bytes)][dilithium_sig][ed25519_sig]
		if len(signature) < 4 {
			return false, fmt.Errorf("signature too short")
		}

		// Extract dilithium signature length
		dilithiumSigLen := int(signature[0])<<24 | int(signature[1])<<16 | int(signature[2])<<8 | int(signature[3])

		if len(signature) < 4+dilithiumSigLen {
			return false, fmt.Errorf("signature too short for embedded dilithium signature")
		}

		// Extract the signatures
		dilithiumSig := signature[4 : 4+dilithiumSigLen]
		ed25519Sig := signature[4+dilithiumSigLen:]

		// Verify both signatures - both must be valid
		dilithiumValid, err := p.pqProvider.Verify(dilithiumKey, Algorithm(AlgorithmDilithium3), data, dilithiumSig)
		if err != nil {
			return false, fmt.Errorf("dilithium verification error: %w", err)
		}

		ed25519Valid, err := p.classicProvider.Verify(ed25519Key, Algorithm(AlgorithmED25519), data, ed25519Sig)
		if err != nil {
			return false, fmt.Errorf("ed25519 verification error: %w", err)
		}

		// Only valid if both signatures verify
		return dilithiumValid && ed25519Valid, nil

	default:
		return false, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
}

// Encrypt encrypts data
func (p *HybridProvider) Encrypt(publicKeyData []byte, algorithm Algorithm, plaintext []byte) ([]byte, error) {
	// Hybrid provider doesn't support direct encryption, only KEM
	return nil, fmt.Errorf("direct encryption not supported in hybrid provider, use KEM instead")
}

// Decrypt decrypts data
func (p *HybridProvider) Decrypt(privateKeyData []byte, algorithm Algorithm, ciphertext []byte) ([]byte, error) {
	// Hybrid provider doesn't support direct decryption, only KEM
	return nil, fmt.Errorf("direct decryption not supported in hybrid provider, use KEM instead")
}

// EncapsulateKey performs key encapsulation (for KEMs)
func (p *HybridProvider) EncapsulateKey(publicKeyData []byte, algorithm Algorithm) (ciphertext []byte, sharedSecret []byte, err error) {
	switch algorithm {
	case Algorithm(AlgorithmHybridKyberECDH):
		// Not fully implemented in this example, as we would need a complete ECDH implementation
		// In a real implementation, we would split the key data and use both Kyber and ECDH

		// For now, just use Kyber
		return p.pqProvider.EncapsulateKey(publicKeyData, Algorithm(AlgorithmKyber768))

	default:
		return nil, nil, fmt.Errorf("unsupported KEM algorithm: %s", algorithm)
	}
}

// DecapsulateKey performs key decapsulation (for KEMs)
func (p *HybridProvider) DecapsulateKey(privateKeyData []byte, algorithm Algorithm, ciphertext []byte) (sharedSecret []byte, err error) {
	switch algorithm {
	case Algorithm(AlgorithmHybridKyberECDH):
		// Not fully implemented in this example
		// In a real implementation, we would split the key data and use both Kyber and ECDH

		// For now, just use Kyber
		return p.pqProvider.DecapsulateKey(privateKeyData, Algorithm(AlgorithmKyber768), ciphertext)

	default:
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", algorithm)
	}
}

// GenerateKeyPair generates a new key pair
func (p *HybridProvider) GenerateKeyPair(algorithm Algorithm, seed io.Reader) (privateKey []byte, publicKey []byte, err error) {
	switch algorithm {
	case Algorithm(AlgorithmHybridDilithiumED25519):
		// Generate Dilithium key pair
		dilithiumPriv, dilithiumPub, err := p.pqProvider.GenerateKeyPair(Algorithm(AlgorithmDilithium3), seed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate Dilithium key pair: %w", err)
		}

		// Generate Ed25519 key pair
		ed25519Priv, ed25519Pub, err := p.classicProvider.GenerateKeyPair(Algorithm(AlgorithmED25519), seed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate Ed25519 key pair: %w", err)
		}

		// Combine private keys
		privateKey = append(dilithiumPriv, ed25519Priv...)

		// Combine public keys
		publicKey = append(dilithiumPub, ed25519Pub...)

		return privateKey, publicKey, nil

	case Algorithm(AlgorithmHybridKyberECDH):
		// Not fully implemented in this example
		// In a real implementation, we would generate both Kyber and ECDH keys

		// For now, just generate Kyber keys
		return p.pqProvider.GenerateKeyPair(Algorithm(AlgorithmKyber768), seed)

	default:
		return nil, nil, fmt.Errorf("unsupported algorithm for key generation: %s", algorithm)
	}
}

// Hash computes a hash of the given data
func (p *HybridProvider) Hash(algorithm Algorithm, data []byte) ([]byte, error) {
	// Delegate to classic provider for hashing
	return p.classicProvider.Hash(algorithm, data)
}

// GetHash returns the crypto.Hash for the given algorithm
func (p *HybridProvider) GetHash(algorithm Algorithm) (crypto.Hash, error) {
	// Delegate to classic provider for hashing
	return p.classicProvider.GetHash(algorithm)
}
