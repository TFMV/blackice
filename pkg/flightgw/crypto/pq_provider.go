package crypto

import (
	"crypto"
	"fmt"
	"io"

	"github.com/cloudflare/circl/kem/kyber/kyber768"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
)

// PQProvider implements CryptoProvider for post-quantum algorithms
type PQProvider struct{}

// NewPQProvider creates a new PQProvider
func NewPQProvider() *PQProvider {
	return &PQProvider{}
}

// GetName returns the name of the provider
func (p *PQProvider) GetName() string {
	return "post-quantum"
}

// GetSupportedAlgorithms returns the algorithms supported by this provider
func (p *PQProvider) GetSupportedAlgorithms(algorithmType string) []Algorithm {
	switch algorithmType {
	case AlgorithmTypeSignature:
		return []Algorithm{
			Algorithm(AlgorithmDilithium3),
		}
	case AlgorithmTypeKEM:
		return []Algorithm{
			Algorithm(AlgorithmKyber768),
		}
	default:
		return []Algorithm{}
	}
}

// Sign creates a signature for the given data
func (p *PQProvider) Sign(privateKeyData []byte, algorithm Algorithm, data []byte) ([]byte, error) {
	switch algorithm {
	case Algorithm(AlgorithmDilithium3):
		// Parse private key - need to unmarshal it first
		var sk mode3.PrivateKey
		if err := sk.UnmarshalBinary(privateKeyData); err != nil {
			return nil, fmt.Errorf("failed to unmarshal Dilithium private key: %w", err)
		}

		// Create signature buffer
		signature := make([]byte, mode3.SignatureSize)

		// Sign the data
		mode3.SignTo(&sk, data, signature)
		return signature, nil

	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
}

// Verify verifies a signature
func (p *PQProvider) Verify(publicKeyData []byte, algorithm Algorithm, data []byte, signature []byte) (bool, error) {
	switch algorithm {
	case Algorithm(AlgorithmDilithium3):
		// Parse public key - need to unmarshal it first
		var pk mode3.PublicKey
		if err := pk.UnmarshalBinary(publicKeyData); err != nil {
			return false, fmt.Errorf("failed to unmarshal Dilithium public key: %w", err)
		}

		// Verify the signature
		return mode3.Verify(&pk, data, signature), nil

	default:
		return false, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
}

// Encrypt encrypts data
// PQ provider doesn't support direct encryption, only KEM
func (p *PQProvider) Encrypt(publicKeyData []byte, algorithm Algorithm, plaintext []byte) ([]byte, error) {
	return nil, fmt.Errorf("direct encryption not supported in post-quantum provider, use KEM instead")
}

// Decrypt decrypts data
// PQ provider doesn't support direct decryption, only KEM
func (p *PQProvider) Decrypt(privateKeyData []byte, algorithm Algorithm, ciphertext []byte) ([]byte, error) {
	return nil, fmt.Errorf("direct decryption not supported in post-quantum provider, use KEM instead")
}

// EncapsulateKey performs key encapsulation (for KEMs)
func (p *PQProvider) EncapsulateKey(publicKeyData []byte, algorithm Algorithm) (ciphertext []byte, sharedSecret []byte, err error) {
	switch algorithm {
	case Algorithm(AlgorithmKyber768):
		// Use scheme to unmarshal the public key
		scheme := kyber768.Scheme()
		pk, err := scheme.UnmarshalBinaryPublicKey(publicKeyData)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal Kyber public key: %w", err)
		}

		// Encapsulate key
		ct, ss, err := scheme.Encapsulate(pk)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encapsulate key: %w", err)
		}

		return ct, ss, nil

	default:
		return nil, nil, fmt.Errorf("unsupported KEM algorithm: %s", algorithm)
	}
}

// DecapsulateKey performs key decapsulation (for KEMs)
func (p *PQProvider) DecapsulateKey(privateKeyData []byte, algorithm Algorithm, ciphertext []byte) (sharedSecret []byte, err error) {
	switch algorithm {
	case Algorithm(AlgorithmKyber768):
		// Use scheme to unmarshal the private key
		scheme := kyber768.Scheme()
		sk, err := scheme.UnmarshalBinaryPrivateKey(privateKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal Kyber private key: %w", err)
		}

		// Decapsulate key
		ss, err := scheme.Decapsulate(sk, ciphertext)
		if err != nil {
			return nil, fmt.Errorf("failed to decapsulate key: %w", err)
		}

		return ss, nil

	default:
		return nil, fmt.Errorf("unsupported KEM algorithm: %s", algorithm)
	}
}

// GenerateKeyPair generates a new key pair
func (p *PQProvider) GenerateKeyPair(algorithm Algorithm, seed io.Reader) (privateKey []byte, publicKey []byte, err error) {
	switch algorithm {
	case Algorithm(AlgorithmDilithium3):
		// Generate Dilithium key pair
		pub, priv, err := mode3.GenerateKey(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate Dilithium key pair: %w", err)
		}

		// Marshal keys to bytes
		publicKeyBytes, err := pub.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal Dilithium public key: %w", err)
		}

		privateKeyBytes, err := priv.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal Dilithium private key: %w", err)
		}

		return privateKeyBytes, publicKeyBytes, nil

	case Algorithm(AlgorithmKyber768):
		// Generate Kyber key pair
		pub, priv, err := kyber768.GenerateKeyPair(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate Kyber key pair: %w", err)
		}

		// Marshal keys to bytes
		publicKeyBytes, err := pub.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal Kyber public key: %w", err)
		}

		privateKeyBytes, err := priv.MarshalBinary()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal Kyber private key: %w", err)
		}

		return privateKeyBytes, publicKeyBytes, nil

	default:
		return nil, nil, fmt.Errorf("unsupported algorithm for key generation: %s", algorithm)
	}
}

// Hash computes a hash of the given data
// PQ provider doesn't add new hash functions, use the classic provider for hashing
func (p *PQProvider) Hash(algorithm Algorithm, data []byte) ([]byte, error) {
	return nil, fmt.Errorf("hashing not supported in post-quantum provider, use classic provider")
}

// GetHash returns the crypto.Hash for the given algorithm
// PQ provider doesn't add new hash functions, use the classic provider for hashing
func (p *PQProvider) GetHash(algorithm Algorithm) (crypto.Hash, error) {
	return 0, fmt.Errorf("hashing not supported in post-quantum provider, use classic provider")
}
