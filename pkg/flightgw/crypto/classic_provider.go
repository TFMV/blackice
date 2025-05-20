package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"

	"github.com/rs/zerolog/log"
)

// ClassicProvider implements CryptoProvider for classical algorithms
type ClassicProvider struct{}

// NewClassicProvider creates a new ClassicProvider
func NewClassicProvider() *ClassicProvider {
	return &ClassicProvider{}
}

// GetName returns the name of the provider
func (p *ClassicProvider) GetName() string {
	return "classic"
}

// GetSupportedAlgorithms returns the algorithms supported by this provider
func (p *ClassicProvider) GetSupportedAlgorithms(algorithmType string) []Algorithm {
	switch algorithmType {
	case AlgorithmTypeSignature:
		return []Algorithm{
			Algorithm(AlgorithmRSAPKCS1SHA256),
			Algorithm(AlgorithmRSAPSSSHA256),
			Algorithm(AlgorithmECDSAP256SHA256),
			Algorithm(AlgorithmED25519),
		}
	case AlgorithmTypeEncryption:
		return []Algorithm{
			Algorithm(AlgorithmAESGCM),
		}
	case AlgorithmTypeHash:
		return []Algorithm{
			Algorithm("SHA-256"),
			Algorithm("SHA-512"),
		}
	default:
		return []Algorithm{}
	}
}

// Sign creates a signature for the given data
func (p *ClassicProvider) Sign(privateKeyData []byte, algorithm Algorithm, data []byte) ([]byte, error) {
	// Parse private key
	privateKey, err := parsePrivateKey(privateKeyData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Hash the data if needed
	var hashed []byte
	switch algorithm {
	case Algorithm(AlgorithmRSAPKCS1SHA256), Algorithm(AlgorithmRSAPSSSHA256), Algorithm(AlgorithmECDSAP256SHA256):
		h := sha256.Sum256(data)
		hashed = h[:]
	default:
		// For ED25519, we use the data directly
		hashed = data
	}

	// Sign the data
	var signature []byte
	switch algorithm {
	case Algorithm(AlgorithmRSAPKCS1SHA256):
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		signature, err = rsa.SignPKCS1v15(nil, rsaKey, crypto.SHA256, hashed)
		if err != nil {
			return nil, fmt.Errorf("error signing with RSA-PKCS1: %w", err)
		}

	case Algorithm(AlgorithmRSAPSSSHA256):
		rsaKey, ok := privateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an RSA private key")
		}
		signature, err = rsa.SignPSS(nil, rsaKey, crypto.SHA256, hashed, nil)
		if err != nil {
			return nil, fmt.Errorf("error signing with RSA-PSS: %w", err)
		}

	case Algorithm(AlgorithmECDSAP256SHA256):
		ecdsaKey, ok := privateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an ECDSA private key")
		}
		signature, err = ecdsa.SignASN1(nil, ecdsaKey, hashed)
		if err != nil {
			return nil, fmt.Errorf("error signing with ECDSA: %w", err)
		}

	case Algorithm(AlgorithmED25519):
		ed25519Key, ok := privateKey.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("key is not an Ed25519 private key")
		}
		signature = ed25519.Sign(ed25519Key, data)

	default:
		return nil, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}

	return signature, nil
}

// Verify verifies a signature
func (p *ClassicProvider) Verify(publicKeyData []byte, algorithm Algorithm, data []byte, signature []byte) (bool, error) {
	// Parse public key
	publicKey, err := parsePublicKey(publicKeyData)
	if err != nil {
		return false, fmt.Errorf("failed to parse public key: %w", err)
	}

	// Hash the data if needed
	var hashed []byte
	switch algorithm {
	case Algorithm(AlgorithmRSAPKCS1SHA256), Algorithm(AlgorithmRSAPSSSHA256), Algorithm(AlgorithmECDSAP256SHA256):
		h := sha256.Sum256(data)
		hashed = h[:]
	default:
		// For ED25519, we use the data directly
		hashed = data
	}

	// Verify the signature
	switch algorithm {
	case Algorithm(AlgorithmRSAPKCS1SHA256):
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("key is not an RSA public key")
		}
		err = rsa.VerifyPKCS1v15(rsaKey, crypto.SHA256, hashed, signature)
		if err != nil {
			log.Debug().Err(err).Msg("RSA PKCS1v15 signature verification failed")
			return false, nil
		}
		return true, nil

	case Algorithm(AlgorithmRSAPSSSHA256):
		rsaKey, ok := publicKey.(*rsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("key is not an RSA public key")
		}
		err = rsa.VerifyPSS(rsaKey, crypto.SHA256, hashed, signature, nil)
		if err != nil {
			log.Debug().Err(err).Msg("RSA PSS signature verification failed")
			return false, nil
		}
		return true, nil

	case Algorithm(AlgorithmECDSAP256SHA256):
		ecdsaKey, ok := publicKey.(*ecdsa.PublicKey)
		if !ok {
			return false, fmt.Errorf("key is not an ECDSA public key")
		}
		valid := ecdsa.VerifyASN1(ecdsaKey, hashed, signature)
		return valid, nil

	case Algorithm(AlgorithmED25519):
		ed25519Key, ok := publicKey.(ed25519.PublicKey)
		if !ok {
			return false, fmt.Errorf("key is not an Ed25519 public key")
		}
		valid := ed25519.Verify(ed25519Key, data, signature)
		return valid, nil

	default:
		return false, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}
}

// Encrypt encrypts data
func (p *ClassicProvider) Encrypt(publicKeyData []byte, algorithm Algorithm, plaintext []byte) ([]byte, error) {
	// For symmetric encryption like AES-GCM, the "publicKeyData" is actually the shared key
	switch algorithm {
	case Algorithm(AlgorithmAESGCM):
		// The publicKeyData in this case is the AES key
		if len(publicKeyData) != 16 && len(publicKeyData) != 24 && len(publicKeyData) != 32 {
			return nil, fmt.Errorf("invalid AES key length: %d", len(publicKeyData))
		}

		// Create AES cipher
		block, err := aes.NewCipher(publicKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}

		// Create GCM mode
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %w", err)
		}

		// Create nonce
		nonce := make([]byte, gcm.NonceSize())
		if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
			return nil, fmt.Errorf("failed to create nonce: %w", err)
		}

		// Encrypt data
		ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
		return ciphertext, nil

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}

// Decrypt decrypts data
func (p *ClassicProvider) Decrypt(privateKeyData []byte, algorithm Algorithm, ciphertext []byte) ([]byte, error) {
	// For symmetric encryption like AES-GCM, the "privateKeyData" is actually the shared key
	switch algorithm {
	case Algorithm(AlgorithmAESGCM):
		// The privateKeyData in this case is the AES key
		if len(privateKeyData) != 16 && len(privateKeyData) != 24 && len(privateKeyData) != 32 {
			return nil, fmt.Errorf("invalid AES key length: %d", len(privateKeyData))
		}

		// Create AES cipher
		block, err := aes.NewCipher(privateKeyData)
		if err != nil {
			return nil, fmt.Errorf("failed to create AES cipher: %w", err)
		}

		// Create GCM mode
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return nil, fmt.Errorf("failed to create GCM: %w", err)
		}

		// Extract nonce
		nonceSize := gcm.NonceSize()
		if len(ciphertext) < nonceSize {
			return nil, fmt.Errorf("ciphertext too short")
		}
		nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

		// Decrypt data
		plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt data: %w", err)
		}
		return plaintext, nil

	default:
		return nil, fmt.Errorf("unsupported encryption algorithm: %s", algorithm)
	}
}

// EncapsulateKey performs key encapsulation (for KEMs)
// Classical provider doesn't support KEMs, this is for the post-quantum provider
func (p *ClassicProvider) EncapsulateKey(publicKeyData []byte, algorithm Algorithm) (ciphertext []byte, sharedSecret []byte, err error) {
	return nil, nil, fmt.Errorf("key encapsulation not supported in classical provider")
}

// DecapsulateKey performs key decapsulation (for KEMs)
// Classical provider doesn't support KEMs, this is for the post-quantum provider
func (p *ClassicProvider) DecapsulateKey(privateKeyData []byte, algorithm Algorithm, ciphertext []byte) (sharedSecret []byte, err error) {
	return nil, fmt.Errorf("key decapsulation not supported in classical provider")
}

// GenerateKeyPair generates a new key pair
func (p *ClassicProvider) GenerateKeyPair(algorithm Algorithm, seed io.Reader) (privateKey []byte, publicKey []byte, err error) {
	if seed == nil {
		seed = rand.Reader
	}

	switch algorithm {
	case Algorithm(AlgorithmRSAPKCS1SHA256), Algorithm(AlgorithmRSAPSSSHA256):
		// Generate RSA key
		rsaKey, err := rsa.GenerateKey(seed, 2048)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate RSA key: %w", err)
		}

		// Marshal private key
		privKeyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privKeyBytes,
		})

		// Marshal public key
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		publicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		return privateKey, publicKey, nil

	case Algorithm(AlgorithmECDSAP256SHA256):
		// Generate ECDSA key
		ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), seed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate ECDSA key: %w", err)
		}

		// Marshal private key
		privKeyBytes, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privKeyBytes,
		})

		// Marshal public key
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&ecdsaKey.PublicKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		publicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		return privateKey, publicKey, nil

	case Algorithm(AlgorithmED25519):
		// Generate Ed25519 key
		pubKey, privKey, err := ed25519.GenerateKey(seed)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
		}

		// Marshal private key
		privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
		}
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privKeyBytes,
		})

		// Marshal public key
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(pubKey)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to marshal public key: %w", err)
		}
		publicKey = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		return privateKey, publicKey, nil

	default:
		return nil, nil, fmt.Errorf("unsupported algorithm for key generation: %s", algorithm)
	}
}

// Hash computes a hash of the given data
func (p *ClassicProvider) Hash(algorithm Algorithm, data []byte) ([]byte, error) {
	switch algorithm {
	case Algorithm("SHA-256"):
		hash := sha256.Sum256(data)
		return hash[:], nil
	case Algorithm("SHA-512"):
		hash := sha512.Sum512(data)
		return hash[:], nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// GetHash returns the crypto.Hash for the given algorithm
func (p *ClassicProvider) GetHash(algorithm Algorithm) (crypto.Hash, error) {
	switch algorithm {
	case Algorithm("SHA-256"):
		return crypto.SHA256, nil
	case Algorithm("SHA-512"):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %s", algorithm)
	}
}

// Helper functions

// parsePrivateKey parses a PEM encoded private key
func parsePrivateKey(keyData []byte) (interface{}, error) {
	block, _ := pem.Decode(keyData)
	if block == nil {
		return nil, fmt.Errorf("failed to parse PEM block")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		return x509.ParsePKCS8PrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}
