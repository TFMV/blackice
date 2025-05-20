package trust

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SourceInfo contains information about a registered data source
type SourceInfo struct {
	SourceID     string            `json:"source_id"`
	Description  string            `json:"description"`
	PublicKey    []byte            `json:"public_key"`
	KeyAlgorithm string            `json:"key_algorithm"`
	RegisteredAt time.Time         `json:"registered_at"`
	LastActivity time.Time         `json:"last_activity"`
	ContentTypes []string          `json:"content_types"`
	Metadata     map[string]string `json:"metadata"`
}

// Registry manages registered data sources
type Registry struct {
	mu          sync.RWMutex
	sources     map[string]*SourceInfo
	trustScorer *TrustScorer
}

// NewRegistry creates a new registry
func NewRegistry(trustScorer *TrustScorer) *Registry {
	return &Registry{
		sources:     make(map[string]*SourceInfo),
		trustScorer: trustScorer,
	}
}

// RegisterSource registers a new data source
func (r *Registry) RegisterSource(
	sourceID string,
	description string,
	publicKeyPath string,
	keyAlgorithm string,
	initialTrustScore int,
	contentTypes []string,
	metadata map[string]string,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sources[sourceID]; exists {
		return fmt.Errorf("source already registered: %s", sourceID)
	}

	// Read public key
	var publicKey []byte
	var err error
	if publicKeyPath != "" {
		publicKey, err = os.ReadFile(publicKeyPath)
		if err != nil {
			return fmt.Errorf("failed to read public key: %w", err)
		}

		// Validate public key
		if err := validatePublicKey(publicKey, keyAlgorithm); err != nil {
			return fmt.Errorf("invalid public key: %w", err)
		}
	} else {
		log.Warn().
			Str("source_id", sourceID).
			Msg("Registering source without a public key")
	}

	now := time.Now()
	r.sources[sourceID] = &SourceInfo{
		SourceID:     sourceID,
		Description:  description,
		PublicKey:    publicKey,
		KeyAlgorithm: keyAlgorithm,
		RegisteredAt: now,
		LastActivity: now,
		ContentTypes: contentTypes,
		Metadata:     metadata,
	}

	// Register with trust scorer
	if r.trustScorer != nil {
		if err := r.trustScorer.RegisterSource(sourceID, initialTrustScore); err != nil {
			// Continue registration even if trust score registration fails
			log.Error().
				Err(err).
				Str("source_id", sourceID).
				Msg("Failed to register source with trust scorer")
		}
	}

	log.Info().
		Str("source_id", sourceID).
		Str("key_algorithm", keyAlgorithm).
		Int("initial_trust_score", initialTrustScore).
		Msg("Registered new data source")

	return nil
}

// GetSource retrieves information about a registered source
func (r *Registry) GetSource(sourceID string) (*SourceInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	source, exists := r.sources[sourceID]
	if !exists {
		return nil, fmt.Errorf("source not found: %s", sourceID)
	}

	return source, nil
}

// UpdateSourceActivity updates the last activity timestamp for a source
func (r *Registry) UpdateSourceActivity(sourceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	source, exists := r.sources[sourceID]
	if !exists {
		return fmt.Errorf("source not found: %s", sourceID)
	}

	source.LastActivity = time.Now()
	return nil
}

// ListSources returns a list of all registered sources
func (r *Registry) ListSources() ([]*SourceInfo, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sources := make([]*SourceInfo, 0, len(r.sources))
	for _, source := range r.sources {
		sources = append(sources, source)
	}

	return sources, nil
}

// RemoveSource removes a registered source
func (r *Registry) RemoveSource(sourceID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.sources[sourceID]; !exists {
		return fmt.Errorf("source not found: %s", sourceID)
	}

	delete(r.sources, sourceID)

	log.Info().
		Str("source_id", sourceID).
		Msg("Removed data source from registry")

	return nil
}

// UpdateSourceMetadata updates the metadata for a source
func (r *Registry) UpdateSourceMetadata(sourceID string, metadata map[string]string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	source, exists := r.sources[sourceID]
	if !exists {
		return fmt.Errorf("source not found: %s", sourceID)
	}

	// Replace the metadata
	source.Metadata = metadata

	log.Info().
		Str("source_id", sourceID).
		Msg("Updated source metadata")

	return nil
}

// IsContentTypeAllowed checks if a content type is allowed for a source
func (r *Registry) IsContentTypeAllowed(sourceID string, contentType string) (bool, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	source, exists := r.sources[sourceID]
	if !exists {
		return false, fmt.Errorf("source not found: %s", sourceID)
	}

	// If no content types are specified, allow all
	if len(source.ContentTypes) == 0 {
		return true, nil
	}

	// Check if the content type is in the allowed list
	for _, ct := range source.ContentTypes {
		if ct == contentType {
			return true, nil
		}
	}

	return false, nil
}

// validatePublicKey checks if a public key is valid
func validatePublicKey(keyData []byte, algorithm string) error {
	// For now, just check if it's a valid PEM block
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to parse PEM block")
	}

	// For standard PKI keys, we can try to parse them
	if algorithm == "RSA" || algorithm == "ECDSA" || algorithm == "ED25519" {
		_, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse public key: %w", err)
		}
	}

	// For post-quantum algorithms, we currently don't have built-in validation
	// We'd need to implement specific validation for each algorithm
	// For now, just assume they're valid if they parse as PEM

	return nil
}
