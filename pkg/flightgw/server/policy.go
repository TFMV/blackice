package server

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// PolicyType defines the type of policy
type PolicyType string

const (
	// SecurityPolicy defines security-related policies
	SecurityPolicy PolicyType = "security"
	// RoutingPolicy defines routing and proxy policies
	RoutingPolicy PolicyType = "routing"
	// RateLimitPolicy defines rate limiting policies
	RateLimitPolicy PolicyType = "ratelimit"
	// AccessPolicy defines access control policies
	AccessPolicy PolicyType = "access"
)

// Policy represents a configurable policy that can be updated at runtime
type Policy struct {
	Type      PolicyType             `json:"type"`
	Name      string                 `json:"name"`
	Version   int                    `json:"version"`
	Enabled   bool                   `json:"enabled"`
	Settings  map[string]interface{} `json:"settings"`
	CreatedAt time.Time              `json:"created_at"`
	UpdatedAt time.Time              `json:"updated_at"`
}

// PolicyManager handles dynamic policy updates for the gateway
type PolicyManager struct {
	mu              sync.RWMutex
	policies        map[string]*Policy
	policyListeners []PolicyUpdateListener
	configPath      string
}

// PolicyUpdateListener is a callback interface for policy change notifications
type PolicyUpdateListener interface {
	OnPolicyUpdate(policy *Policy)
}

// NewPolicyManager creates a new policy manager
func NewPolicyManager(configPath string) *PolicyManager {
	pm := &PolicyManager{
		policies:   make(map[string]*Policy),
		configPath: configPath,
	}
	return pm
}

// RegisterListener adds a listener for policy updates
func (pm *PolicyManager) RegisterListener(listener PolicyUpdateListener) {
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.policyListeners = append(pm.policyListeners, listener)
}

// GetPolicy retrieves a policy by its name
func (pm *PolicyManager) GetPolicy(name string) (*Policy, bool) {
	pm.mu.RLock()
	defer pm.mu.RUnlock()
	policy, exists := pm.policies[name]
	return policy, exists
}

// GetPoliciesByType returns all policies of a given type
func (pm *PolicyManager) GetPoliciesByType(policyType PolicyType) []*Policy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var result []*Policy
	for _, policy := range pm.policies {
		if policy.Type == policyType {
			result = append(result, policy)
		}
	}
	return result
}

// GetAllPolicies returns all policies
func (pm *PolicyManager) GetAllPolicies() []*Policy {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	var result []*Policy
	for _, policy := range pm.policies {
		result = append(result, policy)
	}
	return result
}

// UpdatePolicy updates or adds a policy
func (pm *PolicyManager) UpdatePolicy(policy *Policy) error {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	existingPolicy, exists := pm.policies[policy.Name]
	if exists {
		// Check version to prevent concurrent modification issues
		if policy.Version <= existingPolicy.Version {
			return fmt.Errorf("policy update has older or same version: current=%d, update=%d",
				existingPolicy.Version, policy.Version)
		}
	}

	// Update timestamps
	policy.UpdatedAt = time.Now()
	if !exists {
		policy.CreatedAt = policy.UpdatedAt
	}

	// Store the updated policy
	pm.policies[policy.Name] = policy

	// Notify listeners
	for _, listener := range pm.policyListeners {
		go listener.OnPolicyUpdate(policy)
	}

	log.Info().
		Str("policy", policy.Name).
		Int("version", policy.Version).
		Bool("enabled", policy.Enabled).
		Msg("Policy updated")

	// Save policies to disk
	go pm.savePolicies()

	return nil
}

// DeletePolicy removes a policy
func (pm *PolicyManager) DeletePolicy(name string) bool {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	_, exists := pm.policies[name]
	if !exists {
		return false
	}

	delete(pm.policies, name)

	// Save policies to disk
	go pm.savePolicies()

	return true
}

// LoadPolicies loads policies from the configuration file
func (pm *PolicyManager) LoadPolicies() error {
	if pm.configPath == "" {
		log.Warn().Msg("No policy configuration path set, skipping policy load")
		return nil
	}

	data, err := os.ReadFile(pm.configPath)
	if err != nil {
		if os.IsNotExist(err) {
			log.Info().Str("path", pm.configPath).Msg("Policy file does not exist, will create on first update")
			return nil
		}
		return fmt.Errorf("failed to read policy file: %w", err)
	}

	var policies []*Policy
	if err := json.Unmarshal(data, &policies); err != nil {
		return fmt.Errorf("failed to parse policy file: %w", err)
	}

	pm.mu.Lock()
	defer pm.mu.Unlock()

	// Reset existing policies
	pm.policies = make(map[string]*Policy)

	// Add loaded policies
	for _, policy := range policies {
		pm.policies[policy.Name] = policy
		log.Info().
			Str("policy", policy.Name).
			Int("version", policy.Version).
			Bool("enabled", policy.Enabled).
			Msg("Policy loaded")
	}

	return nil
}

// savePolicies saves the current policies to the configuration file
func (pm *PolicyManager) savePolicies() {
	if pm.configPath == "" {
		log.Warn().Msg("No policy configuration path set, skipping policy save")
		return
	}

	pm.mu.RLock()

	// Convert map to slice for serialization
	var policies []*Policy
	for _, policy := range pm.policies {
		policies = append(policies, policy)
	}

	pm.mu.RUnlock()

	data, err := json.MarshalIndent(policies, "", "  ")
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal policies")
		return
	}

	if err := os.WriteFile(pm.configPath, data, 0644); err != nil {
		log.Error().Err(err).Str("path", pm.configPath).Msg("Failed to save policies")
		return
	}

	log.Debug().Str("path", pm.configPath).Msg("Policies saved to disk")
}
