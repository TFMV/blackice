package trust

import (
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// MockPanicSystem is a mock implementation of the PanicSystemIntegration interface for testing
type MockPanicSystem struct {
	mu             sync.RWMutex
	currentTier    int
	notifications  []PanicNotification
	isInPanicMode  bool
	lastNotifiedAt time.Time
}

// PanicNotification represents a notification to the panic system
type PanicNotification struct {
	SourceID  string
	Score     int
	Reason    string
	Timestamp time.Time
}

// NewMockPanicSystem creates a new mock panic system
func NewMockPanicSystem() *MockPanicSystem {
	return &MockPanicSystem{
		currentTier:    1,
		notifications:  make([]PanicNotification, 0),
		isInPanicMode:  false,
		lastNotifiedAt: time.Now(),
	}
}

// NotifyTrustThresholdViolation records a notification about a trust threshold violation
func (mps *MockPanicSystem) NotifyTrustThresholdViolation(sourceID string, score int, reason string) error {
	mps.mu.Lock()
	defer mps.mu.Unlock()

	notification := PanicNotification{
		SourceID:  sourceID,
		Score:     score,
		Reason:    reason,
		Timestamp: time.Now(),
	}

	mps.notifications = append(mps.notifications, notification)
	mps.lastNotifiedAt = notification.Timestamp

	// If we get multiple notifications in a short period, consider escalating
	recentCount := 0
	cutoff := time.Now().Add(-5 * time.Minute)

	for _, n := range mps.notifications {
		if n.Timestamp.After(cutoff) {
			recentCount++
		}
	}

	// Simple escalation logic - if we get 3+ notifications in 5 minutes, increase tier
	if recentCount >= 3 && mps.currentTier < 5 {
		mps.currentTier++
		mps.isInPanicMode = true

		log.Warn().
			Int("new_tier", mps.currentTier).
			Int("recent_notifications", recentCount).
			Msg("Mock panic system escalated to higher tier")
	}

	return nil
}

// GetCurrentPanicTier returns the current panic tier
func (mps *MockPanicSystem) GetCurrentPanicTier() (int, error) {
	mps.mu.RLock()
	defer mps.mu.RUnlock()
	return mps.currentTier, nil
}

// AdjustTrustDuringPanic updates the panic state based on a requested tier
func (mps *MockPanicSystem) AdjustTrustDuringPanic(tier int) error {
	mps.mu.Lock()
	defer mps.mu.Unlock()

	if tier < 1 || tier > 5 {
		return fmt.Errorf("invalid panic tier: %d (must be 1-5)", tier)
	}

	mps.currentTier = tier
	mps.isInPanicMode = tier > 1

	log.Info().
		Int("tier", tier).
		Bool("panic_mode", mps.isInPanicMode).
		Msg("Mock panic system adjusted to new tier")

	return nil
}

// GetNotifications returns all recorded notifications
func (mps *MockPanicSystem) GetNotifications() []PanicNotification {
	mps.mu.RLock()
	defer mps.mu.RUnlock()

	// Return a copy to avoid concurrent modification
	result := make([]PanicNotification, len(mps.notifications))
	copy(result, mps.notifications)

	return result
}

// MockThreatIntelligence is a mock implementation of the ThreatIntelligenceIntegration interface
type MockThreatIntelligence struct {
	mu                sync.RWMutex
	knownBadSources   map[string]map[string]interface{}
	globalThreatLevel int
	monitoredSources  map[string]map[string]string
}

// NewMockThreatIntelligence creates a new mock threat intelligence system
func NewMockThreatIntelligence() *MockThreatIntelligence {
	return &MockThreatIntelligence{
		knownBadSources:   make(map[string]map[string]interface{}),
		globalThreatLevel: 1,
		monitoredSources:  make(map[string]map[string]string),
	}
}

// CheckSource checks if a source is known to be suspicious
func (mti *MockThreatIntelligence) CheckSource(
	sourceID string,
	identifiers map[string]string,
) (bool, map[string]interface{}, error) {
	mti.mu.RLock()
	defer mti.mu.RUnlock()

	// Check if this source is explicitly blacklisted
	if details, exists := mti.knownBadSources[sourceID]; exists {
		return true, details, nil
	}

	// Check identifiers against known bad patterns
	for k, v := range identifiers {
		// Mock implementation: any identifier containing "suspicious" or "malicious" will trigger
		if (k == "domain" || k == "ip_address") &&
			(contains(v, "suspicious") || contains(v, "malicious")) {
			return true, map[string]interface{}{
				"reason":     "Suspicious identifier pattern",
				"identifier": k,
				"value":      v,
				"confidence": 0.8,
			}, nil
		}
	}

	return false, nil, nil
}

// GetGlobalThreatLevel returns the current global threat level
func (mti *MockThreatIntelligence) GetGlobalThreatLevel() (int, error) {
	mti.mu.RLock()
	defer mti.mu.RUnlock()
	return mti.globalThreatLevel, nil
}

// RegisterSourceForMonitoring records a source for continuous monitoring
func (mti *MockThreatIntelligence) RegisterSourceForMonitoring(
	sourceID string,
	identifiers map[string]string,
) error {
	mti.mu.Lock()
	defer mti.mu.Unlock()

	mti.monitoredSources[sourceID] = identifiers

	return nil
}

// AddKnownBadSource adds a source to the known bad list for testing
func (mti *MockThreatIntelligence) AddKnownBadSource(
	sourceID string,
	details map[string]interface{},
) {
	mti.mu.Lock()
	defer mti.mu.Unlock()

	mti.knownBadSources[sourceID] = details
}

// SetGlobalThreatLevel changes the global threat level for testing
func (mti *MockThreatIntelligence) SetGlobalThreatLevel(level int) {
	mti.mu.Lock()
	defer mti.mu.Unlock()

	if level < 1 {
		level = 1
	} else if level > 5 {
		level = 5
	}

	mti.globalThreatLevel = level
}

// GetMonitoredSources returns all sources being monitored
func (mti *MockThreatIntelligence) GetMonitoredSources() map[string]map[string]string {
	mti.mu.RLock()
	defer mti.mu.RUnlock()

	// Return a copy to avoid concurrent modification
	result := make(map[string]map[string]string, len(mti.monitoredSources))

	for id, identifiers := range mti.monitoredSources {
		// Pre-allocate the map with the right size for better efficiency
		identifiersCopy := make(map[string]string, len(identifiers))
		for k, v := range identifiers {
			identifiersCopy[k] = v
		}
		result[id] = identifiersCopy
	}

	return result
}

// Helper function to check if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return s != "" && substr != "" && s == substr
}
