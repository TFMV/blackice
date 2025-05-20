// Package telemetry provides a secure framework for collecting and exposing metrics
package telemetry

import (
	"fmt"
	"time"

	"github.com/TFMV/blackice/pkg/flightgw/trust"
	"github.com/rs/zerolog/log"
)

// Manager is an adapter for the trust management system to make it compatible
// with the anomaly integration system
type Manager struct {
	trustManager     *trust.TrustManager
	serviceEndpoint  string
	connectionActive bool
}

// NewManager creates a new trust manager adapter for the given endpoint
func NewManager(endpoint string) (*Manager, error) {
	// Create the trust manager configuration
	config := trust.TrustManagerConfig{
		MinScore:                   0,
		ThresholdScore:             50,
		EnableBackgroundProcessing: true,
		BackgroundInterval:         time.Minute,
		PanicIntegration:           true,
		ThreatIntelIntegration:     true,
		RealtimeAnomalyDetection:   true,
		DynamicThresholds:          true,
		CategoryWeights: map[string]float64{
			"verification": 1.0,
			"consistency":  1.0,
			"timing":       1.0,
			"volume":       1.0,
			"behavioral":   1.5, // Higher weight for behavioral issues
			"external":     1.2, // Higher weight for external factors
		},
	}

	// Create the trust manager
	trustManager := trust.NewTrustManager(config)
	if trustManager == nil {
		return nil, fmt.Errorf("failed to create trust manager")
	}

	return &Manager{
		trustManager:     trustManager,
		serviceEndpoint:  endpoint,
		connectionActive: true,
	}, nil
}

// UpdateSourceScore updates the trust score for a source
func (m *Manager) UpdateSourceScore(
	sourceID string,
	category string,
	adjustment int,
	reason string,
	severity int,
	confidence float64,
	technique string,
) error {
	if !m.connectionActive {
		return fmt.Errorf("trust manager connection is not active")
	}

	// Convert severity to trust system severity level
	var sevLevel trust.SeverityLevel
	switch severity {
	case 0:
		sevLevel = trust.SeverityInfo
	case 1:
		sevLevel = trust.SeverityLow
	case 2:
		sevLevel = trust.SeverityMedium
	case 3:
		sevLevel = trust.SeverityHigh
	case 4:
		sevLevel = trust.SeverityCritical
	default:
		sevLevel = trust.SeverityMedium
	}

	// Prepare evidence for anomaly
	evidence := map[string]interface{}{
		"confidence": confidence,
		"reason":     reason,
	}

	if technique != "" {
		evidence["technique"] = technique
	}

	// Report anomaly to trust system
	err := m.trustManager.ReportAnomaly(
		sourceID,
		category,
		reason,
		sevLevel,
		evidence,
	)

	if err != nil {
		log.Error().
			Err(err).
			Str("source", sourceID).
			Str("category", category).
			Int("adjustment", adjustment).
			Msg("Failed to update source trust score")
		return err
	}

	return nil
}

// GetSourceScore retrieves the trust score for a source
func (m *Manager) GetSourceScore(sourceID string) (int, error) {
	if !m.connectionActive {
		return 0, fmt.Errorf("trust manager connection is not active")
	}

	// Get trust score
	score, err := m.trustManager.GetTrustScore(sourceID)
	if err != nil {
		return 0, err
	}

	return score.Score, nil
}

// Close closes the trust manager connection
func (m *Manager) Close() error {
	if m.connectionActive {
		m.trustManager.Shutdown()
		m.connectionActive = false
	}
	return nil
}
