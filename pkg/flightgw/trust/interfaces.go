package trust

import (
	"time"
)

// PanicSystemIntegration defines the interface to the Panic Response system
type PanicSystemIntegration interface {
	// NotifyTrustThresholdViolation notifies when a source drops below critical trust thresholds
	NotifyTrustThresholdViolation(sourceID string, score int, reason string) error

	// GetCurrentPanicTier gets the current panic tier for contextual adjustment
	GetCurrentPanicTier() (int, error)

	// AdjustTrustDuringPanic adjusts trust behavior during active panic situations
	AdjustTrustDuringPanic(tier int) error
}

// ThreatIntelligenceIntegration defines the interface to threat intelligence systems
type ThreatIntelligenceIntegration interface {
	// CheckSource checks if a source is in any threat intelligence feed
	CheckSource(sourceID string, identifiers map[string]string) (bool, map[string]interface{}, error)

	// GetGlobalThreatLevel gets the current global threat level
	GetGlobalThreatLevel() (int, error)

	// RegisterSourceForMonitoring registers a source for continuous monitoring
	RegisterSourceForMonitoring(sourceID string, identifiers map[string]string) error
}

// AnomalyEngineIntegration defines the interface to the Anomaly Engine
type AnomalyEngineIntegration interface {
	// ReportAnomaly reports a trust-related anomaly to the anomaly engine
	ReportAnomaly(sourceID string, category TrustScoreCategory, severity SeverityLevel, details map[string]interface{}) error

	// ReceiveAnomalyNotification receives notifications about anomalies detected elsewhere
	ReceiveAnomalyNotification(anomaly AnomalyRecord) error

	// GetSourceAnomalies retrieves anomalies related to a specific source
	GetSourceAnomalies(sourceID string, since time.Time) ([]AnomalyRecord, error)
}
