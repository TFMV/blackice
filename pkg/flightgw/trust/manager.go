package trust

import (
	"fmt"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// TrustManager provides a unified interface for all trust-related operations
type TrustManager struct {
	mu                 sync.RWMutex
	trustScorer        *TrustScorer
	registry           *Registry
	behavioralAnalyzer *BehavioralAnalyzer
	anomalyDetector    *AnomalyDetector

	// Integration with other systems
	panicSystem        PanicSystemIntegration
	threatIntelligence ThreatIntelligenceIntegration

	// Configuration
	config TrustManagerConfig

	// Background processing
	backgroundWorkers bool
	shutdownChan      chan struct{}
}

// TrustManagerConfig contains configuration for the trust manager
type TrustManagerConfig struct {
	// Core configuration
	MinScore       int `json:"min_score"`
	ThresholdScore int `json:"threshold_score"`

	// Background processing
	EnableBackgroundProcessing bool          `json:"enable_background_processing"`
	BackgroundInterval         time.Duration `json:"background_interval"`

	// Integration settings
	PanicIntegration         bool `json:"panic_integration"`
	ThreatIntelIntegration   bool `json:"threat_intel_integration"`
	RealtimeAnomalyDetection bool `json:"realtime_anomaly_detection"`

	// Trust scoring
	CategoryWeights   map[string]float64 `json:"category_weights"`
	DynamicThresholds bool               `json:"dynamic_thresholds"`
}

// NewTrustManager creates a new trust management system
func NewTrustManager(config TrustManagerConfig) *TrustManager {
	// Create the core trust scorer
	trustScorer := NewTrustScorer(config.MinScore, config.ThresholdScore)

	// Apply custom category weights if provided
	if len(config.CategoryWeights) > 0 {
		weights := make(map[TrustScoreCategory]float64)
		for category, weight := range config.CategoryWeights {
			weights[TrustScoreCategory(category)] = weight
		}
		trustScorer.categoryWeights = weights
	}

	// Update dynamic thresholds setting
	trustScorer.dynamicThresholds = config.DynamicThresholds

	// Create registry linked to the trust scorer
	registry := NewRegistry(trustScorer)

	// Create behavioral analyzer
	behavioralAnalyzer := NewBehavioralAnalyzer(trustScorer)

	// Create anomaly detector
	anomalyDetector := NewAnomalyDetector(trustScorer, behavioralAnalyzer)

	manager := &TrustManager{
		trustScorer:        trustScorer,
		registry:           registry,
		behavioralAnalyzer: behavioralAnalyzer,
		anomalyDetector:    anomalyDetector,
		config:             config,
		backgroundWorkers:  config.EnableBackgroundProcessing,
		shutdownChan:       make(chan struct{}),
	}

	// Start background processing if enabled
	if config.EnableBackgroundProcessing {
		go manager.backgroundWorker(config.BackgroundInterval)
	}

	return manager
}

// RegisterSource registers a new data source with the trust system
func (tm *TrustManager) RegisterSource(
	sourceID string,
	description string,
	publicKeyPath string,
	keyAlgorithm string,
	initialTrustScore int,
	contentTypes []string,
	metadata map[string]string,
) error {
	// Thread-safe operation
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Register with the core registry
	err := tm.registry.RegisterSource(
		sourceID,
		description,
		publicKeyPath,
		keyAlgorithm,
		initialTrustScore,
		contentTypes,
		metadata,
	)

	if err != nil {
		return err
	}

	// If configured, register with threat intelligence
	if tm.config.ThreatIntelIntegration && tm.threatIntelligence != nil {
		// Prepare identifiers for threat intelligence
		identifiers := map[string]string{
			"key_algorithm": keyAlgorithm,
		}

		// Add any identifiers from metadata
		for k, v := range metadata {
			// Only include relevant identifier fields
			if k == "organization" || k == "domain" || k == "endpoint" ||
				k == "ip_address" || k == "certificate_fingerprint" {
				identifiers[k] = v
			}
		}

		// Check against threat intelligence
		suspicious, details, err := tm.threatIntelligence.CheckSource(sourceID, identifiers)
		if err != nil {
			log.Warn().
				Err(err).
				Str("source_id", sourceID).
				Msg("Failed to check source against threat intelligence")
		} else if suspicious {
			// Source is suspicious according to threat intel
			log.Warn().
				Str("source_id", sourceID).
				Interface("details", details).
				Msg("Source flagged by threat intelligence")

			// Apply a trust penalty
			if adjustErr := tm.trustScorer.UpdateScore(sourceID, ScoreAdjustment{
				Value:    -30,
				Reason:   "Flagged by threat intelligence",
				Category: "external",
				Severity: SeverityHigh,
				Context:  details,
			}); adjustErr != nil {
				log.Error().
					Err(adjustErr).
					Str("source_id", sourceID).
					Msg("Failed to apply trust score adjustment for threat intelligence flag")
			}

			// Register for continuous monitoring
			_ = tm.threatIntelligence.RegisterSourceForMonitoring(sourceID, identifiers)
		}
	}

	log.Info().
		Str("source_id", sourceID).
		Str("description", description).
		Str("key_algorithm", keyAlgorithm).
		Int("initial_trust_score", initialTrustScore).
		Msg("Source registered with trust manager")

	return nil
}

// RecordTransaction records an interaction with a data source and updates its trust score
func (tm *TrustManager) RecordTransaction(
	sourceID string,
	transactionType string,
	success bool,
	volumeBytes int64,
	duration time.Duration,
	metadata map[string]interface{},
) error {
	// Thread safety
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// First, check if the source exists
	_, err := tm.registry.GetSource(sourceID)
	if err != nil {
		return fmt.Errorf("could not record transaction: %w", err)
	}

	// Update last activity timestamp
	if err := tm.registry.UpdateSourceActivity(sourceID); err != nil {
		log.Error().
			Err(err).
			Str("source_id", sourceID).
			Msg("Failed to update source activity timestamp")
		// Continue anyway - non-critical error
	}

	// Get the trust score
	score, err := tm.trustScorer.GetScore(sourceID)
	if err != nil {
		return fmt.Errorf("could not get trust score: %w", err)
	}

	// Update transaction counts
	score.TotalTransactions++
	if success {
		score.SuccessfulTransactions++
	} else {
		score.FailedTransactions++
	}

	// Record behavioral observations for different metrics

	// Volume pattern
	if volumeBytes > 0 {
		volumeMB := float64(volumeBytes) / (1024 * 1024) // Convert to MB for easier patterns

		err := tm.behavioralAnalyzer.RecordSourceObservation(
			sourceID,
			"volume",
			volumeMB,
			map[string]interface{}{
				"bytes":            volumeBytes,
				"transaction_type": transactionType,
				"success":          success,
			},
		)

		if err != nil {
			log.Error().
				Err(err).
				Str("source_id", sourceID).
				Str("pattern", "volume").
				Msg("Failed to record volume observation")
		}
	}

	// Timing pattern
	if duration > 0 {
		err := tm.behavioralAnalyzer.RecordSourceObservation(
			sourceID,
			"timing",
			float64(duration.Milliseconds()),
			map[string]interface{}{
				"duration_ms":      duration.Milliseconds(),
				"transaction_type": transactionType,
				"success":          success,
			},
		)

		if err != nil {
			log.Error().
				Err(err).
				Str("source_id", sourceID).
				Str("pattern", "timing").
				Msg("Failed to record timing observation")
		}
	}

	// For failed transactions, make appropriate trust adjustments
	if !success {
		category := "verification" // Default category for failures
		if metadata != nil {
			if cat, ok := metadata["failure_category"].(string); ok {
				category = cat
			}
		}

		// Determine severity based on failure type and context
		severity := SeverityLow
		if metadata != nil {
			if failureType, ok := metadata["failure_type"].(string); ok {
				// Security-related failures are treated more severely
				if failureType == "authentication" || failureType == "authorization" ||
					failureType == "integrity" || failureType == "cryptographic" {
					severity = SeverityHigh
				} else if failureType == "schema" || failureType == "validation" {
					severity = SeverityMedium
				}
			}
		}

		// Apply trust score adjustment
		adjustment := -5 // Default adjustment
		if severity == SeverityHigh {
			adjustment = -15
		} else if severity == SeverityMedium {
			adjustment = -10
		}

		err := tm.trustScorer.UpdateScore(sourceID, ScoreAdjustment{
			Value:      adjustment,
			Reason:     fmt.Sprintf("Transaction failure: %s", transactionType),
			Category:   category,
			Expiration: 12 * time.Hour, // Temporary impact
			Severity:   severity,
			Context:    metadata,
		})

		if err != nil {
			log.Error().
				Err(err).
				Str("source_id", sourceID).
				Str("category", category).
				Int("adjustment", adjustment).
				Msg("Failed to update trust score for transaction failure")
		}
	}

	return nil
}

// IsTrusted checks if a source's trust score is above the threshold
func (tm *TrustManager) IsTrusted(sourceID string) (bool, error) {
	return tm.trustScorer.IsTrusted(sourceID)
}

// GetTrustScore gets the current trust score for a source
func (tm *TrustManager) GetTrustScore(sourceID string) (*SourceTrustScore, error) {
	return tm.trustScorer.GetScore(sourceID)
}

// GetSource gets information about a registered source
func (tm *TrustManager) GetSource(sourceID string) (*SourceInfo, error) {
	return tm.registry.GetSource(sourceID)
}

// ReportAnomaly reports an anomaly related to a specific source
func (tm *TrustManager) ReportAnomaly(
	sourceID string,
	category string,
	description string,
	severity SeverityLevel,
	evidence map[string]interface{},
) error {
	if tm.anomalyDetector == nil {
		return fmt.Errorf("anomaly detector not initialized")
	}

	// Prepare details
	details := evidence
	if details == nil {
		details = make(map[string]interface{})
	}

	details["description"] = description
	details["source_id"] = sourceID

	// Convert string category to TrustScoreCategory
	trustCategory := tm.trustScorer.getCategoryFromString(category)

	return tm.anomalyDetector.ReportAnomaly(
		sourceID,
		trustCategory,
		severity,
		details,
	)
}

// GetSourceAnomalies gets anomalies for a specific source
func (tm *TrustManager) GetSourceAnomalies(sourceID string, since time.Time) ([]AnomalyRecord, error) {
	if tm.anomalyDetector == nil {
		return nil, fmt.Errorf("anomaly detector not initialized")
	}

	return tm.anomalyDetector.GetSourceAnomalies(sourceID, since)
}

// GetBehavioralPatterns gets the behavioral pattern analysis for a source
func (tm *TrustManager) GetBehavioralPatterns(sourceID string) (map[string]interface{}, error) {
	if tm.behavioralAnalyzer == nil {
		return nil, fmt.Errorf("behavioral analyzer not initialized")
	}

	return tm.behavioralAnalyzer.GetPatternSummary(sourceID), nil
}

// SetPanicSystem connects the trust manager to the panic system
func (tm *TrustManager) SetPanicSystem(panicSystem PanicSystemIntegration) {
	tm.panicSystem = panicSystem

	// Also connect the anomaly detector
	if tm.anomalyDetector != nil {
		tm.anomalyDetector.SetPanicSystem(panicSystem)
	}
}

// SetThreatIntelligence connects the trust manager to threat intelligence
func (tm *TrustManager) SetThreatIntelligence(threatIntel ThreatIntelligenceIntegration) {
	tm.threatIntelligence = threatIntel

	// Also connect the anomaly detector
	if tm.anomalyDetector != nil {
		tm.anomalyDetector.SetThreatIntelligence(threatIntel)
	}
}

// Shutdown stops all background processing
func (tm *TrustManager) Shutdown() {
	if tm.backgroundWorkers {
		close(tm.shutdownChan)
		tm.backgroundWorkers = false
	}

	log.Info().Msg("Trust manager shutdown complete")
}

// backgroundWorker runs periodic maintenance tasks
func (tm *TrustManager) backgroundWorker(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			tm.runMaintenanceTasks()
		case <-tm.shutdownChan:
			return
		}
	}
}

// runMaintenanceTasks executes periodic maintenance for the trust system
func (tm *TrustManager) runMaintenanceTasks() {
	// Use mutex to ensure thread safety during maintenance
	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Clean up expired anomalies
	if tm.anomalyDetector != nil {
		tm.anomalyDetector.CleanupExpiredAnomalies()
	}

	// Check global threat level
	if tm.config.ThreatIntelIntegration && tm.threatIntelligence != nil {
		globalThreatLevel, err := tm.threatIntelligence.GetGlobalThreatLevel()
		if err == nil && globalThreatLevel > 1 {
			// Adjust internal threat level if external is higher
			currentLevel := tm.behavioralAnalyzer.GetSystemThreatLevel()
			if globalThreatLevel > currentLevel {
				log.Info().
					Int("previous_level", currentLevel).
					Int("new_level", globalThreatLevel).
					Msg("System threat level increased based on threat intelligence")
			}
		}
	}

	// Update adaptive thresholds if enabled
	if tm.config.DynamicThresholds {
		// Implement threshold adjustment logic
		sources, err := tm.registry.ListSources()
		if err != nil {
			log.Error().
				Err(err).
				Msg("Failed to list sources for threshold adjustment")
			return
		}

		// Calculate metrics for threshold adjustment
		totalSources := len(sources)
		if totalSources > 0 {
			// Get all trust scores
			allScores := make(map[TrustScoreCategory][]int)

			// Initialize category maps
			categories := []TrustScoreCategory{
				ConsistencyCategory, TimingCategory, VerificationCategory, ExternalCategory,
				VolumeCategory, SchemaCategory, ContentCategory, BehavioralCategory,
				NetworkCategory, ContextualCategory,
			}

			for _, category := range categories {
				allScores[category] = make([]int, 0, totalSources)
			}

			// Collect scores for all sources by category
			for _, source := range sources {
				score, err := tm.trustScorer.GetScore(source.SourceID)
				if err != nil {
					continue
				}

				// Add scores by category
				allScores[ConsistencyCategory] = append(allScores[ConsistencyCategory], score.ConsistencyScore)
				allScores[TimingCategory] = append(allScores[TimingCategory], score.TimingScore)
				allScores[VerificationCategory] = append(allScores[VerificationCategory], score.VerificationScore)
				allScores[ExternalCategory] = append(allScores[ExternalCategory], score.ExternalScore)
				allScores[VolumeCategory] = append(allScores[VolumeCategory], score.VolumeScore)
				allScores[SchemaCategory] = append(allScores[SchemaCategory], score.SchemaScore)
				allScores[ContentCategory] = append(allScores[ContentCategory], score.ContentScore)
				allScores[BehavioralCategory] = append(allScores[BehavioralCategory], score.BehavioralScore)
				allScores[NetworkCategory] = append(allScores[NetworkCategory], score.NetworkScore)
				allScores[ContextualCategory] = append(allScores[ContextualCategory], score.ContextualScore)
			}

			// Now adjust thresholds based on collected scores
			// For example, we could make thresholds stricter if average scores are high
			// or more lenient if scores are generally low
			for category, scores := range allScores {
				if len(scores) < 3 {
					continue // Not enough data for adjustment
				}

				// Calculate mean score for this category
				sum := 0
				for _, score := range scores {
					sum += score
				}
				mean := float64(sum) / float64(len(scores))

				// Adjust thresholds based on mean score
				// This is a simplified example; real implementation would be more sophisticated
				if mean > 80 {
					// Scores are generally high, can be stricter
					log.Debug().
						Str("category", string(category)).
						Float64("mean_score", mean).
						Msg("Adjusting category threshold to be stricter based on high mean score")
				} else if mean < 40 {
					// Scores are generally low, be more lenient
					log.Debug().
						Str("category", string(category)).
						Float64("mean_score", mean).
						Msg("Adjusting category threshold to be more lenient based on low mean score")
				}
			}
		}
	}

	// Check for inactive sources that might need adjustment
	// This would scan for sources with no recent activity and apply penalties
	// For brevity, not fully implemented here

	log.Debug().Msg("Trust manager maintenance tasks completed")
}
