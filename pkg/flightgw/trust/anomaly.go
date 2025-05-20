package trust

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// AnomalyDetector provides integration with BlackIce's anomaly detection systems
type AnomalyDetector struct {
	mu               sync.RWMutex
	trustScorer      *TrustScorer
	behaviorAnalyzer *BehavioralAnalyzer

	// Anomaly tracking
	recentAnomalies []AnomalyRecord
	anomalyCounters map[string]map[TrustScoreCategory]int // sourceID -> category -> count
	anomalyCutoff   time.Duration                         // How long anomalies are considered "recent"

	// External integration
	panicSystem PanicSystemIntegration
	threatIntel ThreatIntelligenceIntegration

	// Configuration
	escalationThresholds map[TrustScoreCategory]int // Category -> count threshold for escalation
	severityWeights      map[SeverityLevel]int      // Severity -> weight for scoring
}

// NewAnomalyDetector creates a new anomaly detector integrated with the trust system
func NewAnomalyDetector(
	trustScorer *TrustScorer,
	behaviorAnalyzer *BehavioralAnalyzer,
) *AnomalyDetector {
	detector := &AnomalyDetector{
		trustScorer:      trustScorer,
		behaviorAnalyzer: behaviorAnalyzer,
		recentAnomalies:  make([]AnomalyRecord, 0, 100),
		anomalyCounters:  make(map[string]map[TrustScoreCategory]int),
		anomalyCutoff:    24 * time.Hour, // Default to 24 hours

		// Default escalation thresholds
		escalationThresholds: map[TrustScoreCategory]int{
			ConsistencyCategory:  3, // 3 consistency anomalies to escalate
			VerificationCategory: 1, // Single verification anomaly escalates
			TimingCategory:       5, // 5 timing anomalies to escalate
			VolumeCategory:       3,
			SchemaCategory:       2,
			ContentCategory:      2,
			BehavioralCategory:   3,
			NetworkCategory:      2,
			ContextualCategory:   3,
			ExternalCategory:     1, // Single external intel hit escalates
		},

		// Severity weights for scoring impact
		severityWeights: map[SeverityLevel]int{
			SeverityInfo:     1,
			SeverityLow:      2,
			SeverityMedium:   5,
			SeverityHigh:     10,
			SeverityCritical: 20,
		},
	}

	// Register as the anomaly engine with the behavioral analyzer
	if behaviorAnalyzer != nil {
		behaviorAnalyzer.SetAnomalyEngine(detector)
	}

	return detector
}

// ReportAnomaly receives anomaly reports from detection systems
func (ad *AnomalyDetector) ReportAnomaly(
	sourceID string,
	category TrustScoreCategory,
	severity SeverityLevel,
	details map[string]interface{},
) error {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	// Create anomaly record
	anomaly := AnomalyRecord{
		Timestamp:       time.Now(),
		Category:        category,
		Description:     fmt.Sprintf("Anomaly detected in %s category", category),
		Severity:        severity,
		AdjustmentValue: ad.calculateAdjustmentForSeverity(severity),
		ConfidenceScore: 0.8, // Default confidence
		RawData:         details,
	}

	// If description is provided in details, use it
	if desc, ok := details["description"].(string); ok {
		anomaly.Description = desc
	}

	// If confidence is provided in details, use it
	if confidence, ok := details["confidence"].(float64); ok {
		anomaly.ConfidenceScore = confidence
	}

	// Process MITRE ATT&CK and TTP information if available
	var mitreTechnique string
	var ttpIdentifiers []string

	if mitreData, ok := details["mitre_technique"].(string); ok && mitreData != "" {
		mitreTechnique = mitreData
		// Store in RawData as a map if it's not already a map
		if anomaly.RawData == nil {
			anomaly.RawData = make(map[string]interface{})
		}
		if rawMap, ok := anomaly.RawData.(map[string]interface{}); ok {
			rawMap["mitre_technique"] = mitreTechnique
		}
	}

	if ttpData, ok := details["ttp_identifiers"].([]string); ok && len(ttpData) > 0 {
		ttpIdentifiers = ttpData
		// Store in RawData
		if rawMap, ok := anomaly.RawData.(map[string]interface{}); ok {
			rawMap["ttp_identifiers"] = strings.Join(ttpIdentifiers, ",")
		}
	}

	// Process affected resources if available
	if resources, ok := details["affected_resources"].([]string); ok && len(resources) > 0 {
		if rawMap, ok := anomaly.RawData.(map[string]interface{}); ok {
			rawMap["affected_resources"] = strings.Join(resources, ",")
		}
	}

	// Check for remediation status
	if status, ok := details["remediation_status"].(int); ok {
		if rawMap, ok := anomaly.RawData.(map[string]interface{}); ok {
			rawMap["remediation_status"] = fmt.Sprintf("%d", status)
		}
	}

	// Add to recent anomalies
	ad.recentAnomalies = append(ad.recentAnomalies, anomaly)

	// Trim if too many
	if len(ad.recentAnomalies) > 100 {
		ad.recentAnomalies = ad.recentAnomalies[len(ad.recentAnomalies)-100:]
	}

	// Update anomaly counter for this source and category
	sourceCounters, exists := ad.anomalyCounters[sourceID]
	if !exists {
		sourceCounters = make(map[TrustScoreCategory]int)
		ad.anomalyCounters[sourceID] = sourceCounters
	}

	sourceCounters[category]++

	// Check if we've reached escalation threshold
	if sourceCounters[category] >= ad.escalationThresholds[category] {
		// This category has reached escalation threshold
		ad.handleEscalation(sourceID, category, severity)
	}

	// Now, update the trust score
	if ad.trustScorer != nil {
		err := ad.trustScorer.UpdateScore(sourceID, ScoreAdjustment{
			Value:      anomaly.AdjustmentValue,
			Reason:     anomaly.Description,
			Category:   string(category),
			Expiration: ad.getExpirationForSeverity(severity),
			Severity:   severity,
			Context:    details,
		})

		if err != nil {
			log.Error().
				Err(err).
				Str("source_id", sourceID).
				Str("category", string(category)).
				Str("severity", severityToString(severity)).
				Msg("Failed to update trust score for anomaly")
			return err
		}
	}

	log.Info().
		Str("source_id", sourceID).
		Str("category", string(category)).
		Str("severity", severityToString(severity)).
		Int("adjustment", anomaly.AdjustmentValue).
		Float64("confidence", anomaly.ConfidenceScore).
		Str("mitre_technique", mitreTechnique).
		Msg("Anomaly reported and processed")

	return nil
}

// ReceiveAnomalyNotification handles notifications from other systems
func (ad *AnomalyDetector) ReceiveAnomalyNotification(anomaly AnomalyRecord) error {
	// For external notifications, add source ID validation
	sourceID := "unknown"
	if sourceInfo, exists := anomaly.RawData.(map[string]interface{})["source_id"]; exists {
		if sourceStr, ok := sourceInfo.(string); ok {
			sourceID = sourceStr
		}
	}

	// Forward to standard handling
	return ad.ReportAnomaly(
		sourceID,
		anomaly.Category,
		anomaly.Severity,
		anomaly.RawData.(map[string]interface{}),
	)
}

// GetSourceAnomalies retrieves anomalies for a specific source
func (ad *AnomalyDetector) GetSourceAnomalies(sourceID string, since time.Time) ([]AnomalyRecord, error) {
	ad.mu.RLock()
	defer ad.mu.RUnlock()

	var results []AnomalyRecord

	for _, anomaly := range ad.recentAnomalies {
		// Check if this anomaly is for the requested source
		if anomalySrc, ok := anomaly.RawData.(map[string]interface{})["source_id"]; ok {
			if srcStr, ok := anomalySrc.(string); ok && srcStr == sourceID {
				if anomaly.Timestamp.After(since) {
					results = append(results, anomaly)
				}
			}
		}
	}

	return results, nil
}

// SetPanicSystem connects the anomaly detector to the panic system
func (ad *AnomalyDetector) SetPanicSystem(panicSystem PanicSystemIntegration) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.panicSystem = panicSystem
}

// SetThreatIntelligence connects to threat intelligence
func (ad *AnomalyDetector) SetThreatIntelligence(threatIntel ThreatIntelligenceIntegration) {
	ad.mu.Lock()
	defer ad.mu.Unlock()
	ad.threatIntel = threatIntel
}

// calculateAdjustmentForSeverity determines the trust score impact based on severity
func (ad *AnomalyDetector) calculateAdjustmentForSeverity(severity SeverityLevel) int {
	baseValue := -5 // Default impact

	if weight, exists := ad.severityWeights[severity]; exists {
		// More severe = more negative adjustment
		baseValue = -weight
	}

	return baseValue
}

// getExpirationForSeverity determines how long an adjustment should last
func (ad *AnomalyDetector) getExpirationForSeverity(severity SeverityLevel) time.Duration {
	switch severity {
	case SeverityCritical:
		return 72 * time.Hour // Critical impacts last longer
	case SeverityHigh:
		return 48 * time.Hour
	case SeverityMedium:
		return 24 * time.Hour
	case SeverityLow:
		return 12 * time.Hour
	case SeverityInfo:
		return 6 * time.Hour
	default:
		return 24 * time.Hour
	}
}

// handleEscalation manages escalation when a threshold is reached
func (ad *AnomalyDetector) handleEscalation(
	sourceID string,
	category TrustScoreCategory,
	severity SeverityLevel,
) {
	// Reset the counter for this category
	ad.anomalyCounters[sourceID][category] = 0

	// Only escalate to panic system for high or critical severities
	if severity < SeverityHigh || ad.panicSystem == nil {
		return
	}

	// Check if we should notify the panic system
	go func() {
		err := ad.panicSystem.NotifyTrustThresholdViolation(
			sourceID,
			0, // Score will be retrieved by the panic system
			fmt.Sprintf("Escalation threshold reached for %s category with %s severity",
				category, severityToString(severity)),
		)

		if err != nil {
			log.Error().
				Err(err).
				Str("source_id", sourceID).
				Str("category", string(category)).
				Str("severity", severityToString(severity)).
				Msg("Failed to notify panic system about escalation")
		}
	}()

	log.Warn().
		Str("source_id", sourceID).
		Str("category", string(category)).
		Str("severity", severityToString(severity)).
		Msg("Anomaly escalation threshold reached, panic system notified")
}

// CleanupExpiredAnomalies removes anomalies older than the cutoff
func (ad *AnomalyDetector) CleanupExpiredAnomalies() {
	ad.mu.Lock()
	defer ad.mu.Unlock()

	cutoff := time.Now().Add(-ad.anomalyCutoff)

	// Filter recent anomalies
	var activeAnomalies []AnomalyRecord
	for _, anomaly := range ad.recentAnomalies {
		if anomaly.Timestamp.After(cutoff) {
			activeAnomalies = append(activeAnomalies, anomaly)
		}
	}

	ad.recentAnomalies = activeAnomalies

	// Could also reset counters if needed
	// This implementation keeps them for simplicity
}
