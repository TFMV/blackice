package trust

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// BehavioralAnalyzer provides advanced behavioral pattern analysis for trust scoring
type BehavioralAnalyzer struct {
	mu             sync.RWMutex
	patterns       map[string]map[string]*BehavioralPattern // sourceID -> patternType -> pattern
	globalPatterns map[string]*BehavioralPattern            // System-wide patterns
	anomalyEngine  AnomalyEngineIntegration                 // Optional integration with anomaly engine
	trustScorer    *TrustScorer                             // Reference to the trust scorer

	// Configuration
	windowSizes       map[string]time.Duration // Pattern type -> observation window
	outlierThresholds map[string]float64       // Pattern type -> outlier threshold
	alertThresholds   map[string]float64       // Pattern type -> alert threshold

	// Context awareness
	systemThreatLevel int                    // Current system threat level (1-5)
	contextualFactors map[string]interface{} // System-wide contextual factors
}

// BehavioralPattern represents a pattern of behavior for analysis
type BehavioralPattern struct {
	PatternType       string                // Type of pattern (e.g., "volume", "timing")
	Description       string                // Human-readable description
	SourceID          string                // Source ID (empty for global patterns)
	DataPoints        []BehavioralDataPoint // Historical data points
	Mean              float64               // Statistical mean
	StdDev            float64               // Standard deviation
	Percentiles       map[int]float64       // Key percentiles (50, 90, 95, 99)
	LastUpdated       time.Time             // Last time the pattern was updated
	EstablishedAt     time.Time             // When the pattern was considered established
	OutlierThreshold  float64               // Number of std devs to be considered an outlier
	TotalObservations int                   // Total number of observations ever made
	RecentOutliers    int                   // Number of recent outliers
	OutlierPercentage float64               // Percentage of outliers in the pattern
	BasedOnDataPoints int                   // Number of data points used for current stats
}

// BehavioralDataPoint represents a single observation in a pattern
type BehavioralDataPoint struct {
	Timestamp time.Time              // When the observation was made
	Value     float64                // Observed value
	IsOutlier bool                   // Whether this point is an outlier
	Context   map[string]interface{} // Additional contextual information
}

// NewBehavioralAnalyzer creates a new behavioral analysis system
func NewBehavioralAnalyzer(trustScorer *TrustScorer) *BehavioralAnalyzer {
	analyzer := &BehavioralAnalyzer{
		patterns:          make(map[string]map[string]*BehavioralPattern),
		globalPatterns:    make(map[string]*BehavioralPattern),
		trustScorer:       trustScorer,
		systemThreatLevel: 1,
		contextualFactors: make(map[string]interface{}),

		// Default configuration
		windowSizes: map[string]time.Duration{
			"volume":       24 * time.Hour,
			"timing":       24 * time.Hour,
			"verification": 7 * 24 * time.Hour,
			"schema":       30 * 24 * time.Hour,
			"content":      7 * 24 * time.Hour,
			"network":      24 * time.Hour,
		},

		outlierThresholds: map[string]float64{
			"volume":       3.0, // 3 standard deviations
			"timing":       2.5, // 2.5 standard deviations
			"verification": 1.5, // More sensitive for verification
			"schema":       2.0,
			"content":      2.5,
			"network":      2.5,
		},

		alertThresholds: map[string]float64{
			"volume":       10.0, // Alert at 10% outliers
			"timing":       5.0,  // Alert at 5% outliers
			"verification": 3.0,  // Alert at 3% outliers for verification
			"schema":       5.0,
			"content":      5.0,
			"network":      5.0,
		},
	}

	// Initialize global patterns
	analyzer.initializeGlobalPatterns()

	return analyzer
}

// initializeGlobalPatterns sets up system-wide patterns to monitor
func (ba *BehavioralAnalyzer) initializeGlobalPatterns() {
	now := time.Now()

	// Monitoring overall system volume
	ba.globalPatterns["system_volume"] = &BehavioralPattern{
		PatternType:      "volume",
		Description:      "System-wide data volume",
		DataPoints:       make([]BehavioralDataPoint, 0, 100),
		OutlierThreshold: ba.outlierThresholds["volume"],
		LastUpdated:      now,
	}

	// Monitoring source registration rate
	ba.globalPatterns["source_registration"] = &BehavioralPattern{
		PatternType:      "registration",
		Description:      "Rate of new source registrations",
		DataPoints:       make([]BehavioralDataPoint, 0, 100),
		OutlierThreshold: 2.0, // More sensitive for registration patterns
		LastUpdated:      now,
	}

	// Monitoring verification failure rate
	ba.globalPatterns["verification_failures"] = &BehavioralPattern{
		PatternType:      "verification",
		Description:      "System-wide verification failure rate",
		DataPoints:       make([]BehavioralDataPoint, 0, 100),
		OutlierThreshold: 1.5, // Very sensitive for verification failures
		LastUpdated:      now,
	}

	// Monitoring anomaly detection rate
	ba.globalPatterns["anomaly_rate"] = &BehavioralPattern{
		PatternType:      "anomaly",
		Description:      "Rate of anomaly detections across system",
		DataPoints:       make([]BehavioralDataPoint, 0, 100),
		OutlierThreshold: 2.0,
		LastUpdated:      now,
	}
}

// RecordSourceObservation records an observation for a specific source pattern
func (ba *BehavioralAnalyzer) RecordSourceObservation(
	sourceID string,
	patternType string,
	value float64,
	context map[string]interface{},
) error {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	// Check if this source has patterns initialized
	sourcePatternsMap, exists := ba.patterns[sourceID]
	if !exists {
		sourcePatternsMap = make(map[string]*BehavioralPattern)
		ba.patterns[sourceID] = sourcePatternsMap
	}

	// Get or create the pattern
	pattern, exists := sourcePatternsMap[patternType]
	if !exists {
		// Create a new pattern for this type
		pattern = &BehavioralPattern{
			PatternType:      patternType,
			Description:      fmt.Sprintf("%s pattern for source %s", patternType, sourceID),
			SourceID:         sourceID,
			DataPoints:       make([]BehavioralDataPoint, 0, 100),
			OutlierThreshold: ba.getOutlierThreshold(patternType),
			LastUpdated:      time.Now(),
		}
		sourcePatternsMap[patternType] = pattern
	}

	// Create a new data point
	dataPoint := BehavioralDataPoint{
		Timestamp: time.Now(),
		Value:     value,
		Context:   context,
	}

	// Add to the pattern
	pattern.DataPoints = append(pattern.DataPoints, dataPoint)
	pattern.TotalObservations++
	pattern.LastUpdated = dataPoint.Timestamp

	// Prune old data points
	ba.prunePattern(pattern, patternType)

	// Analyze the pattern
	return ba.analyzePattern(pattern, sourceID, patternType)
}

// RecordGlobalObservation records an observation for a system-wide pattern
func (ba *BehavioralAnalyzer) RecordGlobalObservation(
	patternType string,
	value float64,
	context map[string]interface{},
) error {
	ba.mu.Lock()
	defer ba.mu.Unlock()

	// Get the global pattern
	pattern, exists := ba.globalPatterns[patternType]
	if !exists {
		return fmt.Errorf("global pattern not found: %s", patternType)
	}

	// Create a new data point
	dataPoint := BehavioralDataPoint{
		Timestamp: time.Now(),
		Value:     value,
		Context:   context,
	}

	// Add to the pattern
	pattern.DataPoints = append(pattern.DataPoints, dataPoint)
	pattern.TotalObservations++
	pattern.LastUpdated = dataPoint.Timestamp

	// Prune old data points
	ba.prunePattern(pattern, patternType)

	// Analyze the pattern
	return ba.analyzeGlobalPattern(pattern, patternType)
}

// prunePattern removes data points outside the observation window
func (ba *BehavioralAnalyzer) prunePattern(pattern *BehavioralPattern, patternType string) {
	windowSize := ba.getWindowSize(patternType)
	cutoff := time.Now().Add(-windowSize)

	// Find the index of the first data point that's within the window
	startIdx := 0
	for i, point := range pattern.DataPoints {
		if point.Timestamp.After(cutoff) {
			startIdx = i
			break
		}
	}

	// If some points are outside the window, remove them
	if startIdx > 0 {
		pattern.DataPoints = pattern.DataPoints[startIdx:]
	}
}

// getWindowSize returns the appropriate window size for a pattern type
func (ba *BehavioralAnalyzer) getWindowSize(patternType string) time.Duration {
	if size, exists := ba.windowSizes[patternType]; exists {
		return size
	}
	// Default to 24 hours if not specified
	return 24 * time.Hour
}

// getOutlierThreshold returns the outlier threshold for a pattern type
func (ba *BehavioralAnalyzer) getOutlierThreshold(patternType string) float64 {
	if threshold, exists := ba.outlierThresholds[patternType]; exists {
		return threshold
	}
	// Default to 3.0 standard deviations if not specified
	return 3.0
}

// analyzePattern performs statistical analysis on a source-specific pattern
func (ba *BehavioralAnalyzer) analyzePattern(pattern *BehavioralPattern, sourceID, patternType string) error {
	// Need enough data points for meaningful analysis
	if len(pattern.DataPoints) < 10 {
		return nil
	}

	// Calculate mean and standard deviation
	var sum, sumSquares float64
	for _, point := range pattern.DataPoints {
		sum += point.Value
		sumSquares += point.Value * point.Value
	}

	count := float64(len(pattern.DataPoints))
	mean := sum / count
	variance := (sumSquares / count) - (mean * mean)
	stdDev := math.Sqrt(variance)

	// Update pattern statistics
	pattern.Mean = mean
	pattern.StdDev = stdDev
	pattern.BasedOnDataPoints = len(pattern.DataPoints)

	// Calculate percentiles
	values := make([]float64, len(pattern.DataPoints))
	for i, point := range pattern.DataPoints {
		values[i] = point.Value
	}

	sort.Float64s(values)

	// Calculate key percentiles
	pattern.Percentiles = make(map[int]float64)
	pattern.Percentiles[50] = values[int(count*0.5)]  // Median
	pattern.Percentiles[90] = values[int(count*0.9)]  // 90th percentile
	pattern.Percentiles[95] = values[int(count*0.95)] // 95th percentile
	pattern.Percentiles[99] = values[int(count*0.99)] // 99th percentile

	// Mark outliers and count recent ones
	outliersCount := 0
	recentOutliersCount := 0
	recentCutoff := time.Now().Add(-6 * time.Hour) // Consider last 6 hours as "recent"

	for i := range pattern.DataPoints {
		// Calculate z-score
		zScore := math.Abs(pattern.DataPoints[i].Value-mean) / stdDev
		wasOutlier := pattern.DataPoints[i].IsOutlier
		pattern.DataPoints[i].IsOutlier = zScore > pattern.OutlierThreshold

		if pattern.DataPoints[i].IsOutlier {
			outliersCount++

			// Check if this is a recent outlier
			if pattern.DataPoints[i].Timestamp.After(recentCutoff) {
				recentOutliersCount++
			}

			// If this is a newly detected outlier, consider generating an alert
			if !wasOutlier && ba.trustScorer != nil {
				ba.considerOutlierAlert(sourceID, patternType, &pattern.DataPoints[i], zScore)
			}
		}
	}

	// Update pattern metrics
	pattern.RecentOutliers = recentOutliersCount
	if len(pattern.DataPoints) > 0 {
		pattern.OutlierPercentage = float64(outliersCount) / float64(len(pattern.DataPoints)) * 100.0
	}

	// Mark as established if we have enough observations
	if pattern.EstablishedAt.IsZero() && pattern.TotalObservations >= 100 {
		pattern.EstablishedAt = time.Now()
	}

	// Check for pattern-level anomalies
	alertThreshold := ba.getAlertThreshold(patternType)
	if pattern.OutlierPercentage > alertThreshold && !pattern.EstablishedAt.IsZero() {
		ba.handlePatternAnomaly(sourceID, pattern, patternType)
	}

	return nil
}

// analyzeGlobalPattern analyzes a system-wide pattern
func (ba *BehavioralAnalyzer) analyzeGlobalPattern(pattern *BehavioralPattern, patternType string) error {
	// Similar to analyzePattern but for system-wide patterns
	// This would include additional logic for system-wide responses

	// For brevity, using the same core analysis logic
	if len(pattern.DataPoints) < 10 {
		return nil
	}

	// Calculate statistics similar to analyzePattern
	var sum, sumSquares float64
	for _, point := range pattern.DataPoints {
		sum += point.Value
		sumSquares += point.Value * point.Value
	}

	count := float64(len(pattern.DataPoints))
	mean := sum / count
	variance := (sumSquares / count) - (mean * mean)
	stdDev := math.Sqrt(variance)

	// Update pattern statistics
	pattern.Mean = mean
	pattern.StdDev = stdDev
	pattern.BasedOnDataPoints = len(pattern.DataPoints)

	// Calculate percentiles (abbreviated for brevity)
	// ... similar to analyzePattern

	// Mark outliers
	outliersCount := 0
	for i := range pattern.DataPoints {
		zScore := math.Abs(pattern.DataPoints[i].Value-mean) / stdDev
		pattern.DataPoints[i].IsOutlier = zScore > pattern.OutlierThreshold

		if pattern.DataPoints[i].IsOutlier {
			outliersCount++
		}
	}

	if len(pattern.DataPoints) > 0 {
		pattern.OutlierPercentage = float64(outliersCount) / float64(len(pattern.DataPoints)) * 100.0
	}

	// For global patterns, consider adjusting system threat level
	if pattern.OutlierPercentage > ba.getAlertThreshold(patternType)*1.5 {
		// Potential system-wide issue detected
		ba.considerSystemThreatEscalation(pattern, patternType)
	}

	return nil
}

// getAlertThreshold returns the alert threshold for a pattern type
func (ba *BehavioralAnalyzer) getAlertThreshold(patternType string) float64 {
	if threshold, exists := ba.alertThresholds[patternType]; exists {
		return threshold
	}
	// Default to 10% if not specified
	return 10.0
}

// considerOutlierAlert evaluates whether an outlier should trigger a trust score adjustment
func (ba *BehavioralAnalyzer) considerOutlierAlert(
	sourceID string,
	patternType string,
	dataPoint *BehavioralDataPoint,
	zScore float64,
) {
	if ba.trustScorer == nil {
		return
	}

	// Skip if this is a small deviation
	if zScore < 1.5 {
		return
	}

	// Determine severity based on z-score
	var severity SeverityLevel
	var adjustment int

	if zScore > 5.0 {
		severity = SeverityCritical
		adjustment = -20
	} else if zScore > 4.0 {
		severity = SeverityHigh
		adjustment = -15
	} else if zScore > 3.0 {
		severity = SeverityMedium
		adjustment = -10
	} else if zScore > 2.0 {
		severity = SeverityLow
		adjustment = -5
	} else {
		severity = SeverityInfo
		adjustment = -1
	}

	// Increase impact for verification patterns
	if patternType == "verification" {
		adjustment = int(float64(adjustment) * 1.5)
	}

	// Create adjustment context
	context := map[string]interface{}{
		"pattern_type": patternType,
		"z_score":      zScore,
		"expected":     ba.globalPatterns[patternType].Mean,
		"actual":       dataPoint.Value,
		"std_dev":      ba.globalPatterns[patternType].StdDev,
	}

	// Apply the adjustment
	if err := ba.trustScorer.UpdateScore(sourceID, ScoreAdjustment{
		Value:      adjustment,
		Reason:     fmt.Sprintf("Behavioral outlier detected in %s pattern (z-score: %.2f)", patternType, zScore),
		Category:   patternType, // Will be mapped to the appropriate category
		Expiration: 24 * time.Hour,
		Severity:   severity,
		Context:    context,
	}); err != nil {
		log.Error().Err(err).
			Str("source_id", sourceID).
			Str("pattern", patternType).
			Float64("z_score", zScore).
			Msg("Failed to apply trust adjustment for outlier")
	}
}

// handlePatternAnomaly responds to a pattern-level anomaly
func (ba *BehavioralAnalyzer) handlePatternAnomaly(
	sourceID string,
	pattern *BehavioralPattern,
	patternType string,
) {
	if ba.trustScorer == nil {
		return
	}

	// Determine severity based on outlier percentage
	var severity SeverityLevel
	var adjustment int

	if pattern.OutlierPercentage > 50.0 {
		severity = SeverityCritical
		adjustment = -30
	} else if pattern.OutlierPercentage > 30.0 {
		severity = SeverityHigh
		adjustment = -20
	} else if pattern.OutlierPercentage > 20.0 {
		severity = SeverityMedium
		adjustment = -15
	} else if pattern.OutlierPercentage > 10.0 {
		severity = SeverityLow
		adjustment = -10
	} else {
		severity = SeverityInfo
		adjustment = -5
	}

	// Create adjustment context
	context := map[string]interface{}{
		"pattern_type":    patternType,
		"outlier_percent": pattern.OutlierPercentage,
		"mean":            pattern.Mean,
		"std_dev":         pattern.StdDev,
		"total_points":    len(pattern.DataPoints),
		"recent_outliers": pattern.RecentOutliers,
	}

	// Apply the adjustment
	if err := ba.trustScorer.UpdateScore(sourceID, ScoreAdjustment{
		Value: adjustment,
		Reason: fmt.Sprintf("Anomalous pattern detected: %s (%.2f%% outliers)",
			pattern.Description, pattern.OutlierPercentage),
		Category:   patternType, // Will be mapped to appropriate category
		Expiration: 48 * time.Hour,
		Severity:   severity,
		Context:    context,
	}); err != nil {
		log.Error().Err(err).
			Str("source_id", sourceID).
			Str("pattern", patternType).
			Float64("outlier_pct", pattern.OutlierPercentage).
			Msg("Failed to apply trust adjustment for pattern anomaly")
	}

	// If this is a critical severity, consider notifying other systems
	if severity == SeverityCritical {
		// If we have an anomaly engine integration, report it
		if ba.anomalyEngine != nil {
			go func() {
				category := ba.mapPatternTypeToCategory(patternType)
				if err := ba.anomalyEngine.ReportAnomaly(
					sourceID,
					category,
					severity,
					context,
				); err != nil {
					log.Error().Err(err).Msg("Failed to report pattern anomaly to engine")
				}
			}()
		}
	}
}

// considerSystemThreatEscalation evaluates whether to escalate the system threat level
func (ba *BehavioralAnalyzer) considerSystemThreatEscalation(
	pattern *BehavioralPattern,
	patternType string,
) {
	// This implements a conservative approach to threat level escalation

	// Skip if we're already at maximum threat level
	if ba.systemThreatLevel >= 5 {
		return
	}

	// Calculate how extreme this pattern anomaly is
	anomalyLevel := pattern.OutlierPercentage / ba.getAlertThreshold(patternType)

	// Consider escalation based on anomaly level
	newThreatLevel := ba.systemThreatLevel

	if anomalyLevel > 5.0 {
		// Severe anomaly - consider jumping multiple levels
		newThreatLevel = int(math.Min(5, float64(ba.systemThreatLevel+2)))
	} else if anomalyLevel > 2.0 {
		// Significant anomaly - increase by one level
		newThreatLevel = int(math.Min(5, float64(ba.systemThreatLevel+1)))
	}

	// If we're escalating, log and apply the change
	if newThreatLevel > ba.systemThreatLevel {
		previousLevel := ba.systemThreatLevel
		ba.systemThreatLevel = newThreatLevel

		log.Warn().
			Int("previous_level", previousLevel).
			Int("new_level", newThreatLevel).
			Str("pattern", patternType).
			Float64("anomaly_level", anomalyLevel).
			Float64("outlier_pct", pattern.OutlierPercentage).
			Msg("System threat level escalated due to global pattern anomaly")
	}
}

// mapPatternTypeToCategory maps a pattern type to a TrustScoreCategory
func (ba *BehavioralAnalyzer) mapPatternTypeToCategory(patternType string) TrustScoreCategory {
	switch patternType {
	case "volume":
		return VolumeCategory
	case "timing":
		return TimingCategory
	case "verification":
		return VerificationCategory
	case "schema":
		return SchemaCategory
	case "content":
		return ContentCategory
	case "network":
		return NetworkCategory
	default:
		return BehavioralCategory
	}
}

// SetAnomalyEngine sets the anomaly engine integration
func (ba *BehavioralAnalyzer) SetAnomalyEngine(engine AnomalyEngineIntegration) {
	ba.mu.Lock()
	defer ba.mu.Unlock()
	ba.anomalyEngine = engine
}

// GetSystemThreatLevel returns the current system threat level
func (ba *BehavioralAnalyzer) GetSystemThreatLevel() int {
	ba.mu.RLock()
	defer ba.mu.RUnlock()
	return ba.systemThreatLevel
}

// GetPatternSummary returns a summary of pattern statistics for a source
func (ba *BehavioralAnalyzer) GetPatternSummary(sourceID string) map[string]interface{} {
	ba.mu.RLock()
	defer ba.mu.RUnlock()

	summary := make(map[string]interface{})

	patterns, exists := ba.patterns[sourceID]
	if !exists {
		return summary
	}

	patternStats := make(map[string]interface{})

	for patternType, pattern := range patterns {
		patternStats[patternType] = map[string]interface{}{
			"mean":              pattern.Mean,
			"std_dev":           pattern.StdDev,
			"outlier_threshold": pattern.OutlierThreshold,
			"outlier_percent":   pattern.OutlierPercentage,
			"recent_outliers":   pattern.RecentOutliers,
			"data_points":       len(pattern.DataPoints),
			"established":       !pattern.EstablishedAt.IsZero(),
			"last_updated":      pattern.LastUpdated,
		}
	}

	summary["patterns"] = patternStats
	summary["system_threat_level"] = ba.systemThreatLevel

	return summary
}
