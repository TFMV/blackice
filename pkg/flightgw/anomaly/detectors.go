// Package anomaly provides anomaly detection and response capabilities for the BlackIce system.
package anomaly

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
	"github.com/rs/zerolog/log"
)

// Common interface for all detectors
type AnomalyDetector interface {
	ID() string
	Type() string
	Version() string
	Process(event *TelemetryEvent) ([]*Anomaly, error)
	Parameters() map[string]string
}

// BaseDetector provides common functionality for all detector implementations
type BaseDetector struct {
	id             string
	detectorType   string
	version        string
	state          blackicev1.NodeHealth_State
	params         map[string]string
	eventTypes     map[string]bool
	processingFunc TelemetryProcessorFunc
}

// StatisticalThresholdDetector detects anomalies based on statistical thresholds
type StatisticalThresholdDetector struct {
	BaseDetector
	mu                    sync.RWMutex
	baselines             map[string]*ThresholdBaseline
	windowSize            int
	sensitivityMultiplier float64
	minDataPoints         int
}

// ThresholdBaseline maintains the baseline data for a specific metric
type ThresholdBaseline struct {
	MetricName   string
	Values       []float64
	Mean         float64
	StdDev       float64
	LastUpdated  time.Time
	UpdatePeriod time.Duration
}

// VolumeAnomalyDetector detects anomalies based on event volume
type VolumeAnomalyDetector struct {
	BaseDetector
	mu              sync.RWMutex
	windowDuration  time.Duration
	eventCounts     map[string][]time.Time
	thresholds      map[string]int
	cleanupInterval time.Duration
	lastCleanup     time.Time
}

// BehavioralPatternDetector detects anomalies based on event sequences
type BehavioralPatternDetector struct {
	BaseDetector
	mu             sync.RWMutex
	patterns       map[string][]string
	eventSequences map[string][]string
	maxSequenceLen int
}

// NewStatisticalThresholdDetector creates a new detector for statistical anomalies
func NewStatisticalThresholdDetector(id string, params map[string]string) *StatisticalThresholdDetector {
	windowSize := 100
	if sizeStr, ok := params["window_size"]; ok {
		if size, err := strconv.Atoi(sizeStr); err == nil && size > 0 {
			windowSize = size
		}
	}

	sensitivity := 3.0 // Default to 3 standard deviations
	if sensStr, ok := params["sensitivity"]; ok {
		if sens, err := strconv.ParseFloat(sensStr, 64); err == nil && sens > 0 {
			sensitivity = sens
		}
	}

	minDataPoints := windowSize / 2
	if minStr, ok := params["min_data_points"]; ok {
		if min, err := strconv.Atoi(minStr); err == nil && min > 0 {
			minDataPoints = min
		}
	}

	// Parse event types to monitor
	eventTypes := make(map[string]bool)
	if typesStr, ok := params["event_types"]; ok {
		types := strings.Split(typesStr, ",")
		for _, t := range types {
			eventTypes[strings.TrimSpace(t)] = true
		}
	} else {
		// Default to all numeric metrics
		eventTypes["metric"] = true
	}

	detector := &StatisticalThresholdDetector{
		BaseDetector: BaseDetector{
			id:           id,
			detectorType: "StatisticalThreshold",
			version:      "1.0.0",
			state:        blackicev1.NodeHealth_HEALTHY,
			params:       params,
			eventTypes:   eventTypes,
		},
		baselines:             make(map[string]*ThresholdBaseline),
		windowSize:            windowSize,
		sensitivityMultiplier: sensitivity,
		minDataPoints:         minDataPoints,
	}

	// Set the processing function
	detector.BaseDetector.processingFunc = detector.Process

	return detector
}

// ID returns the detector ID
func (d *BaseDetector) ID() string {
	return d.id
}

// Type returns the detector type
func (d *BaseDetector) Type() string {
	return d.detectorType
}

// Version returns the detector version
func (d *BaseDetector) Version() string {
	return d.version
}

// Parameters returns the detector parameters
func (d *BaseDetector) Parameters() map[string]string {
	return d.params
}

// Process implements anomaly detection for the statistical threshold detector
func (d *StatisticalThresholdDetector) Process(event *TelemetryEvent) ([]*Anomaly, error) {
	// Skip events that don't match our types
	if !d.eventTypes[event.EventType] {
		return nil, nil
	}

	// Process numeric attributes for anomalies
	var anomalies []*Anomaly

	for key, value := range event.Attributes {
		// Only process numeric values
		var numValue float64
		var ok bool

		switch v := value.(type) {
		case int:
			numValue = float64(v)
			ok = true
		case int64:
			numValue = float64(v)
			ok = true
		case float64:
			numValue = v
			ok = true
		}

		if !ok {
			continue
		}

		metricKey := fmt.Sprintf("%s.%s", event.SourceComponentID, key)

		// Check if this metric exceeds thresholds
		anomaly := d.checkThreshold(metricKey, numValue, event)
		if anomaly != nil {
			anomalies = append(anomalies, anomaly)
		}

		// Update the baseline
		d.updateBaseline(metricKey, numValue)
	}

	return anomalies, nil
}

// checkThreshold determines if a value is anomalous compared to the baseline
func (d *StatisticalThresholdDetector) checkThreshold(metricKey string, value float64, event *TelemetryEvent) *Anomaly {
	d.mu.RLock()
	baseline, exists := d.baselines[metricKey]
	d.mu.RUnlock()

	if !exists || len(baseline.Values) < d.minDataPoints {
		// Not enough data to make a determination
		return nil
	}

	// Check if value is outside threshold
	deviation := math.Abs(value - baseline.Mean)
	threshold := baseline.StdDev * d.sensitivityMultiplier

	if deviation > threshold {
		// This is an anomaly
		severity := calculateSeverity(deviation / threshold)
		confidence := math.Min(1.0, (deviation/threshold)/5.0) // Cap at 1.0

		// Determine related MITRE ATT&CK technique based on metric
		var mitreTechnique string
		var ttpIdentifiers []string
		var affectedResources []string
		var remediationStatus RemediationStatus

		// Infer affected resources from the metric key
		parts := strings.Split(metricKey, ".")
		if len(parts) > 0 {
			affectedResources = append(affectedResources, parts[0])
		}

		// Add additional resources if available from event
		if resourceID, ok := event.Attributes["resource_id"].(string); ok {
			affectedResources = append(affectedResources, resourceID)
		}

		// Set default remediation status
		remediationStatus = RemediationPending

		// Identify MITRE techniques based on metric patterns
		if strings.Contains(metricKey, "cpu") || strings.Contains(metricKey, "memory") {
			mitreTechnique = "T1496" // Resource Hijacking
			ttpIdentifiers = append(ttpIdentifiers, "RESOURCE_EXHAUSTION")
		} else if strings.Contains(metricKey, "network") || strings.Contains(metricKey, "traffic") {
			mitreTechnique = "T1498" // Network Denial of Service
			ttpIdentifiers = append(ttpIdentifiers, "NETWORK_FLOOD")
		} else if strings.Contains(metricKey, "disk") || strings.Contains(metricKey, "storage") {
			mitreTechnique = "T1486" // Data Encrypted for Impact
			ttpIdentifiers = append(ttpIdentifiers, "STORAGE_IMPACT")
		} else if strings.Contains(metricKey, "auth") || strings.Contains(metricKey, "login") {
			mitreTechnique = "T1110" // Brute Force
			ttpIdentifiers = append(ttpIdentifiers, "AUTH_ANOMALY")
		}

		return &Anomaly{
			AnomalyID:         generateAnomalyID(),
			SourceComponentID: event.SourceComponentID,
			DetectorID:        d.id,
			DetectionTime:     time.Now(),
			Category:          CategoryVolume,
			Severity:          severity,
			Description:       fmt.Sprintf("Anomalous value for %s: %.2f (outside %.2f std dev from mean %.2f)", metricKey, value, d.sensitivityMultiplier, baseline.Mean),
			RelatedEvents:     []string{event.EventID},
			Attributes: map[string]interface{}{
				"metric_name":     metricKey,
				"value":           value,
				"mean":            baseline.Mean,
				"std_dev":         baseline.StdDev,
				"deviation":       deviation,
				"threshold":       threshold,
				"deviation_ratio": deviation / threshold,
			},
			Confidence:        confidence,
			AffectedResources: affectedResources,
			RemediationStatus: remediationStatus,
			TTPIdentifiers:    ttpIdentifiers,
			MitreTechnique:    mitreTechnique,
			LastUpdated:       time.Now(),
		}
	}

	return nil
}

// updateBaseline updates the baseline for a specific metric
func (d *StatisticalThresholdDetector) updateBaseline(metricKey string, value float64) {
	// First try read lock to check if baseline exists
	d.mu.RLock()
	_, exists := d.baselines[metricKey]
	d.mu.RUnlock()

	if !exists {
		// If baseline doesn't exist, acquire write lock and create it
		d.mu.Lock()
		// Check again to avoid race condition (double-checked locking pattern)
		_, exists = d.baselines[metricKey]
		if !exists {
			// Create a new baseline with pre-allocated capacity
			baseline := &ThresholdBaseline{
				MetricName:   metricKey,
				Values:       make([]float64, 0, d.windowSize),
				Mean:         value,
				StdDev:       0,
				LastUpdated:  time.Now(),
				UpdatePeriod: 1 * time.Hour,
			}
			d.baselines[metricKey] = baseline
		}
		d.mu.Unlock()
	}

	// Now acquire write lock to update the baseline
	d.mu.Lock()
	defer d.mu.Unlock()

	// Get the baseline again inside the lock to ensure consistency
	baseline := d.baselines[metricKey]

	// Pre-compute the sum for more efficient recalculation
	var sum float64 = value
	if len(baseline.Values) > 0 {
		// If we're at max capacity, remove the oldest value from sum
		if len(baseline.Values) >= d.windowSize {
			sum = (baseline.Mean * float64(len(baseline.Values))) - baseline.Values[0] + value
		} else {
			sum = (baseline.Mean * float64(len(baseline.Values))) + value
		}
	}

	// Add the new value
	if len(baseline.Values) >= d.windowSize {
		// Shift values to maintain window size (reuse existing array)
		copy(baseline.Values, baseline.Values[1:])
		baseline.Values[len(baseline.Values)-1] = value
	} else {
		baseline.Values = append(baseline.Values, value)
	}

	// Update mean
	baseline.Mean = sum / float64(len(baseline.Values))

	// Calculate standard deviation
	var sumSquaredDiff float64
	for _, v := range baseline.Values {
		diff := v - baseline.Mean
		sumSquaredDiff += diff * diff
	}
	baseline.StdDev = math.Sqrt(sumSquaredDiff / float64(len(baseline.Values)))
	baseline.LastUpdated = time.Now()
}

// NewVolumeAnomalyDetector creates a new detector for volume-based anomalies
func NewVolumeAnomalyDetector(id string, params map[string]string) *VolumeAnomalyDetector {
	windowStr := params["window_duration"]
	windowDuration := 5 * time.Minute
	if windowStr != "" {
		if duration, err := time.ParseDuration(windowStr); err == nil {
			windowDuration = duration
		}
	}

	thresholds := make(map[string]int)
	for k, v := range params {
		if strings.HasPrefix(k, "threshold.") {
			eventType := strings.TrimPrefix(k, "threshold.")
			if threshold, err := strconv.Atoi(v); err == nil {
				thresholds[eventType] = threshold
			}
		}
	}

	// Default thresholds if none specified
	if len(thresholds) == 0 {
		thresholds["default"] = 100
	}

	// Parse event types to monitor
	eventTypes := make(map[string]bool)
	if typesStr, ok := params["event_types"]; ok {
		types := strings.Split(typesStr, ",")
		for _, t := range types {
			eventTypes[strings.TrimSpace(t)] = true
		}
	} else {
		// Default to all event types
		eventTypes["*"] = true
	}

	detector := &VolumeAnomalyDetector{
		BaseDetector: BaseDetector{
			id:           id,
			detectorType: "VolumeAnomaly",
			version:      "1.0.0",
			state:        blackicev1.NodeHealth_HEALTHY,
			params:       params,
			eventTypes:   eventTypes,
		},
		windowDuration:  windowDuration,
		eventCounts:     make(map[string][]time.Time),
		thresholds:      thresholds,
		cleanupInterval: windowDuration * 2,
		lastCleanup:     time.Now(),
	}

	// Set the processing function
	detector.BaseDetector.processingFunc = detector.Process

	return detector
}

// Process implements anomaly detection for the volume anomaly detector
func (d *VolumeAnomalyDetector) Process(event *TelemetryEvent) ([]*Anomaly, error) {
	// Early check if we need to handle this event type to avoid unnecessary locking
	if !d.eventTypes["*"] && !d.eventTypes[event.EventType] {
		return nil, nil
	}

	// Get the current time once for consistency
	now := time.Now()
	eventKey := event.EventType

	// First check if cleanup is needed using read lock
	d.mu.RLock()
	needsCleanup := now.Sub(d.lastCleanup) > d.cleanupInterval
	d.mu.RUnlock()

	// Handle cleanup if needed with write lock
	if needsCleanup {
		d.mu.Lock()
		// Double-check after acquiring write lock
		if now.Sub(d.lastCleanup) > d.cleanupInterval {
			d.cleanupOldEvents(now)
			d.lastCleanup = now
		}
		d.mu.Unlock()
	}

	// Track this event and get current count
	d.mu.Lock()

	// Initialize event count slice if it doesn't exist
	if _, exists := d.eventCounts[eventKey]; !exists {
		d.eventCounts[eventKey] = make([]time.Time, 0, 100)
	}

	// Append the new event timestamp
	d.eventCounts[eventKey] = append(d.eventCounts[eventKey], now)

	// Calculate count within window
	cutoff := now.Add(-d.windowDuration)
	count := 0
	for _, ts := range d.eventCounts[eventKey] {
		if ts.After(cutoff) {
			count++
		}
	}

	// Get threshold for this event type
	threshold, exists := d.thresholds[eventKey]
	if !exists {
		threshold = d.thresholds["default"]
	}

	// Create anomaly if threshold is exceeded
	var anomaly *Anomaly
	if count > threshold {
		// This is a volume anomaly
		severity := calculateSeverityFromCount(count, threshold)
		ratio := float64(count) / float64(threshold)

		// Determine TTP and MITRE ATT&CK technique based on event type
		var mitreTechnique string
		var ttpIdentifiers []string
		var affectedResources []string

		// Determine affected resources
		affectedResources = append(affectedResources, event.SourceComponentID)
		if resourceID, ok := event.Attributes["resource_id"].(string); ok {
			affectedResources = append(affectedResources, resourceID)
		}

		// Set appropriate TTP and MITRE technique based on event type
		switch eventKey {
		case "authentication":
			mitreTechnique = "T1110" // Brute Force
			ttpIdentifiers = append(ttpIdentifiers, "CREDENTIAL_ACCESS", "PASSWORD_SPRAYING")
		case "network_flow":
			mitreTechnique = "T1046" // Network Service Scanning
			ttpIdentifiers = append(ttpIdentifiers, "DISCOVERY", "NETWORK_SCANNING")
		case "syscall":
			mitreTechnique = "T1059" // Command and Scripting Interpreter
			ttpIdentifiers = append(ttpIdentifiers, "EXECUTION", "COMMAND_EXECUTION")
		case "authorization":
			mitreTechnique = "T1078" // Valid Accounts
			ttpIdentifiers = append(ttpIdentifiers, "PRIVILEGE_ESCALATION", "LATERAL_MOVEMENT")
		default:
			mitreTechnique = "T1562" // Impair Defenses
			ttpIdentifiers = append(ttpIdentifiers, "DEFENSE_EVASION")
		}

		anomaly = &Anomaly{
			AnomalyID:         generateAnomalyID(),
			SourceComponentID: event.SourceComponentID,
			DetectorID:        d.id,
			DetectionTime:     now,
			Category:          CategoryVolume,
			Severity:          severity,
			Description:       fmt.Sprintf("High volume of %s events: %d in %s (threshold: %d)", eventKey, count, d.windowDuration, threshold),
			RelatedEvents:     []string{event.EventID},
			Attributes: map[string]interface{}{
				"event_type":      eventKey,
				"count":           count,
				"threshold":       threshold,
				"window_duration": d.windowDuration.String(),
				"ratio":           ratio,
			},
			Confidence:        math.Min(1.0, ratio/2.0), // Cap at 1.0
			AffectedResources: affectedResources,
			RemediationStatus: RemediationPending,
			TTPIdentifiers:    ttpIdentifiers,
			MitreTechnique:    mitreTechnique,
			LastUpdated:       now,
		}
	}

	d.mu.Unlock()

	if anomaly != nil {
		return []*Anomaly{anomaly}, nil
	}
	return nil, nil
}

// cleanupOldEvents removes events outside the window duration
func (d *VolumeAnomalyDetector) cleanupOldEvents(now time.Time) {
	cutoff := now.Add(-d.windowDuration)

	for eventType, events := range d.eventCounts {
		var newEvents []time.Time
		for _, ts := range events {
			if ts.After(cutoff) {
				newEvents = append(newEvents, ts)
			}
		}
		d.eventCounts[eventType] = newEvents
	}
}

// NewBehavioralPatternDetector creates a new detector for behavioral pattern anomalies
func NewBehavioralPatternDetector(id string, params map[string]string) *BehavioralPatternDetector {
	maxLen := 10
	if maxLenStr, ok := params["max_sequence_length"]; ok {
		if val, err := strconv.Atoi(maxLenStr); err == nil && val > 0 {
			maxLen = val
		}
	}

	// Parse event types to monitor
	eventTypes := make(map[string]bool)
	if typesStr, ok := params["event_types"]; ok {
		types := strings.Split(typesStr, ",")
		for _, t := range types {
			eventTypes[strings.TrimSpace(t)] = true
		}
	} else {
		// Default to authentication and authorization events
		eventTypes["authentication"] = true
		eventTypes["authorization"] = true
	}

	// Parse patterns to detect
	patterns := make(map[string][]string)
	for k, v := range params {
		if strings.HasPrefix(k, "pattern.") {
			patternName := strings.TrimPrefix(k, "pattern.")
			steps := strings.Split(v, ",")
			for i := range steps {
				steps[i] = strings.TrimSpace(steps[i])
			}
			patterns[patternName] = steps
		}
	}

	detector := &BehavioralPatternDetector{
		BaseDetector: BaseDetector{
			id:           id,
			detectorType: "BehavioralPattern",
			version:      "1.0.0",
			state:        blackicev1.NodeHealth_HEALTHY,
			params:       params,
			eventTypes:   eventTypes,
		},
		patterns:       patterns,
		eventSequences: make(map[string][]string),
		maxSequenceLen: maxLen,
	}

	// Set the processing function
	detector.BaseDetector.processingFunc = detector.Process

	return detector
}

// Process implements anomaly detection for the behavioral pattern detector
func (d *BehavioralPatternDetector) Process(event *TelemetryEvent) ([]*Anomaly, error) {
	// Skip events that don't match our types
	if !d.eventTypes[event.EventType] {
		return nil, nil
	}

	// Extract the action from the event
	action, ok := extractAction(event)
	if !ok {
		return nil, nil
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	// Add to the sequence for this source
	source := event.SourceComponentID
	if _, exists := d.eventSequences[source]; !exists {
		d.eventSequences[source] = make([]string, 0, d.maxSequenceLen)
	}

	sequence := append(d.eventSequences[source], action)
	if len(sequence) > d.maxSequenceLen {
		sequence = sequence[1:]
	}
	d.eventSequences[source] = sequence

	// Check for matches to suspicious patterns
	for patternName, pattern := range d.patterns {
		if match, indices := matchesPattern(sequence, pattern); match {
			// Generate event IDs based on the matched pattern
			relatedEvents := []string{event.EventID}

			// Determine TTP and MITRE ATT&CK technique based on pattern
			var mitreTechnique string
			var ttpIdentifiers []string
			var affectedResources []string

			// Set affected resources
			affectedResources = append(affectedResources, source)

			// Extract user or resource IDs from event attributes if available
			if userID, ok := event.Attributes["user_id"].(string); ok {
				affectedResources = append(affectedResources, "user:"+userID)
			}
			if resourceID, ok := event.Attributes["resource_id"].(string); ok {
				affectedResources = append(affectedResources, resourceID)
			}

			// Set appropriate TTP and MITRE technique based on pattern
			switch {
			case strings.Contains(patternName, "failed_auth"):
				mitreTechnique = "T1110" // Brute Force
				ttpIdentifiers = append(ttpIdentifiers, "CREDENTIAL_ACCESS", "PASSWORD_BRUTE_FORCE")
			case strings.Contains(patternName, "privilege"):
				mitreTechnique = "T1078" // Valid Accounts
				ttpIdentifiers = append(ttpIdentifiers, "PRIVILEGE_ESCALATION", "ADMIN_ACCESS")
			case strings.Contains(patternName, "spray"):
				mitreTechnique = "T1110.003" // Password Spraying
				ttpIdentifiers = append(ttpIdentifiers, "CREDENTIAL_ACCESS", "PASSWORD_SPRAYING")
			default:
				mitreTechnique = "T1562" // Impair Defenses
				ttpIdentifiers = append(ttpIdentifiers, "DEFENSE_EVASION", "SUSPICIOUS_BEHAVIOR")
			}

			return []*Anomaly{
				{
					AnomalyID:         generateAnomalyID(),
					SourceComponentID: source,
					DetectorID:        d.id,
					DetectionTime:     time.Now(),
					Category:          CategoryBehavioral,
					Severity:          SeverityMedium, // Default severity for behavioral patterns
					Description:       fmt.Sprintf("Detected suspicious behavior pattern: %s", patternName),
					RelatedEvents:     relatedEvents,
					Attributes: map[string]interface{}{
						"pattern_name":     patternName,
						"pattern":          strings.Join(pattern, ", "),
						"matched_sequence": strings.Join(sequence, ", "),
						"match_indices":    fmt.Sprintf("%v", indices),
					},
					Confidence:        0.85, // Behavioral patterns typically have high confidence
					AffectedResources: affectedResources,
					RemediationStatus: RemediationPending,
					TTPIdentifiers:    ttpIdentifiers,
					MitreTechnique:    mitreTechnique,
					LastUpdated:       time.Now(),
				},
			}, nil
		}
	}

	return nil, nil
}

// Helper functions

// calculateSeverity determines the severity level based on deviation
func calculateSeverity(deviationRatio float64) SeverityLevel {
	if deviationRatio > 5.0 {
		return SeverityCritical
	} else if deviationRatio > 4.0 {
		return SeverityHigh
	} else if deviationRatio > 3.0 {
		return SeverityMedium
	} else if deviationRatio > 2.0 {
		return SeverityLow
	}
	return SeverityInfo
}

// calculateSeverityFromCount determines severity level based on count vs threshold
func calculateSeverityFromCount(count, threshold int) SeverityLevel {
	ratio := float64(count) / float64(threshold)

	if ratio > 5.0 {
		return SeverityCritical
	} else if ratio > 3.0 {
		return SeverityHigh
	} else if ratio > 2.0 {
		return SeverityMedium
	} else if ratio > 1.5 {
		return SeverityLow
	}
	return SeverityInfo
}

// extractAction extracts the action from an event
func extractAction(event *TelemetryEvent) (string, bool) {
	// Look for action in various attribute keys
	for _, key := range []string{"action", "method", "operation", "event"} {
		if val, ok := event.Attributes[key]; ok {
			if strVal, ok := val.(string); ok {
				return strVal, true
			}
		}
	}

	// Use event type as fallback
	return event.EventType, true
}

// matchesPattern checks if a sequence matches a pattern
func matchesPattern(sequence, pattern []string) (bool, []int) {
	if len(pattern) > len(sequence) {
		return false, nil
	}

	// First, check for the simple exact suffix matching case
	isMatch := true
	suffixIndices := make([]int, len(pattern))

	for i := 0; i < len(pattern); i++ {
		seqIdx := len(sequence) - len(pattern) + i
		suffixIndices[i] = seqIdx

		// Skip wildcard checks in the initial suffix check
		if pattern[i] != "*" && pattern[i] != sequence[seqIdx] {
			isMatch = false
			break
		}
	}

	if isMatch {
		return true, suffixIndices
	}

	// Advanced pattern matching with wildcards and flexible positioning
	// Implements a dynamic programming approach for pattern matching

	// Special cases for patterns with wildcards
	hasWildcards := false
	for _, p := range pattern {
		if p == "*" || strings.Contains(p, "?") || strings.Contains(p, "*") {
			hasWildcards = true
			break
		}
	}

	if !hasWildcards {
		// No wildcards, so we can use more efficient algorithms

		// Try to find the pattern anywhere in the sequence using sliding window
		for startPos := 0; startPos <= len(sequence)-len(pattern); startPos++ {
			isMatch = true
			indices := make([]int, len(pattern))

			for i := 0; i < len(pattern); i++ {
				seqIdx := startPos + i
				indices[i] = seqIdx

				if pattern[i] != sequence[seqIdx] {
					isMatch = false
					break
				}
			}

			if isMatch {
				return true, indices
			}
		}

		return false, nil
	}

	// Handle advanced wildcard patterns

	// DP table: dp[i][j] = true if pattern[0..i-1] matches sequence[0..j-1]
	dp := make([][]bool, len(pattern)+1)
	for i := range dp {
		dp[i] = make([]bool, len(sequence)+1)
	}

	// Empty pattern matches empty sequence
	dp[0][0] = true

	// Handle patterns that start with "*" (can match empty sequence)
	for i := 1; i <= len(pattern); i++ {
		if pattern[i-1] == "*" {
			dp[i][0] = dp[i-1][0]
		}
	}

	// Fill the DP table
	for i := 1; i <= len(pattern); i++ {
		p := pattern[i-1]
		for j := 1; j <= len(sequence); j++ {
			s := sequence[j-1]

			if p == "*" {
				// "*" can match zero or more of any character
				dp[i][j] = dp[i-1][j] || dp[i][j-1] || dp[i-1][j-1]
			} else if p == "?" || p == s {
				// "?" matches exactly one of any character, or exact match
				dp[i][j] = dp[i-1][j-1]
			} else if strings.Contains(p, "*") || strings.Contains(p, "?") {
				// Handle complex wildcards within a pattern element using regex
				// Convert the wildcard pattern to regex
				regexPattern := "^" + strings.Replace(strings.Replace(p, "*", ".*", -1), "?", ".", -1) + "$"
				re, err := regexp.Compile(regexPattern)
				if err == nil && re.MatchString(s) {
					dp[i][j] = dp[i-1][j-1]
				}
			} else {
				dp[i][j] = false
			}
		}
	}

	// Check if pattern matches
	if !dp[len(pattern)][len(sequence)] {
		return false, nil
	}

	// Reconstruct the match indices
	indices := make([]int, len(pattern))
	i, j := len(pattern), len(sequence)

	// Start from the end and work backwards
	for idx := len(pattern) - 1; idx >= 0; idx-- {
		if pattern[idx] == "*" {
			// For "*", find the earliest position it can match
			for j > 0 && dp[idx][j] {
				j--
			}
			j++ // Move back to valid position
		}

		indices[idx] = j - 1
		i--
		j--
	}

	return true, indices
}

// RegisterStandardDetectors registers a standard set of anomaly detectors with the service
func RegisterStandardDetectors(service *Service) error {
	// Statistical threshold detector
	statParams := map[string]string{
		"window_size": "100",
		"sensitivity": "3.0", // 3 standard deviations
		"event_types": "metric",
	}
	statDetector := NewStatisticalThresholdDetector("statistical-threshold-1", statParams)
	if err := service.RegisterDetector(
		statDetector.ID(),
		statDetector.Type(),
		statDetector.Version(),
		statDetector.Parameters(),
		statDetector.Process,
	); err != nil {
		return fmt.Errorf("failed to register statistical threshold detector: %w", err)
	}

	// Volume anomaly detector
	volParams := map[string]string{
		"window_duration":          "5m",
		"threshold.authentication": "10",
		"threshold.authorization":  "20",
		"threshold.syscall":        "100",
		"threshold.default":        "50",
		"event_types":              "authentication,authorization,syscall,network_flow",
	}
	volDetector := NewVolumeAnomalyDetector("volume-anomaly-1", volParams)
	if err := service.RegisterDetector(
		volDetector.ID(),
		volDetector.Type(),
		volDetector.Version(),
		volDetector.Parameters(),
		volDetector.Process,
	); err != nil {
		return fmt.Errorf("failed to register volume anomaly detector: %w", err)
	}

	// Behavioral pattern detector
	behParams := map[string]string{
		"max_sequence_length":          "20",
		"event_types":                  "authentication,authorization",
		"pattern.failed_auth_sequence": "failed_auth,failed_auth,failed_auth,successful_auth",
		"pattern.privilege_escalation": "successful_auth,access_sensitive_resource,modify_permissions",
		"pattern.password_spraying":    "failed_auth,failed_auth,failed_auth,failed_auth,failed_auth",
	}
	behDetector := NewBehavioralPatternDetector("behavioral-pattern-1", behParams)
	if err := service.RegisterDetector(
		behDetector.ID(),
		behDetector.Type(),
		behDetector.Version(),
		behDetector.Parameters(),
		behDetector.Process,
	); err != nil {
		return fmt.Errorf("failed to register behavioral pattern detector: %w", err)
	}

	log.Info().Msg("Registered standard anomaly detectors")
	return nil
}
