// Package trust provides trust scoring and evaluation for data sources
package trust

import (
	"sync"
)

// TrustMetricsEmitter defines the interface for components that emit trust-related metrics
type TrustMetricsEmitter interface {
	// EmitTrustScore notifies when a source's trust score changes
	EmitTrustScore(sourceID string, score int, previousScore int)

	// EmitSystemThreatLevel notifies when the system-wide threat level changes
	EmitSystemThreatLevel(newLevel, previousLevel int)

	// EmitAnomalyDetected notifies when a new anomaly is detected
	EmitAnomalyDetected(sourceID string, category TrustScoreCategory, severity SeverityLevel)

	// EmitTrustTierChange notifies when a source's trust tier changes
	EmitTrustTierChange(sourceID string, newTier, previousTier int)

	// EmitDefensivePostureChange notifies when the system's defensive posture changes
	EmitDefensivePostureChange(newPosture, previousPosture string)
}

// TrustMetricsHooks provides instrumentation hooks for the trust system
type TrustMetricsHooks struct {
	mu       sync.RWMutex
	emitters []TrustMetricsEmitter
}

// NewTrustMetricsHooks creates a new instance of TrustMetricsHooks
func NewTrustMetricsHooks() *TrustMetricsHooks {
	return &TrustMetricsHooks{
		emitters: make([]TrustMetricsEmitter, 0),
	}
}

// RegisterEmitter adds a new metrics emitter to the hooks
func (h *TrustMetricsHooks) RegisterEmitter(emitter TrustMetricsEmitter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emitters = append(h.emitters, emitter)
}

// NotifyScoreChange informs all registered emitters about a trust score change
func (h *TrustMetricsHooks) NotifyScoreChange(sourceID string, score int, previousScore int) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitTrustScore(sourceID, score, previousScore)
	}
}

// NotifyThreatLevelChange informs all registered emitters about a threat level change
func (h *TrustMetricsHooks) NotifyThreatLevelChange(newLevel, previousLevel int) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitSystemThreatLevel(newLevel, previousLevel)
	}
}

// NotifyAnomalyDetected informs all registered emitters about a new anomaly
func (h *TrustMetricsHooks) NotifyAnomalyDetected(sourceID string, category TrustScoreCategory, severity SeverityLevel) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitAnomalyDetected(sourceID, category, severity)
	}
}

// NotifyTrustTierChange informs all registered emitters about a trust tier change
func (h *TrustMetricsHooks) NotifyTrustTierChange(sourceID string, newTier, previousTier int) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitTrustTierChange(sourceID, newTier, previousTier)
	}
}

// NotifyDefensivePostureChange informs all registered emitters about a defensive posture change
func (h *TrustMetricsHooks) NotifyDefensivePostureChange(newPosture, previousPosture string) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitDefensivePostureChange(newPosture, previousPosture)
	}
}

// TrustSystemObserver is an adapter that connects Trust System hooks to the telemetry system
type TrustSystemObserver struct {
	emitScoresFn      func(threatLevel int, sourceScores map[string]int, anomalyCount int)
	sourceScores      map[string]int
	totalAnomalies    int
	systemThreatLevel int
	mu                sync.Mutex
}

// NewTrustSystemObserver creates a new observer that will emit metrics using the provided function
func NewTrustSystemObserver(emitFn func(threatLevel int, sourceScores map[string]int, anomalyCount int)) *TrustSystemObserver {
	return &TrustSystemObserver{
		emitScoresFn:      emitFn,
		sourceScores:      make(map[string]int),
		totalAnomalies:    0,
		systemThreatLevel: 1,
	}
}

// EmitTrustScore implements TrustMetricsEmitter
func (o *TrustSystemObserver) EmitTrustScore(sourceID string, score int, previousScore int) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Update local state
	o.sourceScores[sourceID] = score

	// Emit updated metrics
	o.emitMetrics()
}

// EmitSystemThreatLevel implements TrustMetricsEmitter
func (o *TrustSystemObserver) EmitSystemThreatLevel(newLevel, previousLevel int) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Update local state
	o.systemThreatLevel = newLevel

	// Emit updated metrics
	o.emitMetrics()
}

// EmitAnomalyDetected implements TrustMetricsEmitter
func (o *TrustSystemObserver) EmitAnomalyDetected(sourceID string, category TrustScoreCategory, severity SeverityLevel) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Update local state
	o.totalAnomalies++

	// Emit updated metrics
	o.emitMetrics()
}

// EmitTrustTierChange implements TrustMetricsEmitter
func (o *TrustSystemObserver) EmitTrustTierChange(sourceID string, newTier, previousTier int) {
	// Tier changes don't directly affect our metrics collection
	// The score changes associated with tier changes will be captured by EmitTrustScore
}

// EmitDefensivePostureChange implements TrustMetricsEmitter
func (o *TrustSystemObserver) EmitDefensivePostureChange(newPosture, previousPosture string) {
	// Posture changes don't directly affect our metrics collection
	// The threat level changes associated with posture changes will be captured by EmitSystemThreatLevel
}

// emitMetrics sends the current metrics to the registered function
func (o *TrustSystemObserver) emitMetrics() {
	if o.emitScoresFn != nil {
		// Create a copy of sourceScores to avoid concurrent map access issues
		sourceScoresCopy := make(map[string]int, len(o.sourceScores))
		for k, v := range o.sourceScores {
			sourceScoresCopy[k] = v
		}

		o.emitScoresFn(o.systemThreatLevel, sourceScoresCopy, o.totalAnomalies)
	}
}
