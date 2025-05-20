// Package telemetry provides a secure framework for collecting and exposing metrics
package telemetry

import (
	"context"
	"fmt"
	"time"

	"github.com/TFMV/blackice/pkg/flightgw/anomaly"
	"github.com/rs/zerolog/log"
)

// AnomalyIntegration provides integration between the telemetry system and the anomaly detection service
type AnomalyIntegration struct {
	telemetryManager     *TelemetryManager
	anomalyClient        *anomaly.Client
	localBuffer          []*anomaly.TelemetryEvent
	maxBufferSize        int
	bufferFullBehavior   BufferFullBehavior
	telemetryEventTypes  map[string]bool // Event types to forward to anomaly detection
	enrichWithTrustScore bool
	enabled              bool
	ctx                  context.Context
	cancel               context.CancelFunc
}

// BufferFullBehavior defines how to handle a full buffer
type BufferFullBehavior int

const (
	// DropOldest drops the oldest events when the buffer is full
	DropOldest BufferFullBehavior = iota
	// DropNewest drops the newest events when the buffer is full
	DropNewest
	// BlockUntilSpace blocks until there is space in the buffer
	BlockUntilSpace
)

// AnomalyIntegrationConfig contains configuration for the anomaly integration
type AnomalyIntegrationConfig struct {
	// AnomalyServiceAddress is the address of the anomaly detection service
	AnomalyServiceAddress string `mapstructure:"anomaly_service_address"`

	// Buffer configuration
	MaxBufferSize      int                `mapstructure:"max_buffer_size"`
	BufferFullBehavior BufferFullBehavior `mapstructure:"buffer_full_behavior"`

	// Integration configuration
	TelemetryEventTypes  []string `mapstructure:"telemetry_event_types"`
	EnrichWithTrustScore bool     `mapstructure:"enrich_with_trust_score"`
	Enabled              bool     `mapstructure:"enabled"`
}

// DefaultAnomalyIntegrationConfig returns the default configuration for anomaly integration
func DefaultAnomalyIntegrationConfig() *AnomalyIntegrationConfig {
	return &AnomalyIntegrationConfig{
		AnomalyServiceAddress: "localhost:8089",
		MaxBufferSize:         1000,
		BufferFullBehavior:    DropOldest,
		TelemetryEventTypes:   []string{"metric", "log_entry", "network_flow", "syscall"},
		EnrichWithTrustScore:  true,
		Enabled:               true,
	}
}

// NewAnomalyIntegration creates a new integration between telemetry and anomaly detection
func NewAnomalyIntegration(telemetryManager *TelemetryManager, config *AnomalyIntegrationConfig) (*AnomalyIntegration, error) {
	// Skip setup if disabled
	if !config.Enabled {
		log.Info().Msg("Anomaly detection integration is disabled")
		return &AnomalyIntegration{
			telemetryManager: telemetryManager,
			enabled:          false,
		}, nil
	}

	// Create context for this integration
	ctx, cancel := context.WithCancel(context.Background())

	// Create anomaly client
	clientConfig := &anomaly.ClientConfig{
		ServiceAddress:  config.AnomalyServiceAddress,
		BufferSize:      config.MaxBufferSize,
		FlushInterval:   5 * time.Second,
		ReconnectDelay:  5 * time.Second,
		TLSEnabled:      false,
		RetentionPolicy: anomaly.RetentionPolicy("drop_oldest"),
	}

	client, err := anomaly.NewClient(clientConfig)
	if err != nil {
		cancel()
		return nil, err
	}

	// Create map of event types to forward
	eventTypes := make(map[string]bool)
	for _, eventType := range config.TelemetryEventTypes {
		eventTypes[eventType] = true
	}

	integration := &AnomalyIntegration{
		telemetryManager:     telemetryManager,
		anomalyClient:        client,
		localBuffer:          make([]*anomaly.TelemetryEvent, 0, config.MaxBufferSize),
		maxBufferSize:        config.MaxBufferSize,
		bufferFullBehavior:   config.BufferFullBehavior,
		telemetryEventTypes:  eventTypes,
		enrichWithTrustScore: config.EnrichWithTrustScore,
		enabled:              true,
		ctx:                  ctx,
		cancel:               cancel,
	}

	// Register metrics for anomaly integration
	if err := integration.registerMetrics(); err != nil {
		client.Close()
		cancel()
		return nil, err
	}

	// Start background processing
	go integration.processAnomalies()

	log.Info().
		Str("service_address", config.AnomalyServiceAddress).
		Int("buffer_size", config.MaxBufferSize).
		Strs("event_types", config.TelemetryEventTypes).
		Bool("enrich_with_trust", config.EnrichWithTrustScore).
		Msg("Anomaly detection integration started")

	return integration, nil
}

// registerMetrics registers metrics for anomaly integration
func (ai *AnomalyIntegration) registerMetrics() error {
	// Register counter for events forwarded to anomaly detection
	_, err := ai.telemetryManager.RegisterCounter(
		"anomaly_events_forwarded_total",
		"Total number of events forwarded to anomaly detection",
		PublicMetrics,
	)
	if err != nil {
		return err
	}

	// Register counter for anomalies detected
	_, err = ai.telemetryManager.RegisterCounter(
		"anomaly_events_detected_total",
		"Total number of anomalies detected",
		PublicMetrics,
	)
	if err != nil {
		return err
	}

	// Register gauge for anomaly detection service connection status
	_, err = ai.telemetryManager.RegisterGauge(
		"anomaly_service_connected",
		"Connection status to anomaly detection service (1=connected, 0=disconnected)",
		PublicMetrics,
	)
	if err != nil {
		return err
	}

	return nil
}

// Stop stops the anomaly integration
func (ai *AnomalyIntegration) Stop() error {
	if !ai.enabled {
		return nil
	}

	ai.cancel()
	return ai.anomalyClient.Close()
}

// processAnomalies periodically queries for anomalies and updates metrics
func (ai *AnomalyIntegration) processAnomalies() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ai.ctx.Done():
			return
		case <-ticker.C:
			ai.queryAndProcessAnomalies()
		}
	}
}

// queryAndProcessAnomalies queries for anomalies and updates metrics
func (ai *AnomalyIntegration) queryAndProcessAnomalies() {
	// Query for anomalies in the last hour
	endTime := time.Now()
	startTime := endTime.Add(-1 * time.Hour)

	// Query the anomaly service
	anomalies, err := ai.anomalyClient.QueryAnomalies(
		ai.ctx,
		startTime,
		endTime,
		"",
		"",
		anomaly.SeverityInfo,
	)
	if err != nil {
		log.Error().Err(err).Msg("Failed to query anomalies")
		return
	}

	// Update counter with number of anomalies
	ai.telemetryManager.mu.RLock()
	if counter, exists := ai.telemetryManager.counters["anomaly_events_detected_total"]; exists && counter != nil {
		counter.Add(float64(len(anomalies)))
	}
	ai.telemetryManager.mu.RUnlock()

	// TODO: Process anomalies further, e.g., update trust scores, generate alerts, etc.
}

// ForwardTelemetryEvent forwards a telemetry event to the anomaly detection service
func (ai *AnomalyIntegration) ForwardTelemetryEvent(componentID, eventType string, attributes map[string]interface{}, rawData []byte) error {
	if !ai.enabled {
		return nil
	}

	// Check if this event type should be forwarded
	if !ai.telemetryEventTypes[eventType] {
		return nil
	}

	// Create telemetry event
	event := &anomaly.TelemetryEvent{
		EventID:           generateUniqueID(),
		SourceComponentID: componentID,
		EventType:         eventType,
		Timestamp:         time.Now(),
		Attributes:        attributes,
		RawData:           rawData,
	}

	// Enrich with trust score if enabled
	if ai.enrichWithTrustScore {
		// Lookup trust score for this component
		trustScore := ai.lookupTrustScore(componentID)
		if trustScore != nil {
			event.TrustScoreContext = trustScore
		}
	}

	// Forward to anomaly service
	if err := ai.anomalyClient.SendEvent(event); err != nil {
		log.Error().Err(err).Msg("Failed to forward telemetry event to anomaly service")
		return err
	}

	// Update counter for events forwarded
	ai.telemetryManager.mu.RLock()
	if counter, exists := ai.telemetryManager.counters["anomaly_events_forwarded_total"]; exists && counter != nil {
		counter.Add(1)
	}
	ai.telemetryManager.mu.RUnlock()

	return nil
}

// lookupTrustScore retrieves the trust score for a component
func (ai *AnomalyIntegration) lookupTrustScore(componentID string) *anomaly.TrustScoreContext {
	// This would be implemented to query the trust scoring system
	// For now, return a placeholder
	return &anomaly.TrustScoreContext{
		SourceID:     componentID,
		CurrentScore: 85, // Example score
		ScoreHistory: []int{90, 88, 85},
		ScoreTimestamps: []time.Time{
			time.Now().Add(-30 * time.Minute),
			time.Now().Add(-15 * time.Minute),
			time.Now(),
		},
		ScoreCategories: map[string]int{
			"behavioral":  90,
			"consistency": 85,
			"timing":      80,
		},
		LastTransition:   time.Now().Add(-2 * time.Hour),
		TransitionReason: "Regular evaluation",
	}
}

// ProcessDetectedAnomalies handles anomalies detected by the service
func (ai *AnomalyIntegration) ProcessDetectedAnomalies(anomalies []*anomaly.Anomaly) {
	for _, detectedAnomaly := range anomalies {
		// Update metrics
		ai.telemetryManager.mu.RLock()
		if counter, exists := ai.telemetryManager.counters["anomaly_events_detected_total"]; exists && counter != nil {
			counter.Add(1)
		}

		// Track severity-specific metrics
		severityMetricName := fmt.Sprintf("anomaly_severity_%s_total", ai.getSeverityString(detectedAnomaly.Severity))
		if counter, exists := ai.telemetryManager.counters[severityMetricName]; exists && counter != nil {
			counter.Add(1)
		}
		ai.telemetryManager.mu.RUnlock()

		// Log the detected anomaly
		log.Info().
			Str("anomaly_id", detectedAnomaly.AnomalyID).
			Str("source", detectedAnomaly.SourceComponentID).
			Str("category", string(detectedAnomaly.Category)).
			Int("severity", int(detectedAnomaly.Severity)).
			Float64("confidence", detectedAnomaly.Confidence).
			Strs("affected_resources", detectedAnomaly.AffectedResources).
			Str("remediation_status", ai.getRemediationStatusString(detectedAnomaly.RemediationStatus)).
			Msg("Anomaly detected")
	}
}

// getSeverityString converts severity to string
func (ai *AnomalyIntegration) getSeverityString(severity anomaly.SeverityLevel) string {
	switch severity {
	case anomaly.SeverityInfo:
		return "info"
	case anomaly.SeverityLow:
		return "low"
	case anomaly.SeverityMedium:
		return "medium"
	case anomaly.SeverityHigh:
		return "high"
	case anomaly.SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// getRemediationStatusString converts remediation status to string
func (ai *AnomalyIntegration) getRemediationStatusString(status anomaly.RemediationStatus) string {
	switch status {
	case anomaly.RemediationNone:
		return "none"
	case anomaly.RemediationPending:
		return "pending"
	case anomaly.RemediationInProgress:
		return "in_progress"
	case anomaly.RemediationResolved:
		return "resolved"
	case anomaly.RemediationFalsePositive:
		return "false_positive"
	case anomaly.RemediationEscalated:
		return "escalated"
	default:
		return "unknown"
	}
}

// Helper function to generate a unique ID
func generateUniqueID() string {
	return time.Now().Format("20060102150405.000000") + "-" + randomString(8)
}

// Helper function to generate a random string
func randomString(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[int(time.Now().UnixNano())%len(charset)]
		time.Sleep(1 * time.Nanosecond)
	}
	return string(result)
}
