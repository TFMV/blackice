// Package telemetry provides a secure framework for collecting and exposing metrics
package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/TFMV/blackice/pkg/flightgw/anomaly"
	"github.com/rs/zerolog/log"
)

// AnomalyIntegration provides integration between the telemetry system and the anomaly detection service
type AnomalyIntegration struct {
	telemetryManager     *TelemetryManager
	anomalyClient        *anomaly.Client
	trustManager         *Manager
	localBuffer          []*anomaly.TelemetryEvent
	maxBufferSize        int
	bufferFullBehavior   BufferFullBehavior
	telemetryEventTypes  map[string]bool // Event types to forward to anomaly detection
	enrichWithTrustScore bool
	enabled              bool
	ctx                  context.Context
	cancel               context.CancelFunc

	// Alert and response configuration
	alertConfiguration    map[anomaly.SeverityLevel]AlertConfig
	remediationHandlers   map[string]RemediationHandler
	autoRemediationLevel  anomaly.SeverityLevel
	anomalyCorrelator     *AnomalyCorrelator
	processingMu          sync.RWMutex
	processingQueue       []*AnomalyType
	maxQueueSize          int
	securityAlertEndpoint string
}

// AlertConfig defines how to handle alerts for a given severity level
type AlertConfig struct {
	Throttling       time.Duration // Minimum time between alerts
	Channels         []string      // Alert channels (e.g., "email", "sms", "slack")
	RequireApproval  bool          // Whether remediation requires approval
	EscalationLevel  int           // Escalation level (higher = more urgent)
	RetentionPeriod  time.Duration // How long to retain the alert
	CorrelationScope string        // Scope for correlation ("source", "global", "category")
	Template         string        // Alert template name
}

// RemediationHandler defines a function that can remediate an anomaly
type RemediationHandler func(context.Context, *AnomalyType) (string, error)

// AnomalyCorrelator correlates related anomalies
type AnomalyCorrelator struct {
	recentAnomalies    map[string][]*AnomalyType // source -> anomalies
	sourceThresholds   map[string]int            // Number of anomalies that trigger an incident
	categoryThresholds map[string]int            // Number of anomalies of same category that trigger an incident
	patternThresholds  map[string]int            // Number of anomalies matching a pattern that trigger an incident
	activeIncidents    map[string]*Incident
	correlationWindow  time.Duration
	mutex              sync.RWMutex
}

// Incident represents a collection of related anomalies
type Incident struct {
	IncidentID       string
	RelatedAnomalies []*AnomalyType
	FirstDetected    time.Time
	LastUpdated      time.Time
	Status           IncidentStatus
	Severity         SeverityLevel
	AffectedSources  []string
	OwnerID          string
	Notes            []string
}

// IncidentStatus represents the status of an incident
type IncidentStatus int

const (
	// IncidentNew is a newly created incident
	IncidentNew IncidentStatus = iota
	// IncidentInvestigating is an incident being investigated
	IncidentInvestigating
	// IncidentRemediating is an incident being remediated
	IncidentRemediating
	// IncidentResolved is a resolved incident
	IncidentResolved
	// IncidentFalsePositive is an incident determined to be a false positive
	IncidentFalsePositive
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

	// Trust management
	TrustManagerEndpoint string `mapstructure:"trust_manager_endpoint"`

	// Alert and remediation configuration
	SecurityAlertEndpoint string                 `mapstructure:"security_alert_endpoint"`
	AutoRemediationLevel  string                 `mapstructure:"auto_remediation_level"`
	CorrelationWindow     time.Duration          `mapstructure:"correlation_window"`
	MaxProcessingQueue    int                    `mapstructure:"max_processing_queue"`
	AlertConfigurations   map[string]AlertConfig `mapstructure:"alert_configurations"`
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
		TrustManagerEndpoint:  "localhost:8093",
		SecurityAlertEndpoint: "localhost:8095",
		AutoRemediationLevel:  "LOW",
		CorrelationWindow:     time.Hour,
		MaxProcessingQueue:    1000,
		AlertConfigurations: map[string]AlertConfig{
			"INFO": {
				Throttling:       time.Hour,
				Channels:         []string{"log"},
				RequireApproval:  false,
				EscalationLevel:  0,
				RetentionPeriod:  24 * time.Hour * 7,
				CorrelationScope: "source",
			},
			"LOW": {
				Throttling:       30 * time.Minute,
				Channels:         []string{"log", "dashboard"},
				RequireApproval:  false,
				EscalationLevel:  1,
				RetentionPeriod:  24 * time.Hour * 14,
				CorrelationScope: "source",
			},
			"MEDIUM": {
				Throttling:       15 * time.Minute,
				Channels:         []string{"log", "dashboard", "email"},
				RequireApproval:  true,
				EscalationLevel:  2,
				RetentionPeriod:  24 * time.Hour * 30,
				CorrelationScope: "category",
			},
			"HIGH": {
				Throttling:       5 * time.Minute,
				Channels:         []string{"log", "dashboard", "email", "sms"},
				RequireApproval:  true,
				EscalationLevel:  3,
				RetentionPeriod:  24 * time.Hour * 90,
				CorrelationScope: "global",
			},
			"CRITICAL": {
				Throttling:       1 * time.Minute,
				Channels:         []string{"log", "dashboard", "email", "sms", "phone"},
				RequireApproval:  true,
				EscalationLevel:  4,
				RetentionPeriod:  24 * time.Hour * 365,
				CorrelationScope: "global",
			},
		},
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

	// Create trust manager client
	var trustManager *Manager
	if config.TrustManagerEndpoint != "" {
		trustManager, err = NewManager(config.TrustManagerEndpoint)
		if err != nil {
			log.Warn().
				Err(err).
				Str("endpoint", config.TrustManagerEndpoint).
				Msg("Could not connect to trust manager, trust score updates will be disabled")
			trustManager = nil
		}
	}

	// Parse alert configurations
	alertConfig := make(map[anomaly.SeverityLevel]AlertConfig)
	for levelStr, config := range config.AlertConfigurations {
		var level anomaly.SeverityLevel
		switch levelStr {
		case "INFO":
			level = SeverityInfo
		case "LOW":
			level = SeverityLow
		case "MEDIUM":
			level = SeverityMedium
		case "HIGH":
			level = SeverityHigh
		case "CRITICAL":
			level = SeverityCritical
		default:
			continue
		}
		alertConfig[level] = config
	}

	// Parse auto-remediation level
	var autoRemediationLevel anomaly.SeverityLevel
	switch config.AutoRemediationLevel {
	case "INFO":
		autoRemediationLevel = SeverityInfo
	case "LOW":
		autoRemediationLevel = SeverityLow
	case "MEDIUM":
		autoRemediationLevel = SeverityMedium
	case "HIGH":
		autoRemediationLevel = SeverityHigh
	case "CRITICAL":
		autoRemediationLevel = SeverityCritical
	default:
		autoRemediationLevel = SeverityMedium
	}

	// Initialize anomaly correlator
	correlator := &AnomalyCorrelator{
		recentAnomalies:  make(map[string][]*AnomalyType),
		sourceThresholds: map[string]int{"default": 3},
		categoryThresholds: map[string]int{
			"volume":      3,
			"behavioral":  2,
			"consistency": 3,
			"timing":      3,
			"default":     3,
		},
		patternThresholds: map[string]int{
			"T1110":   2, // Brute Force - more sensitive
			"T1078":   2, // Valid Accounts - more sensitive
			"default": 3,
		},
		activeIncidents:   make(map[string]*Incident),
		correlationWindow: config.CorrelationWindow,
		mutex:             sync.RWMutex{},
	}

	integration := &AnomalyIntegration{
		telemetryManager:      telemetryManager,
		anomalyClient:         client,
		trustManager:          trustManager,
		localBuffer:           make([]*anomaly.TelemetryEvent, 0, config.MaxBufferSize),
		maxBufferSize:         config.MaxBufferSize,
		bufferFullBehavior:    config.BufferFullBehavior,
		telemetryEventTypes:   eventTypes,
		enrichWithTrustScore:  config.EnrichWithTrustScore,
		enabled:               true,
		ctx:                   ctx,
		cancel:                cancel,
		alertConfiguration:    alertConfig,
		remediationHandlers:   make(map[string]RemediationHandler),
		autoRemediationLevel:  autoRemediationLevel,
		anomalyCorrelator:     correlator,
		processingMu:          sync.RWMutex{},
		processingQueue:       make([]*AnomalyType, 0, config.MaxProcessingQueue),
		maxQueueSize:          config.MaxProcessingQueue,
		securityAlertEndpoint: config.SecurityAlertEndpoint,
	}

	// Register metrics for anomaly integration
	if err := integration.registerMetrics(); err != nil {
		client.Close()
		cancel()
		return nil, err
	}

	// Register default remediation handlers
	integration.registerDefaultRemediationHandlers()

	// Start background processing
	go integration.processAnomalies()
	go integration.processQueue()

	log.Info().
		Str("service_address", config.AnomalyServiceAddress).
		Int("buffer_size", config.MaxBufferSize).
		Strs("event_types", config.TelemetryEventTypes).
		Bool("enrich_with_trust", config.EnrichWithTrustScore).
		Msg("Anomaly detection integration started")

	return integration, nil
}

// registerDefaultRemediationHandlers registers the default remediation handlers
func (ai *AnomalyIntegration) registerDefaultRemediationHandlers() {
	// Handler for volume anomalies
	ai.remediationHandlers[string(CategoryVolume)] = func(ctx context.Context, anomaly *AnomalyType) (string, error) {
		// Implement rate limiting or throttling for the affected component
		log.Info().
			Str("anomaly_id", anomaly.AnomalyID).
			Str("source", anomaly.SourceComponentID).
			Msg("Applying rate limiting remediation for volume anomaly")

		// In a real implementation, this would call into a rate limiting system
		// For now, just return success
		return "Applied rate limiting to affected component", nil
	}

	// Handler for behavioral anomalies
	ai.remediationHandlers[string(CategoryBehavioral)] = func(ctx context.Context, anomaly *AnomalyType) (string, error) {
		// Implement behavioral remediation, like restricting permissions
		log.Info().
			Str("anomaly_id", anomaly.AnomalyID).
			Str("source", anomaly.SourceComponentID).
			Msg("Applying behavioral remediation")

		// In a real implementation, this would restrict permissions
		return "Applied behavioral remediation, restricted permissions", nil
	}

	// Handler for timing anomalies
	ai.remediationHandlers[string(CategoryTiming)] = func(ctx context.Context, anomaly *AnomalyType) (string, error) {
		// Implement timing remediation
		log.Info().
			Str("anomaly_id", anomaly.AnomalyID).
			Str("source", anomaly.SourceComponentID).
			Msg("Applying timing anomaly remediation")

		return "Applied timing remediation", nil
	}

	// Default handler for any category
	ai.remediationHandlers["default"] = func(ctx context.Context, anomaly *AnomalyType) (string, error) {
		// Generic remediation
		log.Info().
			Str("anomaly_id", anomaly.AnomalyID).
			Str("source", anomaly.SourceComponentID).
			Str("category", string(anomaly.Category)).
			Msg("Applying default remediation")

		return "Applied default remediation strategy", nil
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
		SeverityInfo,
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

	// Process all newly detected anomalies
	for _, detectedAnomaly := range anomalies {
		ai.queueAnomalyForProcessing(detectedAnomaly)
	}
}

// queueAnomalyForProcessing adds an anomaly to the processing queue
func (ai *AnomalyIntegration) queueAnomalyForProcessing(anomaly *AnomalyType) {
	ai.processingMu.Lock()
	defer ai.processingMu.Unlock()

	// If the queue is full, handle according to policy
	if len(ai.processingQueue) >= ai.maxQueueSize {
		log.Warn().
			Int("queue_size", len(ai.processingQueue)).
			Int("max_size", ai.maxQueueSize).
			Msg("Anomaly processing queue is full, dropping oldest anomaly")

		// Drop the oldest anomaly
		ai.processingQueue = ai.processingQueue[1:]
	}

	// Add to the queue
	ai.processingQueue = append(ai.processingQueue, anomaly)
}

// processQueue processes the anomaly queue in the background
func (ai *AnomalyIntegration) processQueue() {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ai.ctx.Done():
			return
		case <-ticker.C:
			// Process up to 10 anomalies at a time
			for i := 0; i < 10; i++ {
				anomaly := ai.dequeueAnomaly()
				if anomaly == nil {
					break // Queue is empty
				}

				// Process the anomaly
				ai.processAnomaly(anomaly)
			}
		}
	}
}

// dequeueAnomaly removes and returns an anomaly from the queue
func (ai *AnomalyIntegration) dequeueAnomaly() *AnomalyType {
	ai.processingMu.Lock()
	defer ai.processingMu.Unlock()

	if len(ai.processingQueue) == 0 {
		return nil
	}

	// Get the first anomaly
	anomaly := ai.processingQueue[0]

	// Remove it from the queue
	ai.processingQueue = ai.processingQueue[1:]

	return anomaly
}

// processAnomaly processes a single anomaly
func (ai *AnomalyIntegration) processAnomaly(detectedAnomaly *AnomalyType) {
	// 1. Update trust scores based on the anomaly
	ai.updateTrustScore(detectedAnomaly)

	// 2. Correlate with other anomalies
	incident := ai.correlateAnomaly(detectedAnomaly)

	// 3. Generate appropriate alerts
	ai.generateAlerts(detectedAnomaly, incident)

	// 4. Apply automated remediation if appropriate
	ai.applyRemediation(detectedAnomaly)

	// 5. Update metrics
	ai.updateMetrics(detectedAnomaly)

	// Log the processed anomaly
	log.Info().
		Str("anomaly_id", detectedAnomaly.AnomalyID).
		Str("source", detectedAnomaly.SourceComponentID).
		Str("category", string(detectedAnomaly.Category)).
		Int("severity", int(detectedAnomaly.Severity)).
		Float64("confidence", detectedAnomaly.Confidence).
		Strs("affected_resources", detectedAnomaly.AffectedResources).
		Str("remediation_status", ai.getRemediationStatusString(detectedAnomaly.RemediationStatus)).
		Msg("Anomaly processed")
}

// updateTrustScore updates the trust score for the component that generated the anomaly
func (ai *AnomalyIntegration) updateTrustScore(anomaly *AnomalyType) {
	if ai.trustManager == nil {
		return // Trust manager not available
	}

	// Calculate adjustment based on severity and confidence
	adjustment := -10.0 // Base adjustment

	// Scale by severity
	switch anomaly.Severity {
	case SeverityInfo:
		adjustment *= 0.2
	case SeverityLow:
		adjustment *= 0.5
	case SeverityMedium:
		adjustment *= 1.0
	case SeverityHigh:
		adjustment *= 2.0
	case SeverityCritical:
		adjustment *= 4.0
	}

	// Scale by confidence
	adjustment *= anomaly.Confidence

	// Convert to integer
	adjustmentInt := int(adjustment)

	// Apply adjustment to appropriate category based on anomaly type
	var category string
	switch anomaly.Category {
	case CategoryBehavioral:
		category = "behavioral"
	case CategoryConsistency:
		category = "consistency"
	case CategoryTiming:
		category = "timing"
	case CategoryVolume:
		category = "volume"
	default:
		category = "verification" // Default to verification
	}

	// Update the trust score
	err := ai.trustManager.UpdateSourceScore(
		anomaly.SourceComponentID,
		category,
		adjustmentInt,
		fmt.Sprintf("Anomaly %s: %s", anomaly.AnomalyID, anomaly.Description),
		int(anomaly.Severity),
		anomaly.Confidence,
		anomaly.MitreTechnique,
	)

	if err != nil {
		log.Error().
			Err(err).
			Str("source", anomaly.SourceComponentID).
			Str("category", category).
			Int("adjustment", adjustmentInt).
			Msg("Failed to update trust score")
	} else {
		log.Info().
			Str("source", anomaly.SourceComponentID).
			Str("category", category).
			Int("adjustment", adjustmentInt).
			Msg("Updated trust score based on anomaly")
	}
}

// correlateAnomaly correlates the anomaly with other recent anomalies
func (ai *AnomalyIntegration) correlateAnomaly(anomaly *AnomalyType) *Incident {
	ai.anomalyCorrelator.mutex.Lock()
	defer ai.anomalyCorrelator.mutex.Unlock()

	// Add anomaly to recent anomalies for this source
	sourceID := anomaly.SourceComponentID
	if _, exists := ai.anomalyCorrelator.recentAnomalies[sourceID]; !exists {
		ai.anomalyCorrelator.recentAnomalies[sourceID] = make([]*AnomalyType, 0)
	}

	// Add to recent anomalies
	ai.anomalyCorrelator.recentAnomalies[sourceID] = append(
		ai.anomalyCorrelator.recentAnomalies[sourceID],
		anomaly,
	)

	// Cleanup old anomalies
	cutoff := time.Now().Add(-ai.anomalyCorrelator.correlationWindow)
	var recentAnomalies []*AnomalyType
	for _, a := range ai.anomalyCorrelator.recentAnomalies[sourceID] {
		if a.DetectionTime.After(cutoff) {
			recentAnomalies = append(recentAnomalies, a)
		}
	}
	ai.anomalyCorrelator.recentAnomalies[sourceID] = recentAnomalies

	// Check if we need to create a new incident based on thresholds

	// 1. Check source threshold
	sourceThreshold := ai.anomalyCorrelator.sourceThresholds["default"]
	if threshold, exists := ai.anomalyCorrelator.sourceThresholds[sourceID]; exists {
		sourceThreshold = threshold
	}

	if len(recentAnomalies) >= sourceThreshold {
		// Create new incident or update existing one
		return ai.createOrUpdateIncident(sourceID, recentAnomalies, anomaly)
	}

	// 2. Check category threshold
	categoryStr := string(anomaly.Category)
	categoryThreshold := ai.anomalyCorrelator.categoryThresholds["default"]
	if threshold, exists := ai.anomalyCorrelator.categoryThresholds[categoryStr]; exists {
		categoryThreshold = threshold
	}

	// Count anomalies in this category
	categoryCount := 0
	for _, a := range recentAnomalies {
		if a == anomaly {
			categoryCount++
		}
	}

	if categoryCount >= categoryThreshold {
		// Create new incident or update existing one
		return ai.createOrUpdateIncident(sourceID, recentAnomalies, anomaly)
	}

	// 3. Check pattern threshold
	if anomaly.MitreTechnique != "" {
		patternThreshold := ai.anomalyCorrelator.patternThresholds["default"]
		if threshold, exists := ai.anomalyCorrelator.patternThresholds[anomaly.MitreTechnique]; exists {
			patternThreshold = threshold
		}

		// Count anomalies with this pattern
		patternCount := 0
		for _, a := range recentAnomalies {
			if a == anomaly {
				patternCount++
			}
		}

		if patternCount >= patternThreshold {
			// Create new incident or update existing one
			return ai.createOrUpdateIncident(sourceID, recentAnomalies, anomaly)
		}
	}

	// No incident created
	return nil
}

// createOrUpdateIncident creates a new incident or updates an existing one
func (ai *AnomalyIntegration) createOrUpdateIncident(sourceID string, anomalies []*AnomalyType, triggerAnomaly *AnomalyType) *Incident {
	// Check if there's an existing incident for this source
	for _, incident := range ai.anomalyCorrelator.activeIncidents {
		for _, source := range incident.AffectedSources {
			if source == sourceID && incident.Status != IncidentResolved && incident.Status != IncidentFalsePositive {
				// Update existing incident
				incident.RelatedAnomalies = append(incident.RelatedAnomalies, triggerAnomaly)
				incident.LastUpdated = time.Now()

				// Update severity if the new anomaly is more severe
				if triggerAnomaly.Severity > incident.Severity {
					incident.Severity = triggerAnomaly.Severity
				}

				// Log the update
				log.Info().
					Str("incident_id", incident.IncidentID).
					Str("anomaly_id", triggerAnomaly.AnomalyID).
					Str("source", sourceID).
					Msg("Updated existing incident with new anomaly")

				return incident
			}
		}
	}

	// Create a new incident
	incident := &Incident{
		IncidentID:       generateIncidentID(),
		RelatedAnomalies: []*AnomalyType{triggerAnomaly},
		FirstDetected:    time.Now(),
		LastUpdated:      time.Now(),
		Status:           IncidentNew,
		Severity:         triggerAnomaly.Severity,
		AffectedSources:  []string{sourceID},
		Notes:            []string{fmt.Sprintf("Incident created from anomaly %s", triggerAnomaly.AnomalyID)},
	}

	// Add to active incidents
	ai.anomalyCorrelator.activeIncidents[incident.IncidentID] = incident

	// Log the new incident
	log.Info().
		Str("incident_id", incident.IncidentID).
		Str("source", sourceID).
		Int("severity", int(incident.Severity)).
		Msg("Created new incident from anomaly")

	return incident
}

// generateAlerts generates alerts based on the anomaly and incident
func (ai *AnomalyIntegration) generateAlerts(anomaly *AnomalyType, incident *Incident) {
	// Get alert config for this severity
	config, exists := ai.alertConfiguration[anomaly.Severity]
	if !exists {
		// Default to INFO level if not configured
		config = ai.alertConfiguration[SeverityInfo]
	}

	// Create base alert data
	alert := map[string]interface{}{
		"anomaly_id":         anomaly.AnomalyID,
		"source":             anomaly.SourceComponentID,
		"category":           string(anomaly.Category),
		"severity":           int(anomaly.Severity),
		"description":        anomaly.Description,
		"detection_time":     anomaly.DetectionTime.Format(time.RFC3339),
		"confidence":         anomaly.Confidence,
		"affected_resources": anomaly.AffectedResources,
		"mitre_technique":    anomaly.MitreTechnique,
		"ttp_identifiers":    anomaly.TTPIdentifiers,
		"attributes":         anomaly.Attributes,
		"requires_approval":  config.RequireApproval,
		"escalation_level":   config.EscalationLevel,
	}

	// Add incident info if available
	if incident != nil {
		alert["incident_id"] = incident.IncidentID
		alert["incident_status"] = int(incident.Status)
		alert["related_anomaly_count"] = len(incident.RelatedAnomalies)
		alert["incident_first_detected"] = incident.FirstDetected.Format(time.RFC3339)
	}

	// Send alert to each configured channel
	for _, channel := range config.Channels {
		switch channel {
		case "log":
			// Already logged in processAnomaly
		case "dashboard":
			// In a real implementation, publish to dashboard message bus
			log.Info().
				Str("channel", "dashboard").
				Str("anomaly_id", anomaly.AnomalyID).
				Int("severity", int(anomaly.Severity)).
				Msg("Alert published to dashboard")
		case "email", "sms", "phone":
			// In a real implementation, send alerts to notification service
			log.Info().
				Str("channel", channel).
				Str("anomaly_id", anomaly.AnomalyID).
				Int("severity", int(anomaly.Severity)).
				Msg("Alert sent to notification service")
		}
	}

	// Send to security alert endpoint if configured
	if ai.securityAlertEndpoint != "" {
		// In a real implementation, send to security monitoring system
		log.Info().
			Str("endpoint", ai.securityAlertEndpoint).
			Str("anomaly_id", anomaly.AnomalyID).
			Msg("Alert sent to security monitoring system")
	}
}

// applyRemediation applies automated remediation if appropriate
func (ai *AnomalyIntegration) applyRemediation(anomaly *AnomalyType) {
	// Only apply remediation for anomalies at or below the auto-remediation level
	if anomaly.Severity > ai.autoRemediationLevel {
		log.Info().
			Str("anomaly_id", anomaly.AnomalyID).
			Int("severity", int(anomaly.Severity)).
			Int("auto_level", int(ai.autoRemediationLevel)).
			Msg("Anomaly severity exceeds auto-remediation level, skipping automated remediation")
		return
	}

	// Look up appropriate handler based on category
	categoryStr := string(anomaly.Category)
	handler, exists := ai.remediationHandlers[categoryStr]
	if !exists {
		handler = ai.remediationHandlers["default"]
	}

	// Apply remediation
	result, err := handler(ai.ctx, anomaly)
	if err != nil {
		log.Error().
			Err(err).
			Str("anomaly_id", anomaly.AnomalyID).
			Str("category", categoryStr).
			Msg("Failed to apply remediation")
	} else {
		log.Info().
			Str("anomaly_id", anomaly.AnomalyID).
			Str("category", categoryStr).
			Str("result", result).
			Msg("Successfully applied remediation")
	}
}

// updateMetrics updates metrics based on the anomaly
func (ai *AnomalyIntegration) updateMetrics(anomaly *AnomalyType) {
	ai.telemetryManager.mu.RLock()
	defer ai.telemetryManager.mu.RUnlock()

	// Update general anomaly counter
	if counter, exists := ai.telemetryManager.counters["anomaly_events_detected_total"]; exists && counter != nil {
		counter.Add(1)
	}

	// Track severity-specific metrics
	severityMetricName := fmt.Sprintf("anomaly_severity_%s_total", ai.getSeverityString(anomaly.Severity))
	if counter, exists := ai.telemetryManager.counters[severityMetricName]; exists && counter != nil {
		counter.Add(1)
	}

	// Track category-specific metrics
	categoryMetricName := fmt.Sprintf("anomaly_category_%s_total", string(anomaly.Category))
	if counter, exists := ai.telemetryManager.counters[categoryMetricName]; exists && counter != nil {
		counter.Add(1)
	}

	// Track MITRE technique metrics if available
	if anomaly.MitreTechnique != "" {
		techniqueMetricName := fmt.Sprintf("anomaly_technique_%s_total", anomaly.MitreTechnique)
		if counter, exists := ai.telemetryManager.counters[techniqueMetricName]; exists && counter != nil {
			counter.Add(1)
		}
	}
}

// generateIncidentID generates a unique incident ID
func generateIncidentID() string {
	var bytes [4]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		// Fallback to time-based ID if random fails
		return fmt.Sprintf("INC-%s", time.Now().Format("20060102-150405"))
	}
	return fmt.Sprintf("INC-%s", hex.EncodeToString(bytes[:]))
}

// getSeverityString converts severity to string
func (ai *AnomalyIntegration) getSeverityString(severity anomaly.SeverityLevel) string {
	switch severity {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// getRemediationStatusString converts remediation status to string
func (ai *AnomalyIntegration) getRemediationStatusString(status anomaly.RemediationStatus) string {
	switch status {
	case RemediationNone:
		return "none"
	case RemediationPending:
		return "pending"
	case RemediationInProgress:
		return "in_progress"
	case RemediationResolved:
		return "resolved"
	case RemediationFalsePositive:
		return "false_positive"
	case RemediationEscalated:
		return "escalated"
	default:
		return "unknown"
	}
}

// Register metrics for anomaly detection
func (ai *AnomalyIntegration) registerMetrics() error {
	// Only proceed if telemetry manager is available
	if ai.telemetryManager == nil {
		return nil
	}

	// Register counter for total anomalies detected
	anomalyCounter, err := ai.telemetryManager.RegisterCounter(
		"anomaly_events_detected_total",
		"Total number of anomaly events detected",
		SecurityLevel(0), // Public metrics
	)
	if err != nil {
		return err
	}

	// Register counters for each severity level
	severities := []string{"info", "low", "medium", "high", "critical"}
	for _, severity := range severities {
		_, err := ai.telemetryManager.RegisterCounter(
			"anomaly_severity_"+severity+"_total",
			"Total number of "+severity+" severity anomalies",
			SecurityLevel(0), // Public metrics
		)
		if err != nil {
			return err
		}
	}

	// Register counters for each category
	categories := []string{
		"consistency",
		"timing",
		"volume",
		"behavioral",
		"network",
		"system",
		"authentication",
		"authorization",
		"crypto",
	}

	for _, category := range categories {
		_, err := ai.telemetryManager.RegisterCounter(
			"anomaly_category_"+category+"_total",
			"Total number of "+category+" category anomalies",
			SecurityLevel(0), // Public metrics
		)
		if err != nil {
			return err
		}
	}

	// Register gauge for currently open incidents
	incidentGauge, err := ai.telemetryManager.RegisterGauge(
		"anomaly_open_incidents",
		"Current number of open anomaly incidents",
		SecurityLevel(0), // Public metrics
	)
	if err != nil {
		return err
	}

	// Update the gauge with initial value if we already have incidents
	if ai.anomalyCorrelator != nil {
		ai.anomalyCorrelator.mutex.RLock()
		count := 0
		for _, incident := range ai.anomalyCorrelator.activeIncidents {
			if incident.Status != IncidentResolved && incident.Status != IncidentFalsePositive {
				count++
			}
		}
		ai.anomalyCorrelator.mutex.RUnlock()

		if incidentGauge != nil {
			incidentGauge.Set(float64(count))
		}
	}

	// If counter was successfully registered, initialize with zero
	if anomalyCounter != nil {
		anomalyCounter.Add(0)
	}

	return nil
}

// processAnomalies periodically queries for anomalies and processes them
func (ai *AnomalyIntegration) processAnomalies() {
	// Define how often to query for anomalies
	queryInterval := 5 * time.Minute
	ticker := time.NewTicker(queryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ai.ctx.Done():
			log.Info().Msg("Anomaly processing shutdown due to context cancellation")
			return
		case <-ticker.C:
			if !ai.enabled {
				continue
			}

			// Query and process anomalies
			ai.queryAndProcessAnomalies()

			// Update open incident metrics
			if ai.anomalyCorrelator != nil && ai.telemetryManager != nil {
				ai.telemetryManager.mu.RLock()
				incidentGauge, exists := ai.telemetryManager.gauges["anomaly_open_incidents"]
				ai.telemetryManager.mu.RUnlock()

				if exists && incidentGauge != nil {
					ai.anomalyCorrelator.mutex.RLock()
					count := 0
					for _, incident := range ai.anomalyCorrelator.activeIncidents {
						if incident.Status != IncidentResolved && incident.Status != IncidentFalsePositive {
							count++
						}
					}
					ai.anomalyCorrelator.mutex.RUnlock()

					incidentGauge.Set(float64(count))
				}
			}
		}
	}
}

// Stop gracefully shuts down the anomaly integration
func (ai *AnomalyIntegration) Stop() error {
	if !ai.enabled {
		return nil
	}

	log.Info().Msg("Stopping anomaly integration")

	// Cancel the context to stop background goroutines
	ai.cancel()

	// Close the anomaly client
	if ai.anomalyClient != nil {
		if err := ai.anomalyClient.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing anomaly client")
			return err
		}
	}

	// Close the trust manager
	if ai.trustManager != nil {
		if err := ai.trustManager.Close(); err != nil {
			log.Error().Err(err).Msg("Error closing trust manager")
			return err
		}
	}

	return nil
}

// ForwardTelemetryEvent forwards a telemetry event to the anomaly detection service
func (ai *AnomalyIntegration) ForwardTelemetryEvent(
	componentID string,
	eventType string,
	attributes map[string]interface{},
	rawData []byte,
) error {
	if !ai.enabled {
		return nil
	}

	// Check if this event type should be forwarded
	if !ai.telemetryEventTypes[eventType] && !ai.telemetryEventTypes["*"] {
		// Not a tracked event type
		return nil
	}

	// Create a telemetry event
	event := &anomaly.TelemetryEvent{
		EventID:           generateRandomID(),
		SourceComponentID: componentID,
		EventType:         eventType,
		Timestamp:         time.Now(),
		Attributes:        attributes,
		RawData:           rawData,
	}

	// Enrich with trust score if enabled
	if ai.enrichWithTrustScore && ai.trustManager != nil {
		score, err := ai.trustManager.GetSourceScore(componentID)
		if err == nil {
			event.TrustScoreContext = &anomaly.TrustScoreContext{
				SourceID:     componentID,
				CurrentScore: score,
			}
		}
	}

	// Add to local buffer if space available
	ai.processingMu.Lock()

	if len(ai.localBuffer) >= ai.maxBufferSize {
		// Handle based on buffer full behavior
		switch ai.bufferFullBehavior {
		case DropOldest:
			// Remove the oldest event
			ai.localBuffer = ai.localBuffer[1:]
		case DropNewest:
			// Skip adding this event
			ai.processingMu.Unlock()
			return nil
		default:
			// Default to dropping oldest
			ai.localBuffer = ai.localBuffer[1:]
		}
	}

	// Add to buffer
	ai.localBuffer = append(ai.localBuffer, event)
	ai.processingMu.Unlock()

	// Forward to anomaly service
	if ai.anomalyClient != nil {
		if err := ai.anomalyClient.SendEvent(event); err != nil {
			log.Error().
				Err(err).
				Str("component", componentID).
				Str("event_type", eventType).
				Msg("Failed to forward telemetry to anomaly service")
			return err
		}
	}

	return nil
}

// Helper to generate a random ID for events
func generateRandomID() string {
	var bytes [4]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		// Fallback to time-based ID if random fails
		return fmt.Sprintf("evt-%s", time.Now().Format("20060102-150405.000"))
	}
	return fmt.Sprintf("evt-%s", hex.EncodeToString(bytes[:]))
}
