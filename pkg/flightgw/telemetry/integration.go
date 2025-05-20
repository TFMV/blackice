// Package telemetry provides integrated observability capabilities
package telemetry

import (
	"context"
	"sync"
	"time"

	"github.com/TFMV/blackice/pkg/flightgw/anomaly"
	"github.com/TFMV/blackice/pkg/flightgw/server"
	"github.com/TFMV/blackice/pkg/flightgw/trust"
	"github.com/rs/zerolog/log"
)

// SystemObserver provides a central observability layer for the BlackIce system
// It automatically collects and exposes metrics from all critical components
type SystemObserver struct {
	mu                 sync.RWMutex
	telemetry          *TelemetryManager
	circuitObserver    *server.CircuitBreakerObserver
	trustObserver      *trust.TrustSystemObserver
	anomalyIntegration *AnomalyIntegration

	// Trust metrics
	sourceTrustScores      map[string]int
	lastTrustSystemRefresh time.Time
	refreshInterval        time.Duration

	// Context for background operations
	ctx    context.Context
	cancel context.CancelFunc
}

// NewSystemObserver creates a new SystemObserver that integrates with system components
func NewSystemObserver(config MetricsConfig) (*SystemObserver, error) {
	telemetry, err := NewTelemetryManager(config)
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())

	observer := &SystemObserver{
		telemetry:              telemetry,
		sourceTrustScores:      make(map[string]int),
		lastTrustSystemRefresh: time.Time{},
		refreshInterval:        30 * time.Second,
		ctx:                    ctx,
		cancel:                 cancel,
	}

	// Create circuit breaker observer
	circuitObserver := server.NewCircuitBreakerObserver(
		func(isOpen bool, failures int, latency time.Duration) {
			telemetry.UpdateCircuitBreakerMetrics(isOpen, failures, latency)
		},
	)
	observer.circuitObserver = circuitObserver

	// Create trust system observer
	trustObserver := trust.NewTrustSystemObserver(
		func(threatLevel int, sourceScores map[string]int, anomalyCount int) {
			telemetry.UpdateTrustMetrics(threatLevel, sourceScores, anomalyCount)
		},
	)
	observer.trustObserver = trustObserver

	return observer, nil
}

// Start begins monitoring the system components and exposing metrics
func (o *SystemObserver) Start() error {
	// Start the telemetry server
	if err := o.telemetry.Start(); err != nil {
		return err
	}

	log.Info().Msg("System observer started")
	return nil
}

// Stop gracefully shuts down the observer
func (o *SystemObserver) Stop() error {
	o.cancel()

	// Stop anomaly integration if it exists
	if o.anomalyIntegration != nil {
		if err := o.anomalyIntegration.Stop(); err != nil {
			log.Error().Err(err).Msg("Error stopping anomaly integration")
		}
	}

	return o.telemetry.Stop(context.Background())
}

// IntegrateCircuitBreaker connects the circuit breaker to the metrics system
func (o *SystemObserver) IntegrateCircuitBreaker(cb interface{}) {
	if cb == nil {
		log.Error().Msg("Cannot integrate nil circuit breaker")
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	// Get the circuit breaker hooks
	// This uses a type assertion to access the GetHooks method
	if breaker, ok := cb.(interface {
		GetHooks() *server.CircuitBreakerHooks
	}); ok {
		hooks := breaker.GetHooks()
		hooks.RegisterEmitter(o.circuitObserver)
		log.Info().Msg("Circuit breaker integrated with metrics system")
	} else {
		log.Error().Msg("Circuit breaker does not implement GetHooks correctly")
	}
}

// IntegrateTrustSystem connects the trust system to the metrics system
func (o *SystemObserver) IntegrateTrustSystem(ts interface{}) {
	if ts == nil {
		log.Error().Msg("Cannot integrate nil trust scorer")
		return
	}

	o.mu.Lock()
	defer o.mu.Unlock()

	// Get the trust system hooks
	// This uses a type assertion to access the GetHooks method
	if scorer, ok := ts.(interface {
		GetHooks() *trust.TrustMetricsHooks
	}); ok {
		hooks := scorer.GetHooks()
		hooks.RegisterEmitter(o.trustObserver)
		log.Info().Msg("Trust system integrated with metrics system")
	} else {
		log.Error().Msg("Trust system does not implement GetHooks correctly")
	}
}

// IntegrateAnomalyDetection connects the anomaly detection service to the telemetry system
func (o *SystemObserver) IntegrateAnomalyDetection(config *AnomalyIntegrationConfig) error {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Create anomaly integration
	integration, err := NewAnomalyIntegration(o.telemetry, config)
	if err != nil {
		return err
	}

	o.anomalyIntegration = integration
	log.Info().Msg("Anomaly detection integrated with telemetry system")
	return nil
}

// ForwardToAnomalyDetection forwards a telemetry event to the anomaly detection service
func (o *SystemObserver) ForwardToAnomalyDetection(componentID, eventType string, attributes map[string]interface{}, rawData []byte) error {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.anomalyIntegration == nil || !o.anomalyIntegration.enabled {
		return nil
	}

	return o.anomalyIntegration.ForwardTelemetryEvent(componentID, eventType, attributes, rawData)
}

// GetAnomalyClient returns the anomaly client for direct interaction with the anomaly detection service
func (o *SystemObserver) GetAnomalyClient() *anomaly.Client {
	o.mu.RLock()
	defer o.mu.RUnlock()

	if o.anomalyIntegration == nil {
		return nil
	}

	return o.anomalyIntegration.anomalyClient
}
