// Package server provides core server functionality for the BlackIce Flight Gateway
package server

import (
	"sync"
	"time"
)

// MetricsEmitter defines the interface for components that emit circuit breaker metrics
type MetricsEmitter interface {
	// EmitCircuitBreakState notifies when the circuit breaker state changes
	EmitCircuitBreakerState(isOpen bool)

	// EmitCircuitBreakerFailure notifies when a failure is recorded
	EmitCircuitBreakerFailure(category FailureCategory, duration time.Duration, errorHash string)

	// EmitCircuitBreakerSuccess notifies when a successful operation occurs
	EmitCircuitBreakerSuccess(duration time.Duration)

	// EmitCircuitBreakerTierChange notifies when the operational tier changes
	EmitCircuitBreakerTierChange(previousTier, newTier CircuitTier)
}

// CircuitBreakerHooks provides instrumentation hooks for the circuit breaker
type CircuitBreakerHooks struct {
	mu       sync.RWMutex
	emitters []MetricsEmitter
}

// NewCircuitBreakerHooks creates a new instance of CircuitBreakerHooks
func NewCircuitBreakerHooks() *CircuitBreakerHooks {
	return &CircuitBreakerHooks{
		emitters: make([]MetricsEmitter, 0),
	}
}

// RegisterEmitter adds a new metrics emitter to the hooks
func (h *CircuitBreakerHooks) RegisterEmitter(emitter MetricsEmitter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emitters = append(h.emitters, emitter)
}

// NotifyStateChange informs all registered emitters about a circuit state change
func (h *CircuitBreakerHooks) NotifyStateChange(isOpen bool) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitCircuitBreakerState(isOpen)
	}
}

// NotifyFailure informs all registered emitters about a circuit failure
func (h *CircuitBreakerHooks) NotifyFailure(category FailureCategory, duration time.Duration, errorHash string) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitCircuitBreakerFailure(category, duration, errorHash)
	}
}

// NotifySuccess informs all registered emitters about a successful operation
func (h *CircuitBreakerHooks) NotifySuccess(duration time.Duration) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitCircuitBreakerSuccess(duration)
	}
}

// NotifyTierChange informs all registered emitters about a tier change
func (h *CircuitBreakerHooks) NotifyTierChange(previousTier, newTier CircuitTier) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitCircuitBreakerTierChange(previousTier, newTier)
	}
}

// CircuitBreakerObserver is an adapter that connects CircuitBreaker hooks to the telemetry system
type CircuitBreakerObserver struct {
	emitFn func(isOpen bool, failures int, latency time.Duration)

	// Stats counters for batching
	openState      bool
	totalFailures  int
	averageLatency time.Duration
	requestCount   int
	mu             sync.Mutex
}

// NewCircuitBreakerObserver creates a new observer that will emit metrics using the provided function
func NewCircuitBreakerObserver(emitFn func(isOpen bool, failures int, latency time.Duration)) *CircuitBreakerObserver {
	return &CircuitBreakerObserver{
		emitFn:         emitFn,
		openState:      false,
		totalFailures:  0,
		averageLatency: 0,
		requestCount:   0,
	}
}

// EmitCircuitBreakerState implements MetricsEmitter
func (o *CircuitBreakerObserver) EmitCircuitBreakerState(isOpen bool) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Update local state
	o.openState = isOpen

	// Emit current metrics
	o.emitMetrics()
}

// EmitCircuitBreakerFailure implements MetricsEmitter
func (o *CircuitBreakerObserver) EmitCircuitBreakerFailure(category FailureCategory, duration time.Duration, errorHash string) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Update local state
	o.totalFailures++
	o.requestCount++

	// Update average latency
	if o.requestCount == 1 {
		o.averageLatency = duration
	} else {
		// Weighted average to avoid recalculating over all requests
		o.averageLatency = time.Duration(
			(float64(o.averageLatency)*(float64(o.requestCount)-1) + float64(duration)) /
				float64(o.requestCount),
		)
	}

	// Emit current metrics
	o.emitMetrics()
}

// EmitCircuitBreakerSuccess implements MetricsEmitter
func (o *CircuitBreakerObserver) EmitCircuitBreakerSuccess(duration time.Duration) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Update local state
	o.requestCount++

	// Update average latency
	if o.requestCount == 1 {
		o.averageLatency = duration
	} else {
		// Weighted average
		o.averageLatency = time.Duration(
			(float64(o.averageLatency)*(float64(o.requestCount)-1) + float64(duration)) /
				float64(o.requestCount),
		)
	}

	// Emit current metrics
	o.emitMetrics()
}

// EmitCircuitBreakerTierChange implements MetricsEmitter
func (o *CircuitBreakerObserver) EmitCircuitBreakerTierChange(previousTier, newTier CircuitTier) {
	// Tier changes don't affect our core metrics, so we don't need to update anything
}

// emitMetrics sends the current metrics to the registered function
func (o *CircuitBreakerObserver) emitMetrics() {
	if o.emitFn != nil {
		o.emitFn(o.openState, o.totalFailures, o.averageLatency)
	}
}
