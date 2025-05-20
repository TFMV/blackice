// Package anomaly provides anomaly detection and response capabilities for the BlackIce system.
package anomaly

import (
	"sync"
)

// AnomalyEmitter defines the interface for components that receive anomaly notifications
type AnomalyEmitter interface {
	// EmitAnomalyDetected is called when a new anomaly is detected
	EmitAnomalyDetected(anomaly *Anomaly)
}

// AnomalyHooks provides a notification mechanism for anomaly events
type AnomalyHooks struct {
	mu       sync.RWMutex
	emitters []AnomalyEmitter
}

// NewAnomalyHooks creates a new instance of AnomalyHooks
func NewAnomalyHooks() *AnomalyHooks {
	return &AnomalyHooks{
		emitters: make([]AnomalyEmitter, 0),
	}
}

// RegisterEmitter adds a new anomaly emitter to the hooks
func (h *AnomalyHooks) RegisterEmitter(emitter AnomalyEmitter) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.emitters = append(h.emitters, emitter)
}

// NotifyAnomalyDetected informs all registered emitters about a new anomaly
func (h *AnomalyHooks) NotifyAnomalyDetected(anomaly *Anomaly) {
	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, emitter := range h.emitters {
		emitter.EmitAnomalyDetected(anomaly)
	}
}

// AnomalyObserver is an adapter that connects to the telemetry system
type AnomalyObserver struct {
	emitFunc func(anomaly *Anomaly)
	mu       sync.Mutex
}

// NewAnomalyObserver creates a new observer that will emit metrics using the provided function
func NewAnomalyObserver(emitFunc func(anomaly *Anomaly)) *AnomalyObserver {
	return &AnomalyObserver{
		emitFunc: emitFunc,
	}
}

// EmitAnomalyDetected implements AnomalyEmitter
func (o *AnomalyObserver) EmitAnomalyDetected(anomaly *Anomaly) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.emitFunc != nil {
		o.emitFunc(anomaly)
	}
}
