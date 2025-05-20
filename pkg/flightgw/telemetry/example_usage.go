// Package telemetry provides integrated observability capabilities
package telemetry

import (
	"log"
	"time"

	"github.com/TFMV/blackice/pkg/flightgw/server"
	"github.com/TFMV/blackice/pkg/flightgw/trust"
)

// ExampleUsage demonstrates how to properly integrate the telemetry system with other components
func ExampleUsage() {
	// 1. Create the telemetry manager with appropriate configuration
	config := DefaultConfig()
	config.PrometheusEnabled = true
	config.PrometheusEndpoint = ":9090"
	config.PrometheusNamespace = "blackice"
	config.EnableAudit = true

	// 2. Create the system observer that coordinates metrics collection
	observer, err := NewSystemObserver(config)
	if err != nil {
		log.Fatalf("Failed to create system observer: %v", err)
	}

	// 3. Start the telemetry server
	if err := observer.Start(); err != nil {
		log.Fatalf("Failed to start system observer: %v", err)
	}

	// Ensure proper cleanup with error handling
	defer func() {
		if err := observer.Stop(); err != nil {
			log.Printf("Error stopping observer: %v", err)
		}
	}()

	// 4. Create and configure the circuit breaker
	cb := server.NewCircuitBreaker(5, 30*time.Second)

	// 5. Create and configure the trust scorer
	ts := trust.NewTrustScorer(0, 50)

	// 6. Integrate components with the metrics system
	// This is much cleaner than having the telemetry system reach into other components
	// Instead, the hooks pattern allows components to emit metrics events directly
	observer.IntegrateCircuitBreaker(cb)
	observer.IntegrateTrustSystem(ts)

	// 7. Use the components as normal - metrics are collected automatically

	// Example of circuit breaker usage
	_ = cb.Execute(func() error {
		// This will automatically emit metrics via the hooks
		return nil
	})

	// Example of trust system usage
	_ = ts.UpdateScore("example-source", trust.ScoreAdjustment{
		Value:    -10,
		Reason:   "Example adjustment",
		Category: "verification",
		Severity: trust.SeverityMedium,
	})

	// Metrics will continue to be collected and exposed through Prometheus endpoint
	// and OpenTelemetry if configured

	// Wait for metrics to be scraped
	time.Sleep(1 * time.Minute)
}
