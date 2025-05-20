// anomalyclient is a test client for the anomaly detection service
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/TFMV/blackice/pkg/flightgw/anomaly"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	serviceAddr   = flag.String("service", "localhost:8089", "Address of the anomaly service")
	logLevel      = flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	sendRate      = flag.Int("rate", 5, "Events per second to send")
	duration      = flag.Duration("duration", 5*time.Minute, "How long to run the test")
	injectAnomaly = flag.Bool("inject-anomaly", true, "Whether to inject anomalous events")
	anomalyRate   = flag.Float64("anomaly-rate", 0.05, "Rate of anomalous events (0.0-1.0)")
)

func main() {
	flag.Parse()

	// Configure logging
	setupLogging()
	log.Info().Msg("Starting BlackIce Anomaly Test Client")

	// Create an anomaly client
	config := &anomaly.ClientConfig{
		ServiceAddress: *serviceAddr,
		BufferSize:     1000,
		FlushInterval:  1 * time.Second,
		ReconnectDelay: 5 * time.Second,
		TLSEnabled:     false,
	}

	client, err := anomaly.NewClient(config)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to create anomaly client")
	}
	defer client.Close()

	// Start sending events
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	eventsCh := make(chan struct{})
	go generateEvents(ctx, client, eventsCh)

	// Wait for completion or interrupt
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	var eventCount int
	log.Info().Msg("Sending events to anomaly service")

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Info().Int("events_sent", eventCount).Msg("Test completed")
			return
		case <-quit:
			log.Info().Int("events_sent", eventCount).Msg("Test interrupted")
			return
		case <-eventsCh:
			eventCount++
		case <-ticker.C:
			// Query for anomalies every 5 seconds
			anomalies, err := client.QueryAnomalies(
				context.Background(),
				time.Now().Add(-10*time.Minute),
				time.Now(),
				"",
				"",
				anomaly.SeverityInfo,
			)
			if err != nil {
				log.Error().Err(err).Msg("Failed to query anomalies")
			} else {
				log.Info().
					Int("events_sent", eventCount).
					Int("anomalies_detected", len(anomalies)).
					Msg("Progress")

				// Log detected anomalies
				for _, a := range anomalies {
					log.Info().
						Str("anomaly_id", a.AnomalyID).
						Str("source", a.SourceComponentID).
						Str("detector", a.DetectorID).
						Int("severity", int(a.Severity)).
						Str("category", string(a.Category)).
						Str("description", a.Description).
						Float64("confidence", a.Confidence).
						Strs("affected_resources", a.AffectedResources).
						Int("remediation_status", int(a.RemediationStatus)).
						Strs("ttp_identifiers", a.TTPIdentifiers).
						Str("mitre_technique", a.MitreTechnique).
						Msg("Anomaly detected")
				}
			}
		}
	}
}

// generateEvents generates and sends telemetry events to the anomaly service
func generateEvents(ctx context.Context, client *anomaly.Client, eventsCh chan struct{}) {
	// Event types to simulate
	eventTypes := []string{
		"authentication",
		"authorization",
		"network_flow",
		"syscall",
		"metric",
	}

	// Components to simulate
	components := []string{
		"auth-service",
		"api-gateway",
		"database",
		"storage-service",
		"user-service",
	}

	// Event interval based on rate
	interval := time.Second / time.Duration(*sendRate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Simulate normal patterns with occasional anomalies
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	var authFailCount int

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Select random event type and component
			eventType := eventTypes[r.Intn(len(eventTypes))]
			component := components[r.Intn(len(components))]

			// Create event attributes based on type
			attributes := make(map[string]interface{})

			switch eventType {
			case "authentication":
				// Simulate authentication events
				if r.Float64() < 0.8 {
					attributes["action"] = "successful_auth"
					attributes["user_id"] = "user-" + generateRandomString(8, r)
					authFailCount = 0
				} else {
					attributes["action"] = "failed_auth"
					attributes["user_id"] = "user-" + generateRandomString(8, r)
					attributes["reason"] = "invalid_credentials"
					authFailCount++

					// Inject pattern anomaly - same user multiple failures
					if authFailCount > 3 && r.Float64() < 0.7 {
						// Keep the same user ID for multiple failures
						attributes["user_id"] = "user-" + generateRandomString(3, r)
					}
				}

			case "authorization":
				actions := []string{
					"resource_access",
					"permission_check",
					"access_denied",
					"modify_permissions",
				}
				attributes["action"] = actions[r.Intn(len(actions))]
				attributes["resource_id"] = "resource-" + generateRandomString(6, r)
				attributes["user_id"] = "user-" + generateRandomString(8, r)

				// Inject anomaly - high privilege access
				if *injectAnomaly && r.Float64() < *anomalyRate {
					attributes["action"] = "access_sensitive_resource"
					attributes["resource_id"] = "sensitive-" + generateRandomString(4, r)
					attributes["privilege_level"] = "admin"
				}

			case "network_flow":
				attributes["source_ip"] = generateRandomIP(r)
				attributes["dest_ip"] = generateRandomIP(r)
				attributes["port"] = 1000 + r.Intn(9000)
				attributes["protocol"] = []string{"TCP", "UDP", "HTTP", "HTTPS"}[r.Intn(4)]
				attributes["bytes_sent"] = 100 + r.Intn(10000)
				attributes["bytes_received"] = 100 + r.Intn(5000)

				// Inject anomaly - unusual port or high traffic
				if *injectAnomaly && r.Float64() < *anomalyRate {
					if r.Float64() < 0.5 {
						attributes["port"] = []int{22, 3389, 4444, 8090}[r.Intn(4)]
					} else {
						attributes["bytes_sent"] = 1000000 + r.Intn(9000000)
					}
				}

			case "syscall":
				syscalls := []string{
					"open", "read", "write", "close", "fork", "exec",
					"socket", "connect", "accept", "send", "recv",
				}
				attributes["syscall"] = syscalls[r.Intn(len(syscalls))]
				attributes["pid"] = 1000 + r.Intn(5000)
				attributes["result"] = 0

				// Inject anomaly - unusual syscall pattern
				if *injectAnomaly && r.Float64() < *anomalyRate {
					attributes["syscall"] = []string{
						"ptrace", "setuid", "setgid", "rawsocket",
					}[r.Intn(4)]
					if r.Float64() < 0.3 {
						attributes["result"] = -1
					}
				}

			case "metric":
				metrics := []string{
					"cpu_usage", "memory_usage", "disk_usage",
					"network_latency", "request_count", "error_rate",
				}
				metricName := metrics[r.Intn(len(metrics))]

				// Normal range values
				var value float64
				switch metricName {
				case "cpu_usage":
					value = 10.0 + r.Float64()*40.0 // 10-50%
				case "memory_usage":
					value = 20.0 + r.Float64()*30.0 // 20-50%
				case "disk_usage":
					value = 30.0 + r.Float64()*40.0 // 30-70%
				case "network_latency":
					value = 50.0 + r.Float64()*100.0 // 50-150ms
				case "request_count":
					value = 10.0 + r.Float64()*90.0 // 10-100 requests
				case "error_rate":
					value = r.Float64() * 2.0 // 0-2%
				}

				// Inject anomaly - unusual metric value
				if *injectAnomaly && r.Float64() < *anomalyRate {
					switch metricName {
					case "cpu_usage":
						value = 90.0 + r.Float64()*10.0 // 90-100%
					case "memory_usage":
						value = 85.0 + r.Float64()*15.0 // 85-100%
					case "disk_usage":
						value = 95.0 + r.Float64()*5.0 // 95-100%
					case "network_latency":
						value = 500.0 + r.Float64()*1500.0 // 500-2000ms
					case "request_count":
						value = 500.0 + r.Float64()*500.0 // 500-1000 requests
					case "error_rate":
						value = 10.0 + r.Float64()*30.0 // 10-40%
					}
				}

				attributes[metricName] = value
			}

			// Create and send the event
			event := &anomaly.TelemetryEvent{
				EventID:           "evt-" + generateRandomString(16, r),
				SourceComponentID: component,
				EventType:         eventType,
				Timestamp:         time.Now(),
				Attributes:        attributes,
			}

			if err := client.SendEvent(event); err != nil {
				log.Error().Err(err).Msg("Failed to send event")
			} else {
				select {
				case eventsCh <- struct{}{}:
				default:
				}
			}
		}
	}
}

// Helper function to generate random string
func generateRandomString(length int, r *rand.Rand) string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, length)
	for i := range result {
		result[i] = charset[r.Intn(len(charset))]
	}
	return string(result)
}

// Helper function to generate random IP address
func generateRandomIP(r *rand.Rand) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		r.Intn(256), r.Intn(256), r.Intn(256), r.Intn(256))
}

// setupLogging configures the logger
func setupLogging() {
	// Parse log level
	level, err := zerolog.ParseLevel(*logLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)

	// Configure logger
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix

	// Log configuration
	log.Info().
		Str("log_level", level.String()).
		Str("service", *serviceAddr).
		Int("rate", *sendRate).
		Str("duration", duration.String()).
		Bool("inject_anomaly", *injectAnomaly).
		Float64("anomaly_rate", *anomalyRate).
		Msg("Logger configured")
}
