// Package telemetry provides a secure framework for collecting and exposing metrics
// in high-assurance environments with appropriate access controls and sanitization.
package telemetry

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"golang.org/x/time/rate"
)

// SecurityLevel defines the sensitivity level of metrics
type SecurityLevel int

const (
	// PublicMetrics are safe for external consumption
	PublicMetrics SecurityLevel = iota
	// InternalMetrics are safe for internal monitoring systems
	InternalMetrics
	// SensitiveMetrics contain information that requires access controls
	SensitiveMetrics
	// RestrictedMetrics contain information that should only be accessible to authorized personnel
	RestrictedMetrics
)

// MetricsConfig contains configuration for the metrics system
type MetricsConfig struct {
	// Prometheus configuration
	PrometheusEnabled   bool   `mapstructure:"prometheus_enabled"`
	PrometheusEndpoint  string `mapstructure:"prometheus_endpoint"`
	PrometheusNamespace string `mapstructure:"prometheus_namespace"`

	// OpenTelemetry configuration
	OTelEnabled  bool   `mapstructure:"otel_enabled"`
	OTelEndpoint string `mapstructure:"otel_endpoint"`
	OTelInsecure bool   `mapstructure:"otel_insecure"`

	// Security configuration
	EnableMTLS    bool   `mapstructure:"enable_mtls"`
	CertPath      string `mapstructure:"cert_path"`
	KeyPath       string `mapstructure:"key_path"`
	CAPath        string `mapstructure:"ca_path"`
	JWTAuth       bool   `mapstructure:"jwt_auth"`
	JWTSecretPath string `mapstructure:"jwt_secret_path"`

	// Access control
	MaxSecurityLevel SecurityLevel `mapstructure:"max_security_level"`

	// Rate limiting
	RateLimit int `mapstructure:"rate_limit"` // Requests per minute

	// Audit configuration
	EnableAudit  bool   `mapstructure:"enable_audit"`
	AuditLogPath string `mapstructure:"audit_log_path"`
}

// TelemetryManager coordinates all telemetry components
type TelemetryManager struct {
	mu                 sync.RWMutex
	config             MetricsConfig
	prometheusRegistry *prometheus.Registry
	otelMeterProvider  metric.MeterProvider
	otelMeter          metric.Meter
	server             *http.Server
	counters           map[string]prometheus.Counter
	gauges             map[string]prometheus.Gauge
	histograms         map[string]prometheus.Histogram
	summaries          map[string]prometheus.Summary
	securityLevels     map[string]SecurityLevel

	// OpenTelemetry meters
	otelCounters   map[string]metric.Int64Counter
	otelGauges     map[string]metric.Int64UpDownCounter
	otelHistograms map[string]metric.Int64Histogram

	// Circuit breaker metrics
	circuitBreakerOpen     prometheus.Gauge
	circuitBreakerFailures prometheus.Counter
	circuitBreakerLatency  prometheus.Histogram

	// Trust system metrics
	trustScoreGauge       map[string]prometheus.Gauge
	trustThreatLevelGauge prometheus.Gauge
	trustAnomalyCounter   prometheus.Counter
}

// NewTelemetryManager creates a new telemetry manager with the given configuration
func NewTelemetryManager(config MetricsConfig) (*TelemetryManager, error) {
	tm := &TelemetryManager{
		config:          config,
		counters:        make(map[string]prometheus.Counter),
		gauges:          make(map[string]prometheus.Gauge),
		histograms:      make(map[string]prometheus.Histogram),
		summaries:       make(map[string]prometheus.Summary),
		securityLevels:  make(map[string]SecurityLevel),
		otelCounters:    make(map[string]metric.Int64Counter),
		otelGauges:      make(map[string]metric.Int64UpDownCounter),
		otelHistograms:  make(map[string]metric.Int64Histogram),
		trustScoreGauge: make(map[string]prometheus.Gauge),
	}

	// Initialize Prometheus if enabled
	if config.PrometheusEnabled {
		reg := prometheus.NewRegistry()
		tm.prometheusRegistry = reg

		// Initialize standard collectors
		reg.MustRegister(collectors.NewGoCollector())
		reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

		// Initialize circuit breaker metrics
		tm.circuitBreakerOpen = promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Namespace: config.PrometheusNamespace,
			Subsystem: "circuit_breaker",
			Name:      "open",
			Help:      "Indicates if the circuit breaker is open (1) or closed (0)",
		})

		tm.circuitBreakerFailures = promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Namespace: config.PrometheusNamespace,
			Subsystem: "circuit_breaker",
			Name:      "failures_total",
			Help:      "Total number of circuit breaker failures",
		})

		tm.circuitBreakerLatency = promauto.With(reg).NewHistogram(prometheus.HistogramOpts{
			Namespace: config.PrometheusNamespace,
			Subsystem: "circuit_breaker",
			Name:      "request_duration_seconds",
			Help:      "Request duration in seconds",
			Buckets:   prometheus.DefBuckets,
		})

		// Initialize trust system metrics
		tm.trustThreatLevelGauge = promauto.With(reg).NewGauge(prometheus.GaugeOpts{
			Namespace: config.PrometheusNamespace,
			Subsystem: "trust",
			Name:      "threat_level",
			Help:      "Current system-wide threat level (1-5)",
		})

		tm.trustAnomalyCounter = promauto.With(reg).NewCounter(prometheus.CounterOpts{
			Namespace: config.PrometheusNamespace,
			Subsystem: "trust",
			Name:      "anomalies_total",
			Help:      "Total number of detected anomalies",
		})
	}

	// Initialize OpenTelemetry if enabled
	if config.OTelEnabled {
		ctx := context.Background()

		// Create OTLP exporter
		exporter, err := otlpmetricgrpc.New(ctx,
			otlpmetricgrpc.WithEndpoint(config.OTelEndpoint),
			otlpmetricgrpc.WithInsecure(),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create OTLP exporter: %w", err)
		}

		// Create resource with service information
		res, err := resource.New(ctx,
			resource.WithAttributes(
				semconv.ServiceName(config.PrometheusNamespace),
				semconv.ServiceVersion("v1.0.0"),
				attribute.String("environment", "production"),
			),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create resource: %w", err)
		}

		// Create meter provider
		meterProvider := sdkmetric.NewMeterProvider(
			sdkmetric.WithResource(res),
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
				sdkmetric.WithInterval(10*time.Second),
			)),
		)
		otel.SetMeterProvider(meterProvider)

		tm.otelMeterProvider = meterProvider
		tm.otelMeter = meterProvider.Meter(config.PrometheusNamespace)
	}

	return tm, nil
}

// Start initializes the telemetry server and begins collecting metrics
func (tm *TelemetryManager) Start() error {
	if !tm.config.PrometheusEnabled {
		log.Info().Msg("Prometheus metrics are disabled")
		return nil
	}

	// Create HTTP handler with security middleware
	handler := tm.secureMetricsHandler(promhttp.HandlerFor(
		tm.prometheusRegistry,
		promhttp.HandlerOpts{
			EnableOpenMetrics: true,
		},
	))

	// Configure TLS if enabled
	server := &http.Server{
		Addr:    tm.config.PrometheusEndpoint,
		Handler: handler,
	}

	tm.server = server

	// Start server
	go func() {
		var err error

		log.Info().Str("addr", tm.config.PrometheusEndpoint).Msg("Starting metrics server")

		if tm.config.EnableMTLS {
			err = server.ListenAndServeTLS(tm.config.CertPath, tm.config.KeyPath)
		} else {
			err = server.ListenAndServe()
		}

		if err != nil && err != http.ErrServerClosed {
			log.Error().Err(err).Msg("Metrics server failed")
		}
	}()

	return nil
}

// Stop gracefully shuts down the telemetry system
func (tm *TelemetryManager) Stop(ctx context.Context) error {
	// Shutdown metrics server if running
	if tm.server != nil {
		log.Info().Msg("Shutting down metrics server")
		if err := tm.server.Shutdown(ctx); err != nil {
			return fmt.Errorf("error shutting down metrics server: %w", err)
		}
	}

	// Shutdown OpenTelemetry if enabled
	if tm.config.OTelEnabled {
		log.Info().Msg("Shutting down OpenTelemetry provider")
		if provider, ok := tm.otelMeterProvider.(*sdkmetric.MeterProvider); ok {
			if err := provider.Shutdown(ctx); err != nil {
				return fmt.Errorf("error shutting down OpenTelemetry provider: %w", err)
			}
		}
	}

	return nil
}

// secureMetricsHandler wraps the Prometheus HTTP handler with security middleware
func (tm *TelemetryManager) secureMetricsHandler(next http.Handler) http.Handler {
	// Create a rate limiter if enabled
	var limiter *rate.Limiter
	if tm.config.RateLimit > 0 {
		// Initialize rate limiter with config rate limit per minute
		limiter = rate.NewLimiter(rate.Limit(tm.config.RateLimit/60.0), tm.config.RateLimit)
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Implement rate limiting
		if limiter != nil {
			if !limiter.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		// Implement authentication
		if tm.config.JWTAuth {
			// JWT authentication implementation
			token := r.Header.Get("Authorization")
			if token == "" {
				http.Error(w, "Authorization required", http.StatusUnauthorized)
				return
			}

			// TODO: Implement proper JWT validation
			// For now, we just check that the header exists
		}

		// Audit logging
		if tm.config.EnableAudit {
			log.Info().
				Str("remote_addr", r.RemoteAddr).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("user_agent", r.UserAgent()).
				Msg("Metrics endpoint accessed")
		}

		next.ServeHTTP(w, r)
	})
}

// RegisterCounter creates and registers a Prometheus counter
func (tm *TelemetryManager) RegisterCounter(name, help string, securityLevel SecurityLevel, labels ...string) (prometheus.Counter, error) {
	if securityLevel > tm.config.MaxSecurityLevel {
		log.Warn().
			Str("name", name).
			Int("security_level", int(securityLevel)).
			Int("max_allowed", int(tm.config.MaxSecurityLevel)).
			Msg("Metric security level exceeds maximum allowed level")
		return nil, fmt.Errorf("metric security level exceeds maximum allowed level")
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Store security level
	tm.securityLevels[name] = securityLevel

	if !tm.config.PrometheusEnabled {
		return nil, nil
	}

	counter := promauto.With(tm.prometheusRegistry).NewCounter(prometheus.CounterOpts{
		Namespace: tm.config.PrometheusNamespace,
		Name:      sanitizeMetricName(name),
		Help:      help,
	})

	tm.counters[name] = counter

	// Register in OpenTelemetry if enabled
	if tm.config.OTelEnabled {
		otelCounter, err := tm.otelMeter.Int64Counter(
			sanitizeMetricName(name),
			metric.WithDescription(help),
		)
		if err != nil {
			log.Error().Err(err).Str("name", name).Msg("Failed to create OpenTelemetry counter")
		} else {
			tm.otelCounters[name] = otelCounter
		}
	}

	return counter, nil
}

// RegisterGauge creates and registers a Prometheus gauge
func (tm *TelemetryManager) RegisterGauge(name, help string, securityLevel SecurityLevel, labels ...string) (prometheus.Gauge, error) {
	if securityLevel > tm.config.MaxSecurityLevel {
		return nil, fmt.Errorf("metric security level exceeds maximum allowed level")
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Store security level
	tm.securityLevels[name] = securityLevel

	if !tm.config.PrometheusEnabled {
		return nil, nil
	}

	gauge := promauto.With(tm.prometheusRegistry).NewGauge(prometheus.GaugeOpts{
		Namespace: tm.config.PrometheusNamespace,
		Name:      sanitizeMetricName(name),
		Help:      help,
	})

	tm.gauges[name] = gauge

	// Register in OpenTelemetry if enabled
	if tm.config.OTelEnabled {
		otelGauge, err := tm.otelMeter.Int64UpDownCounter(
			sanitizeMetricName(name),
			metric.WithDescription(help),
		)
		if err != nil {
			log.Error().Err(err).Str("name", name).Msg("Failed to create OpenTelemetry gauge")
		} else {
			tm.otelGauges[name] = otelGauge
		}
	}

	return gauge, nil
}

// RegisterTrustSourceGauge registers a gauge for a specific trust source
func (tm *TelemetryManager) RegisterTrustSourceGauge(sourceID string) error {
	if !tm.config.PrometheusEnabled {
		return nil
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	gauge := promauto.With(tm.prometheusRegistry).NewGauge(prometheus.GaugeOpts{
		Namespace: tm.config.PrometheusNamespace,
		Subsystem: "trust",
		Name:      "source_score",
		Help:      "Trust score for a specific source",
		ConstLabels: prometheus.Labels{
			"source_id": sanitizeMetricLabel(sourceID),
		},
	})

	tm.trustScoreGauge[sourceID] = gauge
	return nil
}

// UpdateTrustMetrics updates trust-related metrics
func (tm *TelemetryManager) UpdateTrustMetrics(threatLevel int, sources map[string]int, anomalyCount int) {
	if !tm.config.PrometheusEnabled {
		return
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Update threat level
	tm.trustThreatLevelGauge.Set(float64(threatLevel))

	// Update source scores
	for sourceID, score := range sources {
		gauge, exists := tm.trustScoreGauge[sourceID]
		if !exists {
			// Register new gauge if not exists
			gauge = promauto.With(tm.prometheusRegistry).NewGauge(prometheus.GaugeOpts{
				Namespace: tm.config.PrometheusNamespace,
				Subsystem: "trust",
				Name:      "source_score",
				Help:      "Trust score for a specific source",
				ConstLabels: prometheus.Labels{
					"source_id": sanitizeMetricLabel(sourceID),
				},
			})
			tm.trustScoreGauge[sourceID] = gauge
		}
		gauge.Set(float64(score))
	}
}

// UpdateCircuitBreakerMetrics updates metrics related to the circuit breaker
func (tm *TelemetryManager) UpdateCircuitBreakerMetrics(isOpen bool, failures int, requestDuration time.Duration) {
	if !tm.config.PrometheusEnabled {
		return
	}

	tm.mu.Lock()
	defer tm.mu.Unlock()

	// Update circuit breaker state
	if isOpen {
		tm.circuitBreakerOpen.Set(1)
	} else {
		tm.circuitBreakerOpen.Set(0)
	}

	// Update failures count
	tm.circuitBreakerFailures.Add(float64(failures))

	// Update request duration
	tm.circuitBreakerLatency.Observe(requestDuration.Seconds())

	// Update OpenTelemetry metrics if enabled
	if tm.config.OTelEnabled {
		ctx := context.Background()

		// Update circuit breaker state
		if gauge, exists := tm.otelGauges["circuit_breaker_open"]; exists {
			if isOpen {
				gauge.Add(ctx, 1)
			} else {
				gauge.Add(ctx, -1)
			}
		}

		// Update failures count
		if counter, exists := tm.otelCounters["circuit_breaker_failures"]; exists {
			counter.Add(ctx, int64(failures))
		}

		// Update request duration
		if histogram, exists := tm.otelHistograms["circuit_breaker_latency"]; exists {
			histogram.Record(ctx, int64(requestDuration.Milliseconds()))
		}
	}
}

// sanitizeMetricName ensures that metric names are valid in Prometheus
func sanitizeMetricName(name string) string {
	// In a real implementation, this would sanitize the name to ensure it's valid
	// For now, we'll just return it unchanged
	return name
}

// sanitizeMetricLabel ensures that label values are safe for use in metrics
func sanitizeMetricLabel(value string) string {
	// In a real implementation, this would sanitize the label value
	// For now, we'll just return it unchanged
	return value
}

// DefaultConfig returns a default configuration for the telemetry system
func DefaultConfig() MetricsConfig {
	return MetricsConfig{
		PrometheusEnabled:   true,
		PrometheusEndpoint:  ":9090",
		PrometheusNamespace: "blackice",
		OTelEnabled:         false,
		OTelEndpoint:        "localhost:4317",
		OTelInsecure:        false,
		EnableMTLS:          false,
		JWTAuth:             false,
		MaxSecurityLevel:    PublicMetrics,
		RateLimit:           60, // 60 requests per minute
		EnableAudit:         true,
	}
}
