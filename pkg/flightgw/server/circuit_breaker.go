package server

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"slices"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// CircuitBreakerState represents the current state of a circuit breaker
type CircuitBreakerState int

const (
	// CircuitClosed means the circuit is closed (requests flow normally)
	CircuitClosed CircuitBreakerState = iota
	// CircuitOpen means the circuit is open (requests are prevented from executing)
	CircuitOpen
	// CircuitHalfOpen means we're testing whether the circuit can be closed again
	CircuitHalfOpen
)

// FailureCategory classifies different types of failures for targeted response
type FailureCategory int

const (
	// FailureGeneric is the default category for unclassified failures
	FailureGeneric FailureCategory = iota
	// FailureTimeout indicates a request timed out
	FailureTimeout
	// FailureRejection indicates a request was rejected (e.g., 429 Too Many Requests)
	FailureRejection
	// FailureConnection indicates a connection failure (e.g., connection refused)
	FailureConnection
	// FailureSecurity indicates a security-related failure (e.g., TLS error)
	FailureSecurity
	// FailureInternal indicates an internal server error
	FailureInternal
	// FailureBadRequest indicates a client error (e.g., invalid request format)
	FailureBadRequest
)

// CircuitTier represents the operational level of the circuit breaker
type CircuitTier int

const (
	// TierNormal indicates normal operations with no restrictions
	TierNormal CircuitTier = iota
	// TierCautious indicates modest restrictions with increased monitoring
	TierCautious
	// TierRestricted indicates significant restrictions with reduced throughput
	TierRestricted
	// TierMinimal indicates minimal operations, critical-only traffic
	TierMinimal
	// TierEmergency indicates emergency mode, only essential operations
	TierEmergency
)

// FailureRecord stores information about a failure for analysis
type FailureRecord struct {
	Timestamp time.Time
	Category  FailureCategory
	Duration  time.Duration
	ErrorHash string
	ErrorMsg  string
	Source    string
	Context   map[string]string
}

// CircuitMetrics tracks operational metrics for the circuit breaker
type CircuitMetrics struct {
	TotalRequests      int64
	TotalFailures      int64
	ConsecutiveSuccess int
	ConsecutiveFailure int
	LastFailureTime    time.Time
	LastSuccessTime    time.Time
	OpenCircuitCount   int
	CategoryCounts     map[FailureCategory]int
	TotalLatency       time.Duration
	MinLatency         time.Duration
	MaxLatency         time.Duration
	PatternHashes      map[string]int // For attack pattern detection
}

// RequestContext provides contextual information about the request being executed
type RequestContext struct {
	Category   string            // e.g., "auth", "data", "admin"
	Priority   int               // Higher values indicate higher priority
	Timeout    time.Duration     // Request-specific timeout
	MaxRetries int               // Maximum number of retries allowed
	Metadata   map[string]string // Additional request metadata
	Source     string            // Request source identifier
}

// ExecuteResult contains detailed information about an execution attempt
type ExecuteResult struct {
	Success      bool
	Duration     time.Duration
	ErrorMessage string
	Category     FailureCategory
	Retried      int // Number of retry attempts
}

// CircuitBreaker implements the circuit breaker pattern to prevent
// cascading failures when an upstream service is unavailable
type CircuitBreaker struct {
	mu    sync.RWMutex
	state CircuitBreakerState
	tier  CircuitTier

	// Base configuration
	failureThreshold  int
	failureCount      int
	resetTimeout      time.Duration
	lastFailure       time.Time
	halfOpenMaxCalls  int
	halfOpenCallCount int

	// Enhanced multi-tier thresholds
	tierThresholds map[CircuitTier]int
	tierTimeouts   map[CircuitTier]time.Duration

	// Advanced metrics and telemetry
	metrics           CircuitMetrics
	recentFailures    []FailureRecord
	maxFailureHistory int

	// Categorized failure tracking
	categoryThresholds map[FailureCategory]int
	categoryCounts     map[FailureCategory]int

	// Adaptive parameters
	adaptiveThreshold bool
	baselineLatency   time.Duration
	latencyThreshold  float64 // Multiplier over baseline to trigger latency-based opening

	// Context-aware decision making
	contextFilters map[string]string
	priorityLevels map[string]int

	// Self-healing capabilities
	autoRecoveryEnabled bool
	gradualRecoveryRate float64 // % increase in allowed calls per period

	// Attack pattern detection
	patternDetection bool
	patternThreshold int
	knownBadPatterns map[string]bool

	// TODO: Jitter for backoff

	// Metrics hooks for telemetry integration
	hooks *CircuitBreakerHooks
}

// NewCircuitBreaker creates a new circuit breaker with the specified parameters
func NewCircuitBreaker(failureThreshold int, resetTimeout time.Duration) *CircuitBreaker {
	cb := &CircuitBreaker{
		state:            CircuitClosed,
		tier:             TierNormal,
		failureThreshold: failureThreshold,
		resetTimeout:     resetTimeout,
		halfOpenMaxCalls: 3, // Allow 3 test calls in half-open state

		// Initialize enhanced fields with defaults
		tierThresholds: map[CircuitTier]int{
			TierNormal:     failureThreshold,
			TierCautious:   failureThreshold / 2,
			TierRestricted: failureThreshold / 3,
			TierMinimal:    failureThreshold / 4,
			TierEmergency:  1,
		},
		tierTimeouts: map[CircuitTier]time.Duration{
			TierNormal:     resetTimeout,
			TierCautious:   resetTimeout * 2,
			TierRestricted: resetTimeout * 3,
			TierMinimal:    resetTimeout * 4,
			TierEmergency:  resetTimeout * 5,
		},

		// Initialize metrics
		metrics: CircuitMetrics{
			CategoryCounts: make(map[FailureCategory]int),
			PatternHashes:  make(map[string]int),
			MinLatency:     time.Duration(math.MaxInt64),
		},

		// Initialize failure tracking
		maxFailureHistory: 100,
		recentFailures:    make([]FailureRecord, 0, 100),

		// Initialize category tracking
		categoryThresholds: map[FailureCategory]int{
			FailureGeneric:    failureThreshold,
			FailureTimeout:    failureThreshold,
			FailureRejection:  failureThreshold,
			FailureConnection: failureThreshold / 2, // More sensitive to connection issues
			FailureSecurity:   failureThreshold / 4, // Much more sensitive to security issues
			FailureInternal:   failureThreshold,
			FailureBadRequest: failureThreshold * 2, // Less sensitive to client errors
		},
		categoryCounts: make(map[FailureCategory]int),

		// Initialize adaptive parameters
		adaptiveThreshold: true,
		latencyThreshold:  3.0, // 3x normal latency triggers circuit

		// Initialize context filters
		contextFilters: make(map[string]string),
		priorityLevels: make(map[string]int),

		// Initialize self-healing
		autoRecoveryEnabled: true,
		gradualRecoveryRate: 0.1, // 10% increase per period

		// Initialize attack pattern detection
		patternDetection: true,
		patternThreshold: 3,
		knownBadPatterns: make(map[string]bool),

		// Initialize hooks for metrics
		hooks: NewCircuitBreakerHooks(),
	}

	return cb
}

// Execute runs the given request if the circuit is closed or half-open.
// Returns an error if the circuit is open or if the request fails.
func (cb *CircuitBreaker) Execute(request func() error) error {
	// Check if request is allowed based on circuit state
	if !cb.isRequestAllowed() {
		return fmt.Errorf("circuit breaker is open, request denied")
	}

	// Track request timing
	startTime := time.Now()

	// Execute the request
	err := request()
	success := err == nil

	// Calculate request duration
	duration := time.Since(startTime)

	// Notify hooks about the outcome
	if cb.hooks != nil {
		if success {
			cb.hooks.NotifySuccess(duration)
		} else {
			errorMsg := ""
			if err != nil {
				errorMsg = err.Error()
			}
			errorHash := cb.generateErrorHash(errorMsg, nil)
			cb.hooks.NotifyFailure(FailureGeneric, duration, errorHash)
		}
	}

	// Record the result
	cb.recordResult(success)

	// Update metrics
	cb.mu.Lock()
	cb.metrics.TotalRequests++
	cb.metrics.TotalLatency += duration

	// Update min/max latency
	if cb.metrics.MinLatency == 0 || duration < cb.metrics.MinLatency {
		cb.metrics.MinLatency = duration
	}
	if duration > cb.metrics.MaxLatency {
		cb.metrics.MaxLatency = duration
	}

	if !success {
		cb.metrics.TotalFailures++
		cb.metrics.LastFailureTime = time.Now()
		cb.metrics.ConsecutiveFailure++
		cb.metrics.ConsecutiveSuccess = 0
	} else {
		cb.metrics.LastSuccessTime = time.Now()
		cb.metrics.ConsecutiveSuccess++
		cb.metrics.ConsecutiveFailure = 0
	}
	cb.mu.Unlock()

	return err
}

// ExecuteWithContext runs the given request with additional context information
// This is the enhanced version that provides context-awareness and detailed failure handling
func (cb *CircuitBreaker) ExecuteWithContext(
	ctx *RequestContext,
	request func() (ExecuteResult, error),
) (ExecuteResult, error) {
	if ctx == nil {
		ctx = &RequestContext{
			Category:   "default",
			Priority:   1,
			Timeout:    time.Second * 30,
			MaxRetries: 0,
		}
	}

	// Check if request is allowed based on circuit state and context
	if !cb.isRequestAllowedWithContext(ctx) {
		return ExecuteResult{
			Success:      false,
			ErrorMessage: "circuit breaker is open, request denied",
			Category:     FailureRejection,
		}, fmt.Errorf("circuit breaker is open, request denied")
	}

	// Track request timing
	startTime := time.Now()

	// Execute the request
	result, err := request()

	// Calculate request duration
	result.Duration = time.Since(startTime)

	// Record detailed result with context
	cb.recordDetailedResult(ctx, result)

	return result, err
}

// ExecuteWithRetry runs the given request with automatic retry capability
func (cb *CircuitBreaker) ExecuteWithRetry(
	ctx *RequestContext,
	request func() (ExecuteResult, error),
	maxRetries int,
	backoffFactor float64,
) (ExecuteResult, error) {
	if ctx == nil {
		ctx = &RequestContext{
			Category: "default",
			Priority: 1,
			Timeout:  time.Second * 30,
		}
	}

	var lastResult ExecuteResult
	var lastError error

	// Use context max retries if specified
	if ctx.MaxRetries > 0 {
		maxRetries = ctx.MaxRetries
	}

	// Try initial request plus retries
	for attempt := 0; attempt <= maxRetries; attempt++ {
		// Record retry count in result
		lastResult, lastError = cb.ExecuteWithContext(ctx, func() (ExecuteResult, error) {
			result, err := request()
			result.Retried = attempt
			return result, err
		})

		// If successful, return immediately
		if lastResult.Success {
			return lastResult, nil
		}

		// Don't sleep after the final attempt
		if attempt < maxRetries {
			// Calculate backoff with jitter
			backoffDuration := time.Duration(float64(time.Second) *
				math.Pow(backoffFactor, float64(attempt)) *
				(0.5 + 0.5*cb.jitter()))

			// Don't exceed the request timeout
			if ctx.Timeout > 0 && backoffDuration > ctx.Timeout/2 {
				backoffDuration = ctx.Timeout / 2
			}

			time.Sleep(backoffDuration)
		}
	}

	return lastResult, lastError
}

// jitter returns a random value between 0.5 and 1.5 for backoff jitter
func (cb *CircuitBreaker) jitter() float64 {
	// TODO: Use time nanoseconds as a simple source of randomness
	// This is sufficient for jitter purposes
	nanos := float64(time.Now().UnixNano())
	normalized := (nanos / 1e9) - float64(int(nanos/1e9))
	return 0.5 + normalized
}

// isRequestAllowedWithContext determines if a request should be allowed based on context
func (cb *CircuitBreaker) isRequestAllowedWithContext(ctx *RequestContext) bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// High priority requests might bypass circuit breaker in certain cases
	if cb.state == CircuitOpen && ctx.Priority > 8 {
		log.Info().
			Str("category", ctx.Category).
			Int("priority", ctx.Priority).
			Msg("High priority request bypassing open circuit")
		return true
	}

	// Check current tier and adjust behavior based on context
	switch cb.tier {
	case TierNormal:
		// All requests allowed in normal tier
		return true

	case TierCautious:
		// In cautious tier, only allow requests matching priority filters
		if ctx.Priority < 3 {
			return false
		}
		return true

	case TierRestricted:
		// In restricted tier, only allow higher priority requests
		if ctx.Priority < 5 {
			return false
		}
		return true

	case TierMinimal:
		// In minimal tier, only allow high priority requests
		if ctx.Priority < 7 {
			return false
		}
		return true

	case TierEmergency:
		// In emergency tier, only allow critical requests
		if ctx.Priority < 9 {
			return false
		}
		return true
	}

	// Default circuit breaker behavior
	switch cb.state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if reset timeout has elapsed
		if time.Since(cb.lastFailure) > cb.resetTimeout {
			// Need to transition to half-open outside the read lock
			go cb.transitionToHalfOpen()
		}
		return false
	case CircuitHalfOpen:
		// In half-open, prioritize certain request types for testing
		if ctx.Priority > 5 {
			return cb.halfOpenCallCount < cb.halfOpenMaxCalls
		}
		return false
	default:
		return true
	}
}

// recordDetailedResult processes a detailed execution result with context
func (cb *CircuitBreaker) recordDetailedResult(ctx *RequestContext, result ExecuteResult) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Update metrics
	cb.metrics.TotalRequests++

	// Update latency tracking
	cb.metrics.TotalLatency += result.Duration
	if result.Duration < cb.metrics.MinLatency {
		cb.metrics.MinLatency = result.Duration
	}
	if result.Duration > cb.metrics.MaxLatency {
		cb.metrics.MaxLatency = result.Duration
	}

	// Calculate baseline latency if not set
	if cb.baselineLatency == 0 && result.Success {
		cb.baselineLatency = result.Duration
	} else if result.Success {
		// Gradually adjust baseline (exponential moving average)
		cb.baselineLatency = time.Duration(float64(cb.baselineLatency)*0.95 +
			float64(result.Duration)*0.05)
	}

	// Generate an error hash if there's an error
	errorHash := ""
	if !result.Success {
		errorHash = cb.generateErrorHash(result.ErrorMessage, ctx)

		// Check for attack patterns
		if cb.patternDetection {
			cb.metrics.PatternHashes[errorHash]++
			if cb.metrics.PatternHashes[errorHash] >= cb.patternThreshold {
				cb.knownBadPatterns[errorHash] = true
				log.Warn().
					Str("error_hash", errorHash).
					Int("count", cb.metrics.PatternHashes[errorHash]).
					Msg("Potential attack pattern detected")
			}
		}
	}

	// Process successful request
	if result.Success {
		cb.metrics.ConsecutiveSuccess++
		cb.metrics.ConsecutiveFailure = 0
		cb.metrics.LastSuccessTime = time.Now()

		// Handle circuit state transition
		switch cb.state {
		case CircuitClosed:
			// Update failure count
			cb.failureCount = 0
		case CircuitHalfOpen:
			cb.halfOpenCallCount++
			// If all test requests succeeded, close the circuit
			if cb.halfOpenCallCount >= cb.halfOpenMaxCalls {
				cb.closeCircuit()
			}
		}
		return
	}

	// Process failed request
	cb.metrics.TotalFailures++
	cb.metrics.ConsecutiveSuccess = 0
	cb.metrics.ConsecutiveFailure++
	cb.metrics.LastFailureTime = time.Now()

	// Update category counts
	category := result.Category
	cb.categoryCounts[category]++
	cb.metrics.CategoryCounts[category]++

	// Record failure for analysis
	failureRecord := FailureRecord{
		Timestamp: time.Now(),
		Category:  category,
		Duration:  result.Duration,
		ErrorHash: errorHash,
		ErrorMsg:  result.ErrorMessage,
		Source:    ctx.Source,
		Context:   ctx.Metadata,
	}

	// Add to recent failures, maintaining maximum size
	if len(cb.recentFailures) >= cb.maxFailureHistory {
		// Remove oldest failure
		cb.recentFailures = cb.recentFailures[1:]
	}
	cb.recentFailures = append(cb.recentFailures, failureRecord)

	// Check latency threshold if adaptive threshold is enabled
	latencyTriggered := false
	if cb.adaptiveThreshold && cb.baselineLatency > 0 {
		latencyMultiplier := float64(result.Duration) / float64(cb.baselineLatency)
		if latencyMultiplier > cb.latencyThreshold {
			latencyTriggered = true
			log.Warn().
				Float64("multiplier", latencyMultiplier).
				Float64("threshold", cb.latencyThreshold).
				Dur("baseline", cb.baselineLatency).
				Dur("current", result.Duration).
				Msg("Latency threshold exceeded, considering circuit trip")
		}
	}

	// Check for security-related failures that should trigger immediate circuit open
	if category == FailureSecurity {
		log.Warn().
			Str("error", result.ErrorMessage).
			Msg("Security failure detected, immediately opening circuit")
		cb.tripBreaker()
		return
	}

	// Handle circuit state transition based on failure
	switch cb.state {
	case CircuitClosed:
		cb.failureCount++

		// Check if we've exceeded the threshold for this specific category
		categoryThreshold := cb.categoryThresholds[category]
		if cb.categoryCounts[category] >= categoryThreshold {
			log.Warn().
				Int("count", cb.categoryCounts[category]).
				Int("threshold", categoryThreshold).
				Str("category", fmt.Sprintf("%v", category)).
				Msg("Category threshold exceeded, opening circuit")
			cb.tripBreaker()
			return
		}

		// Check if we've exceeded the general threshold
		if cb.failureCount >= cb.failureThreshold || latencyTriggered {
			cb.tripBreaker()
		}

	case CircuitHalfOpen:
		// If any test request fails in half-open state, trip the circuit again
		cb.tripBreaker()
	}
}

// generateErrorHash creates a hash to identify similar errors for pattern detection
func (cb *CircuitBreaker) generateErrorHash(errorMsg string, ctx *RequestContext) string {
	if len(errorMsg) > 100 {
		errorMsg = errorMsg[:100] // Truncate very long messages
	}

	// Create a combined string with context for hashing
	contextStr := errorMsg
	if ctx != nil {
		contextStr += "|" + ctx.Category
		if ctx.Source != "" {
			contextStr += "|" + ctx.Source
		}
	}

	// Hash the error pattern
	hash := sha256.Sum256([]byte(contextStr))
	return hex.EncodeToString(hash[:8]) // Use first 8 bytes for a shorter hash
}

// isRequestAllowed checks if a request should be allowed to execute
func (cb *CircuitBreaker) isRequestAllowed() bool {
	cb.mu.RLock()
	state := cb.state
	timeout := cb.resetTimeout
	lastFailure := cb.lastFailure
	maxHalfOpenCalls := cb.halfOpenMaxCalls
	halfOpenCallCount := cb.halfOpenCallCount
	cb.mu.RUnlock()

	var shouldTransition bool

	switch state {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if reset timeout has elapsed
		if time.Since(lastFailure) > timeout {
			shouldTransition = true
		}

		// If we need to transition, do it outside the lock
		if shouldTransition {
			cb.transitionToHalfOpen()
			// We still deny this request to avoid a race condition
			// The next request will find the circuit in half-open state
			return false
		}
		return false
	case CircuitHalfOpen:
		return halfOpenCallCount < maxHalfOpenCalls
	default:
		return true
	}
}

// recordResult records the result of a request and updates the circuit state
func (cb *CircuitBreaker) recordResult(success bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	switch cb.state {
	case CircuitClosed:
		if !success {
			cb.failureCount++
			if cb.failureCount >= cb.failureThreshold {
				// Instead of calling tripBreaker (which acquires the lock again),
				// we'll directly implement the open circuit logic
				if cb.state != CircuitOpen {
					log.Warn().
						Int("failure_count", cb.failureCount).
						Int("threshold", cb.failureThreshold).
						Msg("Circuit breaker tripped, opening circuit")

					cb.state = CircuitOpen
					cb.lastFailure = time.Now()
					cb.metrics.OpenCircuitCount++

					// Notify metrics hooks about state change
					// It's safe to access hooks here as we still hold the lock
					if cb.hooks != nil {
						cb.hooks.NotifyStateChange(true)
					}
				}
			}
		} else {
			// Reset failure count after a successful request
			cb.failureCount = 0
		}
	case CircuitHalfOpen:
		cb.halfOpenCallCount++
		if !success {
			// If any test request fails, directly implement open circuit logic
			if cb.state != CircuitOpen {
				log.Warn().
					Int("failure_count", cb.failureCount).
					Int("threshold", cb.failureThreshold).
					Msg("Circuit breaker tripped, opening circuit")

				cb.state = CircuitOpen
				cb.lastFailure = time.Now()
				cb.metrics.OpenCircuitCount++

				// Notify metrics hooks about state change
				if cb.hooks != nil {
					cb.hooks.NotifyStateChange(true)
				}
			}
			return
		}
		// If all test requests succeeded, implement close circuit logic
		if cb.halfOpenCallCount >= cb.halfOpenMaxCalls {
			if cb.state != CircuitClosed {
				log.Info().Msg("Circuit breaker reset, closing circuit")
				cb.state = CircuitClosed
				cb.failureCount = 0

				// Notify metrics hooks about state change
				if cb.hooks != nil {
					cb.hooks.NotifyStateChange(false)
				}
			}
		}
	}
}

// transitionToHalfOpen attempts to transition the circuit from open to half-open
func (cb *CircuitBreaker) transitionToHalfOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == CircuitOpen {
		cb.state = CircuitHalfOpen
		cb.halfOpenCallCount = 0
		log.Info().Msg("Circuit transitioning from open to half-open")

		// Notify metrics hooks about state change
		if cb.hooks != nil {
			cb.hooks.NotifyStateChange(false)
		}
	}
}

// tripBreaker opens the circuit, preventing requests from executing
func (cb *CircuitBreaker) tripBreaker() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Only log and increment if we're transitioning from a non-open state
	if cb.state != CircuitOpen {
		log.Warn().
			Int("failure_count", cb.failureCount).
			Int("threshold", cb.failureThreshold).
			Msg("Circuit breaker tripped, opening circuit")

		cb.state = CircuitOpen
		cb.lastFailure = time.Now()
		cb.metrics.OpenCircuitCount++

		// Notify metrics hooks about state change
		if cb.hooks != nil {
			cb.hooks.NotifyStateChange(true)
		}
	}
}

// closeCircuit closes the circuit, allowing requests to flow normally
func (cb *CircuitBreaker) closeCircuit() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Only log if we're transitioning from a non-closed state
	if cb.state != CircuitClosed {
		log.Info().Msg("Circuit breaker reset, closing circuit")
		cb.state = CircuitClosed
		cb.failureCount = 0

		// Notify metrics hooks about state change
		if cb.hooks != nil {
			cb.hooks.NotifyStateChange(false)
		}
	}
}

// GetState returns the current state of the circuit breaker
func (cb *CircuitBreaker) GetState() CircuitBreakerState {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

// ForceOpen forces the circuit to open, typically used for administrative actions
func (cb *CircuitBreaker) ForceOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = CircuitOpen
	cb.lastFailure = time.Now()
	log.Warn().Msg("Circuit manually OPENED by administrative action")
}

// ForceClose forces the circuit to close, typically used for administrative actions
func (cb *CircuitBreaker) ForceClose() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.state = CircuitClosed
	cb.failureCount = 0
	log.Info().Msg("Circuit manually CLOSED by administrative action")
}

// GetTier returns the current operational tier
func (cb *CircuitBreaker) GetTier() CircuitTier {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.tier
}

// SetTier sets the operational tier of the circuit breaker
func (cb *CircuitBreaker) SetTier(tier CircuitTier) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if tier < TierNormal || tier > TierEmergency {
		log.Error().
			Int("tier", int(tier)).
			Msg("Invalid circuit breaker tier, ignoring")
		return
	}

	oldTier := cb.tier

	// Only update if the tier is changing
	if oldTier != tier {
		log.Info().
			Int("old_tier", int(oldTier)).
			Int("new_tier", int(tier)).
			Msg("Circuit breaker tier changing")

		cb.tier = tier

		// Notify metrics hooks about tier change
		if cb.hooks != nil {
			cb.hooks.NotifyTierChange(oldTier, tier)
		}
	}
}

// ActivateSelfHealing enables automatic recovery and self-healing capabilities
func (cb *CircuitBreaker) ActivateSelfHealing(enabled bool) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.autoRecoveryEnabled = enabled
	log.Info().Bool("enabled", enabled).Msg("Self-healing capabilities toggled")

	// If enabling self-healing, start the healing process
	if enabled && cb.state == CircuitOpen {
		go cb.startHealingProcess()
	}
}

// SelfHeal attempts to gradually recover the circuit, even if the timeout hasn't elapsed
func (cb *CircuitBreaker) SelfHeal() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state != CircuitOpen {
		return // Only heal open circuits
	}

	// Check if we have recent successful latency data to determine
	// if the service might be recovering
	recentSuccesses := cb.metrics.ConsecutiveSuccess > 0 &&
		time.Since(cb.metrics.LastSuccessTime) < cb.resetTimeout

	// Only try healing if we've waited at least 1/3 of the reset timeout
	waitThreshold := cb.resetTimeout / 3
	if time.Since(cb.lastFailure) > waitThreshold || recentSuccesses {
		log.Info().Msg("Attempting self-healing transition to HALF-OPEN")
		cb.state = CircuitHalfOpen
		cb.halfOpenCallCount = 0
	}
}

// startHealingProcess runs a background loop to attempt recovery
func (cb *CircuitBreaker) startHealingProcess() {
	// Wait for a portion of the reset timeout
	time.Sleep(cb.resetTimeout / 3)

	// Only proceed if self-healing is still enabled
	cb.mu.RLock()
	selfHealingEnabled := cb.autoRecoveryEnabled
	cb.mu.RUnlock()

	if !selfHealingEnabled {
		return
	}

	// Try to heal the circuit
	cb.SelfHeal()
}

// GetMetrics returns a copy of the current circuit breaker metrics
func (cb *CircuitBreaker) GetMetrics() CircuitMetrics {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// Create a deep copy to avoid concurrent access issues
	metricsCopy := CircuitMetrics{
		TotalRequests:      cb.metrics.TotalRequests,
		TotalFailures:      cb.metrics.TotalFailures,
		ConsecutiveSuccess: cb.metrics.ConsecutiveSuccess,
		ConsecutiveFailure: cb.metrics.ConsecutiveFailure,
		LastFailureTime:    cb.metrics.LastFailureTime,
		LastSuccessTime:    cb.metrics.LastSuccessTime,
		OpenCircuitCount:   cb.metrics.OpenCircuitCount,
		TotalLatency:       cb.metrics.TotalLatency,
		MinLatency:         cb.metrics.MinLatency,
		MaxLatency:         cb.metrics.MaxLatency,
		CategoryCounts:     make(map[FailureCategory]int),
		PatternHashes:      make(map[string]int),
	}

	// Copy maps
	for k, v := range cb.metrics.CategoryCounts {
		metricsCopy.CategoryCounts[k] = v
	}

	for k, v := range cb.metrics.PatternHashes {
		metricsCopy.PatternHashes[k] = v
	}

	return metricsCopy
}

// GetRecentFailures returns a copy of the recent failure records for analysis
func (cb *CircuitBreaker) GetRecentFailures() []FailureRecord {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	// Use slices.Clone for safer copying
	if len(cb.recentFailures) == 0 {
		return []FailureRecord{}
	}

	return slices.Clone(cb.recentFailures)
}

// DetectAttackPatterns analyzes recent failures to identify potential attack patterns
func (cb *CircuitBreaker) DetectAttackPatterns() map[string]int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	patterns := make(map[string]int)

	// Copy patterns that exceed the threshold
	for hash, count := range cb.metrics.PatternHashes {
		if count >= cb.patternThreshold {
			patterns[hash] = count
		}
	}

	return patterns
}

// SetAdaptiveThresholds configures the circuit breaker to dynamically adjust
// thresholds based on observed system behavior
func (cb *CircuitBreaker) SetAdaptiveThresholds(enabled bool, latencyMultiplier float64) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.adaptiveThreshold = enabled
	if latencyMultiplier > 0 {
		cb.latencyThreshold = latencyMultiplier
	}

	log.Info().
		Bool("enabled", enabled).
		Float64("latency_threshold", cb.latencyThreshold).
		Msg("Adaptive thresholds configured")
}

// AddKnownBadPattern adds a known malicious error pattern to the detection system
func (cb *CircuitBreaker) AddKnownBadPattern(pattern string) {
	hash := sha256.Sum256([]byte(pattern))
	hashStr := hex.EncodeToString(hash[:8])

	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.knownBadPatterns[hashStr] = true
	log.Info().
		Str("pattern_hash", hashStr).
		Msg("Added known bad pattern to detection system")
}

// PanicResponse contains information about how the circuit breaker should
// respond to a system-wide panic event
type PanicResponse struct {
	PanicTier         int             // Maps to CircuitTier
	ActionRequired    bool            // Whether the circuit breaker needs to take action
	MaxAllowedTraffic float64         // 0.0-1.0 representing % of traffic to allow
	AllowedCategories map[string]bool // Categories of requests that are still allowed
	ResponseMessage   string          // Message to include in rejected requests
}

// RespondToPanic updates the circuit breaker state in response to a system-wide panic
func (cb *CircuitBreaker) RespondToPanic(response PanicResponse) {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Log the panic response
	log.Warn().
		Int("panic_tier", response.PanicTier).
		Bool("action_required", response.ActionRequired).
		Float64("max_traffic", response.MaxAllowedTraffic).
		Msg("Circuit breaker responding to system panic")

	if !response.ActionRequired {
		return
	}

	// Map panic tier to circuit tier
	newTier := CircuitTier(response.PanicTier)
	if newTier > TierEmergency {
		newTier = TierEmergency
	}

	// Set the new tier
	previousTier := cb.tier
	cb.tier = newTier

	// In higher panic tiers, force the circuit open
	if newTier >= TierRestricted {
		cb.state = CircuitOpen
		cb.lastFailure = time.Now()

		// Set a longer timeout for recovery during panic
		panicTimeout := cb.resetTimeout * 2
		cb.tierTimeouts[cb.tier] = panicTimeout
	}

	log.Warn().
		Str("previous_tier", fmt.Sprintf("%v", previousTier)).
		Str("new_tier", fmt.Sprintf("%v", newTier)).
		Str("circuit_state", fmt.Sprintf("%v", cb.state)).
		Msg("Circuit breaker reconfigured due to system panic")
}

// ResetAfterPanic restores the circuit breaker to normal operation after a panic
func (cb *CircuitBreaker) ResetAfterPanic() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	// Only reset if not in normal tier
	if cb.tier != TierNormal {
		previousTier := cb.tier
		cb.tier = TierNormal

		// Reset failure counters
		cb.failureCount = 0
		for category := range cb.categoryCounts {
			cb.categoryCounts[category] = 0
		}

		// Don't automatically close the circuit, but allow normal operation to resume
		if cb.state == CircuitOpen {
			cb.state = CircuitHalfOpen
			cb.halfOpenCallCount = 0
		}

		log.Info().
			Str("previous_tier", fmt.Sprintf("%v", previousTier)).
			Str("new_tier", fmt.Sprintf("%v", cb.tier)).
			Str("circuit_state", fmt.Sprintf("%v", cb.state)).
			Msg("Circuit breaker reset after system panic")
	}
}

// Snapshot returns a complete snapshot of the circuit breaker state
// for diagnostics and monitoring
func (cb *CircuitBreaker) Snapshot() map[string]interface{} {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	avgLatency := time.Duration(0)
	if cb.metrics.TotalRequests > 0 {
		avgLatency = time.Duration(int64(cb.metrics.TotalLatency) / cb.metrics.TotalRequests)
	}

	snapshot := map[string]interface{}{
		"state":                 fmt.Sprintf("%v", cb.state),
		"tier":                  fmt.Sprintf("%v", cb.tier),
		"failure_count":         cb.failureCount,
		"failure_threshold":     cb.failureThreshold,
		"last_failure":          cb.lastFailure,
		"reset_timeout":         cb.resetTimeout,
		"half_open_max_calls":   cb.halfOpenMaxCalls,
		"half_open_call_count":  cb.halfOpenCallCount,
		"baseline_latency_ms":   cb.baselineLatency.Milliseconds(),
		"latency_threshold":     cb.latencyThreshold,
		"adaptive_threshold":    cb.adaptiveThreshold,
		"self_healing_enabled":  cb.autoRecoveryEnabled,
		"pattern_detection":     cb.patternDetection,
		"total_requests":        cb.metrics.TotalRequests,
		"total_failures":        cb.metrics.TotalFailures,
		"consecutive_success":   cb.metrics.ConsecutiveSuccess,
		"consecutive_failure":   cb.metrics.ConsecutiveFailure,
		"open_circuit_count":    cb.metrics.OpenCircuitCount,
		"avg_latency_ms":        avgLatency.Milliseconds(),
		"min_latency_ms":        cb.metrics.MinLatency.Milliseconds(),
		"max_latency_ms":        cb.metrics.MaxLatency.Milliseconds(),
		"recent_failures_count": len(cb.recentFailures),
		"attack_patterns_count": len(cb.knownBadPatterns),
	}

	// Add category counts
	categoryCounts := make(map[string]int)
	for category, count := range cb.metrics.CategoryCounts {
		categoryCounts[fmt.Sprintf("%v", category)] = count
	}
	snapshot["category_counts"] = categoryCounts

	return snapshot
}

// NewMilitaryGradeCircuitBreaker creates an enhanced circuit breaker with military-grade
// resilience features and multi-tier protection
func NewMilitaryGradeCircuitBreaker(config map[string]interface{}) *CircuitBreaker {
	// Default values
	failureThreshold := 5
	resetTimeout := 30 * time.Second

	// Override with config if provided
	if config != nil {
		if threshold, ok := config["failure_threshold"].(int); ok {
			failureThreshold = threshold
		}
		if timeout, ok := config["reset_timeout"].(time.Duration); ok {
			resetTimeout = timeout
		}
	}

	cb := NewCircuitBreaker(failureThreshold, resetTimeout)

	// Configure military-grade defaults
	cb.adaptiveThreshold = true
	cb.patternDetection = true
	cb.autoRecoveryEnabled = true
	cb.maxFailureHistory = 1000 // Increase historical data

	// Enhanced security sensitivities
	cb.categoryThresholds[FailureSecurity] = 1   // Any security failure trips circuit
	cb.categoryThresholds[FailureConnection] = 3 // More sensitive to connection issues
	cb.patternThreshold = 2                      // Detect patterns more aggressively

	// Configure tiered timeouts
	cb.tierTimeouts[TierCautious] = time.Duration(float64(resetTimeout) * 1.5)
	cb.tierTimeouts[TierRestricted] = resetTimeout * 2
	cb.tierTimeouts[TierMinimal] = resetTimeout * 3
	cb.tierTimeouts[TierEmergency] = resetTimeout * 5

	log.Info().Msg("Military-grade circuit breaker initialized with enhanced resilience features")

	return cb
}

// GetHooks returns the circuit breaker hooks for registering metrics emitters
func (cb *CircuitBreaker) GetHooks() *CircuitBreakerHooks {
	return cb.hooks
}
