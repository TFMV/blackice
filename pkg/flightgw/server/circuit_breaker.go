package server

import (
	"fmt"
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

// CircuitBreaker implements the circuit breaker pattern to prevent
// cascading failures when an upstream service is unavailable
type CircuitBreaker struct {
	mu                sync.RWMutex
	state             CircuitBreakerState
	failureThreshold  int
	failureCount      int
	resetTimeout      time.Duration
	lastFailure       time.Time
	halfOpenMaxCalls  int
	halfOpenCallCount int
}

// NewCircuitBreaker creates a new circuit breaker with the specified parameters
func NewCircuitBreaker(failureThreshold int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:            CircuitClosed,
		failureThreshold: failureThreshold,
		resetTimeout:     resetTimeout,
		halfOpenMaxCalls: 3, // Allow 3 test calls in half-open state
	}
}

// Execute runs the given request if the circuit is closed or half-open.
// Returns an error if the circuit is open or if the request fails.
func (cb *CircuitBreaker) Execute(request func() error) error {
	if !cb.isRequestAllowed() {
		return fmt.Errorf("circuit breaker is open, request denied")
	}

	err := request()
	cb.recordResult(err == nil)
	return err
}

// isRequestAllowed checks if a request should be allowed to execute
func (cb *CircuitBreaker) isRequestAllowed() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

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
		return cb.halfOpenCallCount < cb.halfOpenMaxCalls
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
				cb.tripBreaker()
			}
		} else {
			// Reset failure count after a successful request
			cb.failureCount = 0
		}
	case CircuitHalfOpen:
		cb.halfOpenCallCount++
		if !success {
			// If any test request fails, trip the circuit again
			cb.tripBreaker()
			return
		}
		// If all test requests succeeded, close the circuit
		if cb.halfOpenCallCount >= cb.halfOpenMaxCalls {
			cb.closeCircuit()
		}
	}
}

// transitionToHalfOpen transitions the circuit from open to half-open
func (cb *CircuitBreaker) transitionToHalfOpen() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	if cb.state == CircuitOpen {
		log.Info().Msg("Circuit transitioning from OPEN to HALF-OPEN")
		cb.state = CircuitHalfOpen
		cb.halfOpenCallCount = 0
	}
}

// tripBreaker opens the circuit
func (cb *CircuitBreaker) tripBreaker() {
	cb.state = CircuitOpen
	cb.lastFailure = time.Now()
	log.Warn().
		Int("failure_count", cb.failureCount).
		Time("last_failure", cb.lastFailure).
		Msg("Circuit OPEN: Too many failures")
}

// closeCircuit closes the circuit
func (cb *CircuitBreaker) closeCircuit() {
	cb.state = CircuitClosed
	cb.failureCount = 0
	log.Info().Msg("Circuit CLOSED: System recovered")
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
