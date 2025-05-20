package server

import (
	"errors"
	"testing"
	"time"
)

func TestCircuitBreakerBasicFunctionality(t *testing.T) {
	// Create a circuit breaker with small thresholds for testing
	cb := NewCircuitBreaker(3, 500*time.Millisecond)
	if cb == nil {
		t.Fatal("Failed to create circuit breaker")
	}

	// Initially should be closed
	if cb.GetState() != CircuitClosed {
		t.Errorf("Expected initial state to be CLOSED, got %v", cb.GetState())
	}

	// Execute a successful request
	err := cb.Execute(func() error {
		return nil
	})
	if err != nil {
		t.Errorf("Expected successful execution, got %v", err)
	}

	// Check metrics
	metrics := cb.GetMetrics()
	if metrics.TotalRequests != 1 {
		t.Errorf("Expected 1 total request, got %d", metrics.TotalRequests)
	}
	if metrics.TotalFailures != 0 {
		t.Errorf("Expected 0 failures, got %d", metrics.TotalFailures)
	}
	if metrics.ConsecutiveSuccess != 1 {
		t.Errorf("Expected 1 consecutive success, got %d", metrics.ConsecutiveSuccess)
	}

	// Execute failing requests to trip the breaker
	testError := errors.New("test error")
	for i := 0; i < 3; i++ {
		err = cb.Execute(func() error {
			return testError
		})
		if err == nil {
			t.Errorf("Expected error from failing execution")
		}
	}

	// Circuit should now be open
	if cb.GetState() != CircuitOpen {
		t.Errorf("Expected state to be OPEN after failures, got %v", cb.GetState())
	}

	// Should reject requests when open
	err = cb.Execute(func() error {
		t.Fatal("This should not execute when circuit is open")
		return nil
	})
	if err == nil || err.Error() != "circuit breaker is open, request denied" {
		t.Errorf("Expected circuit open error, got %v", err)
	}

	// Wait for timeout to allow transition to half-open
	time.Sleep(600 * time.Millisecond)

	// Force transition to half-open for testing
	cb.transitionToHalfOpen()

	// Verify the circuit is now half-open
	if cb.GetState() != CircuitHalfOpen {
		t.Errorf("Expected state to be HALF-OPEN after timeout, got %v", cb.GetState())
	}

	// Execute successful requests in half-open state to close circuit
	// Need halfOpenMaxCalls (3) successful requests to transition to closed
	for i := 0; i < 3; i++ {
		err = cb.Execute(func() error {
			return nil
		})
		if err != nil {
			t.Errorf("Expected successful execution in half-open state, got %v", err)
		}
	}

	// Circuit should be closed again
	if cb.GetState() != CircuitClosed {
		t.Errorf("Expected state to be CLOSED after successful recovery, got %v", cb.GetState())
	}

	// Manually force open
	cb.ForceOpen()
	if cb.GetState() != CircuitOpen {
		t.Errorf("Expected state to be OPEN after force open, got %v", cb.GetState())
	}

	// Manually force close
	cb.ForceClose()
	if cb.GetState() != CircuitClosed {
		t.Errorf("Expected state to be CLOSED after force close, got %v", cb.GetState())
	}
}

func TestCircuitBreakerWithContext(t *testing.T) {
	// Create a circuit breaker
	cb := NewCircuitBreaker(3, 500*time.Millisecond)

	// Test with context
	ctx := &RequestContext{
		Category: "test",
		Priority: 5,
		Timeout:  time.Second,
	}

	result, err := cb.ExecuteWithContext(ctx, func() (ExecuteResult, error) {
		return ExecuteResult{
			Success:      true,
			Duration:     time.Millisecond * 50,
			ErrorMessage: "",
			Category:     FailureGeneric,
		}, nil
	})

	if err != nil {
		t.Errorf("Expected successful execution, got %v", err)
	}

	if !result.Success {
		t.Errorf("Expected successful result")
	}

	// Test with retry
	retryResult, retryErr := cb.ExecuteWithRetry(ctx, func() (ExecuteResult, error) {
		return ExecuteResult{
			Success:      true,
			Duration:     time.Millisecond * 50,
			ErrorMessage: "",
			Category:     FailureGeneric,
		}, nil
	}, 3, 1.5)

	if retryErr != nil {
		t.Errorf("Expected successful retry execution, got %v", retryErr)
	}

	if !retryResult.Success {
		t.Errorf("Expected successful retry result")
	}
}

func TestMilitaryGradeCircuitBreaker(t *testing.T) {
	// Create a military-grade circuit breaker
	cb := NewMilitaryGradeCircuitBreaker(nil)
	if cb == nil {
		t.Fatal("Failed to create military-grade circuit breaker")
	}

	// Check default tier
	if cb.GetTier() != TierNormal {
		t.Errorf("Expected initial tier to be NORMAL, got %v", cb.GetTier())
	}

	// Test tier change
	cb.SetTier(TierCautious)
	if cb.GetTier() != TierCautious {
		t.Errorf("Expected tier to be CAUTIOUS after change, got %v", cb.GetTier())
	}

	// Test self-healing activation
	cb.ActivateSelfHealing(true)

	// Test snapshot
	snapshot := cb.Snapshot()
	if snapshot["tier"] != "1" { // TierCautious is 1
		t.Errorf("Expected tier in snapshot to be 1 (TierCautious), got %v", snapshot["tier"])
	}

	if snapshot["self_healing_enabled"] != true {
		t.Errorf("Expected self_healing_enabled to be true in snapshot")
	}

	// Test panic response
	cb.RespondToPanic(PanicResponse{
		PanicTier:         3,
		ActionRequired:    true,
		MaxAllowedTraffic: 0.5,
		AllowedCategories: map[string]bool{"critical": true},
		ResponseMessage:   "System in panic mode",
	})

	// Should be in restricted tier now
	if cb.GetTier() != 3 { // TierRestricted is 3
		t.Errorf("Expected tier to be 3 (TierRestricted) after panic, got %v", cb.GetTier())
	}

	// Reset after panic
	cb.ResetAfterPanic()

	// Should be back to normal tier
	if cb.GetTier() != TierNormal {
		t.Errorf("Expected tier to be NORMAL after reset, got %v", cb.GetTier())
	}
}
