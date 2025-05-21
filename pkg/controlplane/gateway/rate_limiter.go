package gateway

import (
	"fmt"
	"sync"
	"time"
)

// RateLimiter implements a token bucket rate limiter
type RateLimiter struct {
	limit       int           // tokens per interval
	interval    time.Duration // refresh interval
	buckets     map[string]*bucket
	bucketMutex sync.RWMutex
	cleanup     *time.Ticker
}

// bucket represents a token bucket for a single client
type bucket struct {
	tokens     int       // current token count
	lastRefill time.Time // time of last token refill
	mutex      sync.Mutex
}

// NewRateLimiter creates a new rate limiter with the specified limit and interval
func NewRateLimiter(limit int, intervalStr string) (*RateLimiter, error) {
	interval, err := time.ParseDuration(intervalStr)
	if err != nil {
		return nil, fmt.Errorf("invalid interval format: %w", err)
	}

	limiter := &RateLimiter{
		limit:    limit,
		interval: interval,
		buckets:  make(map[string]*bucket),
		cleanup:  time.NewTicker(10 * time.Minute),
	}

	// Start cleanup goroutine
	go limiter.startCleanup()

	return limiter, nil
}

// Allow checks if a request is allowed under the rate limit
func (r *RateLimiter) Allow(key string) bool {
	r.bucketMutex.RLock()
	b, exists := r.buckets[key]
	r.bucketMutex.RUnlock()

	if !exists {
		// Create a new bucket for this client
		b = &bucket{
			tokens:     r.limit - 1, // Use one token for this request
			lastRefill: time.Now(),
		}

		r.bucketMutex.Lock()
		r.buckets[key] = b
		r.bucketMutex.Unlock()

		return true
	}

	// Use existing bucket
	b.mutex.Lock()
	defer b.mutex.Unlock()

	// Check if we need to refill tokens
	now := time.Now()
	elapsed := now.Sub(b.lastRefill)

	// Calculate how many tokens to add based on elapsed time
	tokensToAdd := int(float64(elapsed) / float64(r.interval) * float64(r.limit))

	if tokensToAdd > 0 {
		// Refill tokens up to the limit
		b.tokens = min(b.tokens+tokensToAdd, r.limit)
		b.lastRefill = now
	}

	// Check if there are tokens available
	if b.tokens > 0 {
		b.tokens--
		return true
	}

	return false
}

// startCleanup periodically removes unused buckets to prevent memory leaks
func (r *RateLimiter) startCleanup() {
	for range r.cleanup.C {
		r.cleanupBuckets()
	}
}

// cleanupBuckets removes buckets that haven't been used in a while
func (r *RateLimiter) cleanupBuckets() {
	r.bucketMutex.Lock()
	defer r.bucketMutex.Unlock()

	expiry := time.Now().Add(-24 * time.Hour) // Remove buckets not used for a day
	for key, b := range r.buckets {
		b.mutex.Lock()
		if b.lastRefill.Before(expiry) {
			delete(r.buckets, key)
		}
		b.mutex.Unlock()
	}
}

// Stop stops the rate limiter cleanup ticker
func (r *RateLimiter) Stop() {
	if r.cleanup != nil {
		r.cleanup.Stop()
	}
}

// min returns the minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
