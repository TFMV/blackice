package trust

import (
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// SourceTrustScore represents the trust score for a data source
type SourceTrustScore struct {
	SourceID          string         `json:"source_id"`
	Score             int            `json:"score"`
	LastUpdated       time.Time      `json:"last_updated"`
	ConsistencyScore  int            `json:"consistency_score"`
	TimingScore       int            `json:"timing_score"`
	VerificationScore int            `json:"verification_score"`
	ExternalScore     int            `json:"external_score"`
	ScoreHistory      []ScoreHistory `json:"score_history"`
}

// ScoreHistory represents a historical trust score entry
type ScoreHistory struct {
	Timestamp time.Time `json:"timestamp"`
	Score     int       `json:"score"`
	Reason    string    `json:"reason"`
}

// ScoreAdjustment represents an adjustment to a trust score
type ScoreAdjustment struct {
	Value      int           `json:"value"`
	Reason     string        `json:"reason"`
	Category   string        `json:"category"`   // "consistency", "timing", "verification", "external"
	Expiration time.Duration `json:"expiration"` // Zero means permanent
}

// TrustScorer manages trust scores for data sources
type TrustScorer struct {
	mu                 sync.RWMutex
	scores             map[string]*SourceTrustScore
	minScore           int
	thresholdScore     int
	temporaryPenalties map[string][]temporaryPenalty
}

type temporaryPenalty struct {
	value      int
	reason     string
	category   string
	expiration time.Time
}

// NewTrustScorer creates a new TrustScorer
func NewTrustScorer(minScore, thresholdScore int) *TrustScorer {
	return &TrustScorer{
		scores:             make(map[string]*SourceTrustScore),
		minScore:           minScore,
		thresholdScore:     thresholdScore,
		temporaryPenalties: make(map[string][]temporaryPenalty),
	}
}

// RegisterSource registers a new data source with an initial trust score
func (ts *TrustScorer) RegisterSource(sourceID string, initialScore int) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if _, exists := ts.scores[sourceID]; exists {
		return fmt.Errorf("source already registered: %s", sourceID)
	}

	// Ensure the score is within valid range
	if initialScore < 0 {
		initialScore = 0
	} else if initialScore > 100 {
		initialScore = 100
	}

	now := time.Now()
	ts.scores[sourceID] = &SourceTrustScore{
		SourceID:          sourceID,
		Score:             initialScore,
		LastUpdated:       now,
		ConsistencyScore:  25, // Default scores for each category
		TimingScore:       25,
		VerificationScore: 25,
		ExternalScore:     25,
		ScoreHistory:      []ScoreHistory{{Timestamp: now, Score: initialScore, Reason: "Initial registration"}},
	}

	log.Info().
		Str("source_id", sourceID).
		Int("initial_score", initialScore).
		Msg("Registered new data source")

	return nil
}

// GetScore returns the current trust score for a source
func (ts *TrustScorer) GetScore(sourceID string) (*SourceTrustScore, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	score, exists := ts.scores[sourceID]
	if !exists {
		return nil, fmt.Errorf("source not found: %s", sourceID)
	}

	// Clean up expired penalties
	ts.cleanupExpiredPenalties(sourceID)

	return score, nil
}

// UpdateScore applies an adjustment to a source's trust score
func (ts *TrustScorer) UpdateScore(sourceID string, adjustment ScoreAdjustment) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	score, exists := ts.scores[sourceID]
	if !exists {
		return fmt.Errorf("source not found: %s", sourceID)
	}

	// If the adjustment is temporary, add it to the penalties map
	if adjustment.Expiration > 0 {
		ts.temporaryPenalties[sourceID] = append(ts.temporaryPenalties[sourceID], temporaryPenalty{
			value:      adjustment.Value,
			reason:     adjustment.Reason,
			category:   adjustment.Category,
			expiration: time.Now().Add(adjustment.Expiration),
		})

		log.Debug().
			Str("source_id", sourceID).
			Int("adjustment", adjustment.Value).
			Str("reason", adjustment.Reason).
			Str("category", adjustment.Category).
			Dur("expiration", adjustment.Expiration).
			Msg("Applied temporary trust score adjustment")
	} else {
		// For permanent adjustments, apply them to the appropriate category
		switch adjustment.Category {
		case "consistency":
			score.ConsistencyScore = clampScore(score.ConsistencyScore + adjustment.Value)
		case "timing":
			score.TimingScore = clampScore(score.TimingScore + adjustment.Value)
		case "verification":
			score.VerificationScore = clampScore(score.VerificationScore + adjustment.Value)
		case "external":
			score.ExternalScore = clampScore(score.ExternalScore + adjustment.Value)
		default:
			// Apply to all categories equally
			value := adjustment.Value / 4
			score.ConsistencyScore = clampScore(score.ConsistencyScore + value)
			score.TimingScore = clampScore(score.TimingScore + value)
			score.VerificationScore = clampScore(score.VerificationScore + value)
			score.ExternalScore = clampScore(score.ExternalScore + value)
		}
	}

	// Recalculate the overall score
	ts.recalculateScore(sourceID)

	// Add to history
	now := time.Now()
	score.LastUpdated = now
	score.ScoreHistory = append(score.ScoreHistory, ScoreHistory{
		Timestamp: now,
		Score:     score.Score,
		Reason:    adjustment.Reason,
	})

	// Trim history if it's too long
	if len(score.ScoreHistory) > 100 {
		score.ScoreHistory = score.ScoreHistory[len(score.ScoreHistory)-100:]
	}

	log.Info().
		Str("source_id", sourceID).
		Int("adjustment", adjustment.Value).
		Int("new_score", score.Score).
		Str("reason", adjustment.Reason).
		Str("category", adjustment.Category).
		Msg("Updated trust score")

	return nil
}

// IsTrusted checks if a source's trust score is above the threshold
func (ts *TrustScorer) IsTrusted(sourceID string) (bool, error) {
	score, err := ts.GetScore(sourceID)
	if err != nil {
		return false, err
	}
	return score.Score >= ts.thresholdScore, nil
}

// cleanupExpiredPenalties removes any expired temporary penalties
func (ts *TrustScorer) cleanupExpiredPenalties(sourceID string) {
	now := time.Now()
	penalties := ts.temporaryPenalties[sourceID]
	activeIdx := 0

	for i := range penalties {
		if penalties[i].expiration.After(now) {
			// Keep this penalty as it's still active
			if i != activeIdx {
				penalties[activeIdx] = penalties[i]
			}
			activeIdx++
		}
	}

	if activeIdx < len(penalties) {
		// Truncate the slice to remove expired penalties
		ts.temporaryPenalties[sourceID] = penalties[:activeIdx]
		// Recalculate score since we removed penalties
		ts.recalculateScore(sourceID)
	}
}

// recalculateScore recalculates the overall score from individual components
func (ts *TrustScorer) recalculateScore(sourceID string) {
	score := ts.scores[sourceID]

	// Start with the weighted average of component scores
	// We could adjust weights here based on importance
	baseScore := (score.ConsistencyScore + score.TimingScore + score.VerificationScore + score.ExternalScore) / 4

	// Apply temporary penalties
	tempPenalty := 0
	for _, p := range ts.temporaryPenalties[sourceID] {
		tempPenalty += p.value
	}

	// Calculate final score
	finalScore := baseScore + tempPenalty

	// Clamp to valid range
	score.Score = clampScore(finalScore)
}

// clampScore ensures a score is within the valid range [0-100]
func clampScore(score int) int {
	return int(math.Max(0, math.Min(100, float64(score))))
}
