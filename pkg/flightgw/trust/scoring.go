package trust

import (
	"fmt"
	"math"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
)

// TrustScoreCategory represents a specific category of trust scoring
type TrustScoreCategory string

const (
	// ConsistencyCategory evaluates statistical properties of data compared to historical patterns
	ConsistencyCategory TrustScoreCategory = "consistency"
	// TimingCategory detects anomalous submission patterns or timing inconsistencies
	TimingCategory TrustScoreCategory = "timing"
	// VerificationCategory tracks the frequency of cryptographic validation failures
	VerificationCategory TrustScoreCategory = "verification"
	// ExternalCategory incorporates third-party breach notifications and threat intelligence
	ExternalCategory TrustScoreCategory = "external"
	// VolumeCategory assesses data volume patterns and unexpected changes
	VolumeCategory TrustScoreCategory = "volume"
	// SchemaCategory evaluates adherence to expected schema and data types
	SchemaCategory TrustScoreCategory = "schema"
	// ContentCategory analyzes semantic content for anomalies or suspicious patterns
	ContentCategory TrustScoreCategory = "content"
	// BehavioralCategory tracks broader behavior patterns across multiple dimensions
	BehavioralCategory TrustScoreCategory = "behavioral"
	// NetworkCategory evaluates network-level connection patterns and routing
	NetworkCategory TrustScoreCategory = "network"
	// ContextualCategory incorporates situational context from the broader system
	ContextualCategory TrustScoreCategory = "contextual"
)

// SeverityLevel indicates the severity of a trust score adjustment
type SeverityLevel int

const (
	// SeverityInfo is for minor, informational adjustments
	SeverityInfo SeverityLevel = iota
	// SeverityLow is for low-impact issues
	SeverityLow
	// SeverityMedium is for notable issues that merit attention
	SeverityMedium
	// SeverityHigh is for serious issues that significantly reduce trust
	SeverityHigh
	// SeverityCritical is for critical security concerns requiring immediate action
	SeverityCritical
)

// SourceTrustScore represents the trust score for a data source
type SourceTrustScore struct {
	SourceID          string                                `json:"source_id"`
	Score             int                                   `json:"score"`
	LastUpdated       time.Time                             `json:"last_updated"`
	ConsistencyScore  int                                   `json:"consistency_score"`
	TimingScore       int                                   `json:"timing_score"`
	VerificationScore int                                   `json:"verification_score"`
	ExternalScore     int                                   `json:"external_score"`
	VolumeScore       int                                   `json:"volume_score"`
	SchemaScore       int                                   `json:"schema_score"`
	ContentScore      int                                   `json:"content_score"`
	BehavioralScore   int                                   `json:"behavioral_score"`
	NetworkScore      int                                   `json:"network_score"`
	ContextualScore   int                                   `json:"contextual_score"`
	ScoreHistory      []ScoreHistory                        `json:"score_history"`
	CategoryHistory   map[TrustScoreCategory][]ScoreHistory `json:"category_history"`

	// Behavioral metrics
	FirstObserved             time.Time          `json:"first_observed"`
	TotalTransactions         int64              `json:"total_transactions"`
	SuccessfulTransactions    int64              `json:"successful_transactions"`
	FailedTransactions        int64              `json:"failed_transactions"`
	RecentActivityLevel       float64            `json:"recent_activity_level"` // 0.0-1.0 relative to baseline
	BaselineVolumeEstablished bool               `json:"baseline_volume_established"`
	BaselineVolume            map[string]float64 `json:"baseline_volume"` // daily/hourly expected volumes
	BaselinesLastUpdated      time.Time          `json:"baselines_last_updated"`

	// Pattern analysis
	AccessPatterns    map[string]PatternMetric `json:"access_patterns"`
	DetectedAnomalies []AnomalyRecord          `json:"detected_anomalies"`

	// Current state and context
	CurrentState            string    `json:"current_state"` // "normal", "warning", "probation", "restricted"
	RestrictionExpiresAt    time.Time `json:"restriction_expires_at"`
	ExemptFromAutoDowngrade bool      `json:"exempt_from_auto_downgrade"`
	TrustTier               int       `json:"trust_tier"` // 1-5, with 5 being highest trust

	// Contextual factors
	SituationalAdjustments []SituationalAdjustment `json:"situational_adjustments"`
	EnvironmentalContext   map[string]interface{}  `json:"environmental_context"` // System-wide state that affects trust
}

// PatternMetric tracks a specific access pattern
type PatternMetric struct {
	PatternType      string    `json:"pattern_type"` // e.g., "time_of_day", "request_size", "content_type", etc.
	ObservationCount int       `json:"observation_count"`
	FirstObserved    time.Time `json:"first_observed"`
	LastObserved     time.Time `json:"last_observed"`
	TypicalValues    []float64 `json:"typical_values"`    // Statistical model of expected values
	OutlierFrequency float64   `json:"outlier_frequency"` // Percentage of outliers
	RecentOutliers   int       `json:"recent_outliers"`   // Outliers in the last window
	IsEstablished    bool      `json:"is_established"`    // Whether the pattern is well-established
}

// AnomalyRecord captures details about a detected anomaly
type AnomalyRecord struct {
	Timestamp        time.Time          `json:"timestamp"`
	Category         TrustScoreCategory `json:"category"`
	Description      string             `json:"description"`
	Severity         SeverityLevel      `json:"severity"`
	AdjustmentValue  int                `json:"adjustment_value"`
	RawData          interface{}        `json:"raw_data,omitempty"`
	ConfidenceScore  float64            `json:"confidence_score"`            // 0.0-1.0 confidence in detection
	RelatedAnomalies []string           `json:"related_anomalies,omitempty"` // IDs of related anomalies
	ResolvedAt       time.Time          `json:"resolved_at,omitempty"`       // When/if this anomaly was resolved
	ResolutionNotes  string             `json:"resolution_notes,omitempty"`
}

// SituationalAdjustment represents a contextual adjustment to trust
type SituationalAdjustment struct {
	Timestamp       time.Time          `json:"timestamp"`
	Reason          string             `json:"reason"`
	AdjustmentValue int                `json:"adjustment_value"`
	ExpiresAt       time.Time          `json:"expires_at,omitempty"`
	AppliedBy       string             `json:"applied_by"` // "system" or user ID
	Category        TrustScoreCategory `json:"category"`
	Severity        SeverityLevel      `json:"severity"`
	IsActive        bool               `json:"is_active"`
}

// ScoreHistory represents a historical trust score entry
type ScoreHistory struct {
	Timestamp time.Time          `json:"timestamp"`
	Score     int                `json:"score"`
	Reason    string             `json:"reason"`
	Category  TrustScoreCategory `json:"category,omitempty"`
	Severity  SeverityLevel      `json:"severity,omitempty"`
}

// ScoreAdjustment represents an adjustment to a trust score
type ScoreAdjustment struct {
	Value      int                    `json:"value"`
	Reason     string                 `json:"reason"`
	Category   string                 `json:"category"`          // "consistency", "timing", "verification", "external", etc.
	Expiration time.Duration          `json:"expiration"`        // Zero means permanent
	Severity   SeverityLevel          `json:"severity"`          // Severity level of the adjustment
	Context    map[string]interface{} `json:"context,omitempty"` // Additional context for the adjustment
}

// SystemWideMetrics tracks system-level trust metrics
type SystemWideMetrics struct {
	GlobalThreatLevel        int                        `json:"global_threat_level"`
	LastThreatLevelChange    time.Time                  `json:"last_threat_level_change"`
	SourceDistribution       map[int]int                `json:"source_distribution"` // Map of trust tiers to count
	CategoryHealthScores     map[TrustScoreCategory]int `json:"category_health_scores"`
	RecentThreatSources      []string                   `json:"recent_threat_sources"`
	TotalSources             int                        `json:"total_sources"`
	TrustedSourcesPercentage float64                    `json:"trusted_sources_percentage"`
	SystemConsensus          float64                    `json:"system_consensus"`        // Agreement level across sources (0-1)
	PercentileDistribution   map[int]int                `json:"percentile_distribution"` // Trust score percentiles
	LastUpdated              time.Time                  `json:"last_updated"`

	// Temporal metrics
	TrustTrends           map[string][]int               `json:"trust_trends"` // Trends over time (hourly, daily)
	AnomalyRateByCategory map[TrustScoreCategory]float64 `json:"anomaly_rate_by_category"`

	// Environment factors
	EnvironmentalFactors   map[string]interface{} `json:"environmental_factors"`
	ActiveDefensivePosture string                 `json:"active_defensive_posture"` // normal, cautious, defensive, lockdown
}

// TrustScorer manages trust scores for data sources
type TrustScorer struct {
	mu                 sync.RWMutex
	scores             map[string]*SourceTrustScore
	minScore           int
	thresholdScore     int
	temporaryPenalties map[string][]temporaryPenalty

	// Advanced behavioral analysis
	behavioralPatterns  map[string]map[string]*PatternProfile // sourceID -> patternType -> profile
	baselineEstablished map[string]bool                       // sourceID -> hasBaseline

	// Adaptive thresholds
	categoryThresholds map[TrustScoreCategory]ThresholdConfig   // Different thresholds for different categories
	dynamicThresholds  bool                                     // Whether to use dynamic thresholds
	thresholdHistory   map[TrustScoreCategory][]ThresholdChange // History of threshold changes

	// System-wide context
	systemThreatLevel int                           // 1-5, with 5 being highest threat
	globalPatterns    map[string]*PatternProfile    // System-wide patterns
	recentAnomalies   []AnomalyRecord               // Recent system-wide anomalies
	trustTierCriteria map[int]TrustTierRequirements // Requirements for each trust tier (1-5)
	systemMetrics     *SystemWideMetrics            // System-wide trust metrics

	// Learning and adaptation
	learningEnabled bool    // Whether learning is enabled
	learningRate    float64 // How quickly to adapt to new patterns
	adaptationMode  string  // "conservative", "balanced", "aggressive"

	// Advanced categorization
	categoryWeights map[TrustScoreCategory]float64 // Weights for each category in overall score
	severityImpact  map[SeverityLevel]int          // Impact of each severity level

	// Integration with other systems
	anomalyEngine AnomalyEngineIntegration      // Integration with anomaly detection
	threatIntel   ThreatIntelligenceIntegration // Integration with threat intelligence
	panicSystem   PanicSystemIntegration        // Integration with the panic system

	// Metrics hooks for telemetry integration
	hooks *TrustMetricsHooks
}

type temporaryPenalty struct {
	value      int
	reason     string
	category   string
	expiration time.Time
}

// NewTrustScorer creates a new TrustScorer
func NewTrustScorer(minScore, thresholdScore int) *TrustScorer {
	ts := &TrustScorer{
		scores:             make(map[string]*SourceTrustScore),
		minScore:           minScore,
		thresholdScore:     thresholdScore,
		temporaryPenalties: make(map[string][]temporaryPenalty),

		// Initialize behavioral analysis systems
		behavioralPatterns:  make(map[string]map[string]*PatternProfile),
		baselineEstablished: make(map[string]bool),

		// Initialize adaptive thresholds
		categoryThresholds: initializeDefaultThresholds(),
		dynamicThresholds:  true,
		thresholdHistory:   make(map[TrustScoreCategory][]ThresholdChange),

		// Initialize system context
		systemThreatLevel: 1, // Start at lowest threat level
		globalPatterns:    make(map[string]*PatternProfile),
		recentAnomalies:   make([]AnomalyRecord, 0),
		trustTierCriteria: initializeDefaultTrustTiers(),

		// Learning and adaptation
		learningEnabled: true,
		learningRate:    0.05, // Conservative learning rate
		adaptationMode:  "balanced",

		// Advanced categorization
		categoryWeights: initializeDefaultCategoryWeights(),
		severityImpact:  initializeDefaultSeverityImpacts(),

		// Initialize hooks for metrics
		hooks: NewTrustMetricsHooks(),
	}

	// Initialize global patterns
	ts.initializeGlobalPatterns()

	// Initialize system-wide metrics
	ts.systemMetrics = &SystemWideMetrics{
		GlobalThreatLevel:        1,
		LastThreatLevelChange:    time.Now(),
		SourceDistribution:       make(map[int]int),
		CategoryHealthScores:     make(map[TrustScoreCategory]int),
		RecentThreatSources:      make([]string, 0),
		TotalSources:             0,
		TrustedSourcesPercentage: 100.0, // Start optimistic
		SystemConsensus:          1.0,   // Start with perfect consensus
		PercentileDistribution:   make(map[int]int),
		LastUpdated:              time.Now(),
		TrustTrends:              make(map[string][]int),
		AnomalyRateByCategory:    make(map[TrustScoreCategory]float64),
		EnvironmentalFactors:     make(map[string]interface{}),
		ActiveDefensivePosture:   "normal",
	}

	// Initialize category health scores
	for category := range ts.categoryWeights {
		ts.systemMetrics.CategoryHealthScores[category] = 100 // Start all categories at maximum health
	}

	return ts
}

// initializeDefaultThresholds sets up default threshold configurations for each category
func initializeDefaultThresholds() map[TrustScoreCategory]ThresholdConfig {
	now := time.Now()
	defaults := map[TrustScoreCategory]ThresholdConfig{
		ConsistencyCategory: {
			BaseThreshold:     3,
			MinThreshold:      1,
			MaxThreshold:      10,
			AdaptationRate:    0.1,
			IncreaseThreshold: 10,
			DecreaseThreshold: 2,
			LastUpdated:       now,
			CurrentThreshold:  3,
		},
		TimingCategory: {
			BaseThreshold:     3,
			MinThreshold:      1,
			MaxThreshold:      10,
			AdaptationRate:    0.1,
			IncreaseThreshold: 10,
			DecreaseThreshold: 2,
			LastUpdated:       now,
			CurrentThreshold:  3,
		},
		VerificationCategory: {
			BaseThreshold:     2, // More sensitive to verification failures
			MinThreshold:      1,
			MaxThreshold:      5,
			AdaptationRate:    0.05, // Slower adaptation for verification
			IncreaseThreshold: 20,   // Harder to relax verification thresholds
			DecreaseThreshold: 1,    // Quick to tighten verification thresholds
			LastUpdated:       now,
			CurrentThreshold:  2,
		},
		ExternalCategory: {
			BaseThreshold:     1, // Very sensitive to external threat intel
			MinThreshold:      1,
			MaxThreshold:      3,
			AdaptationRate:    0.02, // Very conservative adaptation
			IncreaseThreshold: 30,   // Hard to relax external intelligence thresholds
			DecreaseThreshold: 1,    // Immediate tightening for external threats
			LastUpdated:       now,
			CurrentThreshold:  1,
		},
		VolumeCategory: {
			BaseThreshold:     5,
			MinThreshold:      2,
			MaxThreshold:      15,
			AdaptationRate:    0.2, // Faster adaptation for volume (likely to vary)
			IncreaseThreshold: 8,
			DecreaseThreshold: 3,
			LastUpdated:       now,
			CurrentThreshold:  5,
		},
		SchemaCategory: {
			BaseThreshold:     3,
			MinThreshold:      1,
			MaxThreshold:      8,
			AdaptationRate:    0.08,
			IncreaseThreshold: 15,
			DecreaseThreshold: 2,
			LastUpdated:       now,
			CurrentThreshold:  3,
		},
		ContentCategory: {
			BaseThreshold:     4,
			MinThreshold:      2,
			MaxThreshold:      10,
			AdaptationRate:    0.1,
			IncreaseThreshold: 12,
			DecreaseThreshold: 2,
			LastUpdated:       now,
			CurrentThreshold:  4,
		},
		BehavioralCategory: {
			BaseThreshold:     3,
			MinThreshold:      1,
			MaxThreshold:      10,
			AdaptationRate:    0.15,
			IncreaseThreshold: 10,
			DecreaseThreshold: 2,
			LastUpdated:       now,
			CurrentThreshold:  3,
		},
		NetworkCategory: {
			BaseThreshold:     3,
			MinThreshold:      1,
			MaxThreshold:      8,
			AdaptationRate:    0.12,
			IncreaseThreshold: 12,
			DecreaseThreshold: 2,
			LastUpdated:       now,
			CurrentThreshold:  3,
		},
		ContextualCategory: {
			BaseThreshold:     2,
			MinThreshold:      1,
			MaxThreshold:      5,
			AdaptationRate:    0.1,
			IncreaseThreshold: 15,
			DecreaseThreshold: 2,
			LastUpdated:       now,
			CurrentThreshold:  2,
		},
	}

	return defaults
}

// initializeDefaultTrustTiers sets up the requirements for each trust tier
func initializeDefaultTrustTiers() map[int]TrustTierRequirements {
	return map[int]TrustTierRequirements{
		// Tier 1: Basic Trust (minimal requirements)
		1: {
			MinOverallScore: 30,
			MinCategoryScores: map[TrustScoreCategory]int{
				VerificationCategory: 20,
			},
			MinLifetime:        time.Duration(0), // No minimum lifetime
			MinTransactions:    0,                // No minimum transactions
			MaxRecentAnomalies: 5,                // Allow up to 5 anomalies
			ProhibitedAnomalies: []SeverityLevel{
				SeverityCritical, // No critical anomalies allowed
			},
		},
		// Tier 2: Standard Trust
		2: {
			MinOverallScore: 50,
			MinCategoryScores: map[TrustScoreCategory]int{
				VerificationCategory: 40,
				ConsistencyCategory:  30,
				TimingCategory:       30,
			},
			MinLifetime:        24 * time.Hour, // At least 1 day history
			MinTransactions:    100,            // At least 100 transactions
			MaxRecentAnomalies: 3,
			ProhibitedAnomalies: []SeverityLevel{
				SeverityCritical,
				SeverityHigh, // No high or critical anomalies
			},
		},
		// Tier 3: Enhanced Trust
		3: {
			MinOverallScore: 70,
			MinCategoryScores: map[TrustScoreCategory]int{
				VerificationCategory: 60,
				ConsistencyCategory:  50,
				TimingCategory:       50,
				BehavioralCategory:   40,
				ContentCategory:      40,
			},
			MinLifetime:        7 * 24 * time.Hour, // At least 1 week history
			MinTransactions:    1000,               // At least 1000 transactions
			MaxRecentAnomalies: 1,
			ProhibitedAnomalies: []SeverityLevel{
				SeverityCritical,
				SeverityHigh,
				SeverityMedium, // No medium or higher anomalies
			},
		},
		// Tier 4: High Trust
		4: {
			MinOverallScore: 85,
			MinCategoryScores: map[TrustScoreCategory]int{
				VerificationCategory: 80,
				ConsistencyCategory:  70,
				TimingCategory:       70,
				BehavioralCategory:   60,
				ContentCategory:      60,
				NetworkCategory:      60,
				SchemaCategory:       70,
			},
			MinLifetime:        30 * 24 * time.Hour, // At least 1 month history
			MinTransactions:    10000,               // At least 10,000 transactions
			MaxRecentAnomalies: 0,                   // No recent anomalies allowed
			ProhibitedAnomalies: []SeverityLevel{
				SeverityCritical,
				SeverityHigh,
				SeverityMedium,
				SeverityLow, // Only info-level anomalies allowed
			},
		},
		// Tier 5: Maximum Trust (very strict requirements)
		5: {
			MinOverallScore: 95,
			MinCategoryScores: map[TrustScoreCategory]int{
				VerificationCategory: 90,
				ConsistencyCategory:  85,
				TimingCategory:       85,
				BehavioralCategory:   80,
				ContentCategory:      80,
				NetworkCategory:      80,
				SchemaCategory:       85,
				ExternalCategory:     90,
				VolumeCategory:       85,
				ContextualCategory:   85,
			},
			MinLifetime:        90 * 24 * time.Hour, // At least 3 months history
			MinTransactions:    100000,              // At least 100,000 transactions
			MaxRecentAnomalies: 0,
			ProhibitedAnomalies: []SeverityLevel{
				SeverityCritical,
				SeverityHigh,
				SeverityMedium,
				SeverityLow,
				SeverityInfo, // No anomalies of any kind allowed
			},
			RequiredVerifications: []string{
				"human_review",
				"cryptographic",
				"external_validation",
				"continuous_monitoring",
			},
		},
	}
}

// initializeDefaultCategoryWeights sets up the weight of each category in the overall score
func initializeDefaultCategoryWeights() map[TrustScoreCategory]float64 {
	return map[TrustScoreCategory]float64{
		VerificationCategory: 0.20, // Highest weight to verification
		ConsistencyCategory:  0.15,
		TimingCategory:       0.10,
		ExternalCategory:     0.15, // Higher weight to external intelligence
		VolumeCategory:       0.05,
		SchemaCategory:       0.05,
		ContentCategory:      0.10,
		BehavioralCategory:   0.10,
		NetworkCategory:      0.05,
		ContextualCategory:   0.05,
		// Total: 1.0 (ensures weights sum to 1)
	}
}

// initializeDefaultSeverityImpacts sets up how much each severity level impacts scores
func initializeDefaultSeverityImpacts() map[SeverityLevel]int {
	return map[SeverityLevel]int{
		SeverityInfo:     -1,
		SeverityLow:      -5,
		SeverityMedium:   -15,
		SeverityHigh:     -30,
		SeverityCritical: -60, // Critical issues have severe impact
	}
}

// initializeGlobalPatterns sets up global pattern monitoring
func (ts *TrustScorer) initializeGlobalPatterns() {
	// Set up patterns for monitoring system-wide behavior
	ts.globalPatterns["hourly_ingestion_volume"] = &PatternProfile{
		PatternType:       "volume",
		Description:       "Hourly data ingestion volume across all sources",
		ObservationWindow: 24 * time.Hour,
		DataPoints:        make([]PatternDataPoint, 0),
		OutlierThreshold:  3.0, // 3 standard deviations
		LastUpdated:       time.Now(),
	}

	ts.globalPatterns["source_creation_rate"] = &PatternProfile{
		PatternType:       "registration",
		Description:       "Rate of new source registrations",
		ObservationWindow: 7 * 24 * time.Hour,
		DataPoints:        make([]PatternDataPoint, 0),
		OutlierThreshold:  2.5, // 2.5 standard deviations
		LastUpdated:       time.Now(),
	}

	ts.globalPatterns["verification_failure_rate"] = &PatternProfile{
		PatternType:       "verification",
		Description:       "Rate of verification failures across all sources",
		ObservationWindow: 24 * time.Hour,
		DataPoints:        make([]PatternDataPoint, 0),
		OutlierThreshold:  2.0, // More sensitive to verification anomalies
		LastUpdated:       time.Now(),
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

	// Create a comprehensive trust score object with all categories
	trustScore := &SourceTrustScore{
		SourceID:    sourceID,
		Score:       initialScore,
		LastUpdated: now,

		// Initialize all category scores to match the initial score to maintain consistency
		ConsistencyScore:  initialScore,
		TimingScore:       initialScore,
		VerificationScore: initialScore,
		ExternalScore:     initialScore,
		VolumeScore:       initialScore,
		SchemaScore:       initialScore,
		ContentScore:      initialScore,
		BehavioralScore:   initialScore,
		NetworkScore:      initialScore,
		ContextualScore:   initialScore,

		// Initialize history tracking
		ScoreHistory:    []ScoreHistory{{Timestamp: now, Score: initialScore, Reason: "Initial registration"}},
		CategoryHistory: make(map[TrustScoreCategory][]ScoreHistory),

		// Initialize behavioral metrics
		FirstObserved:             now,
		TotalTransactions:         0,
		SuccessfulTransactions:    0,
		FailedTransactions:        0,
		RecentActivityLevel:       0.0,
		BaselineVolumeEstablished: false,
		BaselineVolume:            make(map[string]float64),
		BaselinesLastUpdated:      now,

		// Initialize pattern analysis
		AccessPatterns:    make(map[string]PatternMetric),
		DetectedAnomalies: make([]AnomalyRecord, 0),

		// Initialize current state
		CurrentState: "normal",
		TrustTier:    1, // Start at tier 1 (lowest trust)

		// Initialize contextual factors
		SituationalAdjustments: make([]SituationalAdjustment, 0),
		EnvironmentalContext:   make(map[string]interface{}),
	}

	// Initialize category history for each category
	for _, category := range []TrustScoreCategory{
		ConsistencyCategory, TimingCategory, VerificationCategory, ExternalCategory,
		VolumeCategory, SchemaCategory, ContentCategory, BehavioralCategory,
		NetworkCategory, ContextualCategory,
	} {
		trustScore.CategoryHistory[category] = []ScoreHistory{
			{Timestamp: now, Score: initialScore, Reason: "Initial registration", Category: category},
		}
	}

	// Initialize behavioral patterns tracking for this source
	ts.behavioralPatterns[sourceID] = make(map[string]*PatternProfile)

	// Add standard pattern profiles for this source
	ts.initializeSourcePatterns(sourceID)

	// Store the trust score
	ts.scores[sourceID] = trustScore

	// Update global pattern for source creation rate
	ts.updateGlobalPattern("source_creation_rate", 1.0)

	log.Info().
		Str("source_id", sourceID).
		Int("initial_score", initialScore).
		Msg("Registered new data source with enhanced trust scoring")

	return nil
}

// initializeSourcePatterns sets up behavioral pattern tracking for a specific source
func (ts *TrustScorer) initializeSourcePatterns(sourceID string) {
	now := time.Now()

	// Volume patterns
	ts.behavioralPatterns[sourceID]["hourly_volume"] = &PatternProfile{
		PatternType:       "volume",
		Description:       "Hourly data volume for source",
		ObservationWindow: 24 * time.Hour,
		DataPoints:        make([]PatternDataPoint, 0),
		OutlierThreshold:  3.0,
		LastUpdated:       now,
	}

	ts.behavioralPatterns[sourceID]["daily_volume"] = &PatternProfile{
		PatternType:       "volume",
		Description:       "Daily data volume for source",
		ObservationWindow: 7 * 24 * time.Hour,
		DataPoints:        make([]PatternDataPoint, 0),
		OutlierThreshold:  3.0,
		LastUpdated:       now,
	}

	// Timing patterns
	ts.behavioralPatterns[sourceID]["submission_timing"] = &PatternProfile{
		PatternType:       "timing",
		Description:       "Temporal pattern of submissions",
		ObservationWindow: 7 * 24 * time.Hour,
		DataPoints:        make([]PatternDataPoint, 0),
		OutlierThreshold:  2.5,
		LastUpdated:       now,
	}

	// Schema/content patterns
	ts.behavioralPatterns[sourceID]["schema_consistency"] = &PatternProfile{
		PatternType:       "schema",
		Description:       "Schema consistency over time",
		ObservationWindow: 30 * 24 * time.Hour,
		DataPoints:        make([]PatternDataPoint, 0),
		OutlierThreshold:  2.0,
		LastUpdated:       now,
	}

	// Verification patterns
	ts.behavioralPatterns[sourceID]["verification_success"] = &PatternProfile{
		PatternType:       "verification",
		Description:       "Verification success rate",
		ObservationWindow: 30 * 24 * time.Hour,
		DataPoints:        make([]PatternDataPoint, 0),
		OutlierThreshold:  1.5, // More sensitive to verification issues
		LastUpdated:       now,
	}
}

// updateGlobalPattern adds a data point to a global pattern tracking
func (ts *TrustScorer) updateGlobalPattern(patternKey string, value float64) {
	pattern, exists := ts.globalPatterns[patternKey]
	if !exists {
		return
	}

	// Add the data point
	dataPoint := PatternDataPoint{
		Timestamp: time.Now(),
		Value:     value,
		IsOutlier: false, // Determined during analysis
	}

	pattern.DataPoints = append(pattern.DataPoints, dataPoint)
	pattern.LastUpdated = time.Now()

	// Keep pattern data points within the observation window
	ts.prunePatternDataPoints(pattern)
}

// prunePatternDataPoints removes data points outside the observation window
func (ts *TrustScorer) prunePatternDataPoints(pattern *PatternProfile) {
	cutoff := time.Now().Add(-pattern.ObservationWindow)
	newPoints := make([]PatternDataPoint, 0, len(pattern.DataPoints))

	for _, point := range pattern.DataPoints {
		if point.Timestamp.After(cutoff) {
			newPoints = append(newPoints, point)
		}
	}

	pattern.DataPoints = newPoints
}

// UpdateScore applies an adjustment to a data source's trust score
func (ts *TrustScorer) UpdateScore(sourceID string, adjustment ScoreAdjustment) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	log.Debug().
		Str("source_id", sourceID).
		Int("adjustment_value", adjustment.Value).
		Str("category", adjustment.Category).
		Str("reason", adjustment.Reason).
		Int("severity", int(adjustment.Severity)).
		Msg("UpdateScore called")

	// Get the source's trust score
	score, exists := ts.scores[sourceID]
	if !exists {
		// If the source doesn't exist, register it
		log.Debug().Str("source_id", sourceID).Msg("Source not found, registering new source")
		ts.mu.Unlock()
		if err := ts.RegisterSource(sourceID, 100); err != nil {
			return err
		}
		ts.mu.Lock()
		score = ts.scores[sourceID]
	}

	// Get the category
	category := ts.getCategoryFromString(adjustment.Category)

	// Store the previous score for metrics
	previousScore := score.Score
	previousCategoryScore := ts.getCategoryScore(score, category)

	log.Debug().
		Str("source_id", sourceID).
		Int("previous_score", previousScore).
		Str("category", string(category)).
		Int("previous_category_score", previousCategoryScore).
		Msg("Before adjustment")

	// Apply adjustment
	var newCategoryScore int
	if adjustment.Value != 0 {
		// Always apply the adjustment directly to ensure it has an effect
		adjustmentValue := adjustment.Value

		// If severity impact is provided, we can scale the adjustment
		// but we'll always ensure some adjustment is made even if small
		if adjustment.Severity != 0 {
			severityImpact := ts.adjustSeverityImpact(adjustment.Severity)
			// Use at least 50% of the original adjustment even if scaling would reduce it further
			scaledValue := adjustment.Value * severityImpact / 100
			if adjustment.Value < 0 {
				// For negative adjustments, take the more negative value (the smaller one)
				if scaledValue < adjustment.Value {
					adjustmentValue = scaledValue
				} else {
					adjustmentValue = adjustment.Value
				}
			} else {
				// For positive adjustments, take the more positive value (the larger one)
				if scaledValue > adjustment.Value {
					adjustmentValue = scaledValue
				} else {
					adjustmentValue = adjustment.Value
				}
			}
		}

		log.Debug().
			Str("source_id", sourceID).
			Int("original_adjustment", adjustment.Value).
			Int("final_adjustment", adjustmentValue).
			Int("severity_impact", ts.adjustSeverityImpact(adjustment.Severity)).
			Str("category", string(category)).
			Msg("Adjustment value calculated")

		// Apply the adjustment to the category
		newCategoryScore = ts.applyCategoryAdjustment(score, category, adjustmentValue)

		// Track adjustment in patterns for anomaly detection
		if len(adjustment.Context) > 0 {
			ts.trackAdjustmentInPatterns(sourceID, category, adjustment.Value, adjustment.Context)
		}

		// Record in history
		score.ScoreHistory = append(score.ScoreHistory, ScoreHistory{
			Timestamp: time.Now(),
			Score:     score.Score,
			Reason:    adjustment.Reason,
			Category:  category,
			Severity:  adjustment.Severity,
		})

		// Record in category history
		if _, ok := score.CategoryHistory[category]; !ok {
			score.CategoryHistory[category] = make([]ScoreHistory, 0)
		}
		score.CategoryHistory[category] = append(score.CategoryHistory[category], ScoreHistory{
			Timestamp: time.Now(),
			Score:     newCategoryScore,
			Reason:    adjustment.Reason,
			Category:  category,
			Severity:  adjustment.Severity,
		})

		// Prune history if too long
		if len(score.ScoreHistory) > 100 {
			score.ScoreHistory = score.ScoreHistory[len(score.ScoreHistory)-100:]
		}
		if len(score.CategoryHistory[category]) > 50 {
			score.CategoryHistory[category] = score.CategoryHistory[category][len(score.CategoryHistory[category])-50:]
		}
	}

	// Add temporary penalty if expiration is set
	if adjustment.Expiration > 0 {
		penalty := temporaryPenalty{
			value:      adjustment.Value,
			reason:     adjustment.Reason,
			category:   string(category),
			expiration: time.Now().Add(adjustment.Expiration),
		}

		ts.temporaryPenalties[sourceID] = append(ts.temporaryPenalties[sourceID], penalty)
		log.Debug().
			Str("source_id", sourceID).
			Int("value", adjustment.Value).
			Str("category", string(category)).
			Time("expiration", penalty.expiration).
			Msg("Added temporary penalty")
	}

	// Recalculate overall score
	log.Debug().Str("source_id", sourceID).Msg("Recalculating overall score")
	ts.recalculateScore(sourceID)

	// Get updated scores after recalculation
	currentScore := score.Score
	currentCategoryScore := ts.getCategoryScore(score, category)

	log.Debug().
		Str("source_id", sourceID).
		Int("previous_score", previousScore).
		Int("current_score", currentScore).
		Int("previous_cat_score", previousCategoryScore).
		Int("current_cat_score", currentCategoryScore).
		Str("category", string(category)).
		Msg("Score adjustment complete")

	// Check if trust tier changed and notify hooks
	oldTier := score.TrustTier
	newTier := ts.calculateTrustTier(sourceID)

	if newTier != oldTier {
		score.TrustTier = newTier
		// Notify metrics hooks about tier change
		if ts.hooks != nil {
			ts.hooks.NotifyTrustTierChange(sourceID, newTier, oldTier)
		}
	}

	// Notify metrics hooks about score change
	if ts.hooks != nil {
		ts.hooks.NotifyScoreChange(sourceID, score.Score, previousScore)
	}

	// Create an anomaly record if it's a negative adjustment with high severity
	if adjustment.Value < 0 && (adjustment.Severity == SeverityHigh || adjustment.Severity == SeverityCritical) {
		anomalyRecord := AnomalyRecord{
			Timestamp:       time.Now(),
			Category:        category,
			Description:     adjustment.Reason,
			Severity:        adjustment.Severity,
			AdjustmentValue: adjustment.Value,
			ConfidenceScore: 1.0, // Direct adjustment = high confidence
		}

		// Add anomaly to source
		score.DetectedAnomalies = append(score.DetectedAnomalies, anomalyRecord)

		// Notify metrics hooks about anomaly
		if ts.hooks != nil {
			ts.hooks.NotifyAnomalyDetected(sourceID, category, adjustment.Severity)
		}

		// If it's a critical severity, update system-wide metrics too
		if adjustment.Severity == SeverityCritical {
			ts.recentAnomalies = append(ts.recentAnomalies, anomalyRecord)
			if len(ts.recentAnomalies) > 100 {
				ts.recentAnomalies = ts.recentAnomalies[len(ts.recentAnomalies)-100:]
			}
		}
	}

	return nil
}

// getCategoryFromString converts a string category to TrustScoreCategory
func (ts *TrustScorer) getCategoryFromString(category string) TrustScoreCategory {
	switch category {
	case "consistency":
		return ConsistencyCategory
	case "timing":
		return TimingCategory
	case "verification":
		return VerificationCategory
	case "external":
		return ExternalCategory
	case "volume":
		return VolumeCategory
	case "schema":
		return SchemaCategory
	case "content":
		return ContentCategory
	case "behavioral":
		return BehavioralCategory
	case "network":
		return NetworkCategory
	case "contextual":
		return ContextualCategory
	default:
		// Default to consistency if not recognized
		return ConsistencyCategory
	}
}

// severityToString converts a SeverityLevel to its string representation
func severityToString(severity SeverityLevel) string {
	switch severity {
	case SeverityInfo:
		return "info"
	case SeverityLow:
		return "low"
	case SeverityMedium:
		return "medium"
	case SeverityHigh:
		return "high"
	case SeverityCritical:
		return "critical"
	default:
		return "unknown"
	}
}

// trackAdjustmentInPatterns records an adjustment in relevant pattern profiles
func (ts *TrustScorer) trackAdjustmentInPatterns(sourceID string, category TrustScoreCategory, value int, context map[string]interface{}) {
	// Skip if no patterns are being tracked for this source
	patterns, exists := ts.behavioralPatterns[sourceID]
	if !exists {
		return
	}

	// Find the relevant pattern based on the category
	var patternKey string
	switch category {
	case VolumeCategory:
		patternKey = "hourly_volume"
	case TimingCategory:
		patternKey = "submission_timing"
	case SchemaCategory:
		patternKey = "schema_consistency"
	case VerificationCategory:
		patternKey = "verification_success"
	default:
		// Use default pattern if no specific match
		patternKey = "hourly_volume"
	}

	// If we have this pattern, update it
	if pattern, exists := patterns[patternKey]; exists {
		// Determine the value to record based on context and category
		dataValue := float64(value)

		// For some categories, use values from context if available
		if category == VolumeCategory && context != nil {
			if volumeValue, ok := context["volume"].(float64); ok {
				dataValue = volumeValue
			}
		}

		// Add the data point to the pattern
		dataPoint := PatternDataPoint{
			Timestamp: time.Now(),
			Value:     dataValue,
			IsOutlier: false, // Outlier status determined by analysis
		}

		// Add the data point
		pattern.DataPoints = append(pattern.DataPoints, dataPoint)
		pattern.LastUpdated = time.Now()

		// Keep pattern data points within the observation window
		ts.prunePatternDataPoints(pattern)

		// Analyze the pattern for anomalies
		ts.analyzePattern(sourceID, patternKey, pattern)
	}
}

// analyzePattern performs statistical analysis on a pattern to detect anomalies
func (ts *TrustScorer) analyzePattern(sourceID string, patternKey string, pattern *PatternProfile) {
	// Need enough data points for meaningful analysis
	if len(pattern.DataPoints) < 10 {
		return
	}

	// Calculate mean and standard deviation
	var sum, sumSquares float64
	for _, point := range pattern.DataPoints {
		sum += point.Value
		sumSquares += point.Value * point.Value
	}

	count := float64(len(pattern.DataPoints))
	mean := sum / count
	variance := (sumSquares / count) - (mean * mean)
	stdDev := math.Sqrt(variance)

	// Update pattern statistics
	pattern.Mean = mean
	pattern.StdDev = stdDev

	// Calculate percentiles
	values := make([]float64, len(pattern.DataPoints))
	for i, point := range pattern.DataPoints {
		values[i] = point.Value
	}

	// Sort values for percentile calculation
	// In a real implementation, we'd use a more efficient algorithm for large datasets
	// For simplicity, we're sorting the full array here
	sort.Float64s(values)

	// Calculate percentiles
	pattern.Percentiles = make(map[int]float64)
	pattern.Percentiles[50] = values[int(count*0.5)]  // Median
	pattern.Percentiles[90] = values[int(count*0.9)]  // 90th percentile
	pattern.Percentiles[95] = values[int(count*0.95)] // 95th percentile
	pattern.Percentiles[99] = values[int(count*0.99)] // 99th percentile

	// Mark outliers
	outliersCount := 0
	for i := range pattern.DataPoints {
		// Calculate z-score
		zScore := math.Abs(pattern.DataPoints[i].Value-mean) / stdDev
		pattern.DataPoints[i].IsOutlier = zScore > pattern.OutlierThreshold

		if pattern.DataPoints[i].IsOutlier {
			outliersCount++
		}
	}

	// If we've found outliers, calculate outlier percentage
	outliersPercent := 0.0
	if len(pattern.DataPoints) > 0 {
		outliersPercent = float64(outliersCount) / float64(len(pattern.DataPoints)) * 100.0
	}

	// If we find a significant percentage of outliers, record an anomaly
	if outliersPercent > 10.0 { // More than 10% outliers
		ts.recordPatternAnomaly(sourceID, pattern, patternKey, outliersPercent)
	}

	// Mark pattern as established after enough data points
	if !pattern.EstablishedAt.IsZero() && len(pattern.DataPoints) >= 30 {
		pattern.EstablishedAt = time.Now()
	}

	log.Debug().
		Str("source_id", sourceID).
		Str("pattern", patternKey).
		Float64("mean", mean).
		Float64("std_dev", stdDev).
		Int("outliers", outliersCount).
		Float64("outlier_pct", outliersPercent).
		Int("data_points", len(pattern.DataPoints)).
		Msg("Analyzed pattern profile")
}

// recordPatternAnomaly creates an anomaly record based on pattern analysis
func (ts *TrustScorer) recordPatternAnomaly(sourceID string, pattern *PatternProfile, patternKey string, outliersPercent float64) {
	score, exists := ts.scores[sourceID]
	if !exists {
		return
	}

	// Determine category and severity based on pattern type
	category := ts.getCategoryFromPatternType(pattern.PatternType)

	// Determine severity based on outlier percentage
	severity := SeverityLow
	if outliersPercent > 50.0 {
		severity = SeverityCritical
	} else if outliersPercent > 30.0 {
		severity = SeverityHigh
	} else if outliersPercent > 20.0 {
		severity = SeverityMedium
	}

	// Create anomaly record
	anomaly := AnomalyRecord{
		Timestamp:       time.Now(),
		Category:        category,
		Description:     fmt.Sprintf("Anomalous pattern detected: %s (%.2f%% outliers)", pattern.Description, outliersPercent),
		Severity:        severity,
		AdjustmentValue: -int(math.Min(30, math.Ceil(outliersPercent/2.0))), // -1 to -30 based on percentage
		ConfidenceScore: math.Min(0.95, outliersPercent/100.0+0.5),          // 0.5 to 0.95 confidence
		RawData: map[string]interface{}{
			"pattern_type":    pattern.PatternType,
			"outlier_percent": outliersPercent,
			"mean":            pattern.Mean,
			"std_dev":         pattern.StdDev,
			"total_points":    len(pattern.DataPoints),
		},
	}

	// Add to source anomalies
	score.DetectedAnomalies = append(score.DetectedAnomalies, anomaly)

	// Keep anomalies list bounded
	if len(score.DetectedAnomalies) > 50 {
		score.DetectedAnomalies = score.DetectedAnomalies[len(score.DetectedAnomalies)-50:]
	}

	// Add to system-wide anomalies
	ts.recentAnomalies = append(ts.recentAnomalies, anomaly)

	// Keep recent anomalies list bounded
	if len(ts.recentAnomalies) > 100 {
		ts.recentAnomalies = ts.recentAnomalies[len(ts.recentAnomalies)-100:]
	}

	// Apply an adjustment to the appropriate category score
	ts.applyCategoryAdjustment(score, category, anomaly.AdjustmentValue)

	// Adjust trust tier if necessary
	previousTier := score.TrustTier
	newTier := ts.calculateTrustTier(sourceID)
	if previousTier != newTier {
		score.TrustTier = newTier
		log.Info().
			Str("source_id", sourceID).
			Int("previous_tier", previousTier).
			Int("new_tier", newTier).
			Msg("Source trust tier changed")
	}

	// If we have an anomaly engine integration, report it
	if ts.anomalyEngine != nil {
		go func() {
			if err := ts.anomalyEngine.ReportAnomaly(
				sourceID,
				category,
				severity,
				anomaly.RawData.(map[string]interface{}),
			); err != nil {
				log.Error().Err(err).Msg("Failed to report pattern anomaly to engine")
			}
		}()
	}

	// If we have a panic system integration and this is critical, notify
	if severity == SeverityCritical && ts.panicSystem != nil {
		go func() {
			if err := ts.panicSystem.NotifyTrustThresholdViolation(
				sourceID,
				score.Score,
				anomaly.Description,
			); err != nil {
				log.Error().Err(err).Msg("Failed to notify panic system about pattern anomaly")
			}
		}()
	}

	log.Warn().
		Str("source_id", sourceID).
		Str("pattern", patternKey).
		Str("category", string(category)).
		Str("severity", severityToString(severity)).
		Float64("outlier_percent", outliersPercent).
		Float64("confidence", anomaly.ConfidenceScore).
		Int("adjustment", anomaly.AdjustmentValue).
		Msg("Pattern anomaly detected")
}

// getCategoryFromPatternType determines which category a pattern belongs to
func (ts *TrustScorer) getCategoryFromPatternType(patternType string) TrustScoreCategory {
	switch patternType {
	case "volume":
		return VolumeCategory
	case "timing":
		return TimingCategory
	case "schema":
		return SchemaCategory
	case "verification":
		return VerificationCategory
	case "registration":
		return ContextualCategory
	default:
		return BehavioralCategory
	}
}

// applyCategoryAdjustment adjusts a specific category score
func (ts *TrustScorer) applyCategoryAdjustment(score *SourceTrustScore, category TrustScoreCategory, value int) int {
	// Log the adjustment for debugging
	log.Debug().
		Str("source_id", score.SourceID).
		Str("category", string(category)).
		Int("original_value", value).
		Int("current_category_score", ts.getCategoryScore(score, category)).
		Msg("Applying category adjustment")

	// Apply the adjustment to the specified category
	switch category {
	case ConsistencyCategory:
		oldScore := score.ConsistencyScore
		score.ConsistencyScore = clampScore(score.ConsistencyScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.ConsistencyScore).Msg("Updated ConsistencyScore")
	case TimingCategory:
		oldScore := score.TimingScore
		score.TimingScore = clampScore(score.TimingScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.TimingScore).Msg("Updated TimingScore")
	case VerificationCategory:
		oldScore := score.VerificationScore
		score.VerificationScore = clampScore(score.VerificationScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.VerificationScore).Msg("Updated VerificationScore")
	case ExternalCategory:
		oldScore := score.ExternalScore
		score.ExternalScore = clampScore(score.ExternalScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.ExternalScore).Msg("Updated ExternalScore")
	case VolumeCategory:
		oldScore := score.VolumeScore
		score.VolumeScore = clampScore(score.VolumeScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.VolumeScore).Msg("Updated VolumeScore")
	case SchemaCategory:
		oldScore := score.SchemaScore
		score.SchemaScore = clampScore(score.SchemaScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.SchemaScore).Msg("Updated SchemaScore")
	case ContentCategory:
		oldScore := score.ContentScore
		score.ContentScore = clampScore(score.ContentScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.ContentScore).Msg("Updated ContentScore")
	case BehavioralCategory:
		oldScore := score.BehavioralScore
		score.BehavioralScore = clampScore(score.BehavioralScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.BehavioralScore).Msg("Updated BehavioralScore")
	case NetworkCategory:
		oldScore := score.NetworkScore
		score.NetworkScore = clampScore(score.NetworkScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.NetworkScore).Msg("Updated NetworkScore")
	case ContextualCategory:
		oldScore := score.ContextualScore
		score.ContextualScore = clampScore(score.ContextualScore + value)
		log.Debug().Int("from", oldScore).Int("to", score.ContextualScore).Msg("Updated ContextualScore")
	}

	// Force update the score's last updated timestamp
	score.LastUpdated = time.Now()

	// Return the new category score
	newScore := ts.getCategoryScore(score, category)
	log.Debug().Int("final_category_score", newScore).Msg("New category score calculated")
	return newScore
}

// getCategoryScore gets the current score for a specific category
func (ts *TrustScorer) getCategoryScore(score *SourceTrustScore, category TrustScoreCategory) int {
	switch category {
	case ConsistencyCategory:
		return score.ConsistencyScore
	case TimingCategory:
		return score.TimingScore
	case VerificationCategory:
		return score.VerificationScore
	case ExternalCategory:
		return score.ExternalScore
	case VolumeCategory:
		return score.VolumeScore
	case SchemaCategory:
		return score.SchemaScore
	case ContentCategory:
		return score.ContentScore
	case BehavioralCategory:
		return score.BehavioralScore
	case NetworkCategory:
		return score.NetworkScore
	case ContextualCategory:
		return score.ContextualScore
	default:
		return 0
	}
}

// recalculateScore recalculates the overall score with weighted categories and temporary penalties
func (ts *TrustScorer) recalculateScore(sourceID string) {
	score, exists := ts.scores[sourceID]
	if !exists {
		log.Error().Str("source_id", sourceID).Msg("Attempted to recalculate score for non-existent source")
		return
	}

	log.Debug().
		Str("source_id", sourceID).
		Int("before_score", score.Score).
		Int("consistency", score.ConsistencyScore).
		Int("verification", score.VerificationScore).
		Int("timing", score.TimingScore).
		Int("external", score.ExternalScore).
		Msg("Recalculating score for source")

	// Start with weighted average of component scores
	weightedSum := 0.0
	totalWeight := 0.0

	// Add each category with its weight
	weights := ts.categoryWeights
	weightedSum += float64(score.ConsistencyScore) * weights[ConsistencyCategory]
	totalWeight += weights[ConsistencyCategory]

	weightedSum += float64(score.TimingScore) * weights[TimingCategory]
	totalWeight += weights[TimingCategory]

	weightedSum += float64(score.VerificationScore) * weights[VerificationCategory]
	totalWeight += weights[VerificationCategory]

	weightedSum += float64(score.ExternalScore) * weights[ExternalCategory]
	totalWeight += weights[ExternalCategory]

	weightedSum += float64(score.VolumeScore) * weights[VolumeCategory]
	totalWeight += weights[VolumeCategory]

	weightedSum += float64(score.SchemaScore) * weights[SchemaCategory]
	totalWeight += weights[SchemaCategory]

	weightedSum += float64(score.ContentScore) * weights[ContentCategory]
	totalWeight += weights[ContentCategory]

	weightedSum += float64(score.BehavioralScore) * weights[BehavioralCategory]
	totalWeight += weights[BehavioralCategory]

	weightedSum += float64(score.NetworkScore) * weights[NetworkCategory]
	totalWeight += weights[NetworkCategory]

	weightedSum += float64(score.ContextualScore) * weights[ContextualCategory]
	totalWeight += weights[ContextualCategory]

	// Calculate weighted average
	baseScore := 50 // default to neutral score
	if totalWeight > 0 {
		baseScore = int(weightedSum / totalWeight)
	}

	log.Debug().
		Str("source_id", sourceID).
		Float64("weighted_sum", weightedSum).
		Float64("total_weight", totalWeight).
		Int("base_score", baseScore).
		Msg("Calculated weighted score")

	// Apply temporary penalties
	tempPenalty := 0
	now := time.Now()
	activeIdx := 0

	penalties := ts.temporaryPenalties[sourceID]

	for i := range penalties {
		if penalties[i].expiration.After(now) {
			// Keep this penalty as it's still active
			if i != activeIdx {
				penalties[activeIdx] = penalties[i]
			}
			tempPenalty += penalties[i].value
			activeIdx++
		}
	}

	if activeIdx < len(penalties) {
		// Truncate the slice to remove expired penalties
		ts.temporaryPenalties[sourceID] = penalties[:activeIdx]
	}

	// Apply situational adjustments
	situationalPenalty := 0
	activeSituationalIdx := 0

	for i := range score.SituationalAdjustments {
		adjustment := &score.SituationalAdjustments[i]

		// Skip if already inactive
		if !adjustment.IsActive {
			continue
		}

		// Check if expired
		if !adjustment.ExpiresAt.IsZero() && adjustment.ExpiresAt.Before(now) {
			adjustment.IsActive = false
			continue
		}

		// Keep this adjustment as it's still active
		situationalPenalty += adjustment.AdjustmentValue

		if i != activeSituationalIdx {
			score.SituationalAdjustments[activeSituationalIdx] = *adjustment
		}
		activeSituationalIdx++
	}

	if activeSituationalIdx < len(score.SituationalAdjustments) {
		// Truncate the slice to remove inactive adjustments
		score.SituationalAdjustments = score.SituationalAdjustments[:activeSituationalIdx]
	}

	// Apply system threat level adjustment
	threatLevelPenalty := 0
	if ts.systemThreatLevel > 1 {
		// Higher threat levels reduce trust scores system-wide
		threatLevelPenalty = -5 * (ts.systemThreatLevel - 1)
	}

	// Check current global threat level from threat intelligence if available
	if ts.threatIntel != nil {
		globalThreatLevel, err := ts.threatIntel.GetGlobalThreatLevel()
		if err == nil && globalThreatLevel > ts.systemThreatLevel {
			// Use the higher threat level between system and global
			threatLevelPenalty = -5 * (globalThreatLevel - 1)

			// Update system threat level if global is higher
			if globalThreatLevel > ts.systemThreatLevel {
				oldLevel := ts.systemThreatLevel
				ts.systemThreatLevel = globalThreatLevel

				log.Info().
					Int("previous_level", oldLevel).
					Int("new_level", ts.systemThreatLevel).
					Msg("System threat level increased based on threat intelligence")
			}
		}
	}

	// Calculate final score
	finalScore := baseScore + tempPenalty + situationalPenalty + threatLevelPenalty

	log.Debug().
		Str("source_id", sourceID).
		Int("base_score", baseScore).
		Int("temp_penalty", tempPenalty).
		Int("situational", situationalPenalty).
		Int("threat_level", threatLevelPenalty).
		Int("final_score", finalScore).
		Msg("Score components calculated")

	// Save the old score for comparison
	oldScore := score.Score

	// Clamp to valid range
	score.Score = clampScore(finalScore)
	score.LastUpdated = now

	// Log the score change
	if oldScore != score.Score {
		log.Debug().
			Str("source_id", sourceID).
			Int("old_score", oldScore).
			Int("new_score", score.Score).
			Msg("Source trust score changed")
	}
}

// calculateTrustTier determines what trust tier a source qualifies for
func (ts *TrustScorer) calculateTrustTier(sourceID string) int {
	score, exists := ts.scores[sourceID]
	if !exists {
		return 1 // Default to lowest tier
	}

	// Start from highest tier and work down
	for tier := 5; tier > 0; tier-- {
		criteria, exists := ts.trustTierCriteria[tier]
		if !exists {
			continue
		}

		// Check if source meets all requirements for this tier
		if ts.meetsTierRequirements(score, criteria) {
			return tier
		}
	}

	// If no tier requirements met, return lowest tier
	return 1
}

// meetsTierRequirements checks if a source meets all requirements for a trust tier
func (ts *TrustScorer) meetsTierRequirements(score *SourceTrustScore, criteria TrustTierRequirements) bool {
	// Check overall score requirement
	if score.Score < criteria.MinOverallScore {
		return false
	}

	// Check individual category score requirements
	for category, minScore := range criteria.MinCategoryScores {
		if ts.getCategoryScore(score, category) < minScore {
			return false
		}
	}

	// Check lifetime requirement
	lifetime := time.Since(score.FirstObserved)
	if lifetime < criteria.MinLifetime {
		return false
	}

	// Check transactions requirement
	if score.TotalTransactions < int64(criteria.MinTransactions) {
		return false
	}

	// Check recent anomalies
	recentAnomalyCount := 0
	// Count anomalies in the last 24 hours
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, anomaly := range score.DetectedAnomalies {
		if anomaly.Timestamp.After(cutoff) {
			recentAnomalyCount++

			// Check for prohibited severity levels
			for _, prohibited := range criteria.ProhibitedAnomalies {
				if anomaly.Severity == prohibited {
					return false // Has a prohibited anomaly severity
				}
			}
		}
	}

	if recentAnomalyCount > criteria.MaxRecentAnomalies {
		return false
	}

	// Check required verifications
	// This would involve checking if the source has undergone specific verification processes
	// We're simplifying this check here

	// If all checks pass, the source meets the requirements for this tier
	return true
}

// PatternProfile represents a behavioral pattern for analysis
type PatternProfile struct {
	PatternType       string             // Type of pattern (e.g., "volume", "timing")
	Description       string             // Human-readable description
	ObservationWindow time.Duration      // How far back to consider data points
	DataPoints        []PatternDataPoint // Historical data points
	OutlierThreshold  float64            // Number of std devs to be considered an outlier
	LastUpdated       time.Time          // Last time the pattern was updated
	EstablishedAt     time.Time          // When the pattern was considered established
	Mean              float64            // Statistical mean
	StdDev            float64            // Standard deviation
	Percentiles       map[int]float64    // Key percentiles (50, 90, 95, 99)
}

// PatternDataPoint represents a single observation in a pattern
type PatternDataPoint struct {
	Timestamp time.Time              // When the observation was made
	Value     float64                // Observed value
	IsOutlier bool                   // Whether this point is an outlier
	Context   map[string]interface{} // Additional contextual information
}

// ThresholdConfig controls adaptive thresholds for anomaly detection
type ThresholdConfig struct {
	BaseThreshold     float64   // Starting threshold
	MinThreshold      float64   // Minimum allowed threshold
	MaxThreshold      float64   // Maximum allowed threshold
	AdaptationRate    float64   // How quickly threshold adapts (0-1)
	IncreaseThreshold int       // Number of normal observations before relaxing threshold
	DecreaseThreshold int       // Number of anomalies before tightening threshold
	LastUpdated       time.Time // When threshold was last adjusted
	CurrentThreshold  float64   // Current active threshold
}

// ThresholdChange tracks a change to a threshold configuration
type ThresholdChange struct {
	Timestamp       time.Time
	Category        TrustScoreCategory
	PreviousValue   float64
	NewValue        float64
	Reason          string
	AnomalyTriggers int // Number of anomalies that triggered this change
}

// TrustTierRequirements defines the criteria for each trust tier level
type TrustTierRequirements struct {
	MinOverallScore       int                        // Minimum overall trust score required
	MinCategoryScores     map[TrustScoreCategory]int // Minimum scores for specific categories
	MinLifetime           time.Duration              // Minimum time since first observation
	MinTransactions       int                        // Minimum number of successful transactions
	MaxRecentAnomalies    int                        // Maximum number of recent anomalies allowed
	ProhibitedAnomalies   []SeverityLevel            // Anomaly severities not allowed at this tier
	RequiredVerifications []string                   // Verification types required for this tier
}

// clampScore ensures a score is within the valid range (0-100)
func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}

// GetScore returns the trust score for a source
func (ts *TrustScorer) GetScore(sourceID string) (*SourceTrustScore, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	score, exists := ts.scores[sourceID]
	if !exists {
		return nil, fmt.Errorf("source not found: %s", sourceID)
	}

	// Return the reference directly since tests and transaction counters depend on direct updates
	return score, nil
}

// IsTrusted checks if a source's trust score is above the threshold
func (ts *TrustScorer) IsTrusted(sourceID string) (bool, error) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	score, exists := ts.scores[sourceID]
	if !exists {
		return false, fmt.Errorf("source not found: %s", sourceID)
	}

	// A source is trusted if its score is at or above the threshold
	return score.Score >= ts.thresholdScore, nil
}

// SetThreatIntelligence sets the threat intelligence integration
func (ts *TrustScorer) SetThreatIntelligence(threatIntel ThreatIntelligenceIntegration) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.threatIntel = threatIntel
}

// CheckThreatIntelligence checks a source against threat intelligence
// and applies appropriate trust adjustments if suspicious activity is found
func (ts *TrustScorer) CheckThreatIntelligence(sourceID string, identifiers map[string]string) error {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	if ts.threatIntel == nil {
		return fmt.Errorf("threat intelligence integration not configured")
	}

	score, exists := ts.scores[sourceID]
	if !exists {
		return fmt.Errorf("source not found: %s", sourceID)
	}

	// Check source against threat intelligence
	suspicious, details, err := ts.threatIntel.CheckSource(sourceID, identifiers)
	if err != nil {
		log.Warn().
			Err(err).
			Str("source_id", sourceID).
			Msg("Failed to check source against threat intelligence")
		return err
	}

	if suspicious {
		// Determine confidence and severity
		confidence := 0.7 // Default confidence
		if conf, ok := details["confidence"].(float64); ok {
			confidence = conf
		}

		severity := SeverityHigh // Default to high severity for threat intel hits
		if confidenceLevel, ok := details["confidence_level"].(string); ok {
			switch confidenceLevel {
			case "low":
				severity = SeverityLow
			case "medium":
				severity = SeverityMedium
			case "high":
				severity = SeverityHigh
			case "critical":
				severity = SeverityCritical
			}
		}

		// Calculate adjustment based on severity and confidence
		adjustment := -10
		if severity == SeverityCritical {
			adjustment = -50
		} else if severity == SeverityHigh {
			adjustment = -30
		} else if severity == SeverityMedium {
			adjustment = -20
		} else if severity == SeverityLow {
			adjustment = -10
		}

		// Adjust based on confidence
		adjustment = int(float64(adjustment) * confidence)

		// Apply to external category
		ts.applyCategoryAdjustment(score, ExternalCategory, adjustment)

		// Record anomaly
		anomaly := AnomalyRecord{
			Timestamp:       time.Now(),
			Category:        ExternalCategory,
			Description:     "Source flagged by threat intelligence",
			Severity:        severity,
			AdjustmentValue: adjustment,
			ConfidenceScore: confidence,
			RawData:         details,
		}

		// Add to source anomalies
		score.DetectedAnomalies = append(score.DetectedAnomalies, anomaly)

		// Add to overall score history
		score.ScoreHistory = append(score.ScoreHistory, ScoreHistory{
			Timestamp: time.Now(),
			Score:     score.Score,
			Reason:    "Flagged by threat intelligence",
			Category:  ExternalCategory,
			Severity:  severity,
		})

		// Keep history bounded
		if len(score.ScoreHistory) > 100 {
			score.ScoreHistory = score.ScoreHistory[len(score.ScoreHistory)-100:]
		}

		// Register for continuous monitoring
		_ = ts.threatIntel.RegisterSourceForMonitoring(sourceID, identifiers)

		// Recalculate overall score
		ts.recalculateScore(sourceID)

		log.Warn().
			Str("source_id", sourceID).
			Str("severity", severityToString(severity)).
			Float64("confidence", confidence).
			Int("adjustment", adjustment).
			Interface("details", details).
			Msg("Source flagged by threat intelligence, trust score adjusted")
	}

	return nil
}

// UpdateSystemMetrics recalculates system-wide trust metrics
func (ts *TrustScorer) UpdateSystemMetrics() {
	ts.mu.Lock()
	defer ts.mu.Unlock()

	now := time.Now()
	metrics := ts.systemMetrics

	// Reset distribution counters
	metrics.SourceDistribution = make(map[int]int)
	metrics.PercentileDistribution = make(map[int]int)

	// Track total trusted sources
	trustedCount := 0
	metrics.TotalSources = len(ts.scores)

	if metrics.TotalSources == 0 {
		// No sources to analyze
		metrics.LastUpdated = now
		return
	}

	// Collect all scores for percentile and consensus calculations
	allScores := make([]int, 0, len(ts.scores))
	categoryScores := make(map[TrustScoreCategory][]int)

	// Initialize category score collection
	for category := range ts.categoryWeights {
		categoryScores[category] = make([]int, 0, len(ts.scores))
	}

	// Analyze all sources
	for sourceID, score := range ts.scores {
		// Add to tier distribution
		tier := ts.calculateTrustTier(sourceID)
		metrics.SourceDistribution[tier]++

		// Track trusted sources
		if score.Score >= ts.thresholdScore {
			trustedCount++
		}

		// Add to percentile calculations
		allScores = append(allScores, score.Score)

		// Add to category score collections
		categoryScores[ConsistencyCategory] = append(categoryScores[ConsistencyCategory], score.ConsistencyScore)
		categoryScores[TimingCategory] = append(categoryScores[TimingCategory], score.TimingScore)
		categoryScores[VerificationCategory] = append(categoryScores[VerificationCategory], score.VerificationScore)
		categoryScores[ExternalCategory] = append(categoryScores[ExternalCategory], score.ExternalScore)
		categoryScores[VolumeCategory] = append(categoryScores[VolumeCategory], score.VolumeScore)
		categoryScores[SchemaCategory] = append(categoryScores[SchemaCategory], score.SchemaScore)
		categoryScores[ContentCategory] = append(categoryScores[ContentCategory], score.ContentScore)
		categoryScores[BehavioralCategory] = append(categoryScores[BehavioralCategory], score.BehavioralScore)
		categoryScores[NetworkCategory] = append(categoryScores[NetworkCategory], score.NetworkScore)
		categoryScores[ContextualCategory] = append(categoryScores[ContextualCategory], score.ContextualScore)

		// Check if source is a recent threat
		isRecentThreat := false
		for _, anomaly := range score.DetectedAnomalies {
			// Consider high severity anomalies in the last 24 hours
			if anomaly.Severity >= SeverityHigh && anomaly.Timestamp.After(now.Add(-24*time.Hour)) {
				isRecentThreat = true
				break
			}
		}

		if isRecentThreat {
			// Check if source ID already exists in the list
			sourceExists := false
			for _, existingSource := range metrics.RecentThreatSources {
				if existingSource == sourceID {
					sourceExists = true
					break
				}
			}

			if !sourceExists {
				metrics.RecentThreatSources = append(metrics.RecentThreatSources, sourceID)
				// Keep list bounded
				if len(metrics.RecentThreatSources) > 10 {
					metrics.RecentThreatSources = metrics.RecentThreatSources[len(metrics.RecentThreatSources)-10:]
				}
			}
		}
	}

	// Calculate trusted percentage
	if metrics.TotalSources > 0 {
		metrics.TrustedSourcesPercentage = float64(trustedCount) / float64(metrics.TotalSources) * 100.0
	}

	// Calculate percentile distribution
	sort.Ints(allScores)
	for p := 10; p <= 100; p += 10 {
		index := (p * len(allScores)) / 100
		if index > 0 && index <= len(allScores) {
			metrics.PercentileDistribution[p] = allScores[index-1]
		}
	}

	// Calculate system consensus - how closely sources agree on trust categories
	totalVariance := 0.0
	totalCategories := 0

	for category, scores := range categoryScores {
		if len(scores) < 2 {
			continue
		}

		// Calculate mean
		sum := 0
		for _, score := range scores {
			sum += score
		}
		mean := float64(sum) / float64(len(scores))

		// Calculate variance
		variance := 0.0
		for _, score := range scores {
			diff := float64(score) - mean
			variance += diff * diff
		}
		variance /= float64(len(scores))

		// Contribute to total variance
		totalVariance += variance
		totalCategories++

		// Update category health scores based on variance and mean
		healthScore := 100

		// Higher variance = lower health score
		if variance > 400 { // High variance
			healthScore -= 30
		} else if variance > 200 { // Medium variance
			healthScore -= 15
		} else if variance > 100 { // Low variance
			healthScore -= 5
		}

		// Lower mean = lower health score
		if mean < 40 {
			healthScore -= 40
		} else if mean < 60 {
			healthScore -= 20
		} else if mean < 80 {
			healthScore -= 10
		}

		// Calculate anomaly rate for this category
		anomalyCount := 0
		for _, sourceScore := range ts.scores {
			for _, anomaly := range sourceScore.DetectedAnomalies {
				if anomaly.Category == category && anomaly.Timestamp.After(now.Add(-24*time.Hour)) {
					anomalyCount++
				}
			}
		}

		// Anomaly rate as percentage of total sources
		if metrics.TotalSources > 0 {
			metrics.AnomalyRateByCategory[category] = float64(anomalyCount) / float64(metrics.TotalSources) * 100.0

			// Higher anomaly rate = lower health score
			anomalyRate := metrics.AnomalyRateByCategory[category]
			if anomalyRate > 20 {
				healthScore -= 40
			} else if anomalyRate > 10 {
				healthScore -= 20
			} else if anomalyRate > 5 {
				healthScore -= 10
			}
		}

		// Ensure health score stays in valid range
		if healthScore < 0 {
			healthScore = 0
		} else if healthScore > 100 {
			healthScore = 100
		}

		metrics.CategoryHealthScores[category] = healthScore
	}

	// Calculate overall system consensus (0-1 scale, higher is better)
	if totalCategories > 0 {
		// Convert total variance to consensus score (inverse relationship)
		// Lower variance = higher consensus
		avgVariance := totalVariance / float64(totalCategories)

		// Normalize to 0-1 scale (400 is a high variance threshold)
		consensusScore := 1.0 - math.Min(1.0, avgVariance/400.0)
		metrics.SystemConsensus = consensusScore
	}

	// Update trust trends (store last 24 hourly and 30 daily values)

	// Average trust score
	avgScore := 0
	if len(allScores) > 0 {
		sum := 0
		for _, score := range allScores {
			sum += score
		}
		avgScore = sum / len(allScores)
	}

	// Update hourly trend
	hourlyTrend, exists := metrics.TrustTrends["hourly"]
	if !exists {
		hourlyTrend = make([]int, 0, 24)
	}
	hourlyTrend = append(hourlyTrend, avgScore)
	if len(hourlyTrend) > 24 {
		hourlyTrend = hourlyTrend[len(hourlyTrend)-24:]
	}
	metrics.TrustTrends["hourly"] = hourlyTrend

	// Update daily trend
	dailyTrend, exists := metrics.TrustTrends["daily"]
	if !exists {
		dailyTrend = make([]int, 0, 30)
	}
	if len(dailyTrend) == 0 || metrics.LastUpdated.Format("2006-01-02") != now.Format("2006-01-02") {
		dailyTrend = append(dailyTrend, avgScore)
		if len(dailyTrend) > 30 {
			dailyTrend = dailyTrend[len(dailyTrend)-30:]
		}
		metrics.TrustTrends["daily"] = dailyTrend
	}

	// Determine defensive posture
	ts.updateDefensivePosture()

	// Update global threat level based on various indicators
	ts.recalculateGlobalThreatLevel()

	metrics.LastUpdated = now
}

// updateDefensivePosture adjusts the system-wide defensive posture based on the threat level
func (ts *TrustScorer) updateDefensivePosture() {
	prevPosture := ts.systemMetrics.ActiveDefensivePosture

	// Determine new posture based on threat level
	var newPosture string
	switch ts.systemMetrics.GlobalThreatLevel {
	case 1:
		newPosture = "normal"
	case 2:
		newPosture = "cautious"
	case 3:
		newPosture = "defensive"
	case 4, 5:
		newPosture = "lockdown"
	}

	// Update if changed
	if newPosture != ts.systemMetrics.ActiveDefensivePosture {
		log.Info().
			Str("old_posture", ts.systemMetrics.ActiveDefensivePosture).
			Str("new_posture", newPosture).
			Int("threat_level", ts.systemMetrics.GlobalThreatLevel).
			Msg("Defensive posture changing")

		ts.systemMetrics.ActiveDefensivePosture = newPosture

		// Notify metrics hooks about posture change
		ts.hooks.NotifyDefensivePostureChange(newPosture, prevPosture)

		// Notify panic system if integrated
		if ts.panicSystem != nil {
			ts.notifyPanicSystem(newPosture)
		}
	}
}

// recalculateGlobalThreatLevel updates the system-wide threat level based on current metrics
func (ts *TrustScorer) recalculateGlobalThreatLevel() {
	// Store previous threat level for comparison
	prevThreatLevel := ts.systemMetrics.GlobalThreatLevel

	// Calculate base threat level from category health scores
	totalWeight := 0.0
	weightedSum := 0.0

	for category, health := range ts.systemMetrics.CategoryHealthScores {
		weight := ts.categoryWeights[category]
		weightedSum += (100.0 - float64(health)) * weight // Invert health to get threat
		totalWeight += weight
	}

	// Calculate anomaly factors
	anomalyFactor := 0.0
	for _, rate := range ts.systemMetrics.AnomalyRateByCategory {
		anomalyFactor += rate
	}
	anomalyFactor = math.Min(anomalyFactor*10.0, 40.0) // Cap at +40% threat impact

	// Calculate consensus factor: less consensus = more threat
	consensusFactor := (1.0 - ts.systemMetrics.SystemConsensus) * 30.0 // Up to +30% threat impact

	// Calculate trusted source percentage factor
	trustFactor := (100.0 - ts.systemMetrics.TrustedSourcesPercentage) * 0.3 // Up to +30% threat impact

	// Calculate temporal factor based on trend slopes
	trendFactor := 0.0
	if slopes, ok := ts.detectTrustTrendSlopes(); ok {
		// Negative slopes (decreasing trust) increase threat
		trendFactor = math.Min(slopes.hourly*-5.0+slopes.daily*-15.0, 20.0)
		if trendFactor < 0 {
			trendFactor = 0 // Only consider negative trends (decreasing trust)
		}
	}

	// Calculate raw threat score (0-100)
	baseThreadLevel := weightedSum / totalWeight
	if totalWeight == 0 {
		baseThreadLevel = 0
	}

	// Apply modifiers
	threatScore := baseThreadLevel * (1.0 + anomalyFactor/100.0 + consensusFactor/100.0 + trustFactor/100.0 + trendFactor/100.0)

	// Convert to 1-5 threat level
	var newThreatLevel int
	switch {
	case threatScore < 20:
		newThreatLevel = 1 // Normal
	case threatScore < 40:
		newThreatLevel = 2 // Elevated
	case threatScore < 60:
		newThreatLevel = 3 // High
	case threatScore < 80:
		newThreatLevel = 4 // Severe
	default:
		newThreatLevel = 5 // Critical
	}

	// Apply hysteresis to prevent rapid oscillation
	if math.Abs(float64(newThreatLevel-ts.systemMetrics.GlobalThreatLevel)) == 1 {
		// For adjacent levels, require the condition to persist
		timeSinceChange := time.Since(ts.systemMetrics.LastThreatLevelChange)
		if timeSinceChange < 10*time.Minute {
			return // Don't change if we just changed recently
		}
	}

	// Update system metrics
	if newThreatLevel != ts.systemMetrics.GlobalThreatLevel {
		log.Info().
			Int("old_level", ts.systemMetrics.GlobalThreatLevel).
			Int("new_level", newThreatLevel).
			Float64("threat_score", threatScore).
			Float64("anomaly_factor", anomalyFactor).
			Float64("consensus_factor", consensusFactor).
			Float64("trust_factor", trustFactor).
			Float64("trend_factor", trendFactor).
			Msg("System threat level changing")

		ts.systemMetrics.GlobalThreatLevel = newThreatLevel
		ts.systemMetrics.LastThreatLevelChange = time.Now()

		// Notify metrics hooks about threat level change
		ts.hooks.NotifyThreatLevelChange(newThreatLevel, prevThreatLevel)

		// Update the defensive posture
		ts.updateDefensivePosture()
	}
}

// GetSystemMetrics returns the current system-wide trust metrics
func (ts *TrustScorer) GetSystemMetrics() *SystemWideMetrics {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	// Ensure metrics are current
	if time.Since(ts.systemMetrics.LastUpdated) > 5*time.Minute {
		ts.mu.RUnlock()          // Unlock for read
		ts.UpdateSystemMetrics() // Will relock
		ts.mu.RLock()            // Relock for continued reading
	}

	// Return a copy to avoid concurrent modification
	metrics := *ts.systemMetrics
	return &metrics
}

// GetRecentAnomalies returns a slice of recent anomalies across all sources
func (ts *TrustScorer) GetRecentAnomalies(maxResults int) []AnomalyRecord {
	ts.mu.RLock()
	defer ts.mu.RUnlock()

	if len(ts.recentAnomalies) == 0 {
		return []AnomalyRecord{}
	}

	results := slices.Clone(ts.recentAnomalies)

	// Limit results if needed
	if maxResults > 0 && len(results) > maxResults {
		// Return the most recent anomalies
		startIdx := len(results) - maxResults
		if startIdx < 0 {
			startIdx = 0
		}
		results = results[startIdx:]
	}

	return results
}

// GetHooks returns the trust metrics hooks for registering metrics emitters
func (ts *TrustScorer) GetHooks() *TrustMetricsHooks {
	return ts.hooks
}

// adjustSeverityImpact calculates the impact multiplier based on severity level
func (ts *TrustScorer) adjustSeverityImpact(severity SeverityLevel) int {
	if impact, ok := ts.severityImpact[severity]; ok {
		return impact
	}

	// Default values if not in the map
	switch severity {
	case SeverityInfo:
		return 25
	case SeverityLow:
		return 50
	case SeverityMedium:
		return 100
	case SeverityHigh:
		return 150
	case SeverityCritical:
		return 200
	default:
		return 100
	}
}

// notifyPanicSystem notifies the panic system about defensive posture changes
func (ts *TrustScorer) notifyPanicSystem(newPosture string) {
	if ts.panicSystem == nil {
		return
	}

	// Map posture to panic tier
	var panicLevel int
	switch newPosture {
	case "normal":
		panicLevel = 1
	case "cautious":
		panicLevel = 2
	case "defensive":
		panicLevel = 3
	case "lockdown":
		panicLevel = 4
	default:
		panicLevel = 1
	}

	// Notify panic system asynchronously
	go func() {
		if err := ts.panicSystem.NotifyTrustThresholdViolation(
			"system",
			panicLevel,
			fmt.Sprintf("Defensive posture changed to %s", newPosture),
		); err != nil {
			log.Error().Err(err).Msg("Failed to notify panic system about posture change")
		}
	}()
}

// TrustTrendSlopes represents trend analysis of trust scores over time
type TrustTrendSlopes struct {
	hourly float64 // Trust score change per hour
	daily  float64 // Trust score change per day
	weekly float64 // Trust score change per week
}

// detectTrustTrendSlopes analyzes historical trust score trends
func (ts *TrustScorer) detectTrustTrendSlopes() (*TrustTrendSlopes, bool) {
	if len(ts.systemMetrics.TrustTrends) == 0 {
		return nil, false
	}

	// Get hourly trend if available
	hourlySlope := 0.0
	if hourlyTrend, ok := ts.systemMetrics.TrustTrends["hourly"]; ok && len(hourlyTrend) >= 2 {
		// Calculate simple slope (change per hour)
		last := len(hourlyTrend) - 1
		hourlySlope = float64(hourlyTrend[last] - hourlyTrend[last-1])
	}

	// Get daily trend if available
	dailySlope := 0.0
	if dailyTrend, ok := ts.systemMetrics.TrustTrends["daily"]; ok && len(dailyTrend) >= 2 {
		// Calculate simple slope (change per day)
		last := len(dailyTrend) - 1
		dailySlope = float64(dailyTrend[last] - dailyTrend[last-1])
	}

	// Get weekly trend if available
	weeklySlope := 0.0
	if weeklyTrend, ok := ts.systemMetrics.TrustTrends["weekly"]; ok && len(weeklyTrend) >= 2 {
		// Calculate simple slope (change per week)
		last := len(weeklyTrend) - 1
		weeklySlope = float64(weeklyTrend[last] - weeklyTrend[last-1])
	}

	return &TrustTrendSlopes{
		hourly: hourlySlope,
		daily:  dailySlope,
		weekly: weeklySlope,
	}, true
}
