package trust

import (
	"testing"
	"time"
)

func TestTrustScorerBasicFunctionality(t *testing.T) {
	// Create a new trust scorer
	scorer := NewTrustScorer(0, 50)
	if scorer == nil {
		t.Fatal("Failed to create trust scorer")
	}

	// Register a source
	sourceID := "test-source-1"
	err := scorer.RegisterSource(sourceID, 75)
	if err != nil {
		t.Fatalf("Failed to register source: %v", err)
	}

	// Check if source is trusted
	trusted, err := scorer.IsTrusted(sourceID)
	if err != nil {
		t.Fatalf("Error checking trust status: %v", err)
	}
	if !trusted {
		t.Errorf("Source should be trusted with score 75 (threshold 50)")
	}

	// Get the initial score to use as a baseline BEFORE any updates
	beforeScore, err := scorer.GetScore(sourceID)
	if err != nil {
		t.Fatalf("Failed to get initial score: %v", err)
	}

	// Save initial scores for comparison
	initialOverallScore := beforeScore.Score
	initialVerificationScore := beforeScore.VerificationScore
	t.Logf("Initial verification score: %d", initialVerificationScore)

	// Update score with negative adjustment
	err = scorer.UpdateScore(sourceID, ScoreAdjustment{
		Value:      -30,
		Reason:     "Test adjustment",
		Category:   "verification",
		Expiration: 0,
		Severity:   SeverityMedium,
	})
	if err != nil {
		t.Fatalf("Failed to update score: %v", err)
	}

	// Get the updated score AFTER the update
	afterScore, err := scorer.GetScore(sourceID)
	if err != nil {
		t.Fatalf("Failed to get updated score: %v", err)
	}

	// Log both scores for debugging
	t.Logf("Before overall score: %d, After overall score: %d", initialOverallScore, afterScore.Score)
	t.Logf("Before verification score: %d, After verification score: %d",
		initialVerificationScore, afterScore.VerificationScore)

	// The overall score should decrease
	if afterScore.Score >= initialOverallScore {
		t.Errorf("Overall score should decrease from %d, but got %d",
			initialOverallScore, afterScore.Score)
	}

	// The verification score specifically should decrease since we targeted that category
	if afterScore.VerificationScore >= initialVerificationScore {
		t.Errorf("Verification score should decrease from %d, but got %d",
			initialVerificationScore, afterScore.VerificationScore)
	}
}

func TestTrustManagerIntegration(t *testing.T) {
	// Create configuration
	config := TrustManagerConfig{
		MinScore:                   0,
		ThresholdScore:             50,
		EnableBackgroundProcessing: false,
		DynamicThresholds:          true,
	}

	// Create trust manager
	manager := NewTrustManager(config)
	if manager == nil {
		t.Fatal("Failed to create trust manager")
	}

	// Register a source
	sourceID := "test-source-2"
	err := manager.RegisterSource(
		sourceID,
		"Test Source 2",
		"", // No public key path for testing
		"RSA",
		75,
		[]string{"application/json"},
		map[string]string{"type": "test"},
	)
	if err != nil {
		t.Fatalf("Failed to register source with manager: %v", err)
	}

	// Check if source is trusted
	trusted, err := manager.IsTrusted(sourceID)
	if err != nil {
		t.Fatalf("Error checking trust status: %v", err)
	}
	if !trusted {
		t.Errorf("Source should be trusted with score 75 (threshold 50)")
	}

	// Record a transaction
	err = manager.RecordTransaction(
		sourceID,
		"data_upload",
		true,      // successful
		1024*1024, // 1MB
		100*time.Millisecond,
		map[string]interface{}{
			"transaction_type": "test",
		},
	)
	if err != nil {
		t.Fatalf("Failed to record transaction: %v", err)
	}

	// Get trust score
	score, err := manager.GetTrustScore(sourceID)
	if err != nil {
		t.Fatalf("Failed to get trust score: %v", err)
	}

	// Verify transaction count was updated
	if score.TotalTransactions != 1 {
		t.Errorf("Expected total transactions to be 1, got %d", score.TotalTransactions)
	}
	if score.SuccessfulTransactions != 1 {
		t.Errorf("Expected successful transactions to be 1, got %d", score.SuccessfulTransactions)
	}

	// Report an anomaly
	err = manager.ReportAnomaly(
		sourceID,
		"verification",
		"Test anomaly",
		SeverityMedium,
		map[string]interface{}{
			"detail": "Test detail",
		},
	)
	if err != nil {
		t.Fatalf("Failed to report anomaly: %v", err)
	}

	// Get anomalies
	anomalies, err := manager.GetSourceAnomalies(sourceID, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Failed to get anomalies: %v", err)
	}

	// Verify anomaly was recorded
	if len(anomalies) < 1 {
		t.Errorf("Expected at least 1 anomaly, got %d", len(anomalies))
	}

	// Clean up
	manager.Shutdown()
}

func TestSimpleBehavioralAnalysis(t *testing.T) {
	// Create a trust manager which will properly initialize the behavioral analyzer
	config := TrustManagerConfig{
		MinScore:                   0,
		ThresholdScore:             50,
		EnableBackgroundProcessing: false,
		DynamicThresholds:          true,
	}

	manager := NewTrustManager(config)
	if manager == nil {
		t.Fatal("Failed to create trust manager")
	}

	// Register a source
	sourceID := "test-source-3"
	err := manager.RegisterSource(
		sourceID,
		"Test Source 3",
		"", // No public key path for testing
		"RSA",
		75,
		[]string{"application/json"},
		map[string]string{"type": "test"},
	)
	if err != nil {
		t.Fatalf("Failed to register source with manager: %v", err)
	}

	// Record normal behavior through transactions
	for i := 0; i < 5; i++ {
		err = manager.RecordTransaction(
			sourceID,
			"data_upload",
			true,
			int64(1024*1024*(1+i%3)), // 1-3MB variations, convert to int64
			100*time.Millisecond,
			map[string]interface{}{
				"test_run": i,
			},
		)
		if err != nil {
			t.Fatalf("Failed to record transaction: %v", err)
		}
	}

	// Get behavioral patterns
	patterns, err := manager.GetBehavioralPatterns(sourceID)
	if err != nil {
		t.Fatalf("Failed to get behavioral patterns: %v", err)
	}

	// Simply verify we get some patterns back
	if patterns == nil {
		t.Fatal("Expected patterns but got nil")
	}

	// Clean up
	manager.Shutdown()
}

func TestThreatIntelligenceIntegration(t *testing.T) {
	// Create a new trust scorer
	scorer := NewTrustScorer(0, 50)
	if scorer == nil {
		t.Fatal("Failed to create trust scorer")
	}

	// Create and set a mock threat intelligence integration
	mockThreatIntel := NewMockThreatIntelligence()
	scorer.SetThreatIntelligence(mockThreatIntel)

	// Add a known bad source for testing
	mockThreatIntel.AddKnownBadSource("malicious-source", map[string]interface{}{
		"confidence":       0.95,
		"confidence_level": "high",
		"reason":           "Part of known threat actor infrastructure",
		"references":       []string{"threat-feed-1", "blocklist-2"},
	})

	// Register sources
	goodSourceID := "good-source"
	badSourceID := "malicious-source"

	err := scorer.RegisterSource(goodSourceID, 75)
	if err != nil {
		t.Fatalf("Failed to register good source: %v", err)
	}

	err = scorer.RegisterSource(badSourceID, 75)
	if err != nil {
		t.Fatalf("Failed to register malicious source: %v", err)
	}

	// Get initial scores for both sources BEFORE any threat intelligence check
	initialGoodScore, err := scorer.GetScore(goodSourceID)
	if err != nil {
		t.Fatalf("Failed to get initial good source score: %v", err)
	}

	initialBadScore, err := scorer.GetScore(badSourceID)
	if err != nil {
		t.Fatalf("Failed to get initial malicious score: %v", err)
	}

	// Store the initial scores for comparison
	initialGoodScoreValue := initialGoodScore.Score
	initialBadScoreValue := initialBadScore.Score

	// Check against threat intelligence
	err = scorer.CheckThreatIntelligence(goodSourceID, map[string]string{
		"domain":     "example.com",
		"ip_address": "192.168.1.1",
	})
	if err != nil {
		t.Fatalf("Failed to check good source against threat intel: %v", err)
	}

	// Verify good source score is unchanged
	goodScoreAfterCheck, err := scorer.GetScore(goodSourceID)
	if err != nil {
		t.Fatalf("Failed to get good source score: %v", err)
	}
	if goodScoreAfterCheck.Score < initialGoodScoreValue-5 {
		t.Errorf("Good source score should not be significantly affected, got %d (was %d)",
			goodScoreAfterCheck.Score, initialGoodScoreValue)
	}

	// Check malicious source against threat intelligence
	err = scorer.CheckThreatIntelligence(badSourceID, map[string]string{
		"domain":     "malicious.example.com",
		"ip_address": "10.0.0.1",
	})
	if err != nil {
		t.Fatalf("Failed to check malicious source against threat intel: %v", err)
	}

	// Verify malicious source score is reduced
	badScoreAfterCheck, err := scorer.GetScore(badSourceID)
	if err != nil {
		t.Fatalf("Failed to get malicious source score: %v", err)
	}

	// The score should be reduced but may not go below threshold due to weighting
	if badScoreAfterCheck.Score >= initialBadScoreValue {
		t.Errorf("Malicious source score should be reduced from %d, but got %d",
			initialBadScoreValue, badScoreAfterCheck.Score)
	}

	// Verify an anomaly was recorded for the malicious source
	if len(badScoreAfterCheck.DetectedAnomalies) == 0 {
		t.Errorf("Expected anomalies for malicious source")
	}

	// Verify the malicious source was registered for monitoring
	monitoredSources := mockThreatIntel.GetMonitoredSources()
	if _, exists := monitoredSources[badSourceID]; !exists {
		t.Errorf("Malicious source should be registered for monitoring")
	}

	// Get scores before threat level change
	beforeThreatLevelGoodScore := goodScoreAfterCheck.Score
	beforeThreatLevelBadScore := badScoreAfterCheck.Score

	// Test with elevated global threat level
	mockThreatIntel.SetGlobalThreatLevel(4) // High threat level

	// Recalculate scores which should reflect the new threat level
	scorer.recalculateScore(goodSourceID)
	scorer.recalculateScore(badSourceID)

	// Check if scores are affected by global threat level
	goodScoreAfterThreatLevel, _ := scorer.GetScore(goodSourceID)
	badScoreAfterThreatLevel, _ := scorer.GetScore(badSourceID)

	// Higher threat level should reduce scores system-wide
	if goodScoreAfterThreatLevel.Score >= beforeThreatLevelGoodScore {
		t.Errorf("Good source score should be affected by high global threat level, was %d, now %d",
			beforeThreatLevelGoodScore, goodScoreAfterThreatLevel.Score)
	}

	// Bad score should be even lower due to combined effects of threat intel and elevated threat level
	if badScoreAfterThreatLevel.Score >= beforeThreatLevelBadScore {
		t.Errorf("Malicious source score should be reduced with high global threat level, was %d, now %d",
			beforeThreatLevelBadScore, badScoreAfterThreatLevel.Score)
	}
}

func TestSystemWideTrustMetrics(t *testing.T) {
	// Create a trust scorer with multiple sources to test system-wide metrics
	scorer := NewTrustScorer(0, 50)
	if scorer == nil {
		t.Fatal("Failed to create trust scorer")
	}

	// Register several sources with different trust profiles
	sourcesToRegister := []struct {
		id    string
		score int
	}{
		{"high-trust-source-1", 90},
		{"high-trust-source-2", 85},
		{"medium-trust-source-1", 70},
		{"medium-trust-source-2", 65},
		{"low-trust-source-1", 40},
		{"untrusted-source-1", 30},
	}

	for _, src := range sourcesToRegister {
		err := scorer.RegisterSource(src.id, src.score)
		if err != nil {
			t.Fatalf("Failed to register source %s: %v", src.id, err)
		}
	}

	// Add anomalies to some sources
	err := scorer.UpdateScore("medium-trust-source-1", ScoreAdjustment{
		Value:      -10,
		Reason:     "Minor inconsistency detected",
		Category:   "consistency",
		Expiration: 0,
		Severity:   SeverityLow,
	})
	if err != nil {
		t.Fatalf("Failed to update score: %v", err)
	}

	err = scorer.UpdateScore("low-trust-source-1", ScoreAdjustment{
		Value:      -20,
		Reason:     "Verification failure",
		Category:   "verification",
		Expiration: 0,
		Severity:   SeverityHigh,
	})
	if err != nil {
		t.Fatalf("Failed to update score: %v", err)
	}

	// Force an update of system metrics
	scorer.UpdateSystemMetrics()

	// Get system metrics
	metrics := scorer.GetSystemMetrics()
	if metrics == nil {
		t.Fatal("Failed to get system metrics")
	}

	// Verify basic metrics
	if metrics.TotalSources != len(sourcesToRegister) {
		t.Errorf("Expected %d total sources, got %d", len(sourcesToRegister), metrics.TotalSources)
	}

	// Calculate expected trusted percentage (sources with score >= 50)
	expectedTrusted := 0
	for _, src := range sourcesToRegister {
		score, err := scorer.GetScore(src.id)
		if err != nil {
			t.Fatalf("Failed to get score for %s: %v", src.id, err)
		}
		if score.Score >= 50 {
			expectedTrusted++
		}
	}
	expectedPercentage := float64(expectedTrusted) / float64(len(sourcesToRegister)) * 100.0

	// Allow for small floating point differences
	if metrics.TrustedSourcesPercentage < expectedPercentage-1 || metrics.TrustedSourcesPercentage > expectedPercentage+1 {
		t.Errorf("Expected trusted percentage around %.1f%%, got %.1f%%",
			expectedPercentage, metrics.TrustedSourcesPercentage)
	}

	// Verify tier distribution (should have sources in different tiers)
	if len(metrics.SourceDistribution) == 0 {
		t.Error("Expected sources to be distributed across tiers, got empty distribution")
	}

	// Verify category health scores
	for category, health := range metrics.CategoryHealthScores {
		if health < 0 || health > 100 {
			t.Errorf("Health score for %s outside valid range: %d", category, health)
		}
	}

	// Verify system consensus is calculated - should be between 0 and 1 or undefined (0 when consensus is perfect)
	if metrics.SystemConsensus < 0.0 || metrics.SystemConsensus > 1.0 {
		t.Errorf("Expected system consensus between 0-1, got %.2f", metrics.SystemConsensus)
	}

	// Verify defensive posture is set
	if metrics.ActiveDefensivePosture == "" {
		t.Error("Expected defensive posture to be set")
	}

	// Add more anomalies to trigger threat level change
	higherSeverityAnomalies := []struct {
		sourceID string
		category string
		value    int
		reason   string
		severity SeverityLevel
	}{
		{"untrusted-source-1", "verification", -30, "Critical verification failure", SeverityCritical},
		{"low-trust-source-1", "content", -25, "Suspicious content detected", SeverityHigh},
		{"medium-trust-source-2", "timing", -20, "Timing anomaly detected", SeverityHigh},
	}

	for _, anomaly := range higherSeverityAnomalies {
		err := scorer.UpdateScore(anomaly.sourceID, ScoreAdjustment{
			Value:      anomaly.value,
			Reason:     anomaly.reason,
			Category:   anomaly.category,
			Expiration: 0,
			Severity:   anomaly.severity,
		})
		if err != nil {
			t.Fatalf("Failed to update score: %v", err)
		}
	}

	// Update system metrics again
	scorer.UpdateSystemMetrics()

	// Get updated metrics
	updatedMetrics := scorer.GetSystemMetrics()

	// System threat level should be elevated due to multiple high/critical anomalies
	if updatedMetrics.GlobalThreatLevel <= 1 {
		t.Errorf("Expected elevated global threat level, got %d", updatedMetrics.GlobalThreatLevel)
	}

	// Should have some recent threat sources
	if len(updatedMetrics.RecentThreatSources) == 0 {
		t.Error("Expected recent threat sources to be identified")
	}

	// Verify percentile distribution
	if len(updatedMetrics.PercentileDistribution) == 0 {
		t.Error("Expected percentile distribution to be calculated")
	}

	// Verify trust trends are being recorded
	hourlyTrend, exists := updatedMetrics.TrustTrends["hourly"]
	if !exists || len(hourlyTrend) == 0 {
		t.Error("Expected hourly trust trends to be recorded")
	}
}
