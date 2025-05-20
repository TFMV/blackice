package anomaly

import (
	"context"
	"testing"
	"time"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
	"github.com/stretchr/testify/assert"
)

func TestAnomalyDetectionIntegration(t *testing.T) {
	// Create a service
	service := NewService()

	// Register detectors
	err := RegisterStandardDetectors(service)
	assert.NoError(t, err, "Failed to register detectors")

	// Create test telemetry events
	events := []*TelemetryEvent{
		{
			EventID:           "evt-test-1",
			SourceComponentID: "test-auth-service",
			EventType:         "authentication",
			Timestamp:         time.Now(),
			Attributes: map[string]interface{}{
				"action":   "failed_auth",
				"user_id":  "user-123",
				"attempts": 3,
			},
		},
		{
			EventID:           "evt-test-2",
			SourceComponentID: "test-auth-service",
			EventType:         "authentication",
			Timestamp:         time.Now().Add(time.Second),
			Attributes: map[string]interface{}{
				"action":  "failed_auth",
				"user_id": "user-123",
			},
		},
		{
			EventID:           "evt-test-3",
			SourceComponentID: "test-auth-service",
			EventType:         "authentication",
			Timestamp:         time.Now().Add(2 * time.Second),
			Attributes: map[string]interface{}{
				"action":  "failed_auth",
				"user_id": "user-123",
			},
		},
		{
			EventID:           "evt-test-4",
			SourceComponentID: "test-auth-service",
			EventType:         "authentication",
			Timestamp:         time.Now().Add(3 * time.Second),
			Attributes: map[string]interface{}{
				"action":  "successful_auth",
				"user_id": "user-123",
			},
		},
	}

	// Process events
	for _, event := range events {
		for _, detector := range service.detectors {
			anomalies, err := detector.ProcessingFunc(event)
			assert.NoError(t, err, "Failed to process event")

			if len(anomalies) > 0 {
				service.storeAnomalies(anomalies)
			}
		}
	}

	// Query for anomalies
	ctx := context.Background()
	response, err := service.QueryAnomalies(ctx, &blackicev1.QueryAnomaliesRequest{
		SourceComponentIdFilter: "test-auth-service",
		MinSeverityFilter:       blackicev1.Anomaly_INFO,
	})
	assert.NoError(t, err, "Failed to query anomalies")
	assert.Greater(t, len(response.Anomalies), 0, "No anomalies detected")

	// Verify anomaly fields
	for _, anomaly := range response.Anomalies {
		// Check basic fields
		assert.NotEmpty(t, anomaly.Id, "Anomaly ID should not be empty")
		assert.Equal(t, "test-auth-service", anomaly.SourceComponentId, "Source component ID mismatch")
		assert.NotEmpty(t, anomaly.Description, "Description should not be empty")
		assert.NotZero(t, anomaly.DetectedAtUnixNs, "Detection time should be set")

		// Check new fields
		assert.NotEmpty(t, anomaly.Category, "Category should not be empty")

		// Fields may be empty in some cases, but should be present
		assert.NotNil(t, anomaly.RelatedEventIds, "Related event IDs should be present")
		assert.NotNil(t, anomaly.AffectedResources, "Affected resources should be present")
		assert.NotEqual(t, blackicev1.Anomaly_NONE, anomaly.RemediationStatus, "Remediation status should be set")
		assert.NotNil(t, anomaly.TtpIdentifiers, "TTP identifiers should be present")
		assert.NotEmpty(t, anomaly.MitreTechnique, "MITRE technique should be set")
		assert.NotZero(t, anomaly.LastUpdatedUnixNs, "Last updated should be set")
	}

	// Test providing feedback
	if len(response.Anomalies) > 0 {
		anomalyID := response.Anomalies[0].Id
		feedback := &blackicev1.AnalystFeedback{
			FeedbackId:        "test-feedback-1",
			AnomalyId:         anomalyID,
			AnalystId:         "test-analyst",
			IsTruePositive:    true,
			CorrectedSeverity: blackicev1.Anomaly_HIGH,
			Comments:          "This is a valid detection of a sequence of failed logins",
		}

		feedbackResponse, err := service.ProvideFeedback(ctx, &blackicev1.FeedbackRequest{
			Feedback: feedback,
		})
		assert.NoError(t, err, "Failed to provide feedback")
		assert.Equal(t, feedback.FeedbackId, feedbackResponse.FeedbackIdConfirmed, "Feedback ID mismatch")

		// Verify the feedback is stored
		detailsResponse, err := service.GetAnomalyDetails(ctx, &blackicev1.GetAnomalyDetailsRequest{
			AnomalyId: anomalyID,
		})
		assert.NoError(t, err, "Failed to get anomaly details")
		assert.Equal(t, anomalyID, detailsResponse.AnomalyDetails.Id, "Anomaly ID mismatch")
		assert.Equal(t, feedback.AnalystId, detailsResponse.AnomalyDetails.AnalystId, "Analyst ID should be updated")
		assert.Equal(t, blackicev1.Anomaly_HIGH, detailsResponse.AnomalyDetails.Severity, "Severity should be updated")
		assert.NotZero(t, detailsResponse.AnomalyDetails.AnalyzedAtUnixNs, "Analyzed time should be set")
	}
}
