// Package anomaly provides anomaly detection and response capabilities for the BlackIce system.
package anomaly

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"time"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
	"github.com/google/uuid"
	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Service provides the implementation of the AnomalyService interface
type Service struct {
	blackicev1.UnimplementedAnomalyServiceServer

	// Internal storage for detected anomalies
	mu        sync.RWMutex
	anomalies map[string]*Anomaly

	// Detectors registry
	detectors map[string]*Detector

	// Hooks for external integrations
	hooks *AnomalyHooks
}

// Detector represents an anomaly detection module
type Detector struct {
	ID             string
	Type           string
	Version        string
	State          blackicev1.NodeHealth_State
	LastProcessed  time.Time
	Parameters     map[string]string
	ProcessingFunc TelemetryProcessorFunc
}

// TelemetryProcessorFunc is a function type that processes telemetry events and returns detected anomalies
type TelemetryProcessorFunc func(event *TelemetryEvent) ([]*Anomaly, error)

// NewService creates a new anomaly detection service
func NewService() *Service {
	return &Service{
		anomalies: make(map[string]*Anomaly),
		detectors: make(map[string]*Detector),
		hooks:     NewAnomalyHooks(),
	}
}

// RegisterDetector adds a new anomaly detector to the service
func (s *Service) RegisterDetector(id, detectorType, version string, params map[string]string, processor TelemetryProcessorFunc) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.detectors[id]; exists {
		return fmt.Errorf("detector with ID %s already registered", id)
	}

	s.detectors[id] = &Detector{
		ID:             id,
		Type:           detectorType,
		Version:        version,
		State:          blackicev1.NodeHealth_HEALTHY,
		LastProcessed:  time.Now(),
		Parameters:     params,
		ProcessingFunc: processor,
	}

	log.Info().
		Str("detector_id", id).
		Str("type", detectorType).
		Str("version", version).
		Msg("Registered new anomaly detector")

	return nil
}

// SubmitTelemetry implements the AnomalyService SubmitTelemetry RPC
func (s *Service) SubmitTelemetry(stream blackicev1.AnomalyService_SubmitTelemetryServer) error {
	var processedCount int32

	// Process telemetry events from the stream
	for {
		telemetryEvent, err := stream.Recv()
		if err == io.EOF {
			// End of stream, return response
			return stream.SendAndClose(&blackicev1.TelemetryResponse{
				Status: &blackicev1.Status{
					Code:    blackicev1.Status_OK,
					Message: "Successfully processed telemetry events",
				},
				BatchAckId:      generateBatchID(),
				EventsProcessed: processedCount,
			})
		}
		if err != nil {
			log.Error().Err(err).Msg("Error receiving telemetry event")
			return status.Errorf(codes.Internal, "failed to receive telemetry event: %v", err)
		}

		// Convert proto event to internal model
		event := ConvertFromProto(telemetryEvent)
		if event == nil {
			log.Warn().Msg("Received nil telemetry event")
			continue
		}

		// Process the event with all registered detectors
		s.processEvent(event)
		processedCount++
	}
}

// processEvent runs the telemetry event through all registered detectors
func (s *Service) processEvent(event *TelemetryEvent) {
	s.mu.RLock()

	// Create a copy of detector IDs to avoid holding the lock during processing
	detectors := make(map[string]*Detector, len(s.detectors))
	for id, detector := range s.detectors {
		if detector.State == blackicev1.NodeHealth_HEALTHY ||
			detector.State == blackicev1.NodeHealth_GUARDED {
			detectors[id] = detector
		}
	}
	s.mu.RUnlock()

	if len(detectors) == 0 {
		return
	}

	// Use a wait group to track all goroutines
	var wg sync.WaitGroup
	// Channel to collect anomalies from all detectors
	anomalyChan := make(chan []*Anomaly, len(detectors))

	// Process with each detector in parallel
	for _, detector := range detectors {
		wg.Add(1)
		go func(d *Detector, e *TelemetryEvent) {
			defer wg.Done()

			// Process the event
			anomalies, err := d.ProcessingFunc(e)
			if err != nil {
				log.Error().
					Err(err).
					Str("detector_id", d.ID).
					Str("event_id", e.EventID).
					Msg("Error processing telemetry event")
				return
			}

			// Update detector state
			if len(anomalies) > 0 {
				// Only update if we found anomalies
				s.mu.Lock()
				detector, exists := s.detectors[d.ID]
				if exists {
					detector.LastProcessed = time.Now()
				}
				s.mu.Unlock()

				// Send anomalies to channel for collection
				anomalyChan <- anomalies
			}
		}(detector, event)
	}

	// Start a goroutine to collect all anomalies
	go func() {
		// Wait for all detector goroutines to complete
		wg.Wait()
		close(anomalyChan)

		// Collect all anomalies from the channel
		var allAnomalies []*Anomaly
		for anomalies := range anomalyChan {
			allAnomalies = append(allAnomalies, anomalies...)
		}

		// If we found any anomalies, store them
		if len(allAnomalies) > 0 {
			s.storeAnomalies(allAnomalies)
		}
	}()
}

// storeAnomalies stores detected anomalies and notifies hooks
func (s *Service) storeAnomalies(anomalies []*Anomaly) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, anomaly := range anomalies {
		// Ensure we have an anomaly ID
		if anomaly.AnomalyID == "" {
			anomaly.AnomalyID = generateAnomalyID()
		}

		// Store the anomaly
		s.anomalies[anomaly.AnomalyID] = anomaly

		// Notify hooks
		s.hooks.NotifyAnomalyDetected(anomaly)

		log.Info().
			Str("anomaly_id", anomaly.AnomalyID).
			Str("source", anomaly.SourceComponentID).
			Str("detector", anomaly.DetectorID).
			Int("severity", int(anomaly.Severity)).
			Msg("Detected new anomaly")
	}
}

// QueryAnomalies implements the AnomalyService QueryAnomalies RPC
func (s *Service) QueryAnomalies(ctx context.Context, req *blackicev1.QueryAnomaliesRequest) (*blackicev1.QueryAnomaliesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build filtered list of anomalies
	var filteredAnomalies []*Anomaly
	for _, anomaly := range s.anomalies {
		// Apply filters
		if !s.matchesFilter(anomaly, req) {
			continue
		}

		filteredAnomalies = append(filteredAnomalies, anomaly)
	}

	// Convert to proto anomalies
	protoAnomalies := make([]*blackicev1.Anomaly, 0, len(filteredAnomalies))
	for _, anomaly := range filteredAnomalies {
		protoAnomalies = append(protoAnomalies, ConvertAnomalyToProto(anomaly))
	}

	// Return response with filtered anomalies
	return &blackicev1.QueryAnomaliesResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "Successfully retrieved anomalies",
		},
		Anomalies:     protoAnomalies,
		NextPageToken: "", // Pagination not implemented yet
	}, nil
}

// matchesFilter checks if an anomaly matches the filter criteria
func (s *Service) matchesFilter(anomaly *Anomaly, req *blackicev1.QueryAnomaliesRequest) bool {
	// Filter by time range
	if req.StartTimeUnixNs > 0 && anomaly.DetectionTime.UnixNano() < req.StartTimeUnixNs {
		return false
	}
	if req.EndTimeUnixNs > 0 && anomaly.DetectionTime.UnixNano() > req.EndTimeUnixNs {
		return false
	}

	// Filter by source component
	if req.SourceComponentIdFilter != "" && req.SourceComponentIdFilter != anomaly.SourceComponentID {
		return false
	}

	// Filter by severity
	if req.MinSeverityFilter != blackicev1.Anomaly_UNKNOWN &&
		int32(anomaly.Severity) < int32(req.MinSeverityFilter) {
		return false
	}

	// Filter by detector
	if req.DetectorIdFilter != "" && req.DetectorIdFilter != anomaly.DetectorID {
		return false
	}

	// All filters passed
	return true
}

// GetAnomalyDetails implements the AnomalyService GetAnomalyDetails RPC
func (s *Service) GetAnomalyDetails(ctx context.Context, req *blackicev1.GetAnomalyDetailsRequest) (*blackicev1.GetAnomalyDetailsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find the requested anomaly
	anomaly, exists := s.anomalies[req.AnomalyId]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "anomaly with ID %s not found", req.AnomalyId)
	}

	// Convert to proto anomaly
	protoAnomaly := ConvertAnomalyToProto(anomaly)

	// Return response with anomaly details
	return &blackicev1.GetAnomalyDetailsResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "Successfully retrieved anomaly details",
		},
		AnomalyDetails:   protoAnomaly,
		CorrelatedEvents: nil, // Not implemented yet
		FeedbackHistory:  nil, // Not implemented yet
	}, nil
}

// UpdateDetectionModel implements the AnomalyService UpdateDetectionModel RPC
func (s *Service) UpdateDetectionModel(ctx context.Context, req *blackicev1.UpdateModelRequest) (*blackicev1.UpdateModelResponse, error) {
	// TODO: Implement model updating
	return &blackicev1.UpdateModelResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_NOT_FOUND, // Using a standard error code until implemented
			Message: "Method not implemented yet",
		},
	}, nil
}

// ProvideFeedback implements the AnomalyService ProvideFeedback RPC
func (s *Service) ProvideFeedback(ctx context.Context, req *blackicev1.FeedbackRequest) (*blackicev1.FeedbackResponse, error) {
	if req.Feedback == nil {
		return nil, status.Errorf(codes.InvalidArgument, "feedback cannot be nil")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Find the anomaly
	anomalyID := req.Feedback.AnomalyId
	anomaly, exists := s.anomalies[anomalyID]
	if !exists {
		return nil, status.Errorf(codes.NotFound, "anomaly with ID %s not found", anomalyID)
	}

	// Update the anomaly with the feedback
	if req.Feedback.IsTruePositive {
		if req.Feedback.CorrectedSeverity != blackicev1.Anomaly_UNKNOWN {
			anomaly.Severity = SeverityLevel(req.Feedback.CorrectedSeverity)
		}
	} else {
		// Mark as false positive
		anomaly.RemediationStatus = RemediationFalsePositive
	}

	// Update analyst information
	anomaly.AnalystID = req.Feedback.AnalystId
	anomaly.AnalyzedTime = time.Now()
	anomaly.LastUpdated = time.Now()

	// Add comments to attributes if provided
	if req.Feedback.Comments != "" {
		if anomaly.Attributes == nil {
			anomaly.Attributes = make(map[string]interface{})
		}
		anomaly.Attributes["analyst_comments"] = req.Feedback.Comments
	}

	// Store the updated anomaly
	s.anomalies[anomalyID] = anomaly

	// Notify hooks about the feedback
	s.hooks.NotifyAnomalyDetected(anomaly)

	log.Info().
		Str("anomaly_id", anomalyID).
		Str("analyst", req.Feedback.AnalystId).
		Bool("true_positive", req.Feedback.IsTruePositive).
		Int("corrected_severity", int(req.Feedback.CorrectedSeverity)).
		Msg("Analyst feedback provided for anomaly")

	// Create a response with a trust score impact
	// This is a placeholder - in a real system, this would be calculated based on the feedback
	trustScore := &blackicev1.TrustScore{
		Score:           75, // Example score
		SourceId:        anomaly.SourceComponentID,
		EvaluationId:    "feedback-" + generateAnomalyID(),
		TimestampUnixNs: time.Now().UnixNano(),
	}

	return &blackicev1.FeedbackResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "Feedback processed successfully",
		},
		FeedbackIdConfirmed:      req.Feedback.FeedbackId,
		ImpactOnSourceTrustScore: trustScore,
	}, nil
}

// GetDetectorStatus implements the AnomalyService GetDetectorStatus RPC
func (s *Service) GetDetectorStatus(ctx context.Context, req *blackicev1.DetectorStatusRequest) (*blackicev1.DetectorStatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Build list of detectors
	var detectorInfos []*blackicev1.DetectorInfo

	for id, detector := range s.detectors {
		// Filter by detector IDs if specified
		if len(req.DetectorIds) > 0 {
			found := false
			for _, requestedID := range req.DetectorIds {
				if requestedID == id {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		// Convert to proto detector info
		detectorInfos = append(detectorInfos, &blackicev1.DetectorInfo{
			DetectorId:               detector.ID,
			DetectorType:             detector.Type,
			Version:                  detector.Version,
			Status:                   detector.State,
			LastEventProcessedUnixNs: detector.LastProcessed.UnixNano(),
			DetectorParams:           detector.Parameters,
		})
	}

	// Return response with detector status
	return &blackicev1.DetectorStatusResponse{
		Status: &blackicev1.Status{
			Code:    blackicev1.Status_OK,
			Message: "Successfully retrieved detector status",
		},
		Detectors: detectorInfos,
	}, nil
}

// GetHooks returns the anomaly hooks for external integrations
func (s *Service) GetHooks() *AnomalyHooks {
	return s.hooks
}

// Helper function to generate a new anomaly ID
func generateAnomalyID() string {
	return "anomaly-" + uuid.New().String()
}

// Helper function to generate a batch ID
func generateBatchID() string {
	buf := make([]byte, 12)
	_, _ = rand.Read(buf)
	return fmt.Sprintf("batch-%x", buf)
}
