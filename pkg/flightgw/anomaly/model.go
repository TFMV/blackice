// Package anomaly provides anomaly detection and response capabilities for the BlackIce system.
package anomaly

import (
	"fmt"
	"time"

	blackicev1 "github.com/TFMV/blackice/proto/blackice/v1"
)

// SeverityLevel defines the severity levels for detected anomalies
type SeverityLevel int32

const (
	// SeverityInfo represents informational level anomalies
	SeverityInfo SeverityLevel = iota
	// SeverityLow represents low severity anomalies
	SeverityLow
	// SeverityMedium represents medium severity anomalies
	SeverityMedium
	// SeverityHigh represents high severity anomalies
	SeverityHigh
	// SeverityCritical represents critical severity anomalies
	SeverityCritical
)

// Category defines different categories of anomalies
type Category string

const (
	// CategoryConsistency represents anomalies in data consistency
	CategoryConsistency Category = "consistency"
	// CategoryTiming represents anomalies in timing patterns
	CategoryTiming Category = "timing"
	// CategoryVolume represents anomalies in data volume
	CategoryVolume Category = "volume"
	// CategoryBehavioral represents anomalies in behavioral patterns
	CategoryBehavioral Category = "behavioral"
	// CategoryNetwork represents anomalies in network patterns
	CategoryNetwork Category = "network"
	// CategorySystem represents anomalies in system behavior
	CategorySystem Category = "system"
	// CategoryAuthentication represents anomalies in authentication
	CategoryAuthentication Category = "authentication"
	// CategoryAuthorization represents anomalies in authorization
	CategoryAuthorization Category = "authorization"
	// CategoryCrypto represents anomalies in cryptographic operations
	CategoryCrypto Category = "crypto"
)

// RemediationStatus defines the status of remediation for an anomaly
type RemediationStatus int32

const (
	// RemediationNone indicates no remediation has been started
	RemediationNone RemediationStatus = iota
	// RemediationPending indicates remediation is pending
	RemediationPending
	// RemediationInProgress indicates remediation is in progress
	RemediationInProgress
	// RemediationResolved indicates remediation is complete
	RemediationResolved
	// RemediationFalsePositive indicates the anomaly was a false positive
	RemediationFalsePositive
	// RemediationEscalated indicates the anomaly was escalated
	RemediationEscalated
)

// TelemetryEvent is an internal representation of the protobuf TelemetryEvent
type TelemetryEvent struct {
	EventID           string
	SourceComponentID string
	EventType         string
	Timestamp         time.Time
	Attributes        map[string]interface{}
	RawData           []byte
	TrustScoreContext *TrustScoreContext
}

// TrustScoreContext contains trust score information to enrich telemetry events
type TrustScoreContext struct {
	SourceID         string
	CurrentScore     int
	ScoreHistory     []int
	ScoreTimestamps  []time.Time
	ScoreCategories  map[string]int
	LastTransition   time.Time
	TransitionReason string
}

// Anomaly represents a detected anomaly in the system
type Anomaly struct {
	AnomalyID         string
	SourceComponentID string
	DetectorID        string
	DetectionTime     time.Time
	Category          Category
	Severity          SeverityLevel
	Description       string
	RelatedEvents     []string
	Attributes        map[string]interface{}
	Confidence        float64

	// Added fields from the proto enhancement
	AffectedResources []string
	RemediationStatus RemediationStatus
	TTPIdentifiers    []string
	MitreTechnique    string
	LastUpdated       time.Time
	AnalystID         string
	AnalyzedTime      time.Time
}

// ConvertFromProto converts a protobuf TelemetryEvent to an internal TelemetryEvent
func ConvertFromProto(protoEvent *blackicev1.TelemetryEvent) *TelemetryEvent {
	if protoEvent == nil {
		return nil
	}

	attributes := make(map[string]interface{})
	for k, v := range protoEvent.Attributes {
		attributes[k] = convertTelemetryValue(v)
	}

	return &TelemetryEvent{
		EventID:           protoEvent.EventId,
		SourceComponentID: protoEvent.SourceComponentId,
		EventType:         protoEvent.EventType,
		Timestamp:         time.Unix(0, protoEvent.TimestampUnixNs),
		Attributes:        attributes,
		RawData:           protoEvent.RawData,
	}
}

// ConvertToProto converts an internal TelemetryEvent to a protobuf TelemetryEvent
func ConvertToProto(event *TelemetryEvent) *blackicev1.TelemetryEvent {
	if event == nil {
		return nil
	}

	attributes := make(map[string]*blackicev1.TelemetryValue)
	for k, v := range event.Attributes {
		attributes[k] = convertToTelemetryValue(v)
	}

	return &blackicev1.TelemetryEvent{
		EventId:           event.EventID,
		SourceComponentId: event.SourceComponentID,
		EventType:         event.EventType,
		TimestampUnixNs:   event.Timestamp.UnixNano(),
		Attributes:        attributes,
		RawData:           event.RawData,
	}
}

// ConvertAnomalyToProto converts an internal Anomaly to a protobuf Anomaly
func ConvertAnomalyToProto(anomaly *Anomaly) *blackicev1.Anomaly {
	if anomaly == nil {
		return nil
	}

	// Create metadata map for the proto Anomaly
	metadata := make(map[string]string)
	for k, v := range anomaly.Attributes {
		// Convert each attribute to string
		metadata[k] = fmt.Sprintf("%v", v)
	}

	result := &blackicev1.Anomaly{
		Id:                anomaly.AnomalyID,
		Description:       anomaly.Description,
		Confidence:        float32(anomaly.Confidence),
		DetectedAtUnixNs:  anomaly.DetectionTime.UnixNano(),
		DetectorId:        anomaly.DetectorID,
		Metadata:          metadata,
		Severity:          blackicev1.Anomaly_Severity(anomaly.Severity),
		SourceComponentId: anomaly.SourceComponentID,
		Category:          string(anomaly.Category),
		RelatedEventIds:   anomaly.RelatedEvents,
		AffectedResources: anomaly.AffectedResources,
		RemediationStatus: blackicev1.Anomaly_RemediationStatus(anomaly.RemediationStatus),
		TtpIdentifiers:    anomaly.TTPIdentifiers,
		MitreTechnique:    anomaly.MitreTechnique,
	}

	// Only set timestamp fields if they're not zero values
	if !anomaly.LastUpdated.IsZero() {
		result.LastUpdatedUnixNs = anomaly.LastUpdated.UnixNano()
	}

	if !anomaly.AnalyzedTime.IsZero() {
		result.AnalyzedAtUnixNs = anomaly.AnalyzedTime.UnixNano()
	}

	if anomaly.AnalystID != "" {
		result.AnalystId = anomaly.AnalystID
	}

	return result
}

// ConvertAnomalyFromProto converts a protobuf Anomaly to an internal Anomaly
func ConvertAnomalyFromProto(protoAnomaly *blackicev1.Anomaly) *Anomaly {
	if protoAnomaly == nil {
		return nil
	}

	// Convert attributes from string map to interface map
	attributes := make(map[string]interface{})
	for k, v := range protoAnomaly.Metadata {
		attributes[k] = v
	}

	anomaly := &Anomaly{
		AnomalyID:         protoAnomaly.Id,
		Description:       protoAnomaly.Description,
		Confidence:        float64(protoAnomaly.Confidence),
		DetectionTime:     time.Unix(0, protoAnomaly.DetectedAtUnixNs),
		DetectorID:        protoAnomaly.DetectorId,
		Attributes:        attributes,
		Severity:          SeverityLevel(protoAnomaly.Severity),
		SourceComponentID: protoAnomaly.SourceComponentId,
		Category:          Category(protoAnomaly.Category),
		RelatedEvents:     protoAnomaly.RelatedEventIds,
		AffectedResources: protoAnomaly.AffectedResources,
		RemediationStatus: RemediationStatus(protoAnomaly.RemediationStatus),
		TTPIdentifiers:    protoAnomaly.TtpIdentifiers,
		MitreTechnique:    protoAnomaly.MitreTechnique,
		AnalystID:         protoAnomaly.AnalystId,
	}

	// Convert timestamp fields if present
	if protoAnomaly.LastUpdatedUnixNs > 0 {
		anomaly.LastUpdated = time.Unix(0, protoAnomaly.LastUpdatedUnixNs)
	}

	if protoAnomaly.AnalyzedAtUnixNs > 0 {
		anomaly.AnalyzedTime = time.Unix(0, protoAnomaly.AnalyzedAtUnixNs)
	}

	return anomaly
}

// convertTelemetryValue converts a protobuf TelemetryValue to a Go native type
func convertTelemetryValue(value *blackicev1.TelemetryValue) interface{} {
	if value == nil {
		return nil
	}

	switch v := value.ValueType.(type) {
	case *blackicev1.TelemetryValue_StringValue:
		return v.StringValue
	case *blackicev1.TelemetryValue_IntValue:
		return v.IntValue
	case *blackicev1.TelemetryValue_DoubleValue:
		return v.DoubleValue
	case *blackicev1.TelemetryValue_BoolValue:
		return v.BoolValue
	case *blackicev1.TelemetryValue_BytesValue:
		return v.BytesValue
	default:
		return nil
	}
}

// convertToTelemetryValue converts a Go native type to a protobuf TelemetryValue
func convertToTelemetryValue(value interface{}) *blackicev1.TelemetryValue {
	if value == nil {
		return nil
	}

	switch v := value.(type) {
	case string:
		return &blackicev1.TelemetryValue{
			ValueType: &blackicev1.TelemetryValue_StringValue{
				StringValue: v,
			},
		}
	case int:
		return &blackicev1.TelemetryValue{
			ValueType: &blackicev1.TelemetryValue_IntValue{
				IntValue: int64(v),
			},
		}
	case int64:
		return &blackicev1.TelemetryValue{
			ValueType: &blackicev1.TelemetryValue_IntValue{
				IntValue: v,
			},
		}
	case float64:
		return &blackicev1.TelemetryValue{
			ValueType: &blackicev1.TelemetryValue_DoubleValue{
				DoubleValue: v,
			},
		}
	case bool:
		return &blackicev1.TelemetryValue{
			ValueType: &blackicev1.TelemetryValue_BoolValue{
				BoolValue: v,
			},
		}
	case []byte:
		return &blackicev1.TelemetryValue{
			ValueType: &blackicev1.TelemetryValue_BytesValue{
				BytesValue: v,
			},
		}
	default:
		return &blackicev1.TelemetryValue{
			ValueType: &blackicev1.TelemetryValue_StringValue{
				StringValue: "",
			},
		}
	}
}
