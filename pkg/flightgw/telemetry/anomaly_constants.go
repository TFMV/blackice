package telemetry

import (
	"github.com/TFMV/blackice/pkg/flightgw/anomaly"
)

// Type aliases from the anomaly package
type AnomalyType = anomaly.Anomaly
type SeverityLevel = anomaly.SeverityLevel
type Category = anomaly.Category
type RemediationStatus = anomaly.RemediationStatus

// Local copies of anomaly severity levels to avoid import errors
const (
	// SeverityInfo represents informational level anomalies
	SeverityInfo = anomaly.SeverityInfo
	// SeverityLow represents low severity anomalies
	SeverityLow = anomaly.SeverityLow
	// SeverityMedium represents medium severity anomalies
	SeverityMedium = anomaly.SeverityMedium
	// SeverityHigh represents high severity anomalies
	SeverityHigh = anomaly.SeverityHigh
	// SeverityCritical represents critical severity anomalies
	SeverityCritical = anomaly.SeverityCritical
)

// Local copies of anomaly categories to avoid import errors
const (
	// CategoryConsistency represents anomalies in data consistency
	CategoryConsistency = anomaly.CategoryConsistency
	// CategoryTiming represents anomalies in timing patterns
	CategoryTiming = anomaly.CategoryTiming
	// CategoryVolume represents anomalies in data volume
	CategoryVolume = anomaly.CategoryVolume
	// CategoryBehavioral represents anomalies in behavioral patterns
	CategoryBehavioral = anomaly.CategoryBehavioral
	// CategoryNetwork represents anomalies in network patterns
	CategoryNetwork = anomaly.CategoryNetwork
	// CategorySystem represents anomalies in system behavior
	CategorySystem = anomaly.CategorySystem
	// CategoryAuthentication represents anomalies in authentication
	CategoryAuthentication = anomaly.CategoryAuthentication
	// CategoryAuthorization represents anomalies in authorization
	CategoryAuthorization = anomaly.CategoryAuthorization
	// CategoryCrypto represents anomalies in cryptographic operations
	CategoryCrypto = anomaly.CategoryCrypto
)

// Local copies of remediation status constants
const (
	// RemediationNone indicates no remediation has been started
	RemediationNone = anomaly.RemediationNone
	// RemediationPending indicates remediation is pending
	RemediationPending = anomaly.RemediationPending
	// RemediationInProgress indicates remediation is in progress
	RemediationInProgress = anomaly.RemediationInProgress
	// RemediationResolved indicates remediation is complete
	RemediationResolved = anomaly.RemediationResolved
	// RemediationFalsePositive indicates the anomaly was a false positive
	RemediationFalsePositive = anomaly.RemediationFalsePositive
	// RemediationEscalated indicates the anomaly was escalated
	RemediationEscalated = anomaly.RemediationEscalated
)
