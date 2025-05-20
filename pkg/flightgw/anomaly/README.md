# BlackIce Anomaly Detection System

The anomaly detection system provides real-time monitoring and detection of abnormal behavior patterns within the BlackIce Flight Gateway. It integrates with the telemetry system to collect events and metrics, and applies various detection algorithms to identify potential security issues.

## Key Features

- **Real-time anomaly detection** based on statistical models, behavioral patterns, and volume analysis
- **MITRE ATT&CK integration** with technique IDs and TTP (Tactics, Techniques, Procedures) identification
- **Remediation tracking** from detection through analysis and resolution
- **Analyst feedback loop** to improve detection accuracy over time
- **Enhanced context** with affected resources, related events, and categorization
- **Trust score integration** for comprehensive security posture assessment

## Components

### Service

The `AnomalyService` exposes a gRPC API for submitting telemetry, querying anomalies, and providing feedback. Key operations include:

- `SubmitTelemetry`: Stream telemetry events for analysis
- `QueryAnomalies`: Search for anomalies by time, severity, source, etc.
- `GetAnomalyDetails`: Retrieve detailed information about specific anomalies
- `ProvideFeedback`: Allow analysts to provide input on detected anomalies
- `GetDetectorStatus`: Monitor the operational status of detectors

### Detectors

The system includes multiple detector types:

1. **StatisticalThresholdDetector**: Identifies numeric values that deviate significantly from baseline patterns
2. **VolumeAnomalyDetector**: Detects unusual event volumes within specific time windows
3. **BehavioralPatternDetector**: Recognizes suspicious sequences of events

Each detector analyzes events in real-time and generates anomalies with comprehensive metadata.

### Client

The client library provides convenient access to the anomaly detection service with:

- Buffering and batching for efficient event submission
- Automatic reconnection for resilience
- Query capabilities for anomaly analysis

## Anomaly Structure

Anomalies include rich context with fields such as:

- Basic identification (ID, source, detector, timestamps)
- Severity and confidence indicators
- Categorization for classification
- Related event IDs for correlation
- Affected resources to identify impact scope
- Remediation status tracking
- TTP identifiers and MITRE technique references
- Analyst feedback and timestamps

## Integration with Other Systems

- **Telemetry**: Collects and processes events from all system components
- **Trust Scoring**: Factors anomalies into trust score calculations
- **Panic System**: Escalates critical anomalies to system-wide response
- **Storage**: Preserves anomaly history for future analysis

## Usage

1. Start the anomaly service:

   ```
   ./bin/anomalyservice --port=8089 --enable-std-detectors
   ```

2. Use the client to send telemetry:

   ```go
   client, err := anomaly.NewClient(config)
   if err != nil {
       log.Fatal().Err(err).Msg("Failed to create anomaly client")
   }
   
   event := &anomaly.TelemetryEvent{
       EventID:           "evt-123",
       SourceComponentID: "auth-service",
       EventType:         "authentication",
       Timestamp:         time.Now(),
       Attributes: map[string]interface{}{
           "user_id": "user-abc",
           "action": "login_attempt",
           "success": false,
       },
   }
   
   if err := client.SendEvent(event); err != nil {
       log.Error().Err(err).Msg("Failed to send event")
   }
   ```

3. Query for detected anomalies:

   ```go
   anomalies, err := client.QueryAnomalies(
       context.Background(),
       time.Now().Add(-24*time.Hour),
       time.Now(),
       "",
       "",
       anomaly.SeverityLow,
   )
   ```

## Testing

Use the provided test script to verify anomaly detection functionality:

```
./scripts/test_anomaly_integration.sh
```
