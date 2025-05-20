# blackice

# Secure Flight Gateway

The Secure Flight Gateway is a zero-trust proxy for Apache Arrow Flight traffic, providing a secure integration point for BlackIce. It adds cryptographic verification, dynamic trust scoring, and security monitoring while maintaining high performance.

## Features

- **Bidirectional Flight Proxy**: Forward and verify Arrow Flight traffic between clients and upstream services
- **Security Verification**: HMAC validation, Merkle stream verification, and attestation verification
- **Trust Scoring**: Evaluate and score data sources based on multiple factors
- **Multiple Operational Modes**:
  - Pass-through mode: Minimal validation and forwarding
  - Trust-boundary mode: Full security verification and trust enforcement
  - Transformation mode: Data processing during transit
- **Post-Quantum Security**: Hybrid and PQ cryptography support with Kyber and Dilithium
- **Access Control**: Fine-grained policy-based access controls for data access
- **Advanced Circuit Breaker**: Military-grade resilience with adaptive thresholds and advanced posture states
- **Advanced Telemetry Framework**:
  - Integrated metrics collection via Prometheus and OpenTelemetry
  - Zero-trust secure telemetry endpoints with authentication
  - Comprehensive security and performance metrics
  - Support for high-assurance environments

## Trust Scoring System

The BlackIce Flight Gateway includes a sophisticated trust scoring system with the following capabilities:

- **Dynamic Multi-Category Trust Evaluation**: Scores data sources across multiple dimensions:
  - Consistency: Statistical properties compared to historical patterns
  - Timing: Detection of anomalous submission patterns
  - Verification: Tracking of cryptographic validation failures
  - External: Integration with third-party threat intelligence
  - Content, Schema, Volume, Network: Advanced behavioral analysis

- **System-Wide Threat Intelligence**:
  - Automated threat feed integration
  - Global threat level management
  - Defensive posture adjustments based on threat conditions
  - Cross-source consensus analysis

- **Adaptive Trust Tiers**:
  - Five-tier trust classification system
  - Detailed requirements for each tier
  - Automatic tier transitions based on behavior

- **Temporal Pattern Analysis**:
  - Detection of abnormal behavior patterns over time
  - Sophisticated anomaly detection with confidence scoring
  - Trust trends and anomaly rate tracking

## Circuit Breaker System

The gateway includes a resilient circuit breaker implementation:

- **Standard Circuit Breaker Patterns**: Three-state operation (Open, Closed, Half-Open)
- **Tiered Operational Modes**: Normal, Restricted, Emergency postures
- **Context-Aware Decisions**: Adjusts behavior based on system-wide conditions
- **Adaptive Thresholds**: Learns and adjusts failure thresholds over time

## Usage

```
go run cmd/flightgw/main.go -config path/to/config.yaml
```

## Configuration

See example config in `config/example-config.yaml`

## Contributing

Contributions welcome! See CONTRIBUTING.md

## License

© BlackIce Collective

## Getting Started

### Prerequisites

- Go 1.18+
- Apache Arrow Flight
- Docker (optional)

### Building

```bash
cd blackice
go build -o bin/flightgw cmd/flightgw/main.go
```

### Running with Docker

```bash
cd blackice
docker build -t blackice/flightgw -f cmd/flightgw/Dockerfile .
docker run -p 8815:8815 -p 9090:9090 -p 9091:9091 blackice/flightgw
```

### Configuration

The Secure Flight Gateway is configured via a YAML file:

```bash
bin/flightgw -config cmd/flightgw/config.yaml
```

See `cmd/flightgw/config.yaml` for configuration options.

## Health Monitoring

The gateway exposes health check endpoints for monitoring and integration with orchestration systems:

- `/health`: Basic health status endpoint
- `/ready`: Readiness check for load balancers
- `/metrics`: Detailed metrics for monitoring systems

## Military-Grade Circuit Breaker

The gateway implements a military-grade circuit breaker pattern that provides enhanced resilience against cascading failures and sophisticated attacks:

### Multi-Tier Protection

- 5 operational tiers (Normal, Cautious, Restricted, Minimal, Emergency)
- Automated tier adjustments based on failure patterns
- Different thresholds and timeouts for each tier level

### Context-Aware Decision Making

- Priority-based request handling allows critical operations to bypass circuit breaker
- Request categorization for fine-grained failure handling
- Configurable policies for different request types

### Advanced Failure Detection

- Categorized failures with specialized handling for security-related issues
- Latency-based circuit breaking to detect degraded performance
- Attack pattern recognition through error fingerprinting

### Self-Healing Capabilities

- Automatic recovery mechanisms with graduated healing
- Configurable retry strategies with backoff and jitter
- Manual intervention capabilities through admin API

### Integration with System-Wide Protection

- Coordination with Panic Service for comprehensive threat response
- Graceful degradation during system-wide emergencies
- Detailed telemetry for post-incident analysis

### Admin API Endpoints

- `/admin/circuit/state`: Get current circuit breaker state
- `/admin/circuit/force`: Manually force circuit open/closed
- `/admin/circuit/tier`: Adjust protection tier
- `/admin/circuit/metrics`: View performance metrics
- `/admin/circuit/failures`: Analyze recent failures and detected patterns
- `/admin/circuit/recovery`: Manage self-healing capabilities

## Dynamic Trust Scoring System

The gateway implements a military-grade dynamic trust scoring system that automatically evaluates and adjusts confidence in data sources based on behavioral patterns and contextual factors.

### Multi-dimensional Trust Evaluation

- 10 evaluation categories (Consistency, Timing, Verification, External, Volume, Schema, Content, Behavioral, Network, Contextual)
- Weighted scoring algorithm with configurable category importance
- Tiered trust levels with graduated requirements for advancement

### Behavioral Pattern Analysis

- Automated baseline establishment through statistical modeling
- Real-time anomaly detection using standard deviation analysis
- Pattern correlation across multiple behavioral dimensions
- Contextual awareness of system-wide patterns and threats

### Advanced Anomaly Detection

- Z-score based outlier identification with configurable thresholds
- Graduated severity levels (Info, Low, Medium, High, Critical)
- Multi-factor anomaly classification with confidence scoring
- Time-series analysis for identifying subtle behavioral shifts

### Self-adapting Trust Mechanisms

- Dynamic threshold adjustment based on historical patterns
- Category-specific learning rates for optimized adaptation
- Temporal decay functions to emphasize recent behavioral data
- Configurable adaptation modes (Conservative, Balanced, Aggressive)

### Integration with Security Systems

- Threat intelligence feed integration for external validation
- Coordination with Panic Service during system-wide incidents
- Contextual trust adjustments based on system threat level
- Forensic evidence capture for security investigations

### Trust Management API Endpoints

- `/admin/trust/sources`: Manage registered data sources
- `/admin/trust/scores`: View and adjust trust scores
- `/admin/trust/anomalies`: Review detected behavioral anomalies
- `/admin/trust/patterns`: Examine established behavioral patterns
- `/admin/trust/thresholds`: Configure adaptive threshold settings
- `/admin/trust/tiers`: View and manage trust tier requirements

## Advanced Telemetry Framework

The gateway includes a high-assurance telemetry system that provides comprehensive visibility while maintaining security:

### Integrated Metrics Collection

- Metrics are core to the system, not a bolt-on component
- Hooks architecture for automatic metric emission during normal operations
- Complete visibility into circuit breaker state, trust scores, and system health
- Automatic metric generation with minimal code overhead

### Industry-Standard Protocols

- Support for Prometheus metrics exposition
- OpenTelemetry integration for distributed tracing
- Structured logging with correlation IDs
- Metrics endpoint with RBAC and authentication

### Security-First Design

- Configurable metric security levels for sensitive data
- Rate limiting for metrics endpoints to prevent DoS
- Authentication and authorization for metrics access
- Metrics sanitization to prevent information leakage

### Comprehensive System Observability

- Circuit breaker state and failure analysis
- Trust system metrics with source distribution tracking
- System-wide threat level monitoring
- Performance metrics for request handling and latency

### Health and Status Monitoring

- Component health reporting
- System-wide defensive posture tracking
- Anomaly rate monitoring by category
- Warning indicators for potential security issues

### Operational Benefits

- Early warning of system degradation
- Security incident detection and response
- Capacity planning and performance optimization
- Post-incident analysis and investigation

## Policy Management

Dynamic policy management allows updating security and routing policies without service restart:

- Versioned policies with runtime updates
- Support for security, routing, rate limiting, and access control policies
- Policy persistence with automatic loading on startup

## Development

The gateway is implemented as a Go package with modular components:

- `pkg/flightgw/server`: Flight server implementation
- `pkg/flightgw/crypto`: Cryptographic components (HMAC, attestation, Merkle)
- `pkg/flightgw/trust`: Trust scoring system and source registry
- `pkg/flightgw/config`: Configuration management
- `pkg/flightgw/proxy`: Proxy implementation
- `pkg/flightgw/telemetry`: Integrated observability framework

## API Endpoints

### Flight Protocol Endpoints

- Default port: 8815
- Secured with TLS and optional post-quantum cryptography
- Supports all Arrow Flight RPC methods

### Administrative Endpoints

- Default port: 9090
- `/health`: Overall service health
- `/ready`: Service readiness status
- `/metrics`: Performance metrics and diagnostics

### Policy Management API

- Default port: 9091
- REST API for managing security policies
- Supports CRUD operations for all policy types
