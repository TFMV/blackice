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
  - Transform mode: Data transformation capabilities
- **Resilience Features**:
  - Circuit breaker pattern to prevent cascading failures
  - Health monitoring endpoints for service status
  - TLS session resumption for improved reconnection performance
- **Dynamic Configuration**:
  - Real-time policy updates without service restart
  - Centralized policy management with versioning

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

## Circuit Breaker Pattern

The gateway implements a circuit breaker pattern for resilient operations, protecting against cascading failures when upstream services are degraded:

- Automatic detection of failed requests
- Configurable failure thresholds and recovery periods
- Half-open state for testing recovery without flooding upstream services

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
