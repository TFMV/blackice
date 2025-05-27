<p align="center">
  <img src="logo/blackice-logo.svg" alt="BlackIce" height="120"/>
</p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/TFMV/blackice"><img src="https://goreportcard.com/badge/github.com/TFMV/blackice" alt="Go Report Card"/></a>
  <a href="https://github.com/TFMV/blackice/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"/></a>
  <a href="https://pkg.go.dev/github.com/TFMV/blackice"><img src="https://pkg.go.dev/badge/github.com/TFMV/blackice.svg" alt="Go Reference"/></a>
</p>

# BlackIce

> Betrayal-resilient data infrastructure that plans for compromise – and survives it.

BlackIce is a zero-trust data platform built around the conviction that **compromise is inevitable**. Instead of pretending attacks will never land, BlackIce designs for the _aftermath_: immediate containment, cryptographic provenance, adaptive degradation and forensic-first recovery – all while keeping the data moving.

_Not fail-safe. Breach-resilient. Tamper-aware. Unafraid._

---

## ✨ Highlights

| Feature | What it buys you |
|---------|------------------|
| 🚀 **Zero-Trust Flight Gateway** | PQ-TLS, Merkle integrity & adaptive circuit-breakers without sacrificing throughput. |
| 🛰 **Control Plane** | Signed config ledger, real-time fleet health, live policy pushes. |
| 🌀 **Mutation-Aware Storage** | Iceberg-style versioning with cryptographic commits & predictive rollback. |
| 🔍 **Self-Doubt Pipelines** | Behaviour + content anomaly detection that can auto-isolate or burn-back. |
| 🌩 **Decentralised Fallback** | Reed-Solomon / Shamir-sharded backups—survive region loss or legal seizure. |

---

## 🏗️ Layered Architecture

```txt
┌─────────────────────────────────────────────────────────────┐
│           Control Plane  (gRPC + Signed Ledger)             │
└─────────────────────────────────────────────────────────────┘
            ▲                      ▲                  
            │                      │                  
            │ Health / Policy      │ Panic Escalation 
            │                      │                  
┌───────────┴──────────┐   ┌───────┴───────┐    ┌──-──────-────────┐
│  Secure Flight GW    │ ← │ Anomaly Engine │ ← │  Panic Service   │
│  (pkg/flightgw)      │   └────────────────┘   └──────────────────┘
│  HMAC ▪ PQ-TLS ▪ CB  │                                     
└─────────┬────────────┘                                     
          │  Arrow Flight                                    
┌─────────┴────────────┐                                     
│    Data Stores       │  🗄️  Iceberg ▪ DuckDB ▪ S3 ▪ Storj/IPFS
└──────────────────────┘                                     
```

_Every layer can operate independently, yet all layers sign each other's work – creating an immutable chain-of-custody from raw ingress to long-term archive._

---

## 🚀 Quick Start

```bash
set -euo pipefail

# 1. Install CLI tools
go install github.com/TFMV/blackice/cmd/flightdata@latest
go install github.com/TFMV/blackice/cmd/flightclient@latest

# 2. Start an in-memory Secure Flight Gateway
flightdata --listen 0.0.0.0:8815 --ttl 10m

# 3. In another terminal, push & fetch a demo Arrow RecordBatch
flightclient put --file demo.arrow
flightclient get --ticket demo.arrow
```

**Docker one-liner:**

```bash
docker run -p 8815:8815 -p 9090:9090 ghcr.io/tfmv/blackice/flightdata:latest
```

---

## 🧩 Core Components

| Component | Purpose | Key Features |
|-----------|---------|--------------|
| **Secure Flight Gateway** <br/> `pkg/flightgw` | Drop-in Arrow Flight proxy with zero-trust defaults | • Post-Quantum gRPC-TLS (Kyber-x25519-HMAC)<br/>• SHA-256 HMAC per batch, optional Merkle stream verification<br/>• Battle-tested circuit-breaker with five-tier postures<br/>• Dynamic Trust Scoring across ten behavioural dimensions |
| **Control Plane** <br/> `pkg/controlplane` | Central nervous system that keeps every BlackIce node honest | • AuthN/Z pluggable providers, hardware-rooted attestations<br/>• Real-time component registry with heartbeat-based liveness<br/>• Signed configuration ledger with provenance and diffs<br/>• gRPC API from `proto/blackice/v1/controlplane.proto` |
| **Telemetry & Anomaly Detection** <br/> `pkg/flightgw/telemetry` | Multi-modal threat detection | • OpenTelemetry pipelines, Prometheus/Grafana export<br/>• High-dimensional detectors (Isolation Forest, VAEs, DBSCAN)<br/>• <0.1% false-positive rate, MITRE ATT&CK mapping |
| **Panic Service** <br/> `proto/blackice/v1/panic.proto` | Coordinated incident response | • Tier-0 … Tier-5 escalation, burn-back coordination<br/>• Multi-party attestation, immutable forensic ledger |

---

## 📊 Stability Matrix

| Component | Status | Notes |
|-----------|--------|-------|
| Flight Gateway | **Beta** | Production-ready, API stable |
| Control Plane | **Alpha** | Core features complete, API evolving |
| Anomaly Detection | **Beta** | High accuracy, tuning ongoing |
| Panic Service | **Alpha** | Protocol stable, implementation maturing |
| CLI Tools | **Stable** | Ready for daily use |

---

## 📂 Repository Map

```text
art/                 ↳ Vision documents, logos, diagrams
cmd/                 ↳ CLI entry-points (flightdata, flightserver, flightclient …)
proto/               ↳ gRPC / protobuf contracts
pkg/                 ↳ Production Go packages
  ├── controlplane/  ↳ Fleet orchestration & policy engine
  └── flightgw/      ↳ Zero-trust Arrow Flight gateway & helpers
       ├── server/        ↳ Flight server implementations
       ├── proxy/         ↳ Reverse proxy logic
       ├── crypto/        ↳ HMAC, PQ-TLS, Merkle, attestations
       ├── trust/         ↳ Dynamic trust scoring
       ├── anomaly/       ↳ Detectors & alert lifecycle
       └── telemetry/     ↳ Metrics, tracing, logging
```

---

## 🛠 Development

1. **Prerequisites:** Go 1.24+ and `buf` (for protobuf)
2. **Build & Test:** `make lint test` – runs `golangci-lint`, unit tests and race detector
3. **Protobuf:** `make proto` to regenerate gRPC stubs
4. **Dev Environment:** `make dev-shell` for containerized development

Linter config lives in `.golangci.yml`; CI runs on GitHub Actions.

---

## 🤝 Contributing

Bug reports, feature ideas and pull requests are welcome!

- 📖 **Documentation:** [GitHub Pages](https://tfmv.github.io/blackice)
- 💬 **Chat:** Join `#blackice` on [Matrix](https://matrix.to/#/#blackice:matrix.org)
- 🐛 **Good First Issues:** [Help wanted](https://github.com/TFMV/blackice/labels/good%20first%20issue)

Please see `CONTRIBUTING.md` for guidelines.

---

## 📜 License

```
SPDX-License-Identifier: MIT
```

© 2025 TFMV — [MIT License](LICENSE)
