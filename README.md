# SentinelFlow-rs

Network Security Visibility & Detection Platform in Rust

## Overview

SentinelFlow-rs is a lightweight, high-performance network security monitoring system that captures network traffic at the host level, transforms raw packets into structured Network Flow telemetry, and applies detection logic to identify security-relevant anomalies.

## Architecture

```text
┌─────────────────────────────────────────────────────┐
│                  Kubernetes Cluster                  │
│                                                     │
│  ┌──────────────────────────────────────────┐      │
│  │       Rust Security Sensor (DaemonSet)    │      │
│  │   Packet Capture → Flow Engine → Batch    │      │
│  └──────────────────────┬───────────────────┘      │
└─────────────────────────┼────────────────────────────┘
                          │
               ┌──────────┴──────────┐
               │    ClickHouse        │
               └──────────┬──────────┘
                          │
               ┌──────────┴──────────┐
               │   Grafana Dashboard  │
               └─────────────────────┘
```

## Quick Start

### Prerequisites

- Rust 1.75+ (stable)
- Docker (for ClickHouse)
- Kubernetes cluster (for production deployment)

### Development

```bash
# Clone the repository
git clone https://github.com/JacobRyu/sentinel-flow-rs.git
cd sentinel-flow-rs

# Install dependencies
cargo build

# Run tests
cargo nextest run

# Run linter
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format code
cargo fmt --all
```

### Running Locally

```bash
# Option 1: Docker only
docker run -d --name clickhouse \
  -p 8123:8123 -p 9000:9000 \
  clickhouse/clickhouse-server

# Run the sensor
cargo run --bin sentinel-sensor -- --config config/sensor.yaml

# Option 2: Local Kubernetes (kind)
# See docs/local-infrastructure.md for details

# Quick setup
./scripts/dev-deploy.sh

# Teardown
./scripts/dev-teardown.sh

# View logs
./scripts/dev-logs.sh
```

## Project Structure

```text
sentinel-flow-rs/
├── crates/
│   ├── sentinel-sensor/          # Main sensor binary
│   ├── sentinel-parser/          # Packet parsing library
│   ├── sentinel-flow/            # Flow engine library
│   ├── sentinel-detection/       # Detection engine library
│   └── sentinel-enrichment/      # Kubernetes metadata enrichment
├── config/                       # Configuration files
├── deploy/
│   ├── kubernetes/               # Kubernetes manifests
│   └── helm/                     # Helm values
├── docs/                         # Documentation
├── scripts/                      # Development scripts
└── tests/                        # Integration tests
```

## Configuration

See [docs/configuration.md](docs/configuration.md) for detailed configuration options.

## Development

### Prerequisites

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Install cargo-nextest
cargo install cargo-nextest

# Install cargo-deny
cargo install cargo-deny

# Install typos
cargo install typos-cli

# Install pre-commit hooks
pre-commit install
```

### Available Commands

```bash
# Build all crates
cargo build --workspace

# Run all tests
cargo nextest run --workspace

# Run linter
cargo clippy --workspace --all-targets --all-features -- -D warnings

# Format code
cargo fmt --all

# Check dependencies
cargo deny check

# Check for typos
typos

# Generate changelog
git cliff --output CHANGELOG.md
```

## License

MIT
