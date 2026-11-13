# Phase 6: Kafka Transport — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in Kafka transport between the sensor and ClickHouse (`output.mode: direct | kafka`) plus a new `sentinel-sink` consumer crate, so flows reach `network_flows` through the `netflow.raw` topic.

**Architecture:** The sensor's `FlowWriter` (batch/retry/timeout/metrics) stays untouched; `output.mode` only swaps the `FlowStore` implementation (`ClickHouseStore` vs new `KafkaFlowStore` — rdkafka FutureProducer, one JSON message per `FlowRow`, partition key = xxh3_64 of the 5-tuple). A new workspace crate `sentinel-sink` consumes `netflow.raw` (consumer group `clickhouse-sinker`), rebuilds `FlowRow`s, and reuses the sensor's `FlowWriter` + `ClickHouseStore` through a new lib target on the sensor crate. Detection events keep their direct ClickHouse path in both modes.

**Tech Stack:** rdkafka 0.39 (`cmake-build`), xxhash-rust `xxh3_64` (already a workspace dep), serde_json, existing clickhouse 0.11 / prometheus / tokio stack.

**Spec:** `docs/superpowers/specs/2026-11-13-phase6-kafka-design.md`

## Global Constraints

- Rust 2024 workspace; `cargo fmt` max_width = 100.
- Gates before every commit (all must be clean): `cargo nextest run --workspace`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`, `cargo fmt --all -- --check`.
- Baseline test count is **107 passed**; it must stay green at every task boundary.
- Never use `--no-verify`; pre-commit hooks must pass.
- Conventional Commits; no AI attribution (no Co-Authored-By).
- Stage ONLY the files listed in the task. The user's uncommitted files (`README.md` modified, untracked `docs/configuration.md`, `docs/posts/`, `.ua/`) must never be staged or modified.
- `output.mode: direct` (the default) must be behaviorally identical to today. No existing test may change behavior expectations; new code is additive only.
- Delivery semantics: at-least-once everywhere. Duplicate rows in ClickHouse are an accepted property (established ruling).
- Topic scope: `netflow.raw` only. `security.events` stays direct in both modes.
- rdkafka dep (Task 1 adds it): `rdkafka = { version = "0.39", default-features = false, features = ["tokio", "cmake-build", "libz-static"] }`. `cmake-build` compiles librdkafka from source → requires `cmake` and a C compiler; if the environment lacks them, install (`brew install cmake`) and report.
- No test may require a live Kafka broker or ClickHouse. E2E is manual via docker-compose (Task 7); unit tests use mocks only.
- No subagents inside an implementing task; report deviations with reasons instead of improvising silently.

**Spec deviations recorded in this plan (intentional, already decided):**

| Spec says | Plan does | Reason |
|---|---|---|
| `twox-hash` `xxh3_64` | `xxhash-rust::xxh3::xxh3_64` | Already a workspace dependency (sentinel-flow uses it); same 64-bit xxh3 function, no new dep |
| Commit offset "after ClickHouse batch write success" | Lagged commit on a 5s tick | `FlowWriter`'s API does not expose per-batch write completion; a lagging tick never commits ahead of guaranteed writes, so a crash only ever causes redelivery (duplicates), never loss |
| `serde_json` implicitly available | Add `serde_json` to sensor deps | sensor Cargo.toml lacks it today |
| Sink metrics served like sensor (hyper) | Minimal tokio `TcpListener` responder | sensor's `server.rs` is bin-private; duplicating hyper wiring for one endpoint is not worth it |

## File Structure

| File | Task | Responsibility |
|---|---|---|
| `Cargo.toml` (workspace root) | 1 | rdkafka workspace dep; `sentinel-sink` member |
| `crates/sentinel-sink/Cargo.toml`, `src/main.rs` | 1, 6 | sink crate skeleton → full consumer binary |
| `crates/sentinel-sensor/src/lib.rs` | 2 | new lib target: `pub mod config; pub mod metrics; pub mod output;` |
| `crates/sentinel-sensor/src/main.rs`, `capture.rs`, `flow.rs`, `server.rs` | 2, 5 | bin switches `crate::config`→`sentinel_sensor::config` etc.; Task 5 adds store selection |
| `crates/sentinel-sensor/src/output/mod.rs` | 2 | pub re-exports for sink reuse (additive) |
| `crates/sentinel-sensor/src/output/kafka_store.rs` | 5 | `KafkaFlowStore` + key/payload functions |
| `crates/sentinel-sensor/src/config.rs` | 3 | `OutputMode`, `KafkaOutputConfig`, validate rules |
| `crates/sentinel-sensor/src/metrics.rs` | 4 | 2 kafka counters |
| `crates/sentinel-sensor/Cargo.toml` | 5 | adds `serde_json` |
| `crates/sentinel-sink/src/{config,adapter,consumer,metrics}.rs` | 6 | sink internals |
| `config/sensor.yaml` | 3 | `mode: direct` + kafka block |
| `config/sink.yaml` | 6 | sink defaults |
| `docker-compose.kafka.yml`, `docs/runbooks/kafka-replay.md` | 7 | manual E2E + replay runbook |

---

### Task 1: Workspace dependency and sentinel-sink skeleton

**Files:**
- Modify: `Cargo.toml` (workspace root)
- Create: `crates/sentinel-sink/Cargo.toml`
- Create: `crates/sentinel-sink/src/main.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: workspace dep usable as `rdkafka = { workspace = true }` in any member crate; empty `sentinel-sink` member crate that compiles.

- [ ] **Step 1: Add rdkafka and the member to the workspace root**

In `Cargo.toml` (workspace root), add to `[workspace.dependencies]` (alphabetical position):

```toml
rdkafka = { version = "0.39", default-features = false, features = ["tokio", "cmake-build", "libz-static"] }
```

Add to the `members` list:

```toml
    "crates/sentinel-sink",
```

- [ ] **Step 2: Create the sink crate manifest**

Check `crates/sentinel-detection/Cargo.toml` first: if its `[package]` uses `version.workspace = true` / `edition.workspace = true`, mirror that style in the file below (replace the two inline values with the inherited form) and report it as a mechanical deviation.

`crates/sentinel-sink/Cargo.toml`:

```toml
[package]
name = "sentinel-sink"
version = "0.1.0"
edition = "2024"

[dependencies]
tokio = { workspace = true }
```

- [ ] **Step 3: Create the sink entrypoint**

`crates/sentinel-sink/src/main.rs`:

```rust
fn main() {}
```

- [ ] **Step 4: Verify the skeleton builds (rdkafka compiles librdkafka via cmake)**

Run: `cargo build -p sentinel-sink`
Expected: success. If the build fails asking for `cmake` or a C compiler, install cmake (`brew install cmake`) and retry; if still blocked, stop and report `BLOCKED` with the exact error.

- [ ] **Step 5: Run all gates**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: 107 passed; clippy and fmt clean.

- [ ] **Step 6: Commit**

```bash
git add Cargo.toml Cargo.lock crates/sentinel-sink/Cargo.toml crates/sentinel-sink/src/main.rs
git commit -m "chore(deps): add rdkafka workspace dependency and sentinel-sink crate"
```

---

### Task 2: Expose sensor modules via a lib target (sink reuse prerequisite)

The sensor crate is bin-only today; `sentinel-sink` must reuse `FlowWriter`, `ClickHouseStore`, `FlowRow`, and `WRITE_TIMEOUT`. This task creates a lib target that owns `config`, `metrics`, and `output`, adds the pub re-exports the sink needs, and switches the bin to consume the lib. Zero behavior change.

**Files:**
- Create: `crates/sentinel-sensor/src/lib.rs`
- Modify: `crates/sentinel-sensor/src/main.rs` (module declarations + use lines)
- Modify: `crates/sentinel-sensor/src/capture.rs`, `flow.rs`, `server.rs` (mechanical path rewrite)
- Modify: `crates/sentinel-sensor/src/output/mod.rs` (re-export visibility)

**Interfaces:**
- Consumes: existing modules unchanged.
- Produces (for Task 6): `sentinel_sensor::config::SensorConfig`, `sentinel_sensor::config::OutputConfig`, `sentinel_sensor::metrics::SensorMetrics`, `sentinel_sensor::output::{FlowStore, FlowRow, FlowWriter, ClickHouseStore, WRITE_TIMEOUT}` — all pub.

- [ ] **Step 1: Create the lib root**

`crates/sentinel-sensor/src/lib.rs`:

```rust
//! Sentinel sensor library.
//!
//! `config`, `metrics`, and `output` are compiled into this lib so that
//! `sentinel-sink` can reuse the flow writer and ClickHouse store. The
//! `capture`, `flow`, and `server` modules stay private to the binary.

pub mod config;
pub mod metrics;
pub mod output;
```

- [ ] **Step 2: Point the binary at the lib**

In `crates/sentinel-sensor/src/main.rs`:

Remove these three module declarations (keep `mod capture;`, `mod flow;`, `mod server;`):

```rust
mod config;
mod metrics;
mod output;
```

Replace the existing output/config/metrics use lines with:

```rust
use sentinel_sensor::config::SensorConfig;
use sentinel_sensor::metrics::SensorMetrics;
use sentinel_sensor::output::{ClickHouseEventStore, ClickHouseStore, EventWriter, FlowWriter, WRITE_TIMEOUT};
```

- [ ] **Step 3: Rewrite crate-internal paths in the bin-local modules**

In `crates/sentinel-sensor/src/capture.rs`, `flow.rs`, and `server.rs`, mechanically replace every `crate::config` with `sentinel_sensor::config` and every `crate::metrics` with `sentinel_sensor::metrics` (use ripgrep `rg 'crate::(config|metrics)' crates/sentinel-sensor/src/{capture,flow,server}.rs` to enumerate hits first). Do not touch files under `output/` — inside the lib, `crate::config` / `crate::metrics` already resolve correctly.

- [ ] **Step 4: Widen the output re-exports the sink needs**

In `crates/sentinel-sensor/src/output/mod.rs`, replace the existing `pub(crate) use` block with (mod declarations stay untouched):

```rust
pub use clickhouse::{ClickHouseStore, FlowStore};
pub(crate) use event_store::ClickHouseEventStore;
pub(crate) use event_writer::EventWriter;
pub use row::FlowRow;
pub use writer::{FlowWriter, WRITE_TIMEOUT};
```

(`FlowStore` lives in `clickhouse.rs`; `FlowRow` in `row.rs`. These are additive visibility changes — internal `pub(crate)` users are unaffected.)

- [ ] **Step 5: Run all gates**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: 107 passed (no new tests, no behavior change); clippy/fmt clean.

- [ ] **Step 6: Commit**

```bash
git add crates/sentinel-sensor/src/lib.rs crates/sentinel-sensor/src/main.rs crates/sentinel-sensor/src/capture.rs crates/sentinel-sensor/src/flow.rs crates/sentinel-sensor/src/server.rs crates/sentinel-sensor/src/output/mod.rs
git commit -m "refactor(sensor): expose shared modules via lib target"
```

### Task 3: Output mode configuration (`direct | kafka`)

**Files:**
- Modify: `crates/sentinel-sensor/src/config.rs`
- Modify: `config/sensor.yaml`

**Interfaces:**
- Consumes: `OutputConfig` / `SensorConfig::validate()` (Task 2 lib).
- Produces (for Tasks 5/6): `config::OutputMode` (`#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]`, serde `direct`/`kafka` lowercase, default `Direct`), `config::KafkaOutputConfig { brokers: Vec<String>, topic: String }` (serde default), `OutputConfig { ..., mode: OutputMode, kafka: KafkaOutputConfig }`, validate rule: `mode == Kafka` ⇒ brokers and topic non-empty.

- [ ] **Step 1: Write the failing tests**

Append to the existing `#[cfg(test)] mod tests` in `crates/sentinel-sensor/src/config.rs`:

```rust
    #[test]
    fn output_mode_defaults_to_direct() {
        let config = SensorConfig::default();
        assert_eq!(config.output.mode, OutputMode::Direct);
    }

    #[test]
    fn kafka_mode_requires_brokers_and_topic() {
        let mut config = SensorConfig::default();
        config.output.mode = OutputMode::Kafka;
        assert!(config.validate().is_err());

        config.output.kafka.brokers = vec!["localhost:9092".to_string()];
        assert!(config.validate().is_err());

        config.output.kafka.topic = "netflow.raw".to_string();
        config.validate().unwrap();
    }

    #[test]
    fn output_config_parses_kafka_block() {
        // OutputConfig's scalar fields are required by serde (no per-field
        // defaults), so the fixture supplies them alongside the new keys.
        let yaml = "clickhouse_url: http://localhost:8123\nclickhouse_database: sentinel\nbatch_size: 1000\nbatch_timeout_ms: 500\nmode: kafka\nkafka:\n  brokers:\n    - localhost:9092\n  topic: netflow.raw";
        let output: OutputConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(output.mode, OutputMode::Kafka);
        assert_eq!(output.kafka.brokers, vec!["localhost:9092".to_string()]);
        assert_eq!(output.kafka.topic, "netflow.raw");
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo nextest run -p sentinel-sensor config`
Expected: FAIL with unresolved `OutputMode` / missing `mode` field (compile error counts as red).

- [ ] **Step 3: Implement the config types**

In `crates/sentinel-sensor/src/config.rs`, add above the `OutputConfig` definition:

```rust
/// Which sink receives exported flow rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputMode {
    /// Write directly to ClickHouse (default; existing behavior).
    #[default]
    Direct,
    /// Publish each row to the Kafka topic `output.kafka.topic`.
    Kafka,
}

/// Kafka producer settings, used only when `output.mode` is `kafka`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KafkaOutputConfig {
    /// Bootstrap broker list, e.g. ["localhost:9092"].
    #[serde(default)]
    pub brokers: Vec<String>,
    /// Destination topic, e.g. "netflow.raw".
    #[serde(default)]
    pub topic: String,
}
```

Add two fields at the end of `OutputConfig` (after `batch_timeout_ms`):

```rust
    /// Output transport selection; `kafka` uses the `kafka` sub-config below.
    #[serde(default)]
    pub mode: OutputMode,
    /// Kafka producer settings; only read when `mode` is `kafka`.
    #[serde(default)]
    pub kafka: KafkaOutputConfig,
```

Extend `SensorConfig::validate()` right after the existing `output.batch_timeout_ms` check:

```rust
        if self.output.mode == OutputMode::Kafka {
            ensure!(
                !self.output.kafka.brokers.is_empty(),
                "output.kafka.brokers must not be empty when output.mode is kafka"
            );
            ensure!(
                !self.output.kafka.topic.is_empty(),
                "output.kafka.topic must not be empty when output.mode is kafka"
            );
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo nextest run -p sentinel-sensor config`
Expected: the 3 new tests pass; existing config tests unchanged.

- [ ] **Step 5: Extend config/sensor.yaml**

Open `config/sensor.yaml`. Insert `mode: direct` as the first key under the `output:` section, and append this block after the last existing key of the `output:` section (leave every existing key untouched):

```yaml
  mode: direct
```

and

```yaml
  kafka:
    brokers:
      - localhost:9092
    topic: netflow.raw
```

(The shipped default stays `direct`; the kafka block documents the selectable values and feeds `--config` round-trips.)

- [ ] **Step 6: Run all gates**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: 110 passed (107 + 3); clippy/fmt clean.

- [ ] **Step 7: Commit**

```bash
git add crates/sentinel-sensor/src/config.rs config/sensor.yaml
git commit -m "feat(sensor): output mode configuration for kafka"
```

---

### Task 4: Kafka produce metrics

**Files:**
- Modify: `crates/sentinel-sensor/src/metrics.rs`

**Interfaces:**
- Consumes: `SensorMetrics::new()` registration pattern (Task 2 lib).
- Produces (for Task 5): `SensorMetrics { kafka_produced_total: IntCounter, kafka_produce_errors_total: IntCounter }` — incremented inside `KafkaFlowStore` (per-message success / per-failed-attempt), not by `FlowWriter`.

- [ ] **Step 1: Write the failing test**

Append to the existing `#[cfg(test)] mod tests` in `crates/sentinel-sensor/src/metrics.rs` (mirror the structure of `detection_metrics_registered`):

```rust
    #[test]
    fn kafka_metrics_registered() {
        let metrics = SensorMetrics::new().unwrap();
        metrics.kafka_produced_total.inc_by(7);
        metrics.kafka_produce_errors_total.inc();
        let export = metrics.export().unwrap();
        assert!(export.contains("sentinel_kafka_produced_total 7"));
        assert!(export.contains("sentinel_kafka_produce_errors_total 1"));
    }
```

If `export()`'s return type makes `.unwrap()` not compile, adapt mechanically to how `detection_metrics_registered` consumes it and report the deviation.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo nextest run -p sentinel-sensor metrics`
Expected: FAIL — no field `kafka_produced_total` (compile error counts as red).

- [ ] **Step 3: Add the two counters**

In `crates/sentinel-sensor/src/metrics.rs`, add to the `SensorMetrics` struct (after `detection_failed_writes_total`):

```rust
    pub kafka_produced_total: IntCounter,
    pub kafka_produce_errors_total: IntCounter,
```

In `SensorMetrics::new()`, after the detection metric registrations, following the existing construction pattern:

```rust
        let kafka_produced_total = IntCounter::with_opts(prometheus::opts!(
            "sentinel_kafka_produced_total",
            "Kafka messages successfully produced by the flow output store"
        ))?;
        registry.register(Box::new(kafka_produced_total.clone()))?;
        let kafka_produce_errors_total = IntCounter::with_opts(prometheus::opts!(
            "sentinel_kafka_produce_errors_total",
            "Total failed Kafka produce attempts (including retries)"
        ))?;
        registry.register(Box::new(kafka_produce_errors_total.clone()))?;
```

and add both fields to the returned `Self { ... }` initializer.

(The struct already carries `#[allow(dead_code)]`; the counters become live in Task 5.)

- [ ] **Step 4: Run all gates**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: 111 passed; clippy/fmt clean.

- [ ] **Step 5: Commit**

```bash
git add crates/sentinel-sensor/src/metrics.rs
git commit -m "feat(sensor): kafka produce metrics"
```

### Task 5: KafkaFlowStore and mode-based output wiring

The store alone would be dead code under `-D warnings` (no consumer until main.rs selects it), so the store and its wiring land as one task.

**Files:**
- Modify: `crates/sentinel-sensor/Cargo.toml` (add serde_json)
- Create: `crates/sentinel-sensor/src/output/kafka_store.rs`
- Modify: `crates/sentinel-sensor/src/output/mod.rs` (declare the module)
- Modify: `crates/sentinel-sensor/src/main.rs` (store selection by mode)

**Interfaces:**
- Consumes: `FlowStore` trait (`write_batch(&mut self, &[FlowRow]) -> Result<(), Self::Error>`, `Error: Display + Send + Sync + 'static`, empty slice = no-op), `FlowRow` (Serialize), `OutputMode`/`KafkaOutputConfig`, `SensorMetrics.{kafka_produced_total, kafka_produce_errors_total}`, `rdkafka = { workspace = true }`, xxhash-rust `xxh3_64`.
- Produces: `output::kafka_store::KafkaFlowStore` (`pub(crate) mod`), `KafkaFlowStore::new(&OutputConfig, Arc<SensorMetrics>) -> Result<Self, anyhow::Error>`; main.rs `spawn_flow_writer` helper; `flows flow through netflow.raw` when `mode: kafka`.

- [ ] **Step 1: Write the failing tests**

Create `crates/sentinel-sensor/src/output/kafka_store.rs` with only imports, the two pure functions, and this test module (the store struct comes in Step 4 — the file will not compile yet, which is the red):

```rust
//! Kafka implementation of [`FlowStore`]: one JSON message per `FlowRow`.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde_json::to_string;
use xxhash_rust::xxh3::xxh3_64;

use super::clickhouse::FlowStore;
use super::row::FlowRow;
use crate::config::OutputConfig;
use crate::metrics::SensorMetrics;

/// How long a single produce call may block before being treated as failed.
/// Matches the sensor's `WRITE_TIMEOUT` budget.
const PRODUCE_TIMEOUT: Duration = Duration::from_secs(2);

/// Stable partition key for a flow: xxh3_64 of its 5-tuple, hex encoded.
/// Identical 5-tuples land on the same partition; the hash spreads distinct
/// flows evenly (architecture.md section 8.2).
fn partition_key(row: &FlowRow) -> String {
    let tuple = format!(
        "{},{},{},{},{}",
        row.source_ip, row.destination_ip, row.source_port, row.destination_port, row.protocol
    );
    format!("{:016x}", xxh3_64(tuple.as_bytes()))
}

/// Message body for one row: the FlowRow's JSON serialization (byte-exact
/// round-trip — uuid/ips serialize as 16 octets, timestamps as i64 millis).
fn message_payload(row: &FlowRow) -> Result<String, serde_json::Error> {
    to_string(row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::row::sample_flow;

    fn sample_row() -> FlowRow {
        FlowRow::try_from(&sample_flow("1c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e01")).unwrap()
    }

    #[test]
    fn key_depends_only_on_five_tuple() {
        let row = sample_row();
        let mut other = sample_flow("2c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e02");
        other.timestamp_start = "2026-09-25T11:00:00.123+00:00".to_string();
        assert_eq!(partition_key(&row), partition_key(&FlowRow::try_from(&other).unwrap()));
    }

    #[test]
    fn different_destination_maps_to_different_key() {
        let row = sample_row();
        let mut other = sample_flow("1c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e01");
        other.destination_ip = "2001:db8::2".to_string();
        assert_ne!(partition_key(&row), partition_key(&FlowRow::try_from(&other).unwrap()));
    }

    #[test]
    fn payload_round_trips_through_json() {
        let row = sample_row();
        let payload = message_payload(&row).unwrap();
        let decoded: FlowRow = serde_json::from_str(&payload).unwrap();
        assert_eq!(decoded, row);
    }
}
```

Add `pub(crate) mod kafka_store;` to `crates/sentinel-sensor/src/output/mod.rs` (after `mod event_writer;`, keeping alphabetical order — insert before `mod row;`).

Add `serde_json = { workspace = true }` to `[dependencies]` of `crates/sentinel-sensor/Cargo.toml`.

- [ ] **Step 2: Run tests to verify the new tests fail / file compiles**

Run: `cargo nextest run -p sentinel-sensor output::kafka_store`
Expected: the 3 new tests PASS already (they test pure functions — this is acceptable TDD for leaf functions; the wiring red comes from Step 5's store usage). If `sample_flow`'s import or `xxhash_rust::xxh3` path does not resolve, fix the import mechanically and report.

- [ ] **Step 3: Implement the store**

Append to `crates/sentinel-sensor/src/output/kafka_store.rs` (above the test module):

```rust
/// Error surfaced to `FlowWriter`'s retry loop.
#[derive(Debug)]
pub struct KafkaProduceError(String);

impl fmt::Display for KafkaProduceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for KafkaProduceError {}

/// `FlowStore` that publishes each row as one Kafka message.
///
/// Delivery is at-least-once: a partial-batch failure after some rows were
/// accepted means the retried batch re-sends earlier rows; duplicate messages
/// (and ClickHouse rows) are accepted.
pub struct KafkaFlowStore {
    producer: FutureProducer,
    topic: String,
    metrics: Arc<SensorMetrics>,
}

impl KafkaFlowStore {
    /// Fallible only on client configuration errors (e.g. malformed broker
    /// list), matching the fail-fast startup contract of other config
    /// consumers. Broker connectivity itself is exercised at write time.
    pub fn new(config: &OutputConfig, metrics: Arc<SensorMetrics>) -> Result<Self, anyhow::Error> {
        let brokers = config.kafka.brokers.join(",");
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", &brokers)
            .set("acks", "all")
            .set("enable.idempotence", "true")
            .set("compression.type", "lz4")
            .create()?;
        Ok(Self {
            producer,
            topic: config.kafka.topic.clone(),
            metrics,
        })
    }
}

#[async_trait]
impl FlowStore for KafkaFlowStore {
    type Error = KafkaProduceError;

    async fn write_batch(&mut self, rows: &[FlowRow]) -> Result<(), Self::Error> {
        if rows.is_empty() {
            return Ok(());
        }
        for row in rows {
            let key = partition_key(row);
            let payload = message_payload(row)
                .map_err(|err| KafkaProduceError(format!("serialize flow {}: {err}", row.flow_id)))?;
            let record = FutureRecord::<str, str>::to(&self.topic).key(&key).payload(&payload);
            match self
                .producer
                .send(record, rdkafka::Timeout::After(PRODUCE_TIMEOUT))
                .await
            {
                Ok(_delivery) => self.metrics.kafka_produced_total.inc(),
                Err((err, _record)) => {
                    self.metrics.kafka_produce_errors_total.inc();
                    return Err(KafkaProduceError(err.to_string()));
                }
            }
        }
        Ok(())
    }
}
```

- [ ] **Step 4: Run all gates**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: everything passes; `KafkaFlowStore` must NOT trigger dead_code (it is `pub(crate)` and unreferenced — if clippy flags dead code, that is expected at this step: proceed immediately to Step 5 before committing and re-run gates there. Do NOT add `#[allow(dead_code)]`.)

- [ ] **Step 5: Wire mode selection into main.rs**

In `crates/sentinel-sensor/src/main.rs`:

a) Extend imports:

```rust
use sentinel_flow::ExportedFlow;
use sentinel_sensor::config::{OutputConfig, OutputMode, SensorConfig};
```

```rust
use sentinel_sensor::output::{ClickHouseStore, FlowStore, FlowWriter, WRITE_TIMEOUT};
use tokio::task::JoinHandle;
```

and add `KafkaFlowStore` to the output use list.

b) Replace the flow output block (the `let (out_tx, out_rx) = mpsc::channel(10000); ...` block that constructs `FlowWriter` with `ClickHouseStore::new(&config.output)`) with:

```rust
    let (out_tx, out_rx) = mpsc::channel(10000);
    let writer_handle = match config.output.mode {
        OutputMode::Direct => spawn_flow_writer(
            out_rx,
            ClickHouseStore::new(&config.output),
            &config.output,
            metrics.clone(),
        ),
        OutputMode::Kafka => spawn_flow_writer(
            out_rx,
            KafkaFlowStore::new(&config.output, metrics.clone())?,
            &config.output,
            metrics.clone(),
        ),
    };
```

c) Add the helper function (near the other free helper fns, e.g. before `forward`):

```rust
fn spawn_flow_writer<S: FlowStore>(
    out_rx: mpsc::Receiver<ExportedFlow>,
    store: S,
    output: &OutputConfig,
    metrics: Arc<SensorMetrics>,
) -> JoinHandle<S> {
    let writer = FlowWriter::new(
        out_rx,
        store,
        output.batch_size,
        Duration::from_millis(output.batch_timeout_ms),
        WRITE_TIMEOUT,
        metrics,
    );
    tokio::spawn(writer.run())
}
```

Behavior contract: with `mode: direct` the constructed writer is identical to today's (same store type, same `FlowWriter::new` arguments); with `mode: kafka` the only change is the store. Shutdown path, `writer_handle` usage, and everything else stays untouched.

- [ ] **Step 6: Run all gates**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: 114 passed (111 + 3 kafka_store tests); clippy/fmt clean; no dead-code warnings.

- [ ] **Step 7: Commit**

```bash
git add crates/sentinel-sensor/Cargo.toml crates/sentinel-sensor/src/output/kafka_store.rs crates/sentinel-sensor/src/output/mod.rs crates/sentinel-sensor/src/main.rs Cargo.lock
git commit -m "feat(sensor): kafka flow store with mode-based output wiring"
```

### Task 6: sentinel-sink — Kafka to ClickHouse consumer crate

**Files:**
- Modify: `crates/sentinel-sink/Cargo.toml` (full dependency list)
- Create: `crates/sentinel-sink/src/config.rs`, `adapter.rs`, `metrics.rs`, `consumer.rs`
- Rewrite: `crates/sentinel-sink/src/main.rs`
- Create: `config/sink.yaml`

**Interfaces:**
- Consumes: `sentinel_sensor::config::OutputConfig` (all pub fields), `sentinel_sensor::metrics::SensorMetrics`, `sentinel_sensor::output::{FlowStore, FlowRow, FlowWriter, ClickHouseStore, WRITE_TIMEOUT}`, `sentinel_flow::ExportedFlow` (all pub fields), `rdkafka = { workspace = true }`.
- Produces: binary `sentinel-sink`; `SinkConfig::load(&str) -> anyhow::Result<SinkConfig>` + `.validate()`; `KafkaEventSource` trait (`next_message() -> Option<Result<String, SourceError>>`, `commit() -> Result<(), SourceError>`); `consumer::run(source, tx, sink_metrics, shutdown, commit_interval)`; `metrics::SinkMetrics` + `metrics::serve_metrics(listener, sink, sensor, shutdown)`; `adapter::flow_row_to_exported(&FlowRow) -> ExportedFlow`.

- [ ] **Step 1: Complete the sink manifest**

`crates/sentinel-sink/Cargo.toml` (keep the `[package]` style chosen in Task 1; extend `[dependencies]` to):

```toml
[dependencies]
anyhow = { workspace = true }
async-trait = { workspace = true }
chrono = { workspace = true }
clap = { workspace = true }
prometheus = { workspace = true }
rdkafka = { workspace = true }
serde = { workspace = true }
serde_json = { workspace = true }
sentinel-flow = { path = "../sentinel-flow" }
sentinel-sensor = { path = "../sentinel-sensor" }
tokio = { workspace = true }
tracing = { workspace = true }
tracing-subscriber = { workspace = true }
```

- [ ] **Step 2: Write the config module (tests first)**

Create `crates/sentinel-sink/src/config.rs`:

```rust
//! Sink configuration (`config/sink.yaml`).

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use sentinel_sensor::config::OutputConfig;

/// Where to read flows from and where to write them.
#[derive(Debug, Clone, Deserialize)]
pub struct SinkConfig {
    pub kafka: KafkaSourceConfig,
    pub clickhouse: ClickHouseTargetConfig,
    #[serde(default)]
    pub metrics: SinkMetricsConfig,
}

/// Kafka consumer settings.
#[derive(Debug, Clone, Deserialize)]
pub struct KafkaSourceConfig {
    pub brokers: Vec<String>,
    pub topic: String,
    #[serde(default = "default_group_id")]
    pub group_id: String,
}

fn default_group_id() -> String {
    "clickhouse-sinker".to_string()
}

/// ClickHouse target settings.
#[derive(Debug, Clone, Deserialize)]
pub struct ClickHouseTargetConfig {
    pub url: String,
    #[serde(default = "default_database")]
    pub database: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
}

fn default_database() -> String {
    "sentinel".to_string()
}

fn default_batch_size() -> usize {
    1000
}

fn default_batch_timeout_ms() -> u64 {
    500
}

/// Sink metrics endpoint settings.
#[derive(Debug, Clone, Deserialize)]
pub struct SinkMetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

impl Default for SinkMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_metrics_port(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9091
}

impl SinkConfig {
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read sink config from {path}"))?;
        serde_yaml::from_str(&raw).with_context(|| format!("parse sink config from {path}"))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.kafka.brokers.is_empty(),
            "kafka.brokers must not be empty"
        );
        ensure!(!self.kafka.topic.is_empty(), "kafka.topic must not be empty");
        ensure!(self.clickhouse.batch_size >= 1, "clickhouse.batch_size must be >= 1");
        ensure!(
            self.clickhouse.batch_timeout_ms >= 1,
            "clickhouse.batch_timeout_ms must be >= 1"
        );
        Ok(())
    }

    /// Adapter so the sensor's `ClickHouseStore::new` can consume sink settings.
    pub fn output_config(&self) -> OutputConfig {
        OutputConfig {
            clickhouse_url: self.clickhouse.url.clone(),
            clickhouse_database: self.clickhouse.database.clone(),
            clickhouse_user: self.clickhouse.user.clone(),
            clickhouse_password: self.clickhouse.password.clone(),
            batch_size: self.clickhouse.batch_size,
            batch_timeout_ms: self.clickhouse.batch_timeout_ms,
            mode: Default::default(),
            kafka: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "kafka:\n  brokers:\n    - localhost:9092\n  topic: netflow.raw\n  group_id: clickhouse-sinker\nclickhouse:\n  url: http://localhost:8123\n  database: sentinel\n  batch_size: 1000\n  batch_timeout_ms: 500\nmetrics:\n  enabled: true\n  port: 9091";

    #[test]
    fn parses_sample_config() {
        let config: SinkConfig = serde_yaml::from_str(SAMPLE).unwrap();
        assert_eq!(config.kafka.group_id, "clickhouse-sinker");
        assert_eq!(config.kafka.topic, "netflow.raw");
        assert_eq!(config.clickhouse.batch_size, 1000);
        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.port, 9091);
        config.validate().unwrap();
    }

    #[test]
    fn group_id_and_database_have_defaults() {
        let yaml = "kafka:\n  brokers:\n    - localhost:9092\n  topic: netflow.raw\nclickhouse:\n  url: http://localhost:8123";
        let config: SinkConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.kafka.group_id, "clickhouse-sinker");
        assert_eq!(config.clickhouse.database, "sentinel");
    }

    #[test]
    fn rejects_empty_brokers_and_zero_batches() {
        let mut config: SinkConfig = serde_yaml::from_str(SAMPLE).unwrap();
        config.kafka.brokers.clear();
        assert!(config.validate().is_err());
        config.kafka.brokers = vec!["localhost:9092".to_string()];
        config.clickhouse.batch_size = 0;
        assert!(config.validate().is_err());
        config.clickhouse.batch_size = 1;
        config.clickhouse.batch_timeout_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn output_config_maps_clickhouse_fields() {
        let config: SinkConfig = serde_yaml::from_str(SAMPLE).unwrap();
        let output = config.output_config();
        assert_eq!(output.clickhouse_url, "http://localhost:8123");
        assert_eq!(output.clickhouse_database, "sentinel");
        assert_eq!(output.batch_size, 1000);
        assert_eq!(output.batch_timeout_ms, 500);
    }
}
```

If `OutputConfig`'s literal construction does not compile (field set drift), adapt mechanically and report.

- [ ] **Step 3: Create config/sink.yaml**

`config/sink.yaml`:

```yaml
# sentinel-sink configuration: consumes netflow.raw and writes network_flows.
kafka:
  brokers:
    - localhost:9092
  topic: netflow.raw
  group_id: clickhouse-sinker

clickhouse:
  url: http://localhost:8123
  database: sentinel
  batch_size: 1000
  batch_timeout_ms: 500

metrics:
  enabled: true
  port: 9091
```

- [ ] **Step 4: Write the adapter module**

Create `crates/sentinel-sink/src/adapter.rs`:

```rust
//! Bridge between Kafka `FlowRow` payloads and the `ExportedFlow` input type
//! that the sensor's `FlowWriter` consumes.

use chrono::SecondsFormat;
use sentinel_flow::ExportedFlow;
use sentinel_sensor::output::FlowRow;

/// Canonical (bit, name) pairs, mirroring row.rs's flag encoding.
const FLAG_NAMES: [(u8, &str); 6] =
    [(1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"), (16, "ACK"), (32, "URG")];

/// Rebuild an `ExportedFlow` from a deserialized `FlowRow` so the row can be
/// pushed into the sensor's `FlowWriter`, which converts it back to a `FlowRow`
/// internally. Round-trip stable: `FlowRow::try_from(&flow_row_to_exported(row))`
/// equals `row` for any row the sensor produced (unknown flag names were
/// already dropped when the row was built).
pub fn flow_row_to_exported(row: &FlowRow) -> ExportedFlow {
    ExportedFlow {
        flow_id: row.flow_id.to_string(),
        timestamp_start: row.timestamp_start.to_rfc3339_opts(SecondsFormat::Millis, true),
        timestamp_end: row.timestamp_end.to_rfc3339_opts(SecondsFormat::Millis, true),
        source_ip: row.source_ip.to_string(),
        destination_ip: row.destination_ip.to_string(),
        source_port: row.source_port,
        destination_port: row.destination_port,
        protocol: protocol_name(row.protocol).to_string(),
        packets_forward: row.packets_forward,
        packets_reverse: row.packets_reverse,
        bytes_forward: row.bytes_forward,
        bytes_reverse: row.bytes_reverse,
        duration_ms: u64::from(row.duration_ms),
        tcp_flags: FLAG_NAMES
            .iter()
            .filter(|(bit, _)| row.tcp_flags_seen.contains(bit))
            .map(|(_, name)| name.to_string())
            .collect(),
        sensor_node: row.sensor_node.clone(),
    }
}

/// Inverse of the sensor's protocol_code mapping (1=TCP 2=UDP 3=ICMP 4=OTHER).
fn protocol_name(code: i8) -> &'static str {
    match code {
        1 => "TCP",
        2 => "UDP",
        3 => "ICMP",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_exported() -> ExportedFlow {
        ExportedFlow {
            flow_id: "0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e01".to_string(),
            timestamp_start: "2026-09-25T10:00:00.123+00:00".to_string(),
            timestamp_end: "2026-09-25T10:00:01.456+00:00".to_string(),
            source_ip: "10.0.0.1".to_string(),
            destination_ip: "2001:db8::1".to_string(),
            source_port: 44321,
            destination_port: 443,
            protocol: "TCP".to_string(),
            packets_forward: 10,
            packets_reverse: 20,
            bytes_forward: 1000,
            bytes_reverse: 2000,
            duration_ms: 1333,
            tcp_flags: vec!["SYN".to_string(), "ACK".to_string()],
            sensor_node: "node-1".to_string(),
        }
    }

    #[test]
    fn row_rebuilds_into_the_same_row() {
        let original = FlowRow::try_from(&sample_exported()).unwrap();
        let exported = flow_row_to_exported(&original);
        assert_eq!(FlowRow::try_from(&exported).unwrap(), original);
        assert_eq!(exported.tcp_flags, vec!["SYN".to_string(), "ACK".to_string()]);
        assert_eq!(exported.duration_ms, u64::from(Duration::from_millis(1333).as_millis() as u32));
    }
}
```

Note: the sensor's `sample_flow` helper is `#[cfg(test)] pub(crate)` and therefore invisible to this crate — the adapter test builds its own `ExportedFlow` instead. The `duration_ms` assertion uses `u64::from(...) as u32` to mirror `FlowRow`'s `u32` field; simplify to `assert_eq!(exported.duration_ms, 1333);` if `u64::from` import churns the build and report the simplification.

- [ ] **Step 5: Declare the new modules and run the tests written so far**

In `crates/sentinel-sink/src/main.rs` (still `fn main() {}`), add above `fn main`:

```rust
mod adapter;
mod config;
```

Run: `cargo nextest run -p sentinel-sink`
Expected: 5 tests pass (4 config + 1 adapter); report the actual count.

- [ ] **Step 6: Write the metrics module**

Create `crates/sentinel-sink/src/metrics.rs`:

```rust
//! Sink metrics registry and scrape endpoint.

use std::sync::Arc;

use prometheus::{IntCounter, Registry, TextEncoder};
use sentinel_sensor::metrics::SensorMetrics;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::info;

/// Counters owned by the sink process. `FlowWriter`'s own counters
/// (`flows_written_total`, `flows_dropped_total`, ...) come from the sensor's
/// `SensorMetrics` and are gathered alongside these.
pub struct SinkMetrics {
    registry: Registry,
    pub consumed_total: IntCounter,
    pub failed_messages_total: IntCounter,
}

impl SinkMetrics {
    pub fn new() -> anyhow::Result<Self> {
        let registry = Registry::new();
        let consumed_total = IntCounter::with_opts(prometheus::opts!(
            "sentinel_sink_consumed_total",
            "Kafka messages successfully decoded by sentinel-sink"
        ))?;
        registry.register(Box::new(consumed_total.clone()))?;
        let failed_messages_total = IntCounter::with_opts(prometheus::opts!(
            "sentinel_sink_failed_messages_total",
            "Kafka messages dropped after decode or receive failures"
        ))?;
        registry.register(Box::new(failed_messages_total.clone()))?;
        Ok(Self {
            registry,
            consumed_total,
            failed_messages_total,
        })
    }

    /// Sink counters plus the sensor metrics `FlowWriter` runs on.
    pub fn export(&self, sensor: &SensorMetrics) -> Result<String, prometheus::Error> {
        let encoder = TextEncoder::new();
        let mut buffer = String::new();
        encoder.encode_utf8(&self.registry.gather(), &mut buffer)?;
        encoder.encode_utf8(&sensor.registry.gather(), &mut buffer)?;
        Ok(buffer)
    }
}

/// Minimal scrape endpoint: one response per connection, both registries
/// gathered. Mirrors the sensor's metrics server contract (bind, serve until
/// shutdown) with a deliberately tiny HTTP/1.1 responder.
pub async fn serve_metrics(
    listener: TcpListener,
    sink: Arc<SinkMetrics>,
    sensor: Arc<SensorMetrics>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
) -> std::io::Result<()> {
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (mut socket, _) = accepted?;
                let body = sink.export(&sensor).unwrap_or_default();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let mut discard = [0u8; 1024];
                let _ = socket.read(&mut discard).await;
                if socket.write_all(response.as_bytes()).await.is_err() {
                    info!("metrics scrape connection dropped");
                }
            }
        }
    }
}
```

If `SensorMetrics.registry` is private (it is a struct field; the sink needs read access), either make the field `pub(crate)` in the sensor (NOT pub — the sink would then need `pub`) or add a `pub fn gather(&self) -> &Registry` accessor to `SensorMetrics` in the sensor crate; prefer the accessor if it keeps the struct field private, and report which you did. `encode_utf8` exists on `TextEncoder`; if the prometheus version in use lacks it, use `encoder.encode_to_string(&...)` mechanically.

- [ ] **Step 7: Write the consumer module**

Create `crates/sentinel-sink/src/consumer.rs`:

```rust
//! Kafka consumption loop for `sentinel-sink`.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{Consumer, StreamConsumer};
use rdkafka::message::Message;
use rdkafka::{CommitMode, Offset, TopicPartitionList};
use serde_json::from_str;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use sentinel_flow::ExportedFlow;
use sentinel_sensor::output::FlowRow;

use crate::adapter::flow_row_to_exported;
use crate::config::SinkConfig;
use crate::metrics::SinkMetrics;

/// Errors surfaced by the event source.
#[derive(Debug)]
pub struct SourceError(String);

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for SourceError {}

/// Abstraction over Kafka so the consume loop is testable without a broker.
#[async_trait]
pub trait KafkaEventSource: Send {
    /// Next payload, or `None` when the stream has ended.
    async fn next_message(&mut self) -> Option<Result<String, SourceError>>;
    /// Commit the position of the last delivered message.
    async fn commit(&mut self) -> Result<(), SourceError>;
}

/// rdkafka-backed source: delivers payloads and tracks the last offset for
/// commits. Consumer group semantics: `enable.auto.commit=false`, offsets are
/// committed manually by [`run`] on a lagging tick.
pub struct KafkaSource {
    consumer: StreamConsumer,
    last: Option<(String, i32, i64)>,
}

impl KafkaSource {
    pub fn new(config: &SinkConfig) -> anyhow::Result<Self> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", &config.kafka.brokers.join(","))
            .set("group.id", &config.kafka.group_id)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .create()?;
        consumer.subscribe(&[&config.kafka.topic])?;
        Ok(Self {
            consumer,
            last: None,
        })
    }
}

#[async_trait]
impl KafkaEventSource for KafkaSource {
    async fn next_message(&mut self) -> Option<Result<String, SourceError>> {
        match self.consumer.recv().await {
            Ok(message) => {
                self.last = Some((
                    message.topic().to_string(),
                    message.partition(),
                    message.offset(),
                ));
                match message.payload_view::<str>() {
                    Some(Ok(payload)) => Some(Ok(payload.to_string())),
                    Some(Err(err)) => Some(Err(SourceError(err.to_string()))),
                    None => Some(Err(SourceError("message without payload".to_string()))),
                }
            }
            Err(err) => Some(Err(SourceError(err.to_string()))),
        }
    }

    async fn commit(&mut self) -> Result<(), SourceError> {
        let Some((topic, partition, offset)) = self.last.clone() else {
            return Ok(());
        };
        let mut tpl = TopicPartitionList::new();
        tpl.add_partition_offset(&topic, partition, Offset::Offset(offset + 1))
            .map_err(|err| SourceError(err.to_string()))?;
        self.consumer
            .commit(&tpl, CommitMode::Async)
            .map_err(|err| SourceError(err.to_string()))
    }
}

/// Runs until the source ends or `shutdown` fires. Sends every parseable row
/// into the `FlowWriter` channel; poison messages are counted and skipped.
///
/// Commits happen on a **lagging** tick (`commit_interval`, production: 5s),
/// never per message: a crash redelivers everything since the last commit, so
/// messages are only ever duplicated, never lost (at-least-once; the commit
/// position is always behind what `FlowWriter` guarantees on disk).
pub async fn run(
    mut source: impl KafkaEventSource,
    tx: mpsc::Sender<ExportedFlow>,
    metrics: Arc<SinkMetrics>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    commit_interval: Duration,
) {
    let mut commit_tick = tokio::time::interval(commit_interval);
    commit_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    commit_tick.tick().await; // consume the immediate first tick
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = commit_tick.tick() => {
                if let Err(err) = source.commit().await {
                    warn!("offset commit failed: {err}");
                }
            }
            message = source.next_message() => match message {
                None => break,
                Some(Err(err)) => {
                    metrics.failed_messages_total.inc();
                    warn!("kafka receive failed: {err}");
                }
                Some(Ok(payload)) => match from_str::<FlowRow>(&payload) {
                    Ok(row) => {
                        metrics.consumed_total.inc();
                        if let Err(err) = tx.send(flow_row_to_exported(&row)).await {
                            debug!("flow writer gone, stopping: {err}");
                            break;
                        }
                    }
                    Err(err) => {
                        metrics.failed_messages_total.inc();
                        warn!("skipping undecodable message: {err}");
                    }
                },
            },
        }
    }
    if let Err(err) = source.commit().await {
        warn!("final offset commit failed: {err}");
    }
}
```

Append this test module (mock source + end-to-end loop through the real `FlowWriter`):

```rust
#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use async_trait::async_trait;
    use sentinel_sensor::metrics::SensorMetrics;
    use sentinel_sensor::output::{FlowRow, FlowStore, FlowWriter, WRITE_TIMEOUT};
    use tokio::sync::{mpsc, oneshot};

    use super::*;
    use crate::metrics::SinkMetrics;

    struct MockSource {
        messages: Vec<Result<String, SourceError>>,
        commits: usize,
    }

    impl MockSource {
        fn json_payloads() -> Self {
            let exported = sample_exported();
            let row = FlowRow::try_from(&exported).unwrap();
            Self {
                messages: vec![
                    Ok(serde_json::to_string(&row).unwrap()),
                    Ok(serde_json::to_string(&row).unwrap()),
                    Err(SourceError("broker unavailable".to_string())),
                    Ok("not json".to_string()),
                    Ok(serde_json::to_string(&row).unwrap()),
                ],
                commits: 0,
            }
        }
    }

    fn sample_exported() -> ExportedFlow {
        ExportedFlow {
            flow_id: "0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e01".to_string(),
            timestamp_start: "2026-09-25T10:00:00.123+00:00".to_string(),
            timestamp_end: "2026-09-25T10:00:01.456+00:00".to_string(),
            source_ip: "10.0.0.1".to_string(),
            destination_ip: "2001:db8::1".to_string(),
            source_port: 44321,
            destination_port: 443,
            protocol: "TCP".to_string(),
            packets_forward: 10,
            packets_reverse: 20,
            bytes_forward: 1000,
            bytes_reverse: 2000,
            duration_ms: 1333,
            tcp_flags: vec!["SYN".to_string(), "ACK".to_string()],
            sensor_node: "node-1".to_string(),
        }
    }

    #[async_trait]
    impl KafkaEventSource for MockSource {
        async fn next_message(&mut self) -> Option<Result<String, SourceError>> {
            if self.messages.is_empty() {
                return None;
            }
            Some(self.messages.remove(0))
        }

        async fn commit(&mut self) -> Result<(), SourceError> {
            self.commits += 1;
            Ok(())
        }
    }

    struct SinkMockStore {
        batches: Vec<Vec<FlowRow>>,
    }

    #[async_trait]
    impl FlowStore for SinkMockStore {
        type Error = String;

        async fn write_batch(&mut self, rows: &[FlowRow]) -> Result<(), Self::Error> {
            self.batches.push(rows.to_vec());
            Ok(())
        }
    }

    #[tokio::test]
    async fn loop_forwards_rows_counts_failures_and_commits() {
        let source = MockSource::json_payloads();
        let sink_metrics = Arc::new(SinkMetrics::new().unwrap());
        let sensor_metrics = Arc::new(SensorMetrics::new().unwrap());
        let (tx, rx) = mpsc::channel(100);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let consume = tokio::spawn(super::run(
            source,
            tx,
            sink_metrics.clone(),
            shutdown_rx,
            Duration::from_millis(50),
        ));
        let writer = FlowWriter::new(
            rx,
            SinkMockStore { batches: Vec::new() },
            2,
            Duration::from_millis(50),
            WRITE_TIMEOUT,
            sensor_metrics,
        );
        let writer_task = tokio::spawn(writer.run());
        consume.await.unwrap();
        drop(shutdown_tx);
        let store = writer_task.await.unwrap();
        let written: usize = store.batches.iter().map(|batch| batch.len()).sum();
        assert_eq!(written, 3);
        assert_eq!(sink_metrics.consumed_total.get(), 3);
        assert_eq!(sink_metrics.failed_messages_total.get(), 2);
    }
}
```

(The `drop(shutdown_tx)` line is defensive; the mock's stream ending already breaks the loop. Remove it if the compiler flags an unused variable and report.)

- [ ] **Step 8: Wire main.rs**

Rewrite `crates/sentinel-sink/src/main.rs`:

```rust
//! sentinel-sink: consumes `netflow.raw` and writes flows to ClickHouse via
//! the sensor's FlowWriter + ClickHouseStore.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use sentinel_sensor::metrics::SensorMetrics;
use sentinel_sensor::output::{ClickHouseStore, FlowWriter, WRITE_TIMEOUT};
use tokio::sync::mpsc;
use tracing::info;

mod adapter;
mod config;
mod consumer;
mod metrics;

use config::SinkConfig;
use metrics::SinkMetrics;

#[derive(Parser)]
struct Args {
    /// Path to the sink configuration file.
    #[arg(long, default_value = "config/sink.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Copy this tracing init verbatim from crates/sentinel-sensor/src/main.rs.
    let args = Args::parse();
    let config = SinkConfig::load(&args.config)?;
    config.validate()?;
    info!("sink configuration loaded from {}", args.config);

    let sensor_metrics = Arc::new(SensorMetrics::new()?);
    let sink_metrics = Arc::new(SinkMetrics::new()?);

    let output = config.output_config();
    let (tx, rx) = mpsc::channel(10000);
    let writer = FlowWriter::new(
        rx,
        ClickHouseStore::new(&output),
        config.clickhouse.batch_size,
        Duration::from_millis(config.clickhouse.batch_timeout_ms),
        WRITE_TIMEOUT,
        sensor_metrics.clone(),
    );
    let writer_handle = tokio::spawn(writer.run());

    let (metrics_shutdown_tx, metrics_shutdown_rx) = tokio::sync::oneshot::channel();
    let metrics_handle = if config.metrics.enabled {
        let listener = tokio::net::TcpListener::bind(("0.0.0.0", config.metrics.port)).await?;
        info!("sink metrics listening on 0.0.0.0:{}", config.metrics.port);
        Some(tokio::spawn(metrics::serve_metrics(
            listener,
            sink_metrics.clone(),
            sensor_metrics.clone(),
            metrics_shutdown_rx,
        )))
    } else {
        drop(metrics_shutdown_rx);
        None
    };

    let source = consumer::KafkaSource::new(&config)?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let consume_handle = tokio::spawn(consumer::run(
        source,
        tx,
        sink_metrics.clone(),
        shutdown_rx,
        Duration::from_secs(5),
    ));

    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(());
    let _ = consume_handle.await;
    let _ = tokio::time::timeout(Duration::from_secs(30), writer_handle).await;
    if let Some(handle) = metrics_handle {
        let _ = metrics_shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
    info!("sentinel-sink stopped");
    Ok(())
}
```

Copy the exact tracing-subscriber init from `crates/sentinel-sensor/src/main.rs` (including its env-filter default) in place of the comment.

- [ ] **Step 9: Run all gates**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: 120 passed (114 + 4 config + 1 adapter + 1 consumer); report the actual count — clippy/fmt must be clean.

- [ ] **Step 10: Commit**

```bash
git add crates/sentinel-sink/ config/sink.yaml Cargo.lock
git commit -m "feat(sink): kafka to clickhouse consumer crate"
```

### Task 7: docker-compose and replay runbook

**Files:**
- Create: `docker-compose.kafka.yml`
- Create: `docs/runbooks/kafka-replay.md`

**Interfaces:**
- Consumes: `sentinel-sink` binary (Task 6), `output.mode: kafka` (Tasks 3/5).
- Produces: reproducible manual E2E satisfying the spec acceptance "sensor and sink can be stopped/restarted independently and the sink re-reads within the 7-day retention" and "replay capability demonstrated".

- [ ] **Step 1: Create docker-compose.kafka.yml**

```yaml
# Local Kafka + ClickHouse for the Phase 6 kafka transport mode (manual E2E;
# not part of CI). Topic netflow.raw is created by hand — see
# docs/runbooks/kafka-replay.md.
services:
  kafka:
    image: bitnami/kafka:3.7
    ports:
      - "9092:9092"
    environment:
      KAFKA_CFG_NODE_ID: "0"
      KAFKA_CFG_PROCESS_ROLES: controller,broker
      KAFKA_CFG_CONTROLLER_QUORUM_VOTERS: 0@kafka:9093
      KAFKA_CFG_LISTENERS: PLAINTEXT://:9092,CONTROLLER://:9093
      KAFKA_CFG_ADVERTISED_LISTENERS: PLAINTEXT://localhost:9092
      KAFKA_CFG_CONTROLLER_LISTENER_NAMES: CONTROLLER
      KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP: CONTROLLER:PLAINTEXT,PLAINTEXT:PLAINTEXT
      KAFKA_CFG_AUTO_CREATE_TOPICS_ENABLE: "false"

  clickhouse:
    image: clickhouse/clickhouse-server:24.8
    ports:
      - "8123:8123"
```

- [ ] **Step 2: Create the replay runbook**

`docs/runbooks/kafka-replay.md` — write it with this exact structure and content (fill the verified command outputs when you run the demo):

````markdown
# Kafka replay runbook

Manual procedure for the Phase 6 kafka transport (`output.mode: kafka`).
Runs outside CI; needs Docker and ~2 GB RAM. Everything below assumes the
repository root as working directory.

## 1. Start the infrastructure

```bash
docker compose -f docker-compose.kafka.yml up -d
```

## 2. Create the topic (7-day retention, 4 partitions)

```bash
docker exec kafka /opt/bitnami/kafka/bin/kafka-topics.sh --create \
  --topic netflow.raw --partitions 4 --retention-ms 604800000 \
  --bootstrap-server localhost:9092
```

Verify: `... --describe --topic netflow.raw` shows 4 partitions and
`retention.ms=604800000`.

## 3. Produce with the sensor

Set `output.mode: kafka` in `config/sensor.yaml`, then:

```bash
cargo run -p sentinel-sensor -- --config config/sensor.yaml
```

Flows are published as one JSON message per `FlowRow`, partition key =
hex xxh3_64 of the 5-tuple. Note: payloads are byte-exact octet arrays
(flow_id/IP are not human-readable strings); inspect row counts in
ClickHouse instead of reading Kafka payloads.

## 4. Consume with the sink

```bash
cargo run -p sentinel-sink -- --config config/sink.yaml
```

Verify in ClickHouse:

```bash
docker exec clickhouse clickhouse-client --query \
  "SELECT count() FROM sentinel.network_flows"
```

## 5. Replay demo (sink restart)

1. Stop the sink (Ctrl-C), keep the sensor running for a few more seconds
   (or replay an earlier window — retention is 7 days), then stop it.
2. Restart the sink. The consumer group `clickhouse-sinker` resumes from its
   committed offsets and processes everything produced while it was down.
3. `SELECT count() FROM sentinel.network_flows` has grown by the missed rows.

## 6. Full replay (offset reset — duplicates are expected and accepted)

With the sink stopped:

```bash
docker exec kafka /opt/bitnami/kafka/bin/kafka-consumer-groups.sh \
  --bootstrap-server localhost:9092 --group clickhouse-sinker \
  --reset-offsets --to-earliest --execute --topic netflow.raw
```

Restart the sink: the whole retained topic is re-read, so `network_flows`
gains duplicate rows (at-least-once semantics — established project ruling).

## Teardown

```bash
docker compose -f docker-compose.kafka.yml down -v
```
````

- [ ] **Step 3: Run all gates (docs only, hooks must still pass)**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check`
Expected: unchanged counts; clean.

- [ ] **Step 4: Commit**

```bash
git add docker-compose.kafka.yml docs/runbooks/kafka-replay.md
git commit -m "docs: kafka replay runbook and compose file"
```

---

### Task 8: Final verification

No commit unless a fix is needed. Verify the whole feature against the spec.

- [ ] **Step 1: Full gates at HEAD**

Run: `cargo nextest run --workspace && cargo clippy --workspace --all-targets --all-features -- -D warnings && cargo fmt --all -- --check && cargo deny check`
Expected: all clean; report final test count.

- [ ] **Step 2: Spec acceptance traceability**

Check each spec acceptance bullet against the implementation and report the mapping:
1. `mode: direct` default unchanged — all pre-existing tests untouched and green; `main.rs` match arm produces the same `FlowWriter` call as before.
2. `mode: kafka` publishes JSON rows with xxh3 5-tuple keys — `kafka_store.rs` tests + `KafkaFlowStore`.
3. `sentinel-sink` consumes `netflow.raw` via `clickhouse-sinker` with manual commits — `consumer.rs` + `config/sink.yaml`.
4. Independent restart/re-read documented — runbook steps 5-6.
5. Workspace gates green — Step 1 output.

- [ ] **Step 3: Working tree hygiene**

Run: `git status --short`
Expected: only the user's own files remain modified/untracked (`README.md`, `docs/configuration.md`, `docs/posts/`, `.ua/`) — none of them staged or committed by any task.

---

## Self-Review Checklist (completed at plan-writing time)

- **Spec coverage:** transport switch (T3/T5), producer store (T5), metrics (T4), sink crate (T6), config files (T3/T6), compose + replay doc (T7), acceptance verification (T8). Non-scope items (security.events Kafka 化, netflow.enriched, exactly-once, archival) intentionally absent.
- **Type consistency:** `FlowStore::write_batch(&mut self, &[FlowRow]) -> Result<(), Self::Error>` matches both stores; `spawn_flow_writer` returns `JoinHandle<S>` matching the shutdown await; `KafkaEventSource` methods used by both `KafkaSource` and `MockSource`.
- **Known risk:** rdkafka 0.39 minor APIs (`payload_view`, `commit`, `Timeout::After`, bitnami KRaft env vars) may need mechanical adjustment at implementation time — adjust and report, do not redesign.
