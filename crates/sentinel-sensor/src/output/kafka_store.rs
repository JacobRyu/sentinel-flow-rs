//! Kafka implementation of [`FlowStore`]: one JSON message per `FlowRow`.

use std::fmt;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use rdkafka::util::Timeout;
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
        Ok(Self { producer, topic: config.kafka.topic.clone(), metrics })
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
            let payload = message_payload(row).map_err(|err| {
                KafkaProduceError(format!("serialize flow {}: {err}", row.flow_id))
            })?;
            let record = FutureRecord::<str, str>::to(&self.topic).key(&key).payload(&payload);
            match self.producer.send(record, Timeout::After(PRODUCE_TIMEOUT)).await {
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
