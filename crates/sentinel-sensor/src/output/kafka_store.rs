//! Kafka implementation of [`FlowStore`]: one JSON message per `FlowRow`.
//!
//! A batch is enqueued record by record and then awaited as a whole, so the
//! batch costs one delivery round-trip window rather than one round-trip per
//! record.

use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use futures::future::join_all;
use rdkafka::config::ClientConfig;
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::producer::{DeliveryFuture, FutureProducer, FutureRecord};
use serde_json::to_string;
use xxhash_rust::xxh3::xxh3_64;

use super::clickhouse::FlowStore;
use super::row::FlowRow;
use crate::config::OutputConfig;
use crate::metrics::SensorMetrics;

/// How long one record may wait for space in the local producer queue before
/// its enqueue is treated as failed. This mirrors the queue-full retry phase of
/// `FutureProducer::send`; the delivery wait after a successful enqueue is not
/// bounded here — the whole batch is bounded by `FlowWriter`'s `WRITE_TIMEOUT`.
const PRODUCE_TIMEOUT: Duration = Duration::from_secs(2);

/// Delay between enqueue attempts while the local producer queue is full.
const QUEUE_RETRY_DELAY: Duration = Duration::from_millis(100);

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

/// Enqueue one record, retrying while the local producer queue is full for at
/// most [`PRODUCE_TIMEOUT`]. Returns the delivery future to be awaited by the
/// caller; `FutureProducer::send` is not used because it also awaits delivery,
/// which would serialise the batch into one round-trip per record.
async fn enqueue_record(
    producer: &FutureProducer,
    mut record: FutureRecord<'_, str, str>,
) -> Result<DeliveryFuture, KafkaError> {
    let started = Instant::now();
    loop {
        match producer.send_result(record) {
            Ok(delivery) => return Ok(delivery),
            Err((KafkaError::MessageProduction(RDKafkaErrorCode::QueueFull), retry))
                if started.elapsed() < PRODUCE_TIMEOUT =>
            {
                record = retry;
                tokio::time::sleep(QUEUE_RETRY_DELAY).await;
            }
            Err((err, _record)) => return Err(err),
        }
    }
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

    /// Writes every row of the batch.
    ///
    /// All records are enqueued first (each enqueue bounded by
    /// [`PRODUCE_TIMEOUT`]) and only then are their delivery futures awaited
    /// together, so the batch shares one delivery round-trip window instead of
    /// paying one per record. `acks=all` plus idempotence keeps that window
    /// cheap while still confirming broker acknowledgement.
    ///
    /// Failure policy: if any enqueue or delivery fails, the remaining
    /// deliveries are still awaited (no future is left dangling) and the first
    /// error is returned. `FlowWriter` then retries the whole batch, so rows
    /// that already landed are sent again — partial-batch failure produces
    /// duplicate messages, which the pipeline accepts.
    async fn write_batch(&mut self, rows: &[FlowRow]) -> Result<(), Self::Error> {
        if rows.is_empty() {
            return Ok(());
        }

        let mut deliveries = Vec::with_capacity(rows.len());
        let mut first_error: Option<KafkaProduceError> = None;
        for row in rows {
            let key = partition_key(row);
            let payload = match message_payload(row) {
                Ok(payload) => payload,
                Err(err) => {
                    first_error.get_or_insert_with(|| {
                        KafkaProduceError(format!("serialize flow {}: {err}", row.flow_id))
                    });
                    continue;
                }
            };
            let record = FutureRecord::<str, str>::to(&self.topic).key(&key).payload(&payload);
            match enqueue_record(&self.producer, record).await {
                Ok(delivery) => deliveries.push(delivery),
                Err(err) => {
                    self.metrics.kafka_produce_errors_total.inc();
                    first_error.get_or_insert_with(|| KafkaProduceError(err.to_string()));
                }
            }
        }

        for outcome in join_all(deliveries).await {
            match outcome {
                Ok(Ok(_delivery)) => self.metrics.kafka_produced_total.inc(),
                Ok(Err((err, _message))) => {
                    self.metrics.kafka_produce_errors_total.inc();
                    first_error.get_or_insert_with(|| KafkaProduceError(err.to_string()));
                }
                Err(_canceled) => {
                    self.metrics.kafka_produce_errors_total.inc();
                    first_error.get_or_insert_with(|| {
                        KafkaProduceError("delivery canceled: producer shut down".to_string())
                    });
                }
            }
        }

        match first_error {
            Some(err) => Err(err),
            None => Ok(()),
        }
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

    /// Exercises the whole-batch path against rdkafka's in-process mock broker:
    /// every row of one `write_batch` call must be acknowledged and counted.
    #[tokio::test]
    async fn write_batch_delivers_every_row_without_a_live_broker() {
        let mock = rdkafka::mocking::MockCluster::new(1).unwrap();
        let producer: FutureProducer = ClientConfig::new()
            .set("bootstrap.servers", mock.bootstrap_servers())
            .set("acks", "all")
            .set("enable.idempotence", "true")
            .set("compression.type", "lz4")
            .set("message.timeout.ms", "3000")
            .create()
            .unwrap();
        let metrics = Arc::new(SensorMetrics::new().unwrap());
        let mut store = KafkaFlowStore {
            producer,
            topic: "sentinel-flows".to_string(),
            metrics: Arc::clone(&metrics),
        };
        let rows: Vec<FlowRow> = (0..8)
            .map(|i| {
                let flow = format!("1c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e0{i}");
                FlowRow::try_from(&sample_flow(&flow)).unwrap()
            })
            .collect();

        tokio::time::timeout(Duration::from_secs(20), store.write_batch(&rows))
            .await
            .expect("batch write must not hang")
            .expect("every record must be delivered");

        assert_eq!(metrics.kafka_produced_total.get(), rows.len() as u64);
        assert_eq!(metrics.kafka_produce_errors_total.get(), 0);
    }
}
