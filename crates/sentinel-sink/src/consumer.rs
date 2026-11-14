//! Kafka consumption loop for `sentinel-sink`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use rdkafka::config::ClientConfig;
use rdkafka::consumer::{CommitMode, Consumer, StreamConsumer};
use rdkafka::message::Message;
use rdkafka::{Offset, TopicPartitionList};
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

/// rdkafka-backed source: delivers payloads and tracks the last offset and its
/// receive time for commits. Consumer group semantics: `enable.auto.commit=false`,
/// offsets are committed manually by [`run`] on a lagging, grace-gated tick.
pub struct KafkaSource {
    consumer: StreamConsumer,
    last: Option<(String, i32, i64, Instant)>,
}

impl KafkaSource {
    pub fn new(config: &SinkConfig) -> anyhow::Result<Self> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", config.kafka.brokers.join(","))
            .set("group.id", &config.kafka.group_id)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .create()?;
        consumer.subscribe(&[&config.kafka.topic])?;
        Ok(Self { consumer, last: None })
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
                    Instant::now(),
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
        if !should_commit(self.last.clone(), Instant::now()) {
            return Ok(());
        }
        let Some((topic, partition, offset, _)) = self.last.as_ref() else {
            return Ok(());
        };
        let mut tpl = TopicPartitionList::new();
        tpl.add_partition_offset(topic, *partition, Offset::Offset(*offset + 1))
            .map_err(|err| SourceError(err.to_string()))?;
        self.consumer.commit(&tpl, CommitMode::Async).map_err(|err| SourceError(err.to_string()))
    }
}

/// Grace period between receiving a message and allowing its offset to be
/// committed. A row must first traverse the `FlowWriter`: `batch_timeout`
/// (500ms default), then `WRITE_TIMEOUT` (2s) attempts and backoff. The full
/// retry tail is four 2s attempts plus 0.6s of backoff (~9.1s in total), so
/// waiting 10s lets even the worst-case write path finish before an offset
/// advances, and a crash redelivers recent messages instead of skipping rows
/// that never reached disk.
const COMMIT_GRACE: Duration = Duration::from_secs(10);

/// `true` when the last delivered message has aged past [`COMMIT_GRACE`] at
/// `now`. `false` when nothing was delivered yet, or the message is too young
/// to be provably written.
fn should_commit(last: Option<(String, i32, i64, Instant)>, now: Instant) -> bool {
    last.is_some_and(|(_, _, _, received)| now.saturating_duration_since(received) >= COMMIT_GRACE)
}

/// Runs until the source ends or `shutdown` fires. Sends every parseable row
/// into the `FlowWriter` channel; poison messages are counted and skipped.
///
/// Commits happen on a **lagging** tick (`commit_interval`, production: 5s),
/// never per message, and each tick is further gated by [`COMMIT_GRACE`]
/// (10s): an offset only advances once the last delivered message is older
/// than the grace, so in the normal case its batch has already been written to
/// ClickHouse. Recent messages are therefore redelivered on restart; delivery
/// is **at-least-once**, where a crash duplicates rows rather than skipping
/// them. The final commit after the loop uses the same gate, so the tail of a
/// clean shutdown is redelivered too.
///
/// A permanent ClickHouse outage still drops batches under the
/// writer's retry-then-drop policy (see the sensor `FlowWriter`).
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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    use async_trait::async_trait;
    use sentinel_sensor::metrics::SensorMetrics;
    use sentinel_sensor::output::{FlowRow, FlowStore, FlowWriter, WRITE_TIMEOUT};
    use tokio::sync::{mpsc, oneshot};

    use super::*;
    use crate::metrics::SinkMetrics;

    struct MockSource {
        messages: Vec<Result<String, SourceError>>,
        commits: Arc<AtomicUsize>,
        last: Option<Instant>,
    }

    impl MockSource {
        fn json_payloads(commits: Arc<AtomicUsize>) -> Self {
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
                commits,
                last: None,
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
            self.last = Some(Instant::now());
            Some(self.messages.remove(0))
        }

        async fn commit(&mut self) -> Result<(), SourceError> {
            // Mirror `KafkaSource`'s gate so the loop's tick commits and its
            // final commit both go through the same condition.
            let last = self.last.map(|received| ("flows".to_string(), 0, 7, received));
            if should_commit(last, Instant::now()) {
                self.commits.fetch_add(1, Ordering::SeqCst);
            }
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
        let commits = Arc::new(AtomicUsize::new(0));
        let source = MockSource::json_payloads(commits.clone());
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
        // Every message in this test is younger than the commit grace, so both
        // the tick commits and the final commit are skipped: offsets stay put
        // and the messages are redelivered after a restart (at-least-once).
        assert_eq!(commits.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn commit_is_gated_by_grace_on_last_message() {
        let now = Instant::now();
        let young = Some(("flows".to_string(), 0, 7, now));
        let just_under =
            Some(("flows".to_string(), 0, 7, now - COMMIT_GRACE + Duration::from_millis(1)));
        let old = Some(("flows".to_string(), 0, 7, now - COMMIT_GRACE));

        assert!(!super::should_commit(young, now));
        assert!(!super::should_commit(just_under, now));
        assert!(super::should_commit(old, now));
        assert!(!super::should_commit(None, now));
    }
}
