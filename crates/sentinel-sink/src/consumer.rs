//! Kafka consumption loop for `sentinel-sink`.

use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, Ordering};
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
use crate::store::release_rows;

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
    pending: Arc<AtomicIsize>,
}

impl KafkaSource {
    pub fn new(config: &SinkConfig, pending: Arc<AtomicIsize>) -> anyhow::Result<Self> {
        let consumer: StreamConsumer = ClientConfig::new()
            .set("bootstrap.servers", config.kafka.brokers.join(","))
            .set("group.id", &config.kafka.group_id)
            .set("enable.auto.commit", "false")
            .set("auto.offset.reset", "earliest")
            .create()?;
        consumer.subscribe(&[&config.kafka.topic])?;
        Ok(Self { consumer, last: None, pending })
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
        let pending = self.pending.load(Ordering::SeqCst);
        if !should_commit(self.last.clone(), pending, Instant::now()) {
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
/// (500ms default) plus at least one store write. The sensor's worst-case
/// attempt tail is four 2s `WRITE_TIMEOUT` attempts plus 0.6s of backoff
/// (~9.1s), so 10s lets a normal write path finish before an offset advances.
/// The sink uses a much longer per-attempt timeout (`SINK_WRITE_TIMEOUT` in
/// `main.rs`) and leans on the `pending` half of [`should_commit`] to cover
/// arbitrarily long retries; the grace keeps commits lagging by a few batch
/// cycles regardless.
const COMMIT_GRACE: Duration = Duration::from_secs(10);

/// `true` when the last delivered message may be committed at `now`: it aged
/// past [`COMMIT_GRACE`] **and** no rows are still outstanding.
///
/// `pending` is the number of rows handed to the writer that the store has not
/// confirmed yet (saturating, so it can never go negative). Any positive value
/// means some rows are not durable, and committing would place the offset past
/// them — a crash at that point would skip them forever. `false` when nothing
/// was delivered yet either.
fn should_commit(last: Option<(String, i32, i64, Instant)>, pending: isize, now: Instant) -> bool {
    pending <= 0
        && last.is_some_and(|(_, _, _, received)| {
            now.saturating_duration_since(received) >= COMMIT_GRACE
        })
}

/// Runs until the source ends or `shutdown` fires. Sends every parseable row
/// into the `FlowWriter` channel; poison messages are counted and skipped.
///
/// Commits happen on a **lagging** tick (`commit_interval`, production: 5s),
/// never per message, and each tick is gated twice: the last delivered message
/// must be older than [`COMMIT_GRACE`] (10s) *and* `pending` — rows the store
/// wrapper has not confirmed yet — must be zero.
///
/// The committed position therefore always lags durable ClickHouse writes:
///
/// - crash or kill → uncommitted rows are re-consumed on the next start, which
///   duplicates rows but never loses them;
/// - ClickHouse outage → the non-dropping store wrapper keeps retrying, the
///   bounded channel fills, this loop stops receiving, and Kafka buffers the
///   backlog within its retention;
/// - shutdown while rows are still outstanding → the final commit is skipped,
///   leaving those rows for the next start.
///
/// `pending` is incremented here *before* each send and decremented by the
/// store wrapper after a successful write; increments stay ahead of any
/// possible write so a batch landing between `send` and the increment can
/// never hide an unwritten row. The invariant that makes the counter drain
/// again is `FlowRow` → `ExportedFlow` → `FlowRow` being lossless (see
/// `adapter.rs`): a row counted here always reaches the wrapper.
pub async fn run(
    mut source: impl KafkaEventSource,
    tx: mpsc::Sender<ExportedFlow>,
    metrics: Arc<SinkMetrics>,
    mut shutdown: tokio::sync::oneshot::Receiver<()>,
    commit_interval: Duration,
    pending: Arc<AtomicIsize>,
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
                        // Count the row before the writer can see it, so a
                        // batch completing right after `send` cannot let a
                        // commit tick observe `pending == 0`.
                        pending.fetch_add(1, Ordering::SeqCst);
                        if let Err(err) = tx.send(flow_row_to_exported(&row)).await {
                            // Nothing was queued: give the reservation back so
                            // the counter cannot stall every later commit.
                            release_rows(&pending, 1);
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
    if pending.load(Ordering::SeqCst) > 0 {
        warn!(
            pending = pending.load(Ordering::SeqCst),
            "skipping final offset commit: rows are not durable yet, they will be re-consumed"
        );
    } else if let Err(err) = source.commit().await {
        warn!("final offset commit failed: {err}");
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
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
        commit_attempts: Arc<AtomicUsize>,
        pending: Arc<AtomicIsize>,
        last: Option<Instant>,
    }

    impl MockSource {
        fn new(messages: Vec<Result<String, SourceError>>, pending: Arc<AtomicIsize>) -> Self {
            Self {
                messages,
                commits: Arc::new(AtomicUsize::new(0)),
                commit_attempts: Arc::new(AtomicUsize::new(0)),
                pending,
                last: None,
            }
        }

        fn json_payloads(pending: Arc<AtomicIsize>) -> Self {
            let exported = sample_exported();
            let row = FlowRow::try_from(&exported).unwrap();
            Self::new(
                vec![
                    Ok(serde_json::to_string(&row).unwrap()),
                    Ok(serde_json::to_string(&row).unwrap()),
                    Err(SourceError("broker unavailable".to_string())),
                    Ok("not json".to_string()),
                    Ok(serde_json::to_string(&row).unwrap()),
                ],
                pending,
            )
        }

        /// Pretend the last message was received `age` ago.
        fn aged_last(mut self, age: Duration) -> Self {
            self.last = Some(Instant::now() - age);
            self
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
            source_namespace: None,
            source_pod: None,
            source_deployment: None,
            source_service: None,
            source_app: None,
            destination_namespace: None,
            destination_pod: None,
            destination_deployment: None,
            destination_service: None,
            destination_app: None,
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
            self.commit_attempts.fetch_add(1, Ordering::SeqCst);
            let last = self.last.map(|received| ("flows".to_string(), 0, 7, received));
            let pending = self.pending.load(Ordering::SeqCst);
            if should_commit(last, pending, Instant::now()) {
                self.commits.fetch_add(1, Ordering::SeqCst);
            }
            Ok(())
        }
    }

    struct SinkMockStore {
        batches: Vec<Vec<FlowRow>>,
        pending: Arc<AtomicIsize>,
    }

    #[async_trait]
    impl FlowStore for SinkMockStore {
        type Error = String;

        async fn write_batch(&mut self, rows: &[FlowRow]) -> Result<(), Self::Error> {
            self.batches.push(rows.to_vec());
            // Stand-in for `NonDroppingStore`, which releases rows here.
            super::release_rows(&self.pending, rows.len());
            Ok(())
        }
    }

    #[tokio::test]
    async fn loop_forwards_rows_counts_failures_and_commits() {
        let pending = Arc::new(AtomicIsize::new(0));
        let source = MockSource::json_payloads(pending.clone());
        let commits = source.commits.clone();
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
            pending.clone(),
        ));
        let writer = FlowWriter::new(
            rx,
            SinkMockStore { batches: Vec::new(), pending: pending.clone() },
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
        // Every counted row was released once its batch was written.
        assert_eq!(pending.load(Ordering::SeqCst), 0);
        // Every message in this test is younger than the commit grace, so both
        // the tick commits and the final commit are skipped: offsets stay put
        // and the messages are redelivered after a restart (at-least-once).
        assert_eq!(commits.load(Ordering::SeqCst), 0);
    }

    #[tokio::test]
    async fn final_commit_fires_once_nothing_is_pending_and_the_last_message_is_old() {
        let pending = Arc::new(AtomicIsize::new(0));
        let source = MockSource::new(Vec::new(), pending.clone()).aged_last(COMMIT_GRACE);
        let commits = source.commits.clone();
        let attempts = source.commit_attempts.clone();
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        super::run(
            source,
            tx,
            Arc::new(SinkMetrics::new().unwrap()),
            shutdown_rx,
            Duration::from_secs(60),
            pending,
        )
        .await;
        drop(shutdown_tx);

        // (b) positive path, previously untested through `run()`: the source
        // ends immediately and the eligible final commit is the only attempt.
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(commits.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn final_commit_is_skipped_while_rows_are_pending() {
        let pending = Arc::new(AtomicIsize::new(3));
        let source = MockSource::new(Vec::new(), pending.clone()).aged_last(COMMIT_GRACE);
        let attempts = source.commit_attempts.clone();
        let (tx, _rx) = mpsc::channel(1);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        super::run(
            source,
            tx,
            Arc::new(SinkMetrics::new().unwrap()),
            shutdown_rx,
            Duration::from_secs(60),
            pending,
        )
        .await;
        drop(shutdown_tx);

        // Not even attempted: outstanding rows keep the offset where it is.
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn commit_is_gated_by_grace_and_pending_rows() {
        let now = Instant::now();
        let young = Some(("flows".to_string(), 0, 7, now));
        let just_under =
            Some(("flows".to_string(), 0, 7, now - COMMIT_GRACE + Duration::from_millis(1)));
        let old = Some(("flows".to_string(), 0, 7, now - COMMIT_GRACE));

        assert!(!super::should_commit(young, 0, now));
        assert!(!super::should_commit(just_under, 0, now));
        assert!(super::should_commit(old.clone(), 0, now));
        assert!(!super::should_commit(None, 0, now));

        // (a) outstanding rows block an otherwise eligible commit.
        assert!(!super::should_commit(old.clone(), 1, now));
        assert!(!super::should_commit(old, 7, now));
    }
}
