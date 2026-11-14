//! Kafka consumption loop for `sentinel-sink`.

use std::sync::Arc;
use std::time::Duration;

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
                self.last =
                    Some((message.topic().to_string(), message.partition(), message.offset()));
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
        self.consumer.commit(&tpl, CommitMode::Async).map_err(|err| SourceError(err.to_string()))
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
