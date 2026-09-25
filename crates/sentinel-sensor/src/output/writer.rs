//! Writer loop: assemble batches, retry failed writes, flush on shutdown.

use std::sync::Arc;
use std::time::Duration;

use sentinel_flow::ExportedFlow;
use tokio::sync::mpsc;
use tracing::{error, warn};

use super::batch::BatchBuffer;
use super::clickhouse::FlowStore;
use super::row::FlowRow;
use crate::metrics::SensorMetrics;

/// Retries attempted for one batch before it is dropped.
const MAX_RETRIES: u32 = 3;
/// Backoff base between retries: 100ms, 200ms, 300ms.
const RETRY_BACKOFF: Duration = Duration::from_millis(100);
/// Upper bound for one store write. A ClickHouse endpoint that accepts the
/// connection but never answers must not stall the writer (and with it the
/// whole capture pipeline) forever.
pub const WRITE_TIMEOUT: Duration = Duration::from_secs(2);

/// Drains exported flows into a [`FlowStore`] in batches.
///
/// A batch is written when it fills up, when `batch_timeout` elapses, or when
/// the input channel closes (shutdown). A batch that still fails after the
/// retry budget is dropped with metrics rather than stalling capture.
pub struct FlowWriter<S: FlowStore> {
    rx: mpsc::Receiver<ExportedFlow>,
    store: S,
    buffer: BatchBuffer,
    batch_timeout: Duration,
    write_timeout: Duration,
    metrics: Arc<SensorMetrics>,
}

impl<S: FlowStore> FlowWriter<S> {
    pub fn new(
        rx: mpsc::Receiver<ExportedFlow>,
        store: S,
        batch_size: usize,
        batch_timeout: Duration,
        write_timeout: Duration,
        metrics: Arc<SensorMetrics>,
    ) -> Self {
        Self {
            rx,
            store,
            buffer: BatchBuffer::new(batch_size),
            batch_timeout,
            write_timeout,
            metrics,
        }
    }

    /// Consume flows until the input channel closes, flush the remainder,
    /// and hand the store back (callers ignore it).
    pub async fn run(mut self) -> S {
        let mut ticker = tokio::time::interval(self.batch_timeout);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // The first tick of a fresh interval fires immediately; consume it so
        // a one-row batch written right after startup waits the full timeout.
        ticker.tick().await;
        loop {
            tokio::select! {
                maybe = self.rx.recv() => {
                    let Some(flow) = maybe else { break };
                    if self.on_flow(flow) {
                        self.flush().await;
                    }
                }
                _ = ticker.tick() => self.flush().await,
            }
        }
        self.flush().await;
        self.store
    }

    /// Buffer one flow, returning `true` when the batch is full.
    fn on_flow(&mut self, flow: ExportedFlow) -> bool {
        match FlowRow::try_from(&flow) {
            Ok(row) => self.buffer.push(row),
            Err(err) => {
                warn!(flow_id = %flow.flow_id, %err, "dropping unconvertible flow");
                self.metrics.flows_dropped.inc();
                false
            }
        }
    }

    /// Write the buffered rows, retrying transient failures and timeouts.
    async fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let rows = self.buffer.take();
        let started = std::time::Instant::now();
        for attempt in 0..=MAX_RETRIES {
            let outcome =
                match tokio::time::timeout(self.write_timeout, self.store.write_batch(&rows)).await
                {
                    Ok(Ok(())) => {
                        self.metrics.flows_written.inc_by(rows.len() as u64);
                        self.metrics
                            .clickhouse_write_duration
                            .observe(started.elapsed().as_secs_f64());
                        return;
                    }
                    Ok(Err(err)) => err.to_string(),
                    Err(_) => format!("write timed out after {:?}", self.write_timeout),
                };
            self.metrics.clickhouse_write_errors.inc();
            if attempt < MAX_RETRIES {
                warn!(attempt, outcome, "clickhouse write failed, retrying");
                tokio::time::sleep(RETRY_BACKOFF * (attempt + 1)).await;
            } else {
                self.metrics.flows_dropped.inc_by(rows.len() as u64);
                error!(outcome, dropped = rows.len(), "clickhouse write failed, dropping batch");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::row::sample_flow;
    use async_trait::async_trait;
    use std::time::Instant;

    /// Records every accepted batch; can be made to fail on or hang during writes.
    #[derive(Default)]
    struct MockStore {
        batches: Vec<Vec<FlowRow>>,
        failures_left: u32,
        failure: String,
        hang: bool,
    }

    #[async_trait]
    impl FlowStore for MockStore {
        type Error = String;

        async fn write_batch(&mut self, rows: &[FlowRow]) -> Result<(), Self::Error> {
            if self.hang {
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
            if self.failures_left > 0 {
                self.failures_left -= 1;
                return Err(self.failure.clone());
            }
            self.batches.push(rows.to_vec());
            Ok(())
        }
    }

    fn setup(batch_size: usize, batch_timeout: Duration, store: MockStore) -> Handle {
        setup_with_timeout(batch_size, batch_timeout, WRITE_TIMEOUT, store)
    }

    fn setup_with_timeout(
        batch_size: usize,
        batch_timeout: Duration,
        write_timeout: Duration,
        store: MockStore,
    ) -> Handle {
        let (tx, rx) = mpsc::channel(64);
        let metrics = Arc::new(SensorMetrics::new().unwrap());
        let writer =
            FlowWriter::new(rx, store, batch_size, batch_timeout, write_timeout, metrics.clone());
        let task = tokio::spawn(writer.run());
        Handle { tx, metrics, task }
    }

    struct Handle {
        tx: mpsc::Sender<ExportedFlow>,
        metrics: Arc<SensorMetrics>,
        task: tokio::task::JoinHandle<MockStore>,
    }

    impl Handle {
        async fn send(&self, flow: ExportedFlow) {
            self.tx.send(flow).await.expect("writer running");
        }

        async fn shutdown(self) -> (MockStore, Arc<SensorMetrics>) {
            let Handle { tx, metrics, task } = self;
            drop(tx);
            (task.await.expect("writer task"), metrics)
        }
    }

    fn flow(id: u8) -> ExportedFlow {
        sample_flow(&format!("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e{id:02}"))
    }

    async fn wait_until(condition: impl Fn() -> bool) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while !condition() {
            assert!(Instant::now() < deadline, "condition not reached in time");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    #[tokio::test]
    async fn flushes_when_batch_is_full() {
        let handle = setup(2, Duration::from_secs(60), MockStore::default());
        handle.send(flow(1)).await;
        handle.send(flow(2)).await;
        let (store, _metrics) = handle.shutdown().await;

        assert_eq!(store.batches.len(), 1);
        assert_eq!(store.batches[0].len(), 2);
    }

    #[tokio::test]
    async fn flushes_on_timeout() {
        let handle = setup(100, Duration::from_millis(50), MockStore::default());
        handle.send(flow(1)).await;

        // The batch never fills: only the interval flush can have written it.
        let metrics = handle.metrics.clone();
        wait_until(|| metrics.flows_written.get() == 1).await;
        let (store, _metrics) = handle.shutdown().await;

        assert_eq!(store.batches.len(), 1);
        assert_eq!(store.batches[0].len(), 1);
    }

    #[tokio::test]
    async fn flushes_remainder_on_shutdown() {
        let handle = setup(100, Duration::from_secs(60), MockStore::default());
        handle.send(flow(7)).await;
        let (store, metrics) = handle.shutdown().await;

        assert_eq!(store.batches.len(), 1);
        assert_eq!(store.batches[0].len(), 1);
        assert_eq!(metrics.flows_written.get(), 1);
    }

    #[tokio::test]
    async fn retries_transient_write_failures() {
        let store = MockStore {
            failures_left: 1,
            failure: "connection reset".to_string(),
            ..MockStore::default()
        };

        let handle = setup(1, Duration::from_secs(60), store);
        handle.send(flow(3)).await;
        let (store, metrics) = handle.shutdown().await;

        assert_eq!(store.batches.len(), 1);
        assert_eq!(metrics.clickhouse_write_errors.get(), 1);
        assert_eq!(metrics.flows_written.get(), 1);
        assert_eq!(metrics.flows_dropped.get(), 0);
    }

    #[tokio::test]
    async fn drops_batch_after_retry_budget_is_exhausted() {
        let store = MockStore {
            failures_left: u32::MAX,
            failure: "clickhouse down".to_string(),
            ..MockStore::default()
        };

        let handle = setup(1, Duration::from_secs(60), store);
        handle.send(flow(4)).await;
        let (store, metrics) = handle.shutdown().await;

        assert!(store.batches.is_empty());
        assert_eq!(metrics.clickhouse_write_errors.get(), u64::from(MAX_RETRIES) + 1);
        assert_eq!(metrics.flows_dropped.get(), 1);
        assert_eq!(metrics.flows_written.get(), 0);
    }

    #[tokio::test]
    async fn times_out_hung_writes_and_drops_the_batch() {
        let store = MockStore { hang: true, ..MockStore::default() };

        let handle =
            setup_with_timeout(1, Duration::from_secs(60), Duration::from_millis(50), store);
        handle.send(flow(9)).await;
        let (store, metrics) = handle.shutdown().await;

        assert!(store.batches.is_empty());
        assert_eq!(metrics.clickhouse_write_errors.get(), u64::from(MAX_RETRIES) + 1);
        assert_eq!(metrics.flows_dropped.get(), 1);
        assert_eq!(metrics.flows_written.get(), 0);
    }

    #[tokio::test]
    async fn drops_unconvertible_flow_without_losing_others() {
        let handle = setup(1, Duration::from_secs(60), MockStore::default());
        let mut broken = flow(5);
        broken.flow_id = "not-a-uuid".to_string();
        handle.send(broken).await;
        handle.send(flow(6)).await;
        let (store, metrics) = handle.shutdown().await;

        assert_eq!(store.batches.len(), 1);
        assert_eq!(store.batches[0].len(), 1);
        assert_eq!(metrics.flows_dropped.get(), 1);
        assert_eq!(metrics.flows_written.get(), 1);
    }
}
