//! Security-event writer: same batch/retry pipeline discipline as
//! `writer::FlowWriter`, but for `SecurityEvent` rows into `security_events`.

use std::sync::Arc;
use std::time::Duration;

use sentinel_detection::SecurityEvent;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{error, warn};

use super::event_row::EventRow;
use super::event_store::EventStore;
use crate::metrics::SensorMetrics;

/// Retries attempted for one batch before it is dropped.
const MAX_RETRIES: u32 = 3;
/// Backoff base between retries: 100ms, 200ms, 300ms.
const RETRY_BACKOFF: Duration = Duration::from_millis(100);

/// Batches security events and flushes them to the event store.
///
/// Structural mirror of `writer::FlowWriter`; deliberately separate (the
/// generics merge is deferred to the Phase 6 Kafka work).
pub struct EventWriter<S: EventStore> {
    rx: mpsc::Receiver<SecurityEvent>,
    store: S,
    buffer: Vec<EventRow>,
    batch_size: usize,
    batch_timeout: Duration,
    write_timeout: Duration,
    metrics: Arc<SensorMetrics>,
}

impl<S: EventStore> EventWriter<S> {
    pub fn new(
        rx: mpsc::Receiver<SecurityEvent>,
        store: S,
        batch_size: usize,
        batch_timeout: Duration,
        write_timeout: Duration,
        metrics: Arc<SensorMetrics>,
    ) -> Self {
        Self {
            rx,
            store,
            buffer: Vec::with_capacity(batch_size),
            batch_size,
            batch_timeout,
            write_timeout,
            metrics,
        }
    }

    /// Consume events, flush on batch-full or timeout, drain on close, and
    /// hand the store back (callers ignore it).
    pub async fn run(mut self) -> S {
        let mut ticker = tokio::time::interval(self.batch_timeout);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first tick of a fresh interval fires immediately; consume it so
        // a one-row batch written right after startup waits the full timeout.
        ticker.tick().await;
        loop {
            tokio::select! {
                maybe = self.rx.recv() => {
                    let Some(event) = maybe else { break };
                    self.buffer.push(EventRow::from(&event));
                    if self.buffer.len() >= self.batch_size {
                        self.flush().await;
                    }
                }
                _ = ticker.tick() => self.flush().await,
            }
        }
        self.flush().await;
        self.store
    }

    /// Write the buffered rows, retrying transient failures and timeouts.
    async fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let rows = std::mem::take(&mut self.buffer);
        for attempt in 0..=MAX_RETRIES {
            let outcome =
                match tokio::time::timeout(self.write_timeout, self.store.write_batch(&rows)).await
                {
                    Ok(Ok(())) => {
                        self.metrics.detection_events_written.inc_by(rows.len() as u64);
                        return;
                    }
                    Ok(Err(err)) => err.to_string(),
                    Err(_) => format!("write timed out after {:?}", self.write_timeout),
                };
            if attempt < MAX_RETRIES {
                warn!(attempt, outcome, "event write failed, retrying");
                tokio::time::sleep(RETRY_BACKOFF * (attempt + 1)).await;
            } else {
                self.metrics.detection_failed_writes_total.inc_by(rows.len() as u64);
                error!(outcome, dropped = rows.len(), "event write failed, dropping batch");
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use tokio::sync::mpsc;

    use super::*;
    use crate::metrics::SensorMetrics;
    use crate::output::event_row::sample_event;
    use crate::output::writer::WRITE_TIMEOUT;

    struct MockEventStore {
        batches: Vec<Vec<EventRow>>,
        failures_left: usize,
    }

    impl MockEventStore {
        fn returning_ok() -> Self {
            Self { batches: Vec::new(), failures_left: 0 }
        }

        fn failing(times: usize) -> Self {
            Self { batches: Vec::new(), failures_left: times }
        }
    }

    #[async_trait::async_trait]
    impl EventStore for MockEventStore {
        type Error = std::io::Error;

        async fn write_batch(&mut self, rows: &[EventRow]) -> Result<(), Self::Error> {
            if self.failures_left > 0 {
                self.failures_left -= 1;
                return Err(std::io::Error::other("injected write failure"));
            }
            self.batches.push(rows.to_vec());
            Ok(())
        }
    }

    struct WriterHandle {
        tx: mpsc::Sender<SecurityEvent>,
        task: tokio::task::JoinHandle<MockEventStore>,
        metrics: Arc<SensorMetrics>,
    }

    async fn spawn_writer(store: MockEventStore, batch_size: usize) -> WriterHandle {
        let (tx, rx) = mpsc::channel(64);
        let metrics = Arc::new(SensorMetrics::new().unwrap());
        let writer = EventWriter::new(
            rx,
            store,
            batch_size,
            Duration::from_millis(50),
            WRITE_TIMEOUT,
            metrics.clone(),
        );
        let task = tokio::spawn(writer.run());
        WriterHandle { tx, task, metrics }
    }

    /// Poll until `cond()` is true or ~2s elapse (CI scheduling tolerance).
    async fn wait_until(mut cond: impl FnMut() -> bool) {
        for _ in 0..400 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn flushes_when_batch_is_full() {
        let handle = spawn_writer(MockEventStore::returning_ok(), 2).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        handle.tx.send(sample_event("SCAN-001", 22)).await.unwrap();
        handle.tx.send(sample_event("SCAN-001", 23)).await.unwrap(); // stays buffered
        drop(handle.tx);
        let store = handle.task.await.unwrap();
        assert_eq!(store.batches.len(), 2);
        assert_eq!(store.batches[0].len(), 2);
        assert_eq!(store.batches[1].len(), 1);
    }

    #[tokio::test]
    async fn flushes_on_batch_timeout() {
        let handle = spawn_writer(MockEventStore::returning_ok(), 8).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        wait_until(|| handle.metrics.detection_events_written.get() == 1).await;
        assert_eq!(handle.metrics.detection_events_written.get(), 1);
    }

    #[tokio::test]
    async fn drains_remainder_on_channel_close() {
        let handle = spawn_writer(MockEventStore::returning_ok(), 8).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        drop(handle.tx);
        let store = handle.task.await.unwrap();
        assert_eq!(store.batches.len(), 1);
        assert_eq!(store.batches[0].len(), 1);
    }

    #[tokio::test]
    async fn retries_until_ok() {
        let handle = spawn_writer(MockEventStore::failing(1), 2).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        handle.tx.send(sample_event("SCAN-001", 22)).await.unwrap();
        drop(handle.tx);
        let store = handle.task.await.unwrap();
        assert_eq!(store.batches.len(), 1);
        assert_eq!(handle.metrics.detection_failed_writes_total.get(), 0);
    }

    #[tokio::test]
    async fn drops_after_retry_budget() {
        let handle = spawn_writer(MockEventStore::failing(usize::MAX), 2).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        handle.tx.send(sample_event("SCAN-001", 22)).await.unwrap();
        drop(handle.tx);
        let store = handle.task.await.unwrap();
        assert!(store.batches.is_empty());
        assert_eq!(handle.metrics.detection_failed_writes_total.get(), 2);
    }
}
