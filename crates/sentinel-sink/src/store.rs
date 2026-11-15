//! Store wrapper that retries a batch until ClickHouse accepts it.

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use sentinel_sensor::output::{FlowRow, FlowStore};
use tracing::warn;

/// Backoff after the first failed write attempt; doubles per failure.
const INITIAL_BACKOFF: Duration = Duration::from_secs(1);
/// Backoff cap. A long outage costs one attempt per 10s instead of a hot loop.
const MAX_BACKOFF: Duration = Duration::from_secs(10);

/// Wraps a [`FlowStore`] so a batch is retried until the store accepts it.
///
/// The sensor's `FlowWriter` retries a failed batch a few times and then
/// **drops** it. That is right for the sensor, where a stalled capture pipeline
/// is worse than lost rows, but wrong for the sink: offsets are eventually
/// committed, so a batch dropped here would be lost for good during a
/// ClickHouse outage.
///
/// This wrapper never gives the batch back. That loop is the sink's
/// back-pressure mechanism: `FlowWriter::flush` blocks inside it, the bounded
/// channel from the consumer fills, `tx.send` blocks, the consumer stops
/// calling `recv`, and Kafka (7-day retention) buffers the backlog. While rows
/// are outstanding the shared `pending` counter stays positive, which blocks
/// offset commits, so a crash re-consumes them.
pub struct NonDroppingStore<S> {
    inner: S,
    pending: Arc<AtomicIsize>,
    initial_backoff: Duration,
    max_backoff: Duration,
}

impl<S> NonDroppingStore<S> {
    /// Wrap `inner`, sharing its outstanding-row counter with the consumer.
    pub fn new(inner: S, pending: Arc<AtomicIsize>) -> Self {
        Self::with_backoff(inner, pending, INITIAL_BACKOFF, MAX_BACKOFF)
    }

    /// [`new`](Self::new) with an explicit backoff schedule. Tests use
    /// millisecond steps so the retry loop does not dominate the suite.
    fn with_backoff(
        inner: S,
        pending: Arc<AtomicIsize>,
        initial_backoff: Duration,
        max_backoff: Duration,
    ) -> Self {
        Self { inner, pending, initial_backoff, max_backoff }
    }
}

/// `Ok` after the store accepted the batch, otherwise retried forever.
///
/// The error type is [`Infallible`] on purpose: returning `Ok` twice for one
/// batch costs a duplicate row, while returning `Err` would hand the batch to
/// the writer's drop path. The only way a batch is lost is the process dying
/// before the write lands, which leaves its offset uncommitted.
#[async_trait]
impl<S: FlowStore> FlowStore for NonDroppingStore<S> {
    type Error = Infallible;

    async fn write_batch(&mut self, rows: &[FlowRow]) -> Result<(), Self::Error> {
        let mut backoff = self.initial_backoff;
        loop {
            match self.inner.write_batch(rows).await {
                Ok(()) => {
                    release_rows(&self.pending, rows.len());
                    return Ok(());
                }
                Err(err) => {
                    warn!(
                        %err,
                        rows = rows.len(),
                        pending = self.pending.load(Ordering::SeqCst),
                        retry_in_ms = backoff.as_millis(),
                        "clickhouse write failed, retrying (no rows are dropped)"
                    );
                    tokio::time::sleep(backoff).await;
                    backoff = next_backoff(backoff, self.max_backoff);
                }
            }
        }
    }
}

fn next_backoff(current: Duration, max: Duration) -> Duration {
    (current * 2).min(max)
}

/// Saturating decrement of the shared outstanding-row counter.
///
/// Double counting is real: a batch whose write returned just as the writer's
/// outer `tokio::time::timeout` fired is retried and released twice. `isize`
/// plus a CAS loop keeps the counter at zero instead of wrapping to a huge
/// positive value, which would block every future commit.
pub(crate) fn release_rows(pending: &AtomicIsize, rows: usize) {
    let amount = rows.min(isize::MAX as usize) as isize;
    let mut current = pending.load(Ordering::SeqCst);
    while current > 0 {
        // `saturating_sub` floors at `isize::MIN`; the counter's floor is zero.
        let next = current.saturating_sub(amount).max(0);
        match pending.compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return,
            Err(actual) => current = actual,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
    use std::time::Duration;

    use async_trait::async_trait;
    use sentinel_flow::ExportedFlow;
    use sentinel_sensor::output::{FlowRow, FlowStore};

    use super::*;

    fn row(id: u8) -> FlowRow {
        let exported = ExportedFlow {
            flow_id: format!("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e{id:02}"),
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
        };
        FlowRow::try_from(&exported).unwrap()
    }

    /// Fails `failures_left` times, then records the batch.
    #[derive(Default)]
    struct MockInner {
        failures_left: AtomicUsize,
        attempts: AtomicUsize,
        written: Vec<Vec<FlowRow>>,
    }

    #[async_trait]
    impl FlowStore for MockInner {
        type Error = String;

        async fn write_batch(&mut self, rows: &[FlowRow]) -> Result<(), Self::Error> {
            self.attempts.fetch_add(1, Ordering::SeqCst);
            if self.failures_left.load(Ordering::SeqCst) > 0 {
                self.failures_left.fetch_sub(1, Ordering::SeqCst);
                return Err("clickhouse unavailable".to_string());
            }
            self.written.push(rows.to_vec());
            Ok(())
        }
    }

    fn test_store(failures_left: usize, pending: &Arc<AtomicIsize>) -> NonDroppingStore<MockInner> {
        let inner =
            MockInner { failures_left: AtomicUsize::new(failures_left), ..MockInner::default() };
        NonDroppingStore::with_backoff(
            inner,
            pending.clone(),
            Duration::from_millis(1),
            Duration::from_millis(10),
        )
    }

    // (c) retries a failing inner store N times, then succeeds and releases
    // exactly `rows.len()` from the pending counter.
    #[tokio::test]
    async fn retries_failing_inner_store_then_releases_pending() {
        let pending = Arc::new(AtomicIsize::new(2));
        let mut store = test_store(3, &pending);

        store.write_batch(&[row(1), row(2)]).await.unwrap();

        assert_eq!(store.inner.attempts.load(Ordering::SeqCst), 4);
        assert_eq!(store.inner.written.len(), 1);
        assert_eq!(store.inner.written[0].len(), 2);
        assert_eq!(pending.load(Ordering::SeqCst), 0);
    }

    // (d) a retried batch whose first attempt already succeeded must not wrap
    // the saturating counter.
    #[tokio::test]
    async fn double_success_does_not_undercount_pending() {
        let pending = Arc::new(AtomicIsize::new(2));
        let mut store = test_store(0, &pending);
        let rows = [row(1), row(2)];

        store.write_batch(&rows).await.unwrap();
        assert_eq!(pending.load(Ordering::SeqCst), 0);

        // The writer's outer timeout fired after the first `Ok`, so it retries
        // the same batch: the second decrement must clamp at zero instead of
        // wrapping to a huge value that would block every future commit.
        store.write_batch(&rows).await.unwrap();
        assert_eq!(pending.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn release_rows_saturates_at_zero() {
        let pending = AtomicIsize::new(1);
        release_rows(&pending, 5);
        assert_eq!(pending.load(Ordering::SeqCst), 0);

        let pending = AtomicIsize::new(0);
        release_rows(&pending, 0);
        assert_eq!(pending.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn backoff_doubles_up_to_the_cap() {
        let max = Duration::from_secs(10);
        let mut backoff = INITIAL_BACKOFF;
        let mut seen = Vec::new();
        for _ in 0..5 {
            backoff = next_backoff(backoff, max);
            seen.push(backoff);
        }
        assert_eq!(
            seen,
            vec![
                Duration::from_secs(2),
                Duration::from_secs(4),
                Duration::from_secs(8),
                Duration::from_secs(10),
                Duration::from_secs(10),
            ]
        );
    }
}
