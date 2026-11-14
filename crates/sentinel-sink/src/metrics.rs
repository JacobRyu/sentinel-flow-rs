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
        Ok(Self { registry, consumed_total, failed_messages_total })
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
