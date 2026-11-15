//! sentinel-sink: consumes `netflow.raw` and writes flows to ClickHouse via
//! the sensor's `FlowWriter`, wrapped in a store that retries forever instead
//! of dropping batches.

use std::sync::Arc;
use std::sync::atomic::AtomicIsize;
use std::time::Duration;

use clap::Parser;
use sentinel_sensor::metrics::SensorMetrics;
use sentinel_sensor::output::{ClickHouseStore, FlowWriter};
use tokio::sync::mpsc;
use tracing::info;

mod adapter;
mod config;
mod consumer;
mod metrics;
mod store;

use config::SinkConfig;
use metrics::SinkMetrics;
use store::NonDroppingStore;

/// Per-attempt timeout the sensor's `FlowWriter` puts around `write_batch`.
///
/// The writer's own `WRITE_TIMEOUT` (2s) exists to stop a hung sensor write
/// from stalling capture. In the sink it would cut [`NonDroppingStore`]'s retry
/// loop after one attempt and hand the batch to the writer's retry-then-drop
/// policy, i.e. lose rows during a ClickHouse outage. An hour is far beyond any
/// outage the sink should ride out (Kafka retention, 7 days, is the real bound).
///
/// Residual gap: a single attempt stuck for more than an hour goes back to the
/// writer, whose retry budget is four attempts in total. A batch failing for
/// over four hours would still be dropped there, and its row count would stay
/// pending forever, which freezes offset commits (no silent loss, but the sink
/// needs attention). Reaching that state means ClickHouse has taken no write
/// for four hours.
///
/// Shutdown tradeoff: `main` waits at most 30s for the writer, so during an
/// outage the final flush is abandoned. Its rows stay counted as pending, the
/// consumer skips the final offset commit, and they are re-consumed on the next
/// start.
const SINK_WRITE_TIMEOUT: Duration = Duration::from_secs(3600);

#[derive(Parser)]
struct Args {
    /// Path to the sink configuration file.
    #[arg(long, default_value = "config/sink.yaml")]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let args = Args::parse();
    let config = SinkConfig::load(&args.config)?;
    config.validate()?;
    info!("sink configuration loaded from {}", args.config);

    let sensor_metrics = Arc::new(SensorMetrics::new()?);
    let sink_metrics = Arc::new(SinkMetrics::new()?);

    let output = config.output_config();
    // Rows handed to the writer that ClickHouse has not confirmed yet. Shared
    // with `NonDroppingStore` (decrements) and the consumer (gates commits).
    let pending = Arc::new(AtomicIsize::new(0));
    let (tx, rx) = mpsc::channel(10000);
    let writer = FlowWriter::new(
        rx,
        NonDroppingStore::new(ClickHouseStore::new(&output), pending.clone()),
        config.clickhouse.batch_size,
        Duration::from_millis(config.clickhouse.batch_timeout_ms),
        SINK_WRITE_TIMEOUT,
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

    let source = consumer::KafkaSource::new(&config, pending.clone())?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let consume_handle = tokio::spawn(consumer::run(
        source,
        tx,
        sink_metrics.clone(),
        shutdown_rx,
        Duration::from_secs(5),
        pending,
    ));

    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(());
    let _ = consume_handle.await;
    // Bounded wait: during a ClickHouse outage the writer sits in the
    // non-dropping retry loop, so this abandons the final flush. Those rows
    // stay pending, so the consumer skipped the final commit and they are
    // re-consumed on the next start.
    let _ = tokio::time::timeout(Duration::from_secs(30), writer_handle).await;
    if let Some(handle) = metrics_handle {
        let _ = metrics_shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
    info!("sentinel-sink stopped");
    Ok(())
}
