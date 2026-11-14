//! sentinel-sink: consumes `netflow.raw` and writes flows to ClickHouse via
//! the sensor's FlowWriter + ClickHouseStore.

use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use sentinel_sensor::metrics::SensorMetrics;
use sentinel_sensor::output::{ClickHouseStore, FlowWriter, WRITE_TIMEOUT};
use tokio::sync::mpsc;
use tracing::info;

mod adapter;
mod config;
mod consumer;
mod metrics;

use config::SinkConfig;
use metrics::SinkMetrics;

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
    let (tx, rx) = mpsc::channel(10000);
    let writer = FlowWriter::new(
        rx,
        ClickHouseStore::new(&output),
        config.clickhouse.batch_size,
        Duration::from_millis(config.clickhouse.batch_timeout_ms),
        WRITE_TIMEOUT,
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

    let source = consumer::KafkaSource::new(&config)?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let consume_handle = tokio::spawn(consumer::run(
        source,
        tx,
        sink_metrics.clone(),
        shutdown_rx,
        Duration::from_secs(5),
    ));

    tokio::signal::ctrl_c().await?;
    info!("shutdown signal received");
    let _ = shutdown_tx.send(());
    let _ = consume_handle.await;
    let _ = tokio::time::timeout(Duration::from_secs(30), writer_handle).await;
    if let Some(handle) = metrics_handle {
        let _ = metrics_shutdown_tx.send(());
        let _ = tokio::time::timeout(Duration::from_secs(2), handle).await;
    }
    info!("sentinel-sink stopped");
    Ok(())
}
