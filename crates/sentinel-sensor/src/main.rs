mod capture;
mod config;
mod metrics;

use anyhow::Result;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{error, info};

use capture::PacketCapture;
use config::SensorConfig;
use metrics::SensorMetrics;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    info!("Starting SentinelFlow Sensor...");

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let config_path = args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "config/sensor.yaml".to_string());

    // Load configuration
    let config = SensorConfig::load(&config_path)?;
    info!("Loaded configuration from {}", config_path);

    // Initialize metrics
    let metrics = Arc::new(SensorMetrics::new()?);

    // Initialize packet capture
    let (tx, mut rx) = mpsc::channel(10000);
    let capture = PacketCapture::new(&config.capture)?;

    // Start packet capture in background
    let capture_handle = tokio::spawn(async move {
        if let Err(e) = capture.run(tx).await {
            error!("Packet capture error: {}", e);
        }
    });

    // Process packets
    let processor_handle = tokio::spawn(async move {
        let mut packet_count = 0u64;
        let mut byte_count = 0u64;

        while let Some(packet) = rx.recv().await {
            packet_count += 1;
            byte_count += packet.total_len() as u64;

            // Log first few packets for debugging
            if packet_count <= 10 {
                info!("Packet {}: {}", packet_count, packet);
            }

            // Update metrics
            metrics.packets_captured.inc();
            metrics.bytes_captured.inc_by(packet.total_len() as u64);

            // TODO: Flow aggregation (Phase 2)
            // TODO: ClickHouse export (Phase 3)
        }

        info!("Packet processing stopped. Total: {} packets, {} bytes", packet_count, byte_count);
    });

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received...");

    // Cleanup
    capture_handle.abort();
    processor_handle.abort();

    info!("SentinelFlow Sensor stopped.");
    Ok(())
}
