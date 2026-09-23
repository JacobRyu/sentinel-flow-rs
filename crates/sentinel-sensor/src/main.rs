mod capture;
mod config;
mod flow;
mod metrics;

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info};

use capture::PacketCapture;
use config::SensorConfig;
use flow::FlowProcessor;
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

    let sensor_node = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());

    // Process packets: flow aggregation + periodic sweep in one select! loop
    let flow_config = config.flow.clone();
    let processor_handle = tokio::spawn({
        let metrics = metrics.clone();
        async move {
            let mut processor = FlowProcessor::new(&flow_config, sensor_node, metrics.clone());
            let mut sweep_interval = tokio::time::interval(Duration::from_secs(1));
            let mut packet_count = 0u64;
            let mut byte_count = 0u64;

            loop {
                tokio::select! {
                    maybe = rx.recv() => {
                        let Some(packet) = maybe else { break };
                        packet_count += 1;
                        byte_count += packet.total_len() as u64;

                        // Log first few packets for debugging
                        if packet_count <= 10 {
                            info!("Packet {}: {}", packet_count, packet);
                        }

                        metrics.packets_captured.inc();
                        metrics.bytes_captured.inc_by(packet.total_len() as u64);

                        if let Some(exported) = processor.on_packet(&packet) {
                            info!("flow_export: {:?}", exported);
                        }
                    }
                    _ = sweep_interval.tick() => {
                        for exported in processor.sweep() {
                            info!("flow_export: {:?}", exported);
                        }
                    }
                }
            }

            // Flush remaining flows on shutdown (capture tx dropped → rx None)
            for exported in processor.sweep() {
                info!("flow_export: {:?}", exported);
            }

            info!(
                "Packet processing stopped. Total: {} packets, {} bytes",
                packet_count, byte_count
            );
        }
    });

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received...");

    // Abort capture first: drops tx → processor drains → final sweep → exits
    capture_handle.abort();
    match tokio::time::timeout(Duration::from_secs(5), processor_handle).await {
        Ok(Ok(())) => info!("Flow processor stopped."),
        Ok(Err(e)) => error!("Flow processor task failed: {}", e),
        Err(_) => error!("Flow processor shutdown timed out"),
    }

    info!("SentinelFlow Sensor stopped.");
    Ok(())
}
