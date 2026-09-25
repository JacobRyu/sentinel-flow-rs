mod capture;
mod config;
mod flow;
mod metrics;
mod output;
mod server;

use anyhow::Result;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info};

use capture::PacketCapture;
use config::SensorConfig;
use flow::FlowProcessor;
use metrics::SensorMetrics;
use output::{ClickHouseStore, FlowWriter, WRITE_TIMEOUT};
use sentinel_flow::ExportedFlow;

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
    config.validate()?;
    info!("Loaded configuration from {}", config_path);

    // Initialize metrics
    let metrics = Arc::new(SensorMetrics::new()?);

    // Initialize packet capture
    let (tx, mut rx) = mpsc::channel(10000);
    let capture = PacketCapture::new(&config.capture)?;

    // Start packet capture in background. The ready flag tracks whether the
    // datalink channel is actually up (drives /readyz).
    let ready = Arc::new(AtomicBool::new(false));
    let mut capture_handle = tokio::spawn({
        let capture_ready = ready.clone();
        async move {
            if let Err(e) = capture.run(tx, capture_ready).await {
                error!("Packet capture error: {}", e);
            }
        }
    });

    // Prometheus scrape + Kubernetes probe endpoints (/metrics, /healthz, /readyz).
    let (metrics_shutdown, metrics_handle) = if config.metrics.enabled {
        let listener = std::net::TcpListener::bind(("0.0.0.0", config.metrics.port))?;
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let handle =
            tokio::spawn(server::serve(listener, metrics.clone(), ready.clone(), async move {
                let _ = shutdown_rx.await;
            }));
        (Some(shutdown_tx), Some(handle))
    } else {
        info!("Metrics endpoint disabled in config");
        (None, None)
    };

    // Flow output channel: processor produces, writer batches into ClickHouse.
    let (out_tx, out_rx) = mpsc::channel(10000);
    let writer = FlowWriter::new(
        out_rx,
        ClickHouseStore::new(&config.output),
        config.output.batch_size,
        Duration::from_millis(config.output.batch_timeout_ms),
        WRITE_TIMEOUT,
        metrics.clone(),
    );
    let writer_handle = tokio::spawn(writer.run());

    let sensor_node = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());

    // Process packets: flow aggregation + periodic sweep in one select! loop
    let flow_config = config.flow.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let processor_handle = tokio::spawn({
        let metrics = metrics.clone();
        async move {
            let mut processor = FlowProcessor::new(&flow_config, sensor_node, metrics.clone());
            let mut sweep_interval = tokio::time::interval(Duration::from_secs(1));
            let mut packet_count = 0u64;
            let mut byte_count = 0u64;
            let mut shutdown_rx = shutdown_rx;

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
                            forward(&out_tx, &metrics, exported);
                        }
                    }
                    _ = sweep_interval.tick() => {
                        debug!("active_flows={}", processor.active_flows());
                        for exported in processor.sweep() {
                            info!("flow_export: {:?}", exported);
                            forward(&out_tx, &metrics, exported);
                        }
                    }
                    // Ok or Err (sender dropped) both mean shutdown was requested.
                    _ = &mut shutdown_rx => {
                        break;
                    }
                }
            }

            // Flush remaining flows on shutdown (capture tx dropped → rx None)
            for exported in processor.sweep() {
                info!("flow_export: {:?}", exported);
                forward(&out_tx, &metrics, exported);
            }

            info!(
                "Packet processing stopped. Total: {} packets, {} bytes",
                packet_count, byte_count
            );
            // out_tx drops here, closing the writer's input channel.
        }
    });

    // Wait for a shutdown signal, or for capture to die. A capture task that
    // exits (missing interface, permission denied) would otherwise leave a
    // sensor that serves probes but sees no traffic; exiting instead lets
    // Kubernetes restart the pod and surface the failure in its logs/events.
    tokio::select! {
        res = tokio::signal::ctrl_c() => {
            res?;
            info!("Shutdown signal received...");
        }
        res = &mut capture_handle => {
            match res {
                Ok(()) => error!("Packet capture task exited; shutting down"),
                Err(e) => error!("Packet capture task failed: {}; shutting down", e),
            }
        }
    }

    if let Some(shutdown_tx) = metrics_shutdown {
        let _ = shutdown_tx.send(());
    }
    if let Some(handle) = metrics_handle {
        match tokio::time::timeout(Duration::from_secs(2), handle).await {
            Ok(Ok(Ok(()))) => info!("Metrics endpoint stopped."),
            Ok(Ok(Err(e))) => error!("Metrics endpoint failed: {}", e),
            Ok(Err(e)) => error!("Metrics endpoint task failed: {}", e),
            Err(_) => error!("Metrics endpoint shutdown timed out"),
        }
    }

    // Signal the processor first so its select! breaks even if the capture
    // task is blocked in a sync read; then abort capture and join.
    let _ = shutdown_tx.send(());
    capture_handle.abort();
    match tokio::time::timeout(Duration::from_secs(5), processor_handle).await {
        Ok(Ok(())) => info!("Flow processor stopped."),
        Ok(Err(e)) => error!("Flow processor task failed: {}", e),
        Err(_) => error!("Flow processor shutdown timed out"),
    }

    // The processor dropped out_tx; the writer flushes its last batch and
    // exits. Allow several worst-case batches: up to MAX_RETRIES attempts of
    // WRITE_TIMEOUT plus backoff each (~9s per batch) while ClickHouse is
    // unreachable, so 10s could cut a drain short and lose the count.
    match tokio::time::timeout(Duration::from_secs(30), writer_handle).await {
        Ok(Ok(_)) => info!("ClickHouse writer stopped."),
        Ok(Err(e)) => error!("ClickHouse writer task failed: {}", e),
        Err(_) => error!("ClickHouse writer shutdown timed out"),
    }

    info!("SentinelFlow Sensor stopped.");
    Ok(())
}

/// Hand a flow to the writer without blocking packet processing. A full or
/// closed channel drops the flow, counted in `sentinel_flows_dropped_total`.
fn forward(tx: &mpsc::Sender<ExportedFlow>, metrics: &SensorMetrics, flow: ExportedFlow) {
    if let Err(err) = tx.try_send(flow) {
        metrics.flows_dropped.inc();
        match err {
            mpsc::error::TrySendError::Full(_) => debug!("output channel full, dropping flow"),
            mpsc::error::TrySendError::Closed(_) => {
                debug!("output channel closed, dropping flow")
            }
        }
    }
}
