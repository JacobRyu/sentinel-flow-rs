mod capture;
mod server;

use anyhow::Result;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use capture::PacketCapture;
use sentinel_detection::{DetectionEngine, SecurityEvent};
use sentinel_flow::ExportedFlow;
use sentinel_sensor::config::SensorConfig;
use sentinel_sensor::flow::FlowProcessor;
use sentinel_sensor::metrics::SensorMetrics;
use sentinel_sensor::output::{
    ClickHouseEventStore, ClickHouseStore, EventWriter, FlowWriter, WRITE_TIMEOUT,
};

/// Fallback rules file when `detection.rules_path` is not set.
const DEFAULT_RULES_PATH: &str = "config/detection-rules.yaml";

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

    // Detection: loaded before the processor starts so rule defects fail fast at startup.
    let detection = if config.detection.enabled {
        let rules_path =
            config.detection.rules_path.clone().unwrap_or_else(|| DEFAULT_RULES_PATH.to_string());
        let engine = DetectionEngine::load(Path::new(&rules_path))?;
        info!(rules = engine.rule_count(), rules_path = %rules_path, "detection enabled");
        Some(engine)
    } else {
        info!("detection disabled");
        None
    };

    let (events_tx, events_rx) = mpsc::channel(config.detection.event_channel_capacity);
    let event_writer_handle = if config.detection.enabled {
        let event_writer = EventWriter::new(
            events_rx,
            ClickHouseEventStore::new(&config.output),
            config.output.batch_size,
            Duration::from_millis(config.output.batch_timeout_ms),
            WRITE_TIMEOUT,
            metrics.clone(),
        );
        Some(tokio::spawn(event_writer.run()))
    } else {
        // No consumer will drain this receiver; drop it so any stray send is
        // observed as a closed channel instead of buffering silently.
        drop(events_rx);
        None
    };

    let sensor_node = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());

    // Process packets: flow aggregation + periodic sweep in one select! loop
    let flow_config = config.flow.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let processor_handle = tokio::spawn({
        let metrics = metrics.clone();
        async move {
            let mut detection = detection;
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
                            handle_export(&exported, &mut detection, &events_tx, &metrics);
                            forward(&out_tx, &metrics, exported);
                        }
                    }
                    _ = sweep_interval.tick() => {
                        debug!("active_flows={}", processor.active_flows());
                        for exported in processor.sweep() {
                            info!("flow_export: {:?}", exported);
                            handle_export(&exported, &mut detection, &events_tx, &metrics);
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
                handle_export(&exported, &mut detection, &events_tx, &metrics);
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

    if let Some(handle) = event_writer_handle {
        match tokio::time::timeout(Duration::from_secs(30), handle).await {
            Ok(Ok(_)) => info!("Detection event writer stopped."),
            Ok(Err(e)) => error!("Detection event writer task failed: {}", e),
            Err(_) => error!("Detection event writer shutdown timed out"),
        }
    }

    info!("SentinelFlow Sensor stopped.");
    Ok(())
}

/// Evaluate one exported flow against the detection engine, announce and
/// forward every produced event. A no-op when detection is disabled.
fn handle_export(
    exported: &ExportedFlow,
    detection: &mut Option<DetectionEngine>,
    events_tx: &mpsc::Sender<SecurityEvent>,
    metrics: &SensorMetrics,
) {
    let Some(engine) = detection.as_mut() else { return };
    metrics
        .detection_windows_active
        .set(i64::try_from(engine.active_windows()).unwrap_or(i64::MAX));
    for event in engine.evaluate(exported) {
        metrics.detection_events_total.with_label_values(&[&event.rule_id]).inc();
        info!(rule_id = %event.rule_id, severity = %event.severity, "detection event: {}", event.description);
        forward_event(events_tx, event);
    }
}

/// Hand a security event to the event writer without blocking the flow path.
fn forward_event(events_tx: &mpsc::Sender<SecurityEvent>, event: SecurityEvent) {
    if let Err(err) = events_tx.try_send(event) {
        match err {
            mpsc::error::TrySendError::Full(_) => warn!("events channel full, dropping event"),
            mpsc::error::TrySendError::Closed(_) => debug!("events channel closed, dropping event"),
        }
    }
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
