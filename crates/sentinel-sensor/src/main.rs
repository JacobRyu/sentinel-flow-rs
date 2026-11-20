mod capture;
mod server;

use anyhow::Result;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use capture::PacketCapture;
use sentinel_detection::{DetectionEngine, SecurityEvent};
use sentinel_enrichment::informer::{CacheSizeGauge, KubernetesRuntime};
use sentinel_enrichment::kubernetes::KubernetesEnricher;
use sentinel_flow::ExportedFlow;
use sentinel_sensor::config::{OutputConfig, OutputMode, SensorConfig};
use sentinel_sensor::flow::FlowProcessor;
use sentinel_sensor::metrics::SensorMetrics;
use sentinel_sensor::output::{
    ClickHouseEventStore, ClickHouseStore, EventWriter, FlowStore, FlowWriter, KafkaFlowStore,
    WRITE_TIMEOUT,
};
use tokio::task::JoinHandle;

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

    // Flow output channel: processor produces, writer batches into the
    // configured sink (ClickHouse directly, or Kafka when mode is kafka).
    let (out_tx, out_rx) = mpsc::channel(10000);
    let writer_handle = match config.output.mode {
        OutputMode::Direct => spawn_flow_writer(
            out_rx,
            ClickHouseStore::new(&config.output),
            &config.output,
            metrics.clone(),
        ),
        OutputMode::Kafka => spawn_flow_writer(
            out_rx,
            KafkaFlowStore::new(&config.output, metrics.clone())?,
            &config.output,
            metrics.clone(),
        ),
    };

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

    // Kubernetes enrichment: disabled by default. When enabled, connect
    // fail-fast (same contract as detection rules) and start the watchers.
    let mut enricher: Option<Arc<KubernetesEnricher>> = None;
    let mut kubernetes_tasks: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    if config.kubernetes.enabled {
        let client = kube::Client::try_default().await?;
        // `try_default()` only infers configuration; probe the API once so an
        // enabled-but-unreachable cluster fails startup (same contract as the
        // detection rules file) instead of silently serving unenriched flows.
        let version =
            tokio::time::timeout(std::time::Duration::from_secs(5), client.apiserver_version())
                .await
                .map_err(|_| anyhow::anyhow!("kubernetes API probe timed out after 5s"))??;
        info!("kubernetes API reachable (git version {})", version.git_version);
        let shared = Arc::new(KubernetesEnricher::new());
        let gauge = Arc::new(CacheSizeGaugeMetric(metrics.clone()));
        let handles = KubernetesRuntime::start(client, shared.clone(), gauge)?;
        kubernetes_tasks.extend(handles);
        enricher = Some(shared);
    }

    let sensor_node = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());

    // Process packets: flow aggregation + periodic sweep in one select! loop
    let flow_config = config.flow.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let processor_handle = tokio::spawn({
        let metrics = metrics.clone();
        let enricher = enricher.clone();
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

                        if let Some(mut exported) = processor.on_packet(&packet) {
                            enrich_ip(&enricher, &mut exported);
                            info!("flow_export: {:?}", exported);
                            handle_export(&exported, &mut detection, &events_tx, &metrics);
                            forward(&out_tx, &metrics, exported);
                        }
                    }
                    _ = sweep_interval.tick() => {
                        debug!("active_flows={}", processor.active_flows());
                        for mut exported in processor.sweep() {
                            enrich_ip(&enricher, &mut exported);
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
            for mut exported in processor.sweep() {
                enrich_ip(&enricher, &mut exported);
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
    // task is blocked in a sync read; then abort capture and join. The
    // Kubernetes watchers are aborted first so they do not outlive the loop.
    for handle in kubernetes_tasks {
        handle.abort();
    }
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

/// Feeds the enrichment cache size into the sensor's Prometheus gauge.
///
/// A newtype rather than an `impl` on `SensorMetrics`: the metric lives in the
/// sensor's lib target, so only a type local to this binary can implement the
/// enrichment crate's trait for it.
struct CacheSizeGaugeMetric(Arc<SensorMetrics>);

impl CacheSizeGauge for CacheSizeGaugeMetric {
    fn set_cache_size(&self, value: usize) {
        self.0.kubernetes_cache_size.set(i64::try_from(value).unwrap_or(i64::MAX));
    }
}

/// Enrich one exported flow in place. No-op when the enricher is disabled
/// (spec D3) or when either IP fails to parse (should not happen; malformed
/// data must not kill the capture loop).
fn enrich_ip(enricher: &Option<Arc<KubernetesEnricher>>, exported: &mut ExportedFlow) {
    let Some(enricher) = enricher else { return };
    let (Ok(source), Ok(destination)) =
        (exported.source_ip.parse::<IpAddr>(), exported.destination_ip.parse::<IpAddr>())
    else {
        return;
    };
    let now = std::time::Instant::now();
    if let Some(metadata) = enricher.enrich(&source, now) {
        exported.source_namespace = metadata.namespace;
        exported.source_pod = metadata.pod;
        exported.source_deployment = metadata.deployment;
        exported.source_service = metadata.service;
        exported.source_app = metadata.app;
    }
    if let Some(metadata) = enricher.enrich(&destination, now) {
        exported.destination_namespace = metadata.namespace;
        exported.destination_pod = metadata.pod;
        exported.destination_deployment = metadata.deployment;
        exported.destination_service = metadata.service;
        exported.destination_app = metadata.app;
    }
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

/// Spawn the flow writer for whichever store the configured mode selected.
///
/// The store is the writer's return value, and it is unused by the shutdown
/// path; awaiting inside the task keeps both match arms the same type
/// (`JoinHandle<()>`) regardless of store.
fn spawn_flow_writer<S: FlowStore + 'static>(
    out_rx: mpsc::Receiver<ExportedFlow>,
    store: S,
    output: &OutputConfig,
    metrics: Arc<SensorMetrics>,
) -> JoinHandle<()> {
    let writer = FlowWriter::new(
        out_rx,
        store,
        output.batch_size,
        Duration::from_millis(output.batch_timeout_ms),
        WRITE_TIMEOUT,
        metrics,
    );
    tokio::spawn(async move {
        writer.run().await;
    })
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

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_enrichment::kubernetes::PodSnapshot;

    fn sample_exported() -> ExportedFlow {
        ExportedFlow {
            flow_id: "0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e01".to_string(),
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
            source_namespace: None,
            source_pod: None,
            source_deployment: None,
            source_service: None,
            source_app: None,
            destination_namespace: None,
            destination_pod: None,
            destination_deployment: None,
            destination_service: None,
            destination_app: None,
        }
    }

    #[test]
    fn enrich_ip_fills_metadata_when_enabled_and_noops_when_disabled() {
        // Disabled path (spec D3): fields stay None.
        let mut flow = sample_exported();
        enrich_ip(&None, &mut flow);
        assert_eq!(flow.source_namespace, None);
        assert_eq!(flow.source_pod, None);

        // Enabled path: a pod cached for 10.0.0.1 fills the source side only.
        let enricher = Arc::new(KubernetesEnricher::new());
        // `apply_pod` normalizes IPv4 to its IPv6-mapped form itself, so the
        // raw address is the right input here.
        enricher.apply_pod(
            IpAddr::from([10, 0, 0, 1]),
            PodSnapshot {
                name: "web-7f9c".to_string(),
                namespace: "prod".to_string(),
                owner_uid: None,
                labels: Default::default(),
                node: "node-a".to_string(),
                updated_at: std::time::Instant::now(),
            },
        );
        let mut flow = sample_exported();
        enrich_ip(&Some(enricher), &mut flow);
        assert_eq!(flow.source_pod.as_deref(), Some("web-7f9c"));
        assert_eq!(flow.source_namespace.as_deref(), Some("prod"));
        assert_eq!(flow.source_deployment, None);
        assert_eq!(flow.destination_pod, None);
    }
}
