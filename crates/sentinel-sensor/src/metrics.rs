use anyhow::Result;
use prometheus::{Encoder, IntCounter, IntGauge, Registry, TextEncoder};

/// Sensor metrics for Prometheus
#[allow(dead_code)]
pub struct SensorMetrics {
    pub registry: Registry,
    pub packets_captured: IntCounter,
    pub bytes_captured: IntCounter,
    pub packets_dropped: IntCounter,
    pub active_flows: IntGauge,
    pub flows_exported: IntCounter,
}

impl SensorMetrics {
    /// Create new metrics
    pub fn new() -> Result<Self> {
        let registry = Registry::new();

        let packets_captured = IntCounter::with_opts(prometheus::opts!(
            "sentinel_packets_captured_total",
            "Total packets captured"
        ))?;

        let bytes_captured = IntCounter::with_opts(prometheus::opts!(
            "sentinel_bytes_captured_total",
            "Total bytes captured"
        ))?;

        let packets_dropped = IntCounter::with_opts(prometheus::opts!(
            "sentinel_packets_dropped_total",
            "Total packets dropped"
        ))?;

        let active_flows = IntGauge::with_opts(prometheus::opts!(
            "sentinel_flows_active",
            "Current active flows"
        ))?;

        let flows_exported = IntCounter::with_opts(prometheus::opts!(
            "sentinel_flows_exported_total",
            "Total flows exported"
        ))?;

        registry.register(Box::new(packets_captured.clone()))?;
        registry.register(Box::new(bytes_captured.clone()))?;
        registry.register(Box::new(packets_dropped.clone()))?;
        registry.register(Box::new(active_flows.clone()))?;
        registry.register(Box::new(flows_exported.clone()))?;

        Ok(Self {
            registry,
            packets_captured,
            bytes_captured,
            packets_dropped,
            active_flows,
            flows_exported,
        })
    }

    /// Export metrics as Prometheus text format
    #[allow(dead_code)]
    pub fn export(&self) -> Result<String> {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer)?;
        Ok(String::from_utf8(buffer)?)
    }
}
