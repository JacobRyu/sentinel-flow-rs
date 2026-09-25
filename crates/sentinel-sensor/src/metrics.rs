use anyhow::Result;
use prometheus::{Encoder, Histogram, HistogramOpts, IntCounter, IntGauge, Registry, TextEncoder};

/// Sensor metrics for Prometheus
#[allow(dead_code)]
pub struct SensorMetrics {
    pub registry: Registry,
    pub packets_captured: IntCounter,
    pub bytes_captured: IntCounter,
    pub packets_dropped: IntCounter,
    pub active_flows: IntGauge,
    pub flows_exported: IntCounter,
    pub flows_written: IntCounter,
    pub flows_dropped: IntCounter,
    pub clickhouse_write_errors: IntCounter,
    pub clickhouse_write_duration: Histogram,
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

        let flows_written = IntCounter::with_opts(prometheus::opts!(
            "sentinel_flows_written_total",
            "Total flows written to ClickHouse"
        ))?;

        let flows_dropped = IntCounter::with_opts(prometheus::opts!(
            "sentinel_flows_dropped_total",
            "Total flows dropped due to conversion failure, backpressure, or write failure"
        ))?;

        let clickhouse_write_errors = IntCounter::with_opts(prometheus::opts!(
            "sentinel_clickhouse_write_errors_total",
            "Total failed ClickHouse write attempts (including retries)"
        ))?;

        let clickhouse_write_duration = Histogram::with_opts(
            HistogramOpts::new(
                "sentinel_clickhouse_write_duration_seconds",
                "ClickHouse batch write latency, including retries and backoff; recorded on success",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]),
        )?;

        registry.register(Box::new(packets_captured.clone()))?;
        registry.register(Box::new(bytes_captured.clone()))?;
        registry.register(Box::new(packets_dropped.clone()))?;
        registry.register(Box::new(active_flows.clone()))?;
        registry.register(Box::new(flows_exported.clone()))?;
        registry.register(Box::new(flows_written.clone()))?;
        registry.register(Box::new(flows_dropped.clone()))?;
        registry.register(Box::new(clickhouse_write_errors.clone()))?;
        registry.register(Box::new(clickhouse_write_duration.clone()))?;

        Ok(Self {
            registry,
            packets_captured,
            bytes_captured,
            packets_dropped,
            active_flows,
            flows_exported,
            flows_written,
            flows_dropped,
            clickhouse_write_errors,
            clickhouse_write_duration,
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
