use anyhow::Result;
use prometheus::{
    Encoder, Histogram, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Registry, TextEncoder,
};

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
    pub detection_events_total: IntCounterVec,
    pub detection_windows_active: IntGauge,
    pub detection_events_written: IntCounter,
    pub detection_failed_writes_total: IntCounter,
    pub kafka_produced_total: IntCounter,
    pub kafka_produce_errors_total: IntCounter,
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

        let detection_events_total = IntCounterVec::new(
            prometheus::opts!(
                "sentinel_detection_events_total",
                "Total security events emitted by the detection engine"
            ),
            &["rule_id"],
        )?;

        let detection_windows_active = IntGauge::with_opts(prometheus::opts!(
            "sentinel_detection_windows_active",
            "Live per-source scan windows in the detection engine"
        ))?;

        let detection_events_written = IntCounter::with_opts(prometheus::opts!(
            "sentinel_detection_events_written_total",
            "Security events successfully written to ClickHouse"
        ))?;

        let detection_failed_writes_total = IntCounter::with_opts(prometheus::opts!(
            "sentinel_detection_failed_writes_total",
            "Security events dropped after exhausting the write retry budget"
        ))?;

        registry.register(Box::new(packets_captured.clone()))?;
        registry.register(Box::new(bytes_captured.clone()))?;
        registry.register(Box::new(packets_dropped.clone()))?;
        registry.register(Box::new(active_flows.clone()))?;
        registry.register(Box::new(flows_exported.clone()))?;
        registry.register(Box::new(flows_written.clone()))?;
        registry.register(Box::new(flows_dropped.clone()))?;
        registry.register(Box::new(clickhouse_write_errors.clone()))?;
        registry.register(Box::new(clickhouse_write_duration.clone()))?;
        registry.register(Box::new(detection_events_total.clone()))?;
        registry.register(Box::new(detection_windows_active.clone()))?;
        registry.register(Box::new(detection_events_written.clone()))?;
        registry.register(Box::new(detection_failed_writes_total.clone()))?;

        let kafka_produced_total = IntCounter::with_opts(prometheus::opts!(
            "sentinel_kafka_produced_total",
            "Kafka messages successfully produced by the flow output store"
        ))?;
        registry.register(Box::new(kafka_produced_total.clone()))?;
        let kafka_produce_errors_total = IntCounter::with_opts(prometheus::opts!(
            "sentinel_kafka_produce_errors_total",
            "Total failed Kafka produce attempts (including retries)"
        ))?;
        registry.register(Box::new(kafka_produce_errors_total.clone()))?;

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
            detection_events_total,
            detection_windows_active,
            detection_events_written,
            detection_failed_writes_total,
            kafka_produced_total,
            kafka_produce_errors_total,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detection_metrics_registered() {
        let metrics = SensorMetrics::new().unwrap();
        // Fire the label-bearing counter once so the series materializes.
        metrics.detection_events_total.with_label_values(&["SCAN-001"]).inc();
        let exported = metrics.export().unwrap();
        assert!(exported.contains("sentinel_detection_events_total"));
        assert!(exported.contains("sentinel_detection_windows_active"));
        assert!(exported.contains("sentinel_detection_events_written_total"));
        assert!(exported.contains("sentinel_detection_failed_writes_total"));
    }

    #[test]
    fn kafka_metrics_registered() {
        let metrics = SensorMetrics::new().unwrap();
        metrics.kafka_produced_total.inc_by(7);
        metrics.kafka_produce_errors_total.inc();
        let export = metrics.export().unwrap();
        assert!(export.contains("sentinel_kafka_produced_total 7"));
        assert!(export.contains("sentinel_kafka_produce_errors_total 1"));
    }
}
