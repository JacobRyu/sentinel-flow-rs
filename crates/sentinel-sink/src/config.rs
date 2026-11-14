//! Sink configuration (`config/sink.yaml`).

use anyhow::{Context, Result, ensure};
use sentinel_sensor::config::OutputConfig;
use serde::Deserialize;

/// Where to read flows from and where to write them.
#[derive(Debug, Clone, Deserialize)]
pub struct SinkConfig {
    pub kafka: KafkaSourceConfig,
    pub clickhouse: ClickHouseTargetConfig,
    #[serde(default)]
    pub metrics: SinkMetricsConfig,
}

/// Kafka consumer settings.
#[derive(Debug, Clone, Deserialize)]
pub struct KafkaSourceConfig {
    pub brokers: Vec<String>,
    pub topic: String,
    #[serde(default = "default_group_id")]
    pub group_id: String,
}

fn default_group_id() -> String {
    "clickhouse-sinker".to_string()
}

/// ClickHouse target settings.
#[derive(Debug, Clone, Deserialize)]
pub struct ClickHouseTargetConfig {
    pub url: String,
    #[serde(default = "default_database")]
    pub database: String,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    #[serde(default = "default_batch_timeout_ms")]
    pub batch_timeout_ms: u64,
}

fn default_database() -> String {
    "sentinel".to_string()
}

fn default_batch_size() -> usize {
    1000
}

fn default_batch_timeout_ms() -> u64 {
    500
}

/// Sink metrics endpoint settings.
#[derive(Debug, Clone, Deserialize)]
pub struct SinkMetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_port")]
    pub port: u16,
}

impl Default for SinkMetricsConfig {
    fn default() -> Self {
        Self { enabled: true, port: default_metrics_port() }
    }
}

fn default_true() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9091
}

impl SinkConfig {
    pub fn load(path: &str) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("read sink config from {path}"))?;
        serde_yaml::from_str(&raw).with_context(|| format!("parse sink config from {path}"))
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(!self.kafka.brokers.is_empty(), "kafka.brokers must not be empty");
        ensure!(!self.kafka.topic.is_empty(), "kafka.topic must not be empty");
        ensure!(self.clickhouse.batch_size >= 1, "clickhouse.batch_size must be >= 1");
        ensure!(self.clickhouse.batch_timeout_ms >= 1, "clickhouse.batch_timeout_ms must be >= 1");
        Ok(())
    }

    /// Adapter so the sensor's `ClickHouseStore::new` can consume sink settings.
    pub fn output_config(&self) -> OutputConfig {
        OutputConfig {
            clickhouse_url: self.clickhouse.url.clone(),
            clickhouse_database: self.clickhouse.database.clone(),
            clickhouse_user: self.clickhouse.user.clone(),
            clickhouse_password: self.clickhouse.password.clone(),
            batch_size: self.clickhouse.batch_size,
            batch_timeout_ms: self.clickhouse.batch_timeout_ms,
            mode: Default::default(),
            kafka: Default::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "kafka:\n  brokers:\n    - localhost:9092\n  topic: netflow.raw\n  group_id: clickhouse-sinker\nclickhouse:\n  url: http://localhost:8123\n  database: sentinel\n  batch_size: 1000\n  batch_timeout_ms: 500\nmetrics:\n  enabled: true\n  port: 9091";

    #[test]
    fn parses_sample_config() {
        let config: SinkConfig = serde_yaml::from_str(SAMPLE).unwrap();
        assert_eq!(config.kafka.group_id, "clickhouse-sinker");
        assert_eq!(config.kafka.topic, "netflow.raw");
        assert_eq!(config.clickhouse.batch_size, 1000);
        assert!(config.metrics.enabled);
        assert_eq!(config.metrics.port, 9091);
        config.validate().unwrap();
    }

    #[test]
    fn group_id_and_database_have_defaults() {
        let yaml = "kafka:\n  brokers:\n    - localhost:9092\n  topic: netflow.raw\nclickhouse:\n  url: http://localhost:8123";
        let config: SinkConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(config.kafka.group_id, "clickhouse-sinker");
        assert_eq!(config.clickhouse.database, "sentinel");
    }

    #[test]
    fn rejects_empty_brokers_and_zero_batches() {
        let mut config: SinkConfig = serde_yaml::from_str(SAMPLE).unwrap();
        config.kafka.brokers.clear();
        assert!(config.validate().is_err());
        config.kafka.brokers = vec!["localhost:9092".to_string()];
        config.clickhouse.batch_size = 0;
        assert!(config.validate().is_err());
        config.clickhouse.batch_size = 1;
        config.clickhouse.batch_timeout_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn output_config_maps_clickhouse_fields() {
        let config: SinkConfig = serde_yaml::from_str(SAMPLE).unwrap();
        let output = config.output_config();
        assert_eq!(output.clickhouse_url, "http://localhost:8123");
        assert_eq!(output.clickhouse_database, "sentinel");
        assert_eq!(output.batch_size, 1000);
        assert_eq!(output.batch_timeout_ms, 500);
    }
}
