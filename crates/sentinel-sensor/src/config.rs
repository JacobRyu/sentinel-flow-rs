use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Capture configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    /// Network interface to capture
    pub interface: String,

    /// Ring buffer size in frames
    pub buffer_size: usize,

    /// Maximum packet length to capture
    pub snap_len: u32,
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self { interface: "eth0".to_string(), buffer_size: 4096, snap_len: 65535 }
    }
}

/// Flow engine configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowConfig {
    /// Inactive timeout in seconds
    pub inactive_timeout_secs: u64,

    /// Active timeout in seconds
    pub active_timeout_secs: u64,

    /// Maximum concurrent flows
    pub max_flows: usize,
}

impl Default for FlowConfig {
    fn default() -> Self {
        Self { inactive_timeout_secs: 30, active_timeout_secs: 300, max_flows: 100_000 }
    }
}

/// Which sink receives exported flow rows.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OutputMode {
    /// Write directly to ClickHouse (default; existing behavior).
    #[default]
    Direct,
    /// Publish each row to the Kafka topic `output.kafka.topic`.
    Kafka,
}

/// Kafka producer settings, used only when `output.mode` is `kafka`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct KafkaOutputConfig {
    /// Bootstrap broker list, e.g. ["localhost:9092"].
    #[serde(default)]
    pub brokers: Vec<String>,
    /// Destination topic, e.g. "netflow.raw".
    #[serde(default)]
    pub topic: String,
}

/// Output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputConfig {
    /// ClickHouse URL
    pub clickhouse_url: String,

    /// ClickHouse database
    pub clickhouse_database: String,

    /// ClickHouse user (optional)
    #[serde(default)]
    pub clickhouse_user: Option<String>,

    /// ClickHouse password (optional)
    #[serde(default)]
    pub clickhouse_password: Option<String>,

    /// Batch size for writes
    pub batch_size: usize,

    /// Batch timeout in milliseconds
    pub batch_timeout_ms: u64,

    /// Output transport selection; `kafka` uses the `kafka` sub-config below.
    #[serde(default)]
    pub mode: OutputMode,

    /// Kafka producer settings; only read when `mode` is `kafka`.
    #[serde(default)]
    pub kafka: KafkaOutputConfig,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            clickhouse_url: "http://localhost:8123".to_string(),
            clickhouse_database: "sentinel".to_string(),
            clickhouse_user: None,
            clickhouse_password: None,
            batch_size: 1000,
            // Kept below the <1s export-to-ClickHouse latency budget.
            batch_timeout_ms: 500,
            mode: OutputMode::Direct,
            kafka: KafkaOutputConfig::default(),
        }
    }
}

/// Detection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    /// Enable detection engine
    pub enabled: bool,

    /// Path to detection rules
    pub rules_path: Option<String>,

    /// 検知イベントの mpsc チャネル容量。EventWriter (Task 8) 導入の flow で使用。
    #[serde(default = "default_event_channel_capacity")]
    pub event_channel_capacity: usize,
}

fn default_event_channel_capacity() -> usize {
    1000
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_path: None,
            event_channel_capacity: default_event_channel_capacity(),
        }
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Enable Prometheus metrics
    pub enabled: bool,

    /// Metrics port
    pub port: u16,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self { enabled: true, port: 9090 }
    }
}

/// Main sensor configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SensorConfig {
    /// Capture settings
    pub capture: CaptureConfig,

    /// Flow engine settings
    pub flow: FlowConfig,

    /// Output settings
    pub output: OutputConfig,

    /// Detection settings
    pub detection: DetectionConfig,

    /// Metrics settings
    pub metrics: MetricsConfig,
}

impl SensorConfig {
    /// Load configuration from YAML file
    pub fn load(path: &str) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_yaml::from_str(&content)?;
        Ok(config)
    }

    /// Check invariants that deserialization cannot express.
    ///
    /// `batch_timeout_ms: 0` would panic inside the writer task (tokio
    /// intervals require a non-zero period), taking output down silently.
    pub fn validate(&self) -> Result<()> {
        anyhow::ensure!(
            self.output.batch_size >= 1,
            "output.batch_size must be at least 1, got {}",
            self.output.batch_size
        );
        anyhow::ensure!(
            self.output.batch_timeout_ms >= 1,
            "output.batch_timeout_ms must be at least 1, got {}",
            self.output.batch_timeout_ms
        );
        if self.output.mode == OutputMode::Kafka {
            anyhow::ensure!(
                !self.output.kafka.brokers.is_empty(),
                "output.kafka.brokers must not be empty when output.mode is kafka"
            );
            anyhow::ensure!(
                !self.output.kafka.topic.is_empty(),
                "output.kafka.topic must not be empty when output.mode is kafka"
            );
        }
        anyhow::ensure!(
            self.detection.event_channel_capacity >= 1,
            "detection.event_channel_capacity must be >= 1 (EventWriter sizing)",
        );
        Ok(())
    }

    #[allow(dead_code)]
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = serde_yaml::to_string(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = SensorConfig::default();
        assert_eq!(config.capture.interface, "eth0");
        assert_eq!(config.flow.max_flows, 100_000);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_zero_output_settings() {
        let mut config = SensorConfig::default();
        config.output.batch_size = 0;
        assert!(config.validate().is_err());

        let mut config = SensorConfig::default();
        config.output.batch_timeout_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn rejects_zero_event_channel_capacity() {
        let mut config = SensorConfig::default();
        config.detection.event_channel_capacity = 0;
        assert!(config.validate().unwrap_err().to_string().contains("event_channel_capacity"),);
    }

    #[test]
    fn output_mode_defaults_to_direct() {
        let config = SensorConfig::default();
        assert_eq!(config.output.mode, OutputMode::Direct);
    }

    #[test]
    fn kafka_mode_requires_brokers_and_topic() {
        let mut config = SensorConfig::default();
        config.output.mode = OutputMode::Kafka;
        assert!(config.validate().is_err());

        config.output.kafka.brokers = vec!["localhost:9092".to_string()];
        assert!(config.validate().is_err());

        config.output.kafka.topic = "netflow.raw".to_string();
        config.validate().unwrap();
    }

    #[test]
    fn output_config_parses_kafka_block() {
        // OutputConfig's scalar fields are required by serde (no per-field
        // defaults), so the fixture supplies them alongside the new keys.
        let yaml = "clickhouse_url: http://localhost:8123\nclickhouse_database: sentinel\nbatch_size: 1000\nbatch_timeout_ms: 500\nmode: kafka\nkafka:\n  brokers:\n    - localhost:9092\n  topic: netflow.raw";
        let output: OutputConfig = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(output.mode, OutputMode::Kafka);
        assert_eq!(output.kafka.brokers, vec!["localhost:9092".to_string()]);
        assert_eq!(output.kafka.topic, "netflow.raw");
    }
}
