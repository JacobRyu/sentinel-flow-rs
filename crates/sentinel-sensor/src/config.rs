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
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self { enabled: true, rules_path: None }
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
}
