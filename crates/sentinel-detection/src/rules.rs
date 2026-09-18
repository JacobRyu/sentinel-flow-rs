use serde::{Deserialize, Serialize};

/// Detection rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleConfig {
    /// Rule ID
    pub id: String,

    /// Rule name
    pub name: String,

    /// Rule type (static, threshold, baseline)
    pub rule_type: String,

    /// Condition description
    pub condition: String,

    /// Severity level
    pub severity: String,

    /// Confidence score (0.0 - 1.0)
    pub confidence: f32,

    /// Parameters (for threshold rules)
    #[serde(default)]
    pub parameters: std::collections::HashMap<String, serde_json::Value>,
}

/// Detection rule
#[derive(Debug, Clone)]
pub struct Rule {
    pub config: RuleConfig,
}

impl Rule {
    /// Create a new rule from config
    pub fn new(config: RuleConfig) -> Self {
        Self { config }
    }

    /// Check if a flow matches this rule
    pub fn check(&self, _flow: &sentinel_flow::ExportedFlow) -> bool {
        // TODO: Implement rule matching logic
        false
    }
}
