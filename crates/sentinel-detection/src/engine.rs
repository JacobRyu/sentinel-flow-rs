use crate::Rule;

/// Detection engine for security events
pub struct DetectionEngine {
    rules: Vec<Rule>,
}

impl DetectionEngine {
    /// Create a new detection engine
    pub fn new() -> Self {
        Self { rules: Vec::new() }
    }

    /// Add a rule
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Check a flow against all rules
    pub fn check_flow(&self, flow: &sentinel_flow::ExportedFlow) -> Vec<String> {
        let mut triggered = Vec::new();
        for rule in &self.rules {
            if rule.check(flow) {
                triggered.push(rule.config.id.clone());
            }
        }
        triggered
    }
}

impl Default for DetectionEngine {
    fn default() -> Self {
        Self::new()
    }
}
