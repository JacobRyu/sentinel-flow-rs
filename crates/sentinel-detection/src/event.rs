//! 検知イベント。detection 側で生成され、sensor の EventWriter が ClickHouse へ書き込む。

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::rules::Severity;

/// ClickHouse `security_events` テーブル (architecture.md §7.4) に対応するイベント。
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub rule_id: String,
    pub rule_name: String,
    pub event_type: String, // 例: "port_scanning" (= rule_name)
    pub severity: Severity,
    pub confidence: f32,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub protocol: String,
    pub description: String,
    pub tags: Vec<String>,
    pub mitigation_suggestions: Vec<String>,
}

/// 需要 fields から 1 つの SecurityEvent を発行する（timestamp/uuid はここで採番）。
#[allow(dead_code)] // wired into DetectionEngine in Task 3
#[allow(clippy::too_many_arguments)] // API fixed by the Task 2 brief; consumed by engine (Task 3)
pub(crate) fn build_event(
    rule_id: &str,
    rule_name: &str,
    severity: Severity,
    confidence: f32,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    destination_port: u16,
    protocol: &str,
    description: String,
    tags: Vec<String>,
    mitigation_suggestions: Vec<String>,
) -> SecurityEvent {
    SecurityEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        rule_id: rule_id.to_owned(),
        rule_name: rule_name.to_owned(),
        event_type: rule_name.to_owned(),
        severity,
        confidence,
        source_ip,
        destination_ip,
        destination_port,
        protocol: protocol.to_owned(),
        description,
        tags,
        mitigation_suggestions,
    }
}

/// `{key}` プレースホルダを埋める。未知の key はそのまま残す（EXT 系ルールの説明文など）。
#[allow(dead_code)] // wired into DetectionEngine in Task 3
pub(crate) fn fill_template(template: &str, values: &[(&str, u64)]) -> String {
    let mut out = template.to_owned();
    for (key, value) in values {
        let placeholder = format!("{{{key}}}");
        if out.contains(&placeholder) {
            out = out.replace(&placeholder, value.to_string().as_str());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn sample_rule_fields() -> (&'static str, Severity, f32) {
        ("SCAN-001", Severity::Critical, 0.9)
    }

    #[test]
    fn fill_template_replaces_known_placeholders() {
        let out = fill_template(
            "over {threshold} distinct ports in {window_secs}s",
            &[("threshold", 50), ("window_secs", 60), ("source_port", 8080)],
        );
        assert_eq!(out, "over 50 distinct ports in 60s");
    }

    #[test]
    fn fill_template_keeps_unknown_placeholders() {
        let out = fill_template("Port scanning detected: {unknown}", &[]);
        assert_eq!(out, "Port scanning detected: {unknown}");
    }

    #[test]
    fn build_event_sets_type_from_rule_name() {
        let (rule_id, severity, confidence) = sample_rule_fields();
        let event = build_event(
            rule_id,
            "port_scanning",
            severity,
            confidence,
            IpAddr::from([10, 0, 0, 9]),
            IpAddr::from([203, 0, 113, 10]),
            443,
            "TCP",
            "Port scanning detected".to_string(),
            vec!["scan".to_string()],
            vec!["Rate-limit the source.".to_string()],
        );
        assert_eq!(event.rule_id, "SCAN-001");
        assert_eq!(event.rule_name, "port_scanning");
        assert_eq!(event.event_type, "port_scanning");
        assert_eq!(event.destination_port, 443);
        assert_eq!(event.protocol, "TCP");
        assert!(!event.event_id.is_nil());
        assert!(event.timestamp <= chrono::Utc::now());
    }
}
