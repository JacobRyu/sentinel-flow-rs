//! Security-event ClickHouse row mapping (`security_events` schema).

use std::net::{IpAddr, Ipv6Addr};

use chrono::{DateTime, Utc};
use clickhouse::Row;
use sentinel_detection::SecurityEvent;
#[cfg(test)]
use sentinel_detection::Severity;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::row::{datetime64_ms, ipv6, protocol_code};

/// One `security_events` row. Encoding mirrors `FlowRow`: `DateTime64(3)` as
/// epoch milliseconds, `IPv6` as 16 raw octets (IPv4 as v4-mapped), `Enum8`
/// protocol/severity as numeric tags.
#[allow(dead_code)] // wired into the event writer by task 8
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Row)]
pub struct EventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub event_id: Uuid,
    #[serde(with = "datetime64_ms")]
    pub timestamp: DateTime<Utc>,
    /// MVP emits no flow correlation (Phase 7 metadata enrichment adds it).
    pub source_flow_ids: Vec<Uuid>,
    pub event_type: String,
    pub severity: i8,
    pub confidence: f32,
    #[serde(with = "ipv6")]
    pub source_ip: Ipv6Addr,
    #[serde(with = "ipv6")]
    pub destination_ip: Ipv6Addr,
    pub destination_port: u16,
    pub protocol: i8,
    pub description: String,
    pub rule_id: String,
    pub rule_name: String,
    pub tags: Vec<String>,
    pub mitigation_suggestions: Vec<String>,
}

impl From<&SecurityEvent> for EventRow {
    fn from(event: &SecurityEvent) -> Self {
        Self {
            event_id: event.event_id,
            timestamp: event.timestamp,
            source_flow_ids: Vec::new(),
            event_type: event.event_type.clone(),
            severity: event.severity.code(),
            confidence: event.confidence,
            source_ip: to_ipv6(event.source_ip),
            destination_ip: to_ipv6(event.destination_ip),
            destination_port: event.destination_port,
            protocol: protocol_code(&event.protocol),
            description: event.description.clone(),
            rule_id: event.rule_id.clone(),
            rule_name: event.rule_name.clone(),
            tags: event.tags.clone(),
            mitigation_suggestions: event.mitigation_suggestions.clone(),
        }
    }
}

/// Map a family-tagged IP onto the schema's IPv6 column (v4-mapped for IPv4).
#[allow(dead_code)] // only reachable through `EventRow::from` until task 8
fn to_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Shared sample event for the output-module test suites (row/store/writer).
#[cfg(test)]
pub(crate) fn sample_event(rule_id: &str, port: u16) -> SecurityEvent {
    use chrono::TimeZone;

    let timestamp = Utc.with_ymd_and_hms(2026, 11, 10, 10, 0, 0).unwrap();
    SecurityEvent {
        event_id: Uuid::from_u128(0xf00d + u128::from(port)),
        timestamp,
        rule_id: rule_id.to_string(),
        rule_name: "port_scanning".to_string(),
        event_type: "port_scanning".to_string(),
        severity: Severity::High,
        confidence: 0.8,
        source_ip: "10.0.0.9".parse().unwrap(),
        destination_ip: "198.51.100.7".parse().unwrap(),
        destination_port: port,
        protocol: "TCP".to_string(),
        description: "Unknown external destination".to_string(),
        tags: vec!["outbound".to_string()],
        mitigation_suggestions: vec!["Verify destination legitimacy with the user.".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_event_converts_to_clickhouse_row() {
        let event = sample_event("EXT-001", 443);
        let row = EventRow::from(&event);
        assert_eq!(row.event_id, event.event_id);
        assert_eq!(row.timestamp, event.timestamp);
        assert_eq!(row.severity, 3); // high → Enum8 tag
        assert_eq!(row.source_ip, std::net::Ipv4Addr::new(10, 0, 0, 9).to_ipv6_mapped());
        assert_eq!(row.destination_ip, std::net::Ipv4Addr::new(198, 51, 100, 7).to_ipv6_mapped());
        assert!(row.source_flow_ids.is_empty());
        assert_eq!(row.protocol, 1); // TCP → Enum8 tag
        assert_eq!(row.tags, vec!["outbound".to_string()]);
        assert!(!row.description.is_empty());
    }
}
