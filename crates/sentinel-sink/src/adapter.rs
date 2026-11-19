//! Bridge between Kafka `FlowRow` payloads and the `ExportedFlow` input type
//! that the sensor's `FlowWriter` consumes.

use chrono::SecondsFormat;
use sentinel_flow::ExportedFlow;
use sentinel_sensor::output::FlowRow;

/// Canonical (bit, name) pairs, mirroring row.rs's flag encoding.
const FLAG_NAMES: [(u8, &str); 6] =
    [(1, "FIN"), (2, "SYN"), (4, "RST"), (8, "PSH"), (16, "ACK"), (32, "URG")];

/// Rebuild an `ExportedFlow` from a deserialized `FlowRow` so the row can be
/// pushed into the sensor's `FlowWriter`, which converts it back to a `FlowRow`
/// internally. Round-trip stable: `FlowRow::try_from(&flow_row_to_exported(row))`
/// equals `row` for any row the sensor produced (unknown flag names were
/// already dropped when the row was built).
pub fn flow_row_to_exported(row: &FlowRow) -> ExportedFlow {
    ExportedFlow {
        flow_id: row.flow_id.to_string(),
        timestamp_start: row.timestamp_start.to_rfc3339_opts(SecondsFormat::Millis, true),
        timestamp_end: row.timestamp_end.to_rfc3339_opts(SecondsFormat::Millis, true),
        source_ip: row.source_ip.to_string(),
        destination_ip: row.destination_ip.to_string(),
        source_port: row.source_port,
        destination_port: row.destination_port,
        protocol: protocol_name(row.protocol).to_string(),
        packets_forward: row.packets_forward,
        packets_reverse: row.packets_reverse,
        bytes_forward: row.bytes_forward,
        bytes_reverse: row.bytes_reverse,
        duration_ms: u64::from(row.duration_ms),
        tcp_flags: FLAG_NAMES
            .iter()
            .filter(|(bit, _)| row.tcp_flags_seen.contains(bit))
            .map(|(_, name)| name.to_string())
            .collect(),
        sensor_node: row.sensor_node.clone(),
        source_namespace: row.source_namespace.clone(),
        source_pod: row.source_pod.clone(),
        source_deployment: row.source_deployment.clone(),
        source_service: row.source_service.clone(),
        source_app: row.source_app.clone(),
        destination_namespace: row.destination_namespace.clone(),
        destination_pod: row.destination_pod.clone(),
        destination_deployment: row.destination_deployment.clone(),
        destination_service: row.destination_service.clone(),
        destination_app: row.destination_app.clone(),
    }
}

/// Inverse of the sensor's protocol_code mapping (1=TCP 2=UDP 3=ICMP 4=OTHER).
fn protocol_name(code: i8) -> &'static str {
    match code {
        1 => "TCP",
        2 => "UDP",
        3 => "ICMP",
        _ => "OTHER",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn sample_exported() -> ExportedFlow {
        ExportedFlow {
            flow_id: "0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e01".to_string(),
            timestamp_start: "2026-09-25T10:00:00.123+00:00".to_string(),
            timestamp_end: "2026-09-25T10:00:01.456+00:00".to_string(),
            source_ip: "10.0.0.1".to_string(),
            destination_ip: "2001:db8::1".to_string(),
            source_port: 44321,
            destination_port: 443,
            protocol: "TCP".to_string(),
            packets_forward: 10,
            packets_reverse: 20,
            bytes_forward: 1000,
            bytes_reverse: 2000,
            duration_ms: 1333,
            tcp_flags: vec!["SYN".to_string(), "ACK".to_string()],
            sensor_node: "node-1".to_string(),
            source_namespace: None,
            source_pod: None,
            source_deployment: None,
            source_service: None,
            source_app: None,
            destination_namespace: None,
            destination_pod: None,
            destination_deployment: None,
            destination_service: None,
            destination_app: None,
        }
    }

    #[test]
    fn row_rebuilds_into_the_same_row() {
        let original = FlowRow::try_from(&sample_exported()).unwrap();
        let exported = flow_row_to_exported(&original);
        assert_eq!(FlowRow::try_from(&exported).unwrap(), original);
        assert_eq!(exported.tcp_flags, vec!["SYN".to_string(), "ACK".to_string()]);
        assert_eq!(exported.duration_ms, u64::from(Duration::from_millis(1333).as_millis() as u32));
    }

    #[test]
    fn metadata_survives_the_sink_roundtrip() {
        let mut row = FlowRow::try_from(&sample_exported()).unwrap();
        row.source_namespace = Some("prod".to_string());
        row.source_pod = Some("web-7f9c".to_string());
        row.source_deployment = Some("web".to_string());
        row.source_service = Some("web-svc".to_string());
        row.source_app = Some("web".to_string());
        row.destination_pod = Some("billing-2d4e".to_string());

        let exported = flow_row_to_exported(&row);
        assert_eq!(exported.source_pod.as_deref(), Some("web-7f9c"));
        assert_eq!(exported.source_namespace.as_deref(), Some("prod"));
        assert_eq!(exported.destination_pod.as_deref(), Some("billing-2d4e"));

        // Lossless invariant: rebuilding the row must reproduce every field.
        assert_eq!(FlowRow::try_from(&exported).unwrap(), row);
    }
}
