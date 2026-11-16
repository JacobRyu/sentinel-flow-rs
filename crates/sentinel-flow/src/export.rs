use serde::{Deserialize, Serialize};

use crate::FlowEntry;
use crate::FlowKey;

/// Exported flow record.
///
/// `source_ip`/`destination_ip` (and the forward/reverse counters) use the
/// canonical key orientation (lower-address side), which is not necessarily
/// the connection initiator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportedFlow {
    pub flow_id: String,
    pub timestamp_start: String,
    pub timestamp_end: String,
    pub source_ip: String,
    pub destination_ip: String,
    pub source_port: u16,
    pub destination_port: u16,
    pub protocol: String,
    pub packets_forward: u32,
    pub packets_reverse: u32,
    pub bytes_forward: u64,
    pub bytes_reverse: u64,
    pub duration_ms: u64,
    pub tcp_flags: Vec<String>,
    pub sensor_node: String,
    /// Source namespace from Kubernetes metadata; None when not enriched.
    pub source_namespace: Option<String>,
    /// Source pod name; None when not enriched.
    pub source_pod: Option<String>,
    /// Source workload's owning Deployment name; None when not enriched.
    pub source_deployment: Option<String>,
    /// Source Service name; None when not enriched.
    pub source_service: Option<String>,
    /// Source pod's app label (`app.kubernetes.io/name`); None when absent.
    pub source_app: Option<String>,
    /// Destination namespace; None when not enriched.
    pub destination_namespace: Option<String>,
    /// Destination pod name; None when not enriched.
    pub destination_pod: Option<String>,
    /// Destination Deployment name; None when not enriched.
    pub destination_deployment: Option<String>,
    /// Destination Service name; None when not enriched.
    pub destination_service: Option<String>,
    /// Destination app label; None when absent.
    pub destination_app: Option<String>,
}

impl ExportedFlow {
    /// Create from flow key and entry
    pub fn from_flow(key: &FlowKey, entry: &FlowEntry, sensor_node: &str) -> Self {
        Self {
            flow_id: entry.flow_id.clone(),
            timestamp_start: entry.timestamp_start.to_rfc3339(),
            timestamp_end: entry.timestamp_end.to_rfc3339(),
            source_ip: ip_to_string(&key.src_ip),
            destination_ip: ip_to_string(&key.dst_ip),
            source_port: key.src_port,
            destination_port: key.dst_port,
            protocol: key.protocol_str().to_string(),
            packets_forward: entry.packets_forward,
            packets_reverse: entry.packets_reverse,
            bytes_forward: entry.bytes_forward,
            bytes_reverse: entry.bytes_reverse,
            duration_ms: entry.duration_ms(),
            tcp_flags: entry.tcp_flags.to_vec().into_iter().map(String::from).collect(),
            sensor_node: sensor_node.to_string(),
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
}

/// Flow exporter that converts flow entries to exported format
pub struct FlowExporter {
    sensor_node: String,
}

impl FlowExporter {
    /// Create a new flow exporter
    pub fn new(sensor_node: String) -> Self {
        Self { sensor_node }
    }

    /// Export a single flow
    pub fn export_flow(&self, key: &FlowKey, entry: &FlowEntry) -> ExportedFlow {
        ExportedFlow::from_flow(key, entry, &self.sensor_node)
    }

    /// Export multiple flows
    pub fn export_flows(&self, flows: &[(FlowKey, FlowEntry)]) -> Vec<ExportedFlow> {
        flows.iter().map(|(key, entry)| self.export_flow(key, entry)).collect()
    }
}

/// Convert 16-byte IP address to string
fn ip_to_string(ip: &[u8; 16]) -> String {
    // Check if IPv4-mapped
    if ip[..10] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0] && ip[10..12] == [0xff, 0xff] {
        format!("{}.{}.{}.{}", ip[12], ip[13], ip[14], ip[15])
    } else {
        format!(
            "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
            u16::from_be_bytes([ip[0], ip[1]]),
            u16::from_be_bytes([ip[2], ip[3]]),
            u16::from_be_bytes([ip[4], ip[5]]),
            u16::from_be_bytes([ip[6], ip[7]]),
            u16::from_be_bytes([ip[8], ip[9]]),
            u16::from_be_bytes([ip[10], ip[11]]),
            u16::from_be_bytes([ip[12], ip[13]]),
            u16::from_be_bytes([ip[14], ip[15]]),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_flow() -> ExportedFlow {
        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];
        let key = FlowKey::new(ip1, ip2, 12345, 80, 6);
        let mut entry = FlowEntry::new();
        entry.update(100, Some(0x02), true);

        let exporter = FlowExporter::new("node-1".to_string());
        exporter.export_flow(&key, &entry)
    }

    #[test]
    fn test_export_flow() {
        let exported = test_flow();

        assert_eq!(exported.source_ip, "10.0.0.1");
        assert_eq!(exported.destination_ip, "10.0.0.2");
        assert_eq!(exported.protocol, "TCP");
        assert_eq!(exported.sensor_node, "node-1");
    }

    #[test]
    fn from_flow_leaves_metadata_empty() {
        let flow = test_flow();
        assert!(flow.source_namespace.is_none());
        assert!(flow.source_pod.is_none());
        assert!(flow.source_deployment.is_none());
        assert!(flow.source_service.is_none());
        assert!(flow.source_app.is_none());
        assert!(flow.destination_namespace.is_none());
        assert!(flow.destination_pod.is_none());
        assert!(flow.destination_deployment.is_none());
        assert!(flow.destination_service.is_none());
        assert!(flow.destination_app.is_none());
    }

    #[test]
    fn metadata_fields_serialize_as_null_when_none() {
        let flow = test_flow();
        let json = serde_json::to_string(&flow).unwrap();
        assert!(json.contains("\"source_pod\":null"));
        assert!(json.contains("\"destination_app\":null"));

        // Payloads written before Kubernetes enrichment existed carry no
        // metadata keys at all; serde must still decode them, with every
        // absent `Option` field defaulting to `None`.
        let mut legacy = serde_json::to_value(&flow).unwrap();
        let object = legacy.as_object_mut().unwrap();
        for key in [
            "source_namespace",
            "source_pod",
            "source_deployment",
            "source_service",
            "source_app",
            "destination_namespace",
            "destination_pod",
            "destination_deployment",
            "destination_service",
            "destination_app",
        ] {
            object.remove(key);
        }
        let decoded: ExportedFlow = serde_json::from_value(legacy).unwrap();
        assert!(decoded.source_namespace.is_none());
        assert!(decoded.source_pod.is_none());
        assert!(decoded.source_deployment.is_none());
        assert!(decoded.source_service.is_none());
        assert!(decoded.source_app.is_none());
        assert!(decoded.destination_namespace.is_none());
        assert!(decoded.destination_pod.is_none());
        assert!(decoded.destination_deployment.is_none());
        assert!(decoded.destination_service.is_none());
        assert!(decoded.destination_app.is_none());
    }
}
