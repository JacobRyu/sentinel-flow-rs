use serde::{Deserialize, Serialize};

use crate::FlowEntry;
use crate::FlowKey;

/// Exported flow record
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

    #[test]
    fn test_export_flow() {
        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];
        let key = FlowKey::new(ip1, ip2, 12345, 80, 6);
        let mut entry = FlowEntry::new(true);
        entry.update(100, Some(0x02));

        let exporter = FlowExporter::new("node-1".to_string());
        let exported = exporter.export_flow(&key, &entry);

        assert_eq!(exported.source_ip, "10.0.0.1");
        assert_eq!(exported.destination_ip, "10.0.0.2");
        assert_eq!(exported.protocol, "TCP");
        assert_eq!(exported.sensor_node, "node-1");
    }
}
