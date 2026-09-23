use std::sync::Arc;

use sentinel_flow::{ExportedFlow, FlowError, FlowExporter, FlowKey, FlowTable, FlowTableConfig};
use sentinel_parser::ParsedPacket;
use tracing::debug;

use crate::config::FlowConfig;
use crate::metrics::SensorMetrics;

const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

/// Aggregates parsed packets into flows and exports them on timeout / FIN / RST.
pub struct FlowProcessor {
    table: FlowTable,
    exporter: FlowExporter,
    metrics: Arc<SensorMetrics>,
}

impl FlowProcessor {
    pub fn new(config: &FlowConfig, sensor_node: String, metrics: Arc<SensorMetrics>) -> Self {
        let table = FlowTable::new(FlowTableConfig {
            max_flows: config.max_flows,
            inactive_timeout_secs: config.inactive_timeout_secs,
            active_timeout_secs: config.active_timeout_secs,
        });
        Self { table, exporter: FlowExporter::new(sensor_node), metrics }
    }

    /// Process one packet into the flow table.
    /// Returns `Some(exported)` when FIN/RST triggered immediate export
    /// (architecture.md §5.4).
    pub fn on_packet(&mut self, pkt: &ParsedPacket) -> Option<ExportedFlow> {
        let key = FlowKey::new(
            pkt.src_ip_bytes(),
            pkt.dst_ip_bytes(),
            pkt.src_port,
            pkt.dst_port,
            pkt.protocol.ip_number(),
        );
        let bytes = pkt.total_len() as u64;

        match self.table.update_flow(key.clone(), bytes, pkt.tcp_flags) {
            Ok(()) => self.metrics.active_flows.set(self.table.len() as i64),
            Err(FlowError::TableFull(_)) => {
                self.metrics.packets_dropped.inc();
                debug!("flow table full, dropping packet");
            }
            Err(e) => debug!("flow update error: {}", e),
        }

        let fin_or_rst = pkt.tcp_flags.is_some_and(|f| f & TCP_FIN != 0 || f & TCP_RST != 0);
        if !fin_or_rst {
            return None;
        }

        let (key, entry) = self.table.take_flow(&key)?;
        let exported = self.exporter.export_flow(&key, &entry);
        self.metrics.flows_exported.inc();
        self.metrics.active_flows.set(self.table.len() as i64);
        Some(exported)
    }

    /// Collect expired flows (inactive / active timeout) and export them.
    /// Logging is the caller's responsibility.
    pub fn sweep(&mut self) -> Vec<ExportedFlow> {
        let expired = self.table.get_expired_flows();
        if expired.is_empty() {
            return Vec::new();
        }
        let flows = self.exporter.export_flows(&expired);
        self.metrics.flows_exported.inc_by(flows.len() as u64);
        self.metrics.active_flows.set(self.table.len() as i64);
        flows
    }

    /// Current number of active flows in the table.
    pub fn active_flows(&self) -> usize {
        self.table.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_parser::parse_packet;

    fn test_metrics() -> Arc<SensorMetrics> {
        Arc::new(SensorMetrics::new().unwrap())
    }

    fn immediate_expiry_config() -> FlowConfig {
        FlowConfig { inactive_timeout_secs: 0, active_timeout_secs: 300, max_flows: 100 }
    }

    /// Build a minimal Ethernet+IPv4+TCP frame and parse it.
    fn make_tcp_packet(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8,
    ) -> ParsedPacket {
        let mut data = vec![0u8; 54];
        data[12] = 0x08;
        data[13] = 0x00;
        data[14] = 0x45;
        data[16..18].copy_from_slice(&40u16.to_be_bytes());
        data[22] = 64;
        data[23] = 6; // TCP
        data[26..30].copy_from_slice(&src);
        data[30..34].copy_from_slice(&dst);
        data[34..36].copy_from_slice(&sport.to_be_bytes());
        data[36..38].copy_from_slice(&dport.to_be_bytes());
        data[46] = 0x50;
        data[47] = flags;
        parse_packet(&data).unwrap()
    }

    #[test]
    fn test_on_packet_creates_flow_and_sweep_exports() {
        let metrics = test_metrics();
        let mut proc =
            FlowProcessor::new(&immediate_expiry_config(), "node-1".into(), metrics.clone());

        let pkt = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x02); // SYN
        assert!(proc.on_packet(&pkt).is_none());
        assert_eq!(proc.active_flows(), 1);

        // inactive_timeout_secs = 0 → すぐ期限切れ
        let exported = proc.sweep();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].source_ip, "10.0.0.1");
        assert_eq!(exported[0].destination_ip, "10.0.0.2");
        assert_eq!(exported[0].source_port, 12345);
        assert_eq!(exported[0].destination_port, 80);
        assert_eq!(exported[0].protocol, "TCP");
        assert_eq!(exported[0].packets_forward, 1);
        assert_eq!(exported[0].sensor_node, "node-1");
        assert_eq!(proc.active_flows(), 0);
        assert_eq!(metrics.flows_exported.get(), 1);
        assert_eq!(metrics.active_flows.get(), 0);
    }

    #[test]
    fn test_bidirectional_single_flow() {
        let mut proc =
            FlowProcessor::new(&immediate_expiry_config(), "node-1".into(), test_metrics());

        let fwd = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x02);
        let rev = make_tcp_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 12345, 0x10);
        proc.on_packet(&fwd);
        proc.on_packet(&rev);

        assert_eq!(proc.active_flows(), 1);

        let exported = proc.sweep();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].packets_forward, 1);
        assert_eq!(exported[0].packets_reverse, 1);
    }

    #[test]
    fn test_fin_triggers_immediate_export() {
        let mut proc =
            FlowProcessor::new(&immediate_expiry_config(), "node-1".into(), test_metrics());

        // FIN + ACK
        let pkt = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x11);
        let exported = proc.on_packet(&pkt);
        assert!(exported.is_some());
        assert_eq!(exported.unwrap().destination_port, 80);
        assert_eq!(proc.active_flows(), 0);
        // 既に export 済みなので sweep には出ない
        assert!(proc.sweep().is_empty());
    }

    #[test]
    fn test_rst_triggers_immediate_export() {
        let mut proc =
            FlowProcessor::new(&immediate_expiry_config(), "node-1".into(), test_metrics());

        let pkt = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x04); // RST
        assert!(proc.on_packet(&pkt).is_some());
        assert_eq!(proc.active_flows(), 0);
    }

    #[test]
    fn test_table_full_drops_packet() {
        let config = FlowConfig { max_flows: 1, ..immediate_expiry_config() };
        let metrics = test_metrics();
        let mut proc = FlowProcessor::new(&config, "node-1".into(), metrics.clone());

        // 異なる2フロー、max_flows = 1
        proc.on_packet(&make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x10));
        proc.on_packet(&make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 3], 12345, 80, 0x10));

        assert_eq!(proc.active_flows(), 1);
        assert_eq!(metrics.packets_dropped.get(), 1);
    }

    #[test]
    fn test_table_full_fin_packet_no_export() {
        let config = FlowConfig { max_flows: 1, ..immediate_expiry_config() };
        let metrics = test_metrics();
        let mut proc = FlowProcessor::new(&config, "node-1".into(), metrics.clone());

        // Fill the table with a different 5-tuple
        proc.on_packet(&make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x10));
        assert_eq!(proc.active_flows(), 1);

        // FIN for a NEW unknown 5-tuple: update_flow → TableFull → dropped,
        // take_flow → None → no export
        let fin = make_tcp_packet([10, 0, 0, 4], [10, 0, 0, 5], 40000, 443, 0x11);
        assert!(proc.on_packet(&fin).is_none());
        assert_eq!(metrics.packets_dropped.get(), 1);
        assert_eq!(proc.active_flows(), 1);
        assert_eq!(metrics.flows_exported.get(), 0);
    }
}
