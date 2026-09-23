use chrono::Utc;
use dashmap::DashMap;

use crate::FlowEntry;
use crate::FlowKey;

/// Flow table configuration
#[derive(Debug, Clone)]
pub struct FlowTableConfig {
    /// Maximum number of concurrent flows
    pub max_flows: usize,

    /// Inactive timeout in seconds (flow exported after this time of inactivity)
    pub inactive_timeout_secs: u64,

    /// Active timeout in seconds (long-lived flow exported periodically)
    pub active_timeout_secs: u64,
}

impl Default for FlowTableConfig {
    fn default() -> Self {
        Self { max_flows: 100_000, inactive_timeout_secs: 30, active_timeout_secs: 300 }
    }
}

/// Flow table for managing active flows
pub struct FlowTable {
    config: FlowTableConfig,
    flows: DashMap<FlowKey, FlowEntry>,
}

impl FlowTable {
    /// Create a new flow table
    pub fn new(config: FlowTableConfig) -> Self {
        Self { config, flows: DashMap::with_capacity_and_shard_amount(1024, 64) }
    }

    /// Update or create a flow.
    /// The key is canonicalized internally so both directions map to one entry.
    pub fn update_flow(
        &self,
        key: FlowKey,
        bytes: u64,
        tcp_flags: Option<u8>,
    ) -> Result<(), crate::FlowError> {
        let canonical =
            FlowKey::canonical(key.src_ip, key.dst_ip, key.src_port, key.dst_port, key.protocol);
        let is_forward = key == canonical;

        // Check if table is full
        if self.flows.len() >= self.config.max_flows && !self.flows.contains_key(&canonical) {
            return Err(crate::FlowError::TableFull(self.config.max_flows));
        }

        // Update existing flow or create new one
        if let Some(mut entry) = self.flows.get_mut(&canonical) {
            entry.update(bytes, tcp_flags, is_forward);
        } else {
            let mut entry = FlowEntry::new();
            entry.update(bytes, tcp_flags, is_forward);
            self.flows.insert(canonical, entry);
        }

        Ok(())
    }

    /// Take a flow out of the table (immediate export on FIN/RST).
    /// The key is canonicalized internally.
    pub fn take_flow(&self, key: &FlowKey) -> Option<(FlowKey, FlowEntry)> {
        let canonical =
            FlowKey::canonical(key.src_ip, key.dst_ip, key.src_port, key.dst_port, key.protocol);
        self.flows.remove(&canonical)
    }

    /// Get expired flows (inactive or active timeout)
    pub fn get_expired_flows(&self) -> Vec<(FlowKey, FlowEntry)> {
        let now = Utc::now();
        let mut expired = Vec::new();

        self.flows.retain(|key, entry| {
            let inactive_expired = now.signed_duration_since(entry.last_activity).num_seconds()
                as u64
                >= self.config.inactive_timeout_secs;

            let active_expired = now.signed_duration_since(entry.timestamp_start).num_seconds()
                as u64
                >= self.config.active_timeout_secs;

            if inactive_expired || active_expired {
                expired.push((key.clone(), entry.clone()));
                false
            } else {
                true
            }
        });

        expired
    }

    /// Get all active flows
    pub fn get_active_flows(&self) -> Vec<(FlowKey, FlowEntry)> {
        self.flows.iter().map(|r| (r.key().clone(), r.value().clone())).collect()
    }

    /// Get flow count
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    /// Check if table is empty
    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    /// Clear all flows
    pub fn clear(&self) {
        self.flows.clear();
    }
}

impl std::fmt::Display for FlowTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FlowTable(active={}, max={})", self.flows.len(), self.config.max_flows,)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_table_new() {
        let config = FlowTableConfig::default();
        let table = FlowTable::new(config);
        assert_eq!(table.len(), 0);
        assert!(table.is_empty());
    }

    #[test]
    fn test_flow_table_update() {
        let config = FlowTableConfig::default();
        let table = FlowTable::new(config);

        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];
        let key = FlowKey::new(ip1, ip2, 12345, 80, 6);

        table.update_flow(key.clone(), 100, Some(0x02)).unwrap();
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn test_flow_table_full() {
        let config = FlowTableConfig { max_flows: 2, ..Default::default() };
        let table = FlowTable::new(config);

        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];
        let ip3 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 3];

        let key1 = FlowKey::new(ip1, ip2, 12345, 80, 6);
        let key2 = FlowKey::new(ip1, ip3, 12346, 80, 6);
        let key3 = FlowKey::new(ip1, ip2, 12347, 80, 6);

        table.update_flow(key1, 100, None).unwrap();
        table.update_flow(key2, 100, None).unwrap();
        assert!(table.update_flow(key3, 100, None).is_err());
    }

    #[test]
    fn test_flow_table_bidirectional_counts() {
        let config = FlowTableConfig::default();
        let table = FlowTable::new(config);

        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];

        let fwd = FlowKey::new(ip1, ip2, 12345, 80, 6);
        let rev = FlowKey::new(ip2, ip1, 80, 12345, 6);

        table.update_flow(fwd, 100, Some(0x02)).unwrap(); // SYN
        table.update_flow(rev, 50, Some(0x10)).unwrap(); // ACK

        assert_eq!(table.len(), 1, "bidirectional packets must share one entry");

        let flows = table.get_active_flows();
        let (_, entry) = &flows[0];
        assert_eq!(entry.packets_forward, 1);
        assert_eq!(entry.bytes_forward, 100);
        assert_eq!(entry.packets_reverse, 1);
        assert_eq!(entry.bytes_reverse, 50);
        assert!(entry.tcp_flags.syn);
        assert!(entry.tcp_flags.ack);
    }

    #[test]
    fn test_flow_table_take_flow() {
        let config = FlowTableConfig::default();
        let table = FlowTable::new(config);

        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];

        // 逆向きで登録
        let rev = FlowKey::new(ip2, ip1, 80, 12345, 6);
        table.update_flow(rev, 100, None).unwrap();

        // 正向きキーで take（canonical で同一エントリ）
        let fwd = FlowKey::new(ip1, ip2, 12345, 80, 6);
        let taken = table.take_flow(&fwd);
        assert!(taken.is_some());
        assert!(table.is_empty());

        let taken_again = table.take_flow(&fwd);
        assert!(taken_again.is_none());
    }
}
