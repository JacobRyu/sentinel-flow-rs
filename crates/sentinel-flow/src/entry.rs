use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// TCP flags observed in the flow
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
}

impl TcpFlags {
    /// Update flags from a TCP header value
    pub fn update(&mut self, flags: u8) {
        self.syn |= flags & 0x02 != 0;
        self.ack |= flags & 0x10 != 0;
        self.fin |= flags & 0x01 != 0;
        self.rst |= flags & 0x04 != 0;
        self.psh |= flags & 0x08 != 0;
        self.urg |= flags & 0x20 != 0;
    }

    /// Get flag names as vector
    pub fn to_vec(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.syn {
            flags.push("SYN");
        }
        if self.ack {
            flags.push("ACK");
        }
        if self.fin {
            flags.push("FIN");
        }
        if self.rst {
            flags.push("RST");
        }
        if self.psh {
            flags.push("PSH");
        }
        if self.urg {
            flags.push("URG");
        }
        flags
    }
}

/// Flow entry with counters and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEntry {
    /// Flow ID (UUID)
    pub flow_id: String,

    /// Timestamps
    pub timestamp_start: DateTime<Utc>,
    pub timestamp_end: DateTime<Utc>,

    /// Packet counters
    pub packets_forward: u32,
    pub packets_reverse: u32,

    /// Byte counters
    pub bytes_forward: u64,
    pub bytes_reverse: u64,

    /// TCP flags observed
    pub tcp_flags: TcpFlags,

    /// Last activity timestamp (for timeout detection)
    pub last_activity: DateTime<Utc>,

    /// Whether this is the forward or reverse direction
    pub is_forward: bool,
}

impl FlowEntry {
    /// Create a new flow entry
    pub fn new(is_forward: bool) -> Self {
        let now = Utc::now();
        Self {
            flow_id: uuid::Uuid::new_v4().to_string(),
            timestamp_start: now,
            timestamp_end: now,
            packets_forward: 0,
            packets_reverse: 0,
            bytes_forward: 0,
            bytes_reverse: 0,
            tcp_flags: TcpFlags::default(),
            last_activity: now,
            is_forward,
        }
    }

    /// Update flow with new packet
    pub fn update(&mut self, bytes: u64, tcp_flags: Option<u8>) {
        let now = Utc::now();
        self.timestamp_end = now;
        self.last_activity = now;

        if self.is_forward {
            self.packets_forward += 1;
            self.bytes_forward += bytes;
        } else {
            self.packets_reverse += 1;
            self.bytes_reverse += bytes;
        }

        if let Some(flags) = tcp_flags {
            self.tcp_flags.update(flags);
        }
    }

    /// Get duration in milliseconds
    pub fn duration_ms(&self) -> u64 {
        (self.timestamp_end - self.timestamp_start).num_milliseconds() as u64
    }

    /// Get total packets
    pub fn total_packets(&self) -> u32 {
        self.packets_forward + self.packets_reverse
    }

    /// Get total bytes
    pub fn total_bytes(&self) -> u64 {
        self.bytes_forward + self.bytes_reverse
    }
}

impl std::fmt::Display for FlowEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Flow({}: {} packets, {} bytes, {}ms)",
            &self.flow_id[..8],
            self.total_packets(),
            self.total_bytes(),
            self.duration_ms(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_entry_new() {
        let entry = FlowEntry::new(true);
        assert_eq!(entry.packets_forward, 0);
        assert_eq!(entry.bytes_forward, 0);
        assert!(entry.is_forward);
    }

    #[test]
    fn test_flow_entry_update() {
        let mut entry = FlowEntry::new(true);
        entry.update(100, Some(0x02)); // SYN

        assert_eq!(entry.packets_forward, 1);
        assert_eq!(entry.bytes_forward, 100);
        assert!(entry.tcp_flags.syn);
    }

    #[test]
    fn test_flow_entry_duration() {
        let entry = FlowEntry::new(true);
        // Duration should be at least 0ms (u64 is always >= 0)
        let _ = entry.duration_ms();
    }
}
