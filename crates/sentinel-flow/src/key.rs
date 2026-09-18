use std::hash::{Hash, Hasher};

/// 5-tuple flow key for identifying network flows
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

impl FlowKey {
    /// Create a new flow key
    pub fn new(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        Self { src_ip, dst_ip, src_port, dst_port, protocol }
    }

    /// Create a canonical flow key (smaller IP first)
    pub fn canonical(
        src_ip: [u8; 16],
        dst_ip: [u8; 16],
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Self {
        if src_ip < dst_ip || (src_ip == dst_ip && src_port <= dst_port) {
            Self::new(src_ip, dst_ip, src_port, dst_port, protocol)
        } else {
            Self::new(dst_ip, src_ip, dst_port, src_port, protocol)
        }
    }

    /// Get protocol number as string
    pub fn protocol_str(&self) -> &str {
        match self.protocol {
            6 => "TCP",
            17 => "UDP",
            1 => "ICMP",
            _ => "OTHER",
        }
    }
}

impl Hash for FlowKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // Use xxhash for fast hashing
        let mut hasher = xxhash_rust::xxh3::Xxh3::new();
        hasher.write(&self.src_ip);
        hasher.write(&self.dst_ip);
        hasher.write(&self.src_port.to_be_bytes());
        hasher.write(&self.dst_port.to_be_bytes());
        hasher.write_u8(self.protocol);
        hasher.finish().hash(state);
    }
}

impl std::fmt::Display for FlowKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}:{} -> {}:{} ({})",
            ip_to_string(&self.src_ip),
            self.src_port,
            ip_to_string(&self.dst_ip),
            self.dst_port,
            self.protocol_str(),
        )
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
    fn test_flow_key_canonical() {
        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];

        let key1 = FlowKey::canonical(ip1, ip2, 12345, 80, 6);
        let key2 = FlowKey::canonical(ip2, ip1, 80, 12345, 6);

        assert_eq!(key1, key2);
    }

    #[test]
    fn test_flow_key_display() {
        let ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 192, 168, 1, 1];
        let key = FlowKey::new(ip, ip, 12345, 80, 6);
        assert_eq!(key.to_string(), "192.168.1.1:12345 -> 192.168.1.1:80 (TCP)");
    }
}
