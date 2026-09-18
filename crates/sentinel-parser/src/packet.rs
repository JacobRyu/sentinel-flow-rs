use crate::{EthernetFrame, IpHeader};

/// Protocol type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Other(n) => write!(f, "OTHER({})", n),
        }
    }
}

/// Parsed packet with all extracted fields
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub ethernet: EthernetFrame,
    pub ip: IpHeader,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub payload_len: usize,
}

impl ParsedPacket {
    /// Get source IP as string
    pub fn src_ip(&self) -> String {
        self.ip.src_ip_str()
    }

    /// Get destination IP as string
    pub fn dst_ip(&self) -> String {
        self.ip.dst_ip_str()
    }

    /// Get source IP as 16-byte array
    pub fn src_ip_bytes(&self) -> [u8; 16] {
        self.ip.src_ip_bytes()
    }

    /// Get destination IP as 16-byte array
    pub fn dst_ip_bytes(&self) -> [u8; 16] {
        self.ip.dst_ip_bytes()
    }

    /// Get total packet length
    pub fn total_len(&self) -> usize {
        self.ethernet.header_len() + self.ip_header_len() + self.payload_len
    }

    /// Get IP header length
    fn ip_header_len(&self) -> usize {
        match &self.ip {
            IpHeader::V4(hdr) => hdr.header_len(),
            IpHeader::V6(hdr) => hdr.header_len(),
        }
    }
}

impl std::fmt::Display for ParsedPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} {}:{} -> {}:{} ({}) len={}",
            self.protocol,
            self.src_ip(),
            self.src_port,
            self.dst_ip(),
            self.dst_port,
            self.ethernet.src_mac_str(),
            self.total_len(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Other(1).to_string(), "OTHER(1)");
    }
}
