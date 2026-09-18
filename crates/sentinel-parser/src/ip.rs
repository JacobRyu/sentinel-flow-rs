use crate::ParserError;

/// IP version
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpVersion {
    V4,
    V6,
}

/// IPv4 header
#[derive(Debug, Clone)]
pub struct Ipv4Header {
    pub version: u8,
    pub ihl: u8,
    pub dscp: u8,
    pub ecn: u8,
    pub total_length: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
}

impl Ipv4Header {
    /// Parse an IPv4 header from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, ParserError> {
        if data.len() < 20 {
            return Err(ParserError::PacketTooShort(20, data.len()));
        }

        let version = (data[0] >> 4) & 0x0f;
        if version != 4 {
            return Err(ParserError::InvalidIpVersion(version));
        }

        let ihl = data[0] & 0x0f;
        if ihl < 5 {
            return Err(ParserError::ParseError("IHL too small".into()));
        }

        let dscp = (data[1] >> 2) & 0x3f;
        let ecn = data[1] & 0x03;
        let total_length = u16::from_be_bytes([data[2], data[3]]);
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags = (data[6] >> 5) & 0x07;
        let fragment_offset = u16::from_be_bytes([data[6], data[7]]) & 0x1fff;
        let ttl = data[8];
        let protocol = data[9];
        let checksum = u16::from_be_bytes([data[10], data[11]]);

        let mut src_ip = [0u8; 4];
        let mut dst_ip = [0u8; 4];
        src_ip.copy_from_slice(&data[12..16]);
        dst_ip.copy_from_slice(&data[16..20]);

        Ok(Self {
            version,
            ihl,
            dscp,
            ecn,
            total_length,
            identification,
            flags,
            fragment_offset,
            ttl,
            protocol,
            checksum,
            src_ip,
            dst_ip,
        })
    }

    /// Header length in bytes
    pub fn header_len(&self) -> usize {
        self.ihl as usize * 4
    }

    /// Get source IP as string
    pub fn src_ip_str(&self) -> String {
        format!("{}.{}.{}.{}", self.src_ip[0], self.src_ip[1], self.src_ip[2], self.src_ip[3])
    }

    /// Get destination IP as string
    pub fn dst_ip_str(&self) -> String {
        format!("{}.{}.{}.{}", self.dst_ip[0], self.dst_ip[1], self.dst_ip[2], self.dst_ip[3])
    }

    /// Convert to IPv6-mapped address
    pub fn src_ip_to_ipv6(&self) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12..16].copy_from_slice(&self.src_ip);
        addr
    }

    pub fn dst_ip_to_ipv6(&self) -> [u8; 16] {
        let mut addr = [0u8; 16];
        addr[10] = 0xff;
        addr[11] = 0xff;
        addr[12..16].copy_from_slice(&self.dst_ip);
        addr
    }
}

/// IPv6 header
#[derive(Debug, Clone)]
pub struct Ipv6Header {
    pub version: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
    pub next_header: u8,
    pub hop_limit: u8,
    pub src_ip: [u8; 16],
    pub dst_ip: [u8; 16],
}

impl Ipv6Header {
    /// Parse an IPv6 header from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, ParserError> {
        if data.len() < 40 {
            return Err(ParserError::PacketTooShort(40, data.len()));
        }

        let version = (data[0] >> 4) & 0x0f;
        if version != 6 {
            return Err(ParserError::InvalidIpVersion(version));
        }

        let traffic_class = ((data[0] & 0x0f) << 4) | ((data[1] >> 4) & 0x0f);
        let flow_label = u32::from_be_bytes([0, data[1] & 0x0f, data[2], data[3]]);
        let payload_length = u16::from_be_bytes([data[4], data[5]]);
        let next_header = data[6];
        let hop_limit = data[7];

        let mut src_ip = [0u8; 16];
        let mut dst_ip = [0u8; 16];
        src_ip.copy_from_slice(&data[8..24]);
        dst_ip.copy_from_slice(&data[24..40]);

        Ok(Self {
            version,
            traffic_class,
            flow_label,
            payload_length,
            next_header,
            hop_limit,
            src_ip,
            dst_ip,
        })
    }

    /// Header length in bytes (fixed)
    pub fn header_len(&self) -> usize {
        40
    }

    /// Get source IP as string
    pub fn src_ip_str(&self) -> String {
        format!(
            "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
            u16::from_be_bytes([self.src_ip[0], self.src_ip[1]]),
            u16::from_be_bytes([self.src_ip[2], self.src_ip[3]]),
            u16::from_be_bytes([self.src_ip[4], self.src_ip[5]]),
            u16::from_be_bytes([self.src_ip[6], self.src_ip[7]]),
            u16::from_be_bytes([self.src_ip[8], self.src_ip[9]]),
            u16::from_be_bytes([self.src_ip[10], self.src_ip[11]]),
            u16::from_be_bytes([self.src_ip[12], self.src_ip[13]]),
            u16::from_be_bytes([self.src_ip[14], self.src_ip[15]]),
        )
    }

    /// Get destination IP as string
    pub fn dst_ip_str(&self) -> String {
        format!(
            "{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}:{:04x}",
            u16::from_be_bytes([self.dst_ip[0], self.dst_ip[1]]),
            u16::from_be_bytes([self.dst_ip[2], self.dst_ip[3]]),
            u16::from_be_bytes([self.dst_ip[4], self.dst_ip[5]]),
            u16::from_be_bytes([self.dst_ip[6], self.dst_ip[7]]),
            u16::from_be_bytes([self.dst_ip[8], self.dst_ip[9]]),
            u16::from_be_bytes([self.dst_ip[10], self.dst_ip[11]]),
            u16::from_be_bytes([self.dst_ip[12], self.dst_ip[13]]),
            u16::from_be_bytes([self.dst_ip[14], self.dst_ip[15]]),
        )
    }
}

/// IP header (either v4 or v6)
#[derive(Debug, Clone)]
pub enum IpHeader {
    V4(Ipv4Header),
    V6(Ipv6Header),
}

impl IpHeader {
    /// Parse an IPv4 header
    pub fn parse_ipv4(data: &[u8]) -> Result<Self, ParserError> {
        Ok(Self::V4(Ipv4Header::parse(data)?))
    }

    /// Parse an IPv6 header
    pub fn parse_ipv6(data: &[u8]) -> Result<Self, ParserError> {
        Ok(Self::V6(Ipv6Header::parse(data)?))
    }

    /// Get IP version
    pub fn version(&self) -> IpVersion {
        match self {
            Self::V4(_) => IpVersion::V4,
            Self::V6(_) => IpVersion::V6,
        }
    }

    /// Get source IP as string
    pub fn src_ip_str(&self) -> String {
        match self {
            Self::V4(hdr) => hdr.src_ip_str(),
            Self::V6(hdr) => hdr.src_ip_str(),
        }
    }

    /// Get destination IP as string
    pub fn dst_ip_str(&self) -> String {
        match self {
            Self::V4(hdr) => hdr.dst_ip_str(),
            Self::V6(hdr) => hdr.dst_ip_str(),
        }
    }

    /// Get source IP as 16-byte IPv6 address
    pub fn src_ip_bytes(&self) -> [u8; 16] {
        match self {
            Self::V4(hdr) => hdr.src_ip_to_ipv6(),
            Self::V6(hdr) => hdr.src_ip,
        }
    }

    /// Get destination IP as 16-byte IPv6 address
    pub fn dst_ip_bytes(&self) -> [u8; 16] {
        match self {
            Self::V4(hdr) => hdr.dst_ip_to_ipv6(),
            Self::V6(hdr) => hdr.dst_ip,
        }
    }

    /// Get TTL/hop limit
    pub fn ttl(&self) -> u8 {
        match self {
            Self::V4(hdr) => hdr.ttl,
            Self::V6(hdr) => hdr.hop_limit,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ipv4() {
        let mut data = vec![0u8; 20];
        data[0] = 0x45; // version=4, ihl=5
        data[2..4].copy_from_slice(&100u16.to_be_bytes()); // total length
        data[8] = 64; // ttl
        data[9] = 6; // protocol (TCP)
        data[12..16].copy_from_slice(&[10, 0, 0, 1]); // src
        data[16..20].copy_from_slice(&[10, 0, 0, 2]); // dst

        let hdr = Ipv4Header::parse(&data).unwrap();
        assert_eq!(hdr.version, 4);
        assert_eq!(hdr.ihl, 5);
        assert_eq!(hdr.src_ip, [10, 0, 0, 1]);
        assert_eq!(hdr.dst_ip, [10, 0, 0, 2]);
    }

    #[test]
    fn test_parse_ipv6() {
        let mut data = vec![0u8; 40];
        data[0] = 0x60; // version=6
        data[6] = 59; // next header
        data[7] = 64; // hop limit
        data[8..24].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        data[24..40].copy_from_slice(&[0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);

        let hdr = Ipv6Header::parse(&data).unwrap();
        assert_eq!(hdr.version, 6);
        assert_eq!(hdr.next_header, 59);
        assert_eq!(hdr.src_ip[0], 0xfe);
        assert_eq!(hdr.src_ip[1], 0x80);
    }
}
