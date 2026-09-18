use crate::ParserError;

/// UDP header
#[derive(Debug, Clone)]
pub struct UdpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl UdpHeader {
    /// Parse a UDP header from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, ParserError> {
        if data.len() < 8 {
            return Err(ParserError::PacketTooShort(8, data.len()));
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);

        Ok(Self { src_port, dst_port, length, checksum })
    }

    /// Header length in bytes (fixed)
    pub fn header_len(&self) -> usize {
        8
    }

    /// Get source and destination ports
    pub fn ports(&self) -> (u16, u16) {
        (self.src_port, self.dst_port)
    }

    /// Get payload length
    pub fn payload_len(&self) -> u16 {
        self.length - 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_udp() {
        let mut data = vec![0u8; 8];
        data[0..2].copy_from_slice(&12345u16.to_be_bytes()); // src port
        data[2..4].copy_from_slice(&53u16.to_be_bytes()); // dst port (DNS)
        data[4..6].copy_from_slice(&20u16.to_be_bytes()); // length

        let hdr = UdpHeader::parse(&data).unwrap();
        assert_eq!(hdr.src_port, 12345);
        assert_eq!(hdr.dst_port, 53);
        assert_eq!(hdr.length, 20);
        assert_eq!(hdr.payload_len(), 12);
    }

    #[test]
    fn test_parse_udp_too_short() {
        let data = [0u8; 4];
        assert!(UdpHeader::parse(&data).is_err());
    }
}
