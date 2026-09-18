use crate::ParserError;

/// TCP header
#[derive(Debug, Clone)]
pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_num: u32,
    pub ack_num: u32,
    pub data_offset: u8,
    pub reserved: u8,
    pub flags: u8,
    pub window: u16,
    pub checksum: u16,
    pub urgent_ptr: u16,
}

impl TcpHeader {
    /// Parse a TCP header from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, ParserError> {
        if data.len() < 20 {
            return Err(ParserError::PacketTooShort(20, data.len()));
        }

        let src_port = u16::from_be_bytes([data[0], data[1]]);
        let dst_port = u16::from_be_bytes([data[2], data[3]]);
        let seq_num = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let ack_num = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = (data[12] >> 4) & 0x0f;
        let reserved = data[12] & 0x0e;
        let flags = data[13];
        let window = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_ptr = u16::from_be_bytes([data[18], data[19]]);

        if data_offset < 5 {
            return Err(ParserError::InvalidTcpDataOffset(data_offset));
        }

        Ok(Self {
            src_port,
            dst_port,
            seq_num,
            ack_num,
            data_offset,
            reserved,
            flags,
            window,
            checksum,
            urgent_ptr,
        })
    }

    /// Header length in bytes
    pub fn header_len(&self) -> usize {
        self.data_offset as usize * 4
    }

    /// Get source and destination ports
    pub fn ports(&self) -> (u16, u16) {
        (self.src_port, self.dst_port)
    }

    /// Check if SYN flag is set
    pub fn is_syn(&self) -> bool {
        self.flags & 0x02 != 0
    }

    /// Check if ACK flag is set
    pub fn is_ack(&self) -> bool {
        self.flags & 0x10 != 0
    }

    /// Check if FIN flag is set
    pub fn is_fin(&self) -> bool {
        self.flags & 0x01 != 0
    }

    /// Check if RST flag is set
    pub fn is_rst(&self) -> bool {
        self.flags & 0x04 != 0
    }

    /// Check if PSH flag is set
    pub fn is_psh(&self) -> bool {
        self.flags & 0x08 != 0
    }

    /// Check if URG flag is set
    pub fn is_urg(&self) -> bool {
        self.flags & 0x20 != 0
    }

    /// Get flag names as string
    pub fn flag_names(&self) -> Vec<&'static str> {
        let mut flags = Vec::new();
        if self.is_fin() {
            flags.push("FIN");
        }
        if self.is_syn() {
            flags.push("SYN");
        }
        if self.is_rst() {
            flags.push("RST");
        }
        if self.is_psh() {
            flags.push("PSH");
        }
        if self.is_ack() {
            flags.push("ACK");
        }
        if self.is_urg() {
            flags.push("URG");
        }
        flags
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_tcp() {
        let mut data = vec![0u8; 20];
        data[0..2].copy_from_slice(&12345u16.to_be_bytes()); // src port
        data[2..4].copy_from_slice(&80u16.to_be_bytes()); // dst port
        data[4..8].copy_from_slice(&123456u32.to_be_bytes()); // seq
        data[8..12].copy_from_slice(&789u32.to_be_bytes()); // ack
        data[12] = 0x50; // data offset = 5, reserved = 0
        data[13] = 0x02; // SYN flag

        let hdr = TcpHeader::parse(&data).unwrap();
        assert_eq!(hdr.src_port, 12345);
        assert_eq!(hdr.dst_port, 80);
        assert_eq!(hdr.seq_num, 123456);
        assert_eq!(hdr.ack_num, 789);
        assert_eq!(hdr.data_offset, 5);
        assert!(hdr.is_syn());
        assert!(!hdr.is_ack());
    }

    #[test]
    fn test_parse_tcp_too_short() {
        let data = [0u8; 10];
        assert!(TcpHeader::parse(&data).is_err());
    }

    #[test]
    fn test_tcp_flags() {
        let mut data = vec![0u8; 20];
        data[12] = 0x50;
        data[13] = 0x12; // SYN + ACK

        let hdr = TcpHeader::parse(&data).unwrap();
        assert!(hdr.is_syn());
        assert!(hdr.is_ack());
        assert!(!hdr.is_fin());
    }
}
