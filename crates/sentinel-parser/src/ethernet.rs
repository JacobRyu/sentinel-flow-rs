use crate::ParserError;

/// Ethernet frame header
#[derive(Debug, Clone)]
pub struct EthernetFrame {
    pub dst_mac: [u8; 6],
    pub src_mac: [u8; 6],
    pub ethertype: u16,
    pub vlan_id: Option<u16>,
}

impl EthernetFrame {
    /// Parse an Ethernet frame from raw bytes
    pub fn parse(data: &[u8]) -> Result<Self, ParserError> {
        if data.len() < 14 {
            return Err(ParserError::PacketTooShort(14, data.len()));
        }

        let mut dst_mac = [0u8; 6];
        let mut src_mac = [0u8; 6];
        dst_mac.copy_from_slice(&data[0..6]);
        src_mac.copy_from_slice(&data[6..12]);

        let ethertype = u16::from_be_bytes([data[12], data[13]]);

        // Check for VLAN tag (802.1Q)
        let (ethertype, vlan_id) = if ethertype == 0x8100 {
            if data.len() < 18 {
                return Err(ParserError::PacketTooShort(18, data.len()));
            }
            let vlan_id = u16::from_be_bytes([data[14], data[15]]);
            let real_ethertype = u16::from_be_bytes([data[16], data[17]]);
            (real_ethertype, Some(vlan_id))
        } else {
            (ethertype, None)
        };

        Ok(Self { dst_mac, src_mac, ethertype, vlan_id })
    }

    /// Header length in bytes
    pub fn header_len(&self) -> usize {
        14 + if self.vlan_id.is_some() { 4 } else { 0 }
    }

    /// Get MAC addresses as strings
    pub fn dst_mac_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.dst_mac[0],
            self.dst_mac[1],
            self.dst_mac[2],
            self.dst_mac[3],
            self.dst_mac[4],
            self.dst_mac[5]
        )
    }

    pub fn src_mac_str(&self) -> String {
        format!(
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.src_mac[0],
            self.src_mac[1],
            self.src_mac[2],
            self.src_mac[3],
            self.src_mac[4],
            self.src_mac[5]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ethernet_frame() {
        // Ethernet frame: dst(6) + src(6) + ethertype(2) = 14 bytes
        let mut data = vec![0u8; 14];
        data[0..6].copy_from_slice(&[0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        data[6..12].copy_from_slice(&[0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        data[12..14].copy_from_slice(&0x0800u16.to_be_bytes());

        let frame = EthernetFrame::parse(&data).unwrap();
        assert_eq!(frame.dst_mac, [0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        assert_eq!(frame.src_mac, [0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb]);
        assert_eq!(frame.ethertype, 0x0800);
        assert_eq!(frame.vlan_id, None);
    }

    #[test]
    fn test_parse_ethernet_frame_too_short() {
        let data = [0u8; 10];
        assert!(EthernetFrame::parse(&data).is_err());
    }

    #[test]
    fn test_parse_ethernet_frame_with_vlan() {
        let mut data = vec![0u8; 18];
        data[12..14].copy_from_slice(&0x8100u16.to_be_bytes());
        data[14..16].copy_from_slice(&100u16.to_be_bytes());
        data[16..18].copy_from_slice(&0x0800u16.to_be_bytes());

        let frame = EthernetFrame::parse(&data).unwrap();
        assert_eq!(frame.ethertype, 0x0800);
        assert_eq!(frame.vlan_id, Some(100));
    }
}
