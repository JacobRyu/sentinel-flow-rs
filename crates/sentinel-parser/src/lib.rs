mod error;
mod ethernet;
mod ip;
mod packet;
mod tcp;
mod udp;

pub use error::ParserError;
pub use ethernet::EthernetFrame;
pub use ip::{IpHeader, IpVersion};
pub use packet::{ParsedPacket, Protocol};
pub use tcp::TcpHeader;
pub use udp::UdpHeader;

/// Parse a raw Ethernet frame into a ParsedPacket
pub fn parse_packet(data: &[u8]) -> Result<ParsedPacket, ParserError> {
    let ethernet = EthernetFrame::parse(data)?;

    // Calculate payload offset
    let payload_offset = ethernet.header_len();

    match ethernet.ethertype {
        0x0800 => {
            // IPv4
            let ip = IpHeader::parse_ipv4(&data[payload_offset..])?;
            let (protocol, src_port, dst_port, payload_len, tcp_flags) = match &ip {
                IpHeader::V4(hdr) => {
                    let ip_header_len = hdr.ihl as usize * 4;
                    let remaining_offset = payload_offset + ip_header_len;
                    let remaining = &data[remaining_offset..];
                    match hdr.protocol {
                        6 => {
                            // TCP
                            let tcp = TcpHeader::parse(remaining)?;
                            let ports = (tcp.src_port, tcp.dst_port);
                            let tcp_header_len = tcp.data_offset as usize * 4;
                            (
                                Protocol::Tcp,
                                ports.0,
                                ports.1,
                                remaining.len() - tcp_header_len,
                                Some(tcp.flags),
                            )
                        }
                        17 => {
                            // UDP
                            let udp = UdpHeader::parse(remaining)?;
                            let ports = (udp.src_port, udp.dst_port);
                            (Protocol::Udp, ports.0, ports.1, remaining.len() - 8, None)
                        }
                        1 => (Protocol::Icmp, 0, 0, remaining.len(), None),
                        _ => (Protocol::Other(hdr.protocol), 0, 0, remaining.len(), None),
                    }
                }
                IpHeader::V6(_) => unreachable!(),
            };

            Ok(ParsedPacket { ethernet, ip, src_port, dst_port, protocol, payload_len, tcp_flags })
        }
        0x86DD => {
            // IPv6
            let ip = IpHeader::parse_ipv6(&data[payload_offset..])?;
            let remaining_offset = payload_offset + 40; // IPv6 header is fixed 40 bytes
            let remaining = &data[remaining_offset..];
            let (protocol, src_port, dst_port, tcp_flags) = match &ip {
                IpHeader::V6(hdr) => match hdr.next_header {
                    6 => {
                        let tcp = TcpHeader::parse(remaining)?;
                        let ports = (tcp.src_port, tcp.dst_port);
                        (Protocol::Tcp, ports.0, ports.1, Some(tcp.flags))
                    }
                    17 => {
                        let udp = UdpHeader::parse(remaining)?;
                        let ports = (udp.src_port, udp.dst_port);
                        (Protocol::Udp, ports.0, ports.1, None)
                    }
                    _ => (Protocol::Other(hdr.next_header), 0, 0, None),
                },
                _ => unreachable!(),
            };

            Ok(ParsedPacket {
                ethernet,
                ip,
                src_port,
                dst_port,
                protocol,
                payload_len: remaining.len(),
                tcp_flags,
            })
        }
        _ => Err(ParserError::UnsupportedEtherType(ethernet.ethertype)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal Ethernet+IPv4+TCP frame
    fn build_tcp_frame(tcp_flags: u8) -> Vec<u8> {
        let mut data = vec![0u8; 14 + 20 + 20];
        // Ethernet
        data[12] = 0x08;
        data[13] = 0x00;
        // IPv4 at offset 14
        data[14] = 0x45; // version=4, ihl=5
        data[16..18].copy_from_slice(&40u16.to_be_bytes()); // total length
        data[22] = 64; // ttl (14+8)
        data[23] = 6; // protocol = TCP (14+9)
        data[26..30].copy_from_slice(&[10, 0, 0, 1]); // src (14+12)
        data[30..34].copy_from_slice(&[10, 0, 0, 2]); // dst (14+16)
        // TCP at offset 34
        data[34..36].copy_from_slice(&12345u16.to_be_bytes()); // src port
        data[36..38].copy_from_slice(&80u16.to_be_bytes()); // dst port
        data[46] = 0x50; // data offset = 5 (34+12)
        data[47] = tcp_flags; // flags (34+13)
        data
    }

    /// Build a minimal Ethernet+IPv4+UDP frame
    fn build_udp_frame() -> Vec<u8> {
        let mut data = vec![0u8; 14 + 20 + 8];
        data[12] = 0x08;
        data[13] = 0x00;
        data[14] = 0x45;
        data[16..18].copy_from_slice(&42u16.to_be_bytes());
        data[22] = 64;
        data[23] = 17; // protocol = UDP
        data[26..30].copy_from_slice(&[10, 0, 0, 1]);
        data[30..34].copy_from_slice(&[10, 0, 0, 2]);
        // UDP at offset 34
        data[34..36].copy_from_slice(&53u16.to_be_bytes()); // src port
        data[36..38].copy_from_slice(&5353u16.to_be_bytes()); // dst port
        data
    }

    #[test]
    fn test_parse_packet_too_short() {
        let data = [0u8; 10];
        assert!(parse_packet(&data).is_err());
    }

    #[test]
    fn test_parse_packet_tcp_flags() {
        let frame = build_tcp_frame(0x12); // SYN + ACK
        let pkt = parse_packet(&frame).unwrap();
        assert_eq!(pkt.tcp_flags, Some(0x12));
        assert_eq!(pkt.protocol, Protocol::Tcp);
        assert_eq!(pkt.src_port, 12345);
        assert_eq!(pkt.dst_port, 80);
        assert_eq!(pkt.src_ip(), "10.0.0.1");
        assert_eq!(pkt.dst_ip(), "10.0.0.2");
    }

    #[test]
    fn test_parse_packet_udp_no_tcp_flags() {
        let frame = build_udp_frame();
        let pkt = parse_packet(&frame).unwrap();
        assert_eq!(pkt.tcp_flags, None);
        assert_eq!(pkt.protocol, Protocol::Udp);
        assert_eq!(pkt.src_port, 53);
        assert_eq!(pkt.dst_port, 5353);
    }
}
