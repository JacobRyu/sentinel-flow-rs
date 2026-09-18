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
            let (protocol, src_port, dst_port, payload_len) = match &ip {
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
                            (Protocol::Tcp, ports.0, ports.1, remaining.len() - tcp_header_len)
                        }
                        17 => {
                            // UDP
                            let udp = UdpHeader::parse(remaining)?;
                            let ports = (udp.src_port, udp.dst_port);
                            (Protocol::Udp, ports.0, ports.1, remaining.len() - 8)
                        }
                        1 => (Protocol::Icmp, 0, 0, remaining.len()),
                        _ => (Protocol::Other(hdr.protocol), 0, 0, remaining.len()),
                    }
                }
                IpHeader::V6(_) => unreachable!(),
            };

            Ok(ParsedPacket { ethernet, ip, src_port, dst_port, protocol, payload_len })
        }
        0x86DD => {
            // IPv6
            let ip = IpHeader::parse_ipv6(&data[payload_offset..])?;
            let remaining_offset = payload_offset + 40; // IPv6 header is fixed 40 bytes
            let remaining = &data[remaining_offset..];
            let (protocol, src_port, dst_port) = match &ip {
                IpHeader::V6(hdr) => match hdr.next_header {
                    6 => {
                        let tcp = TcpHeader::parse(remaining)?;
                        let ports = (tcp.src_port, tcp.dst_port);
                        (Protocol::Tcp, ports.0, ports.1)
                    }
                    17 => {
                        let udp = UdpHeader::parse(remaining)?;
                        let ports = (udp.src_port, udp.dst_port);
                        (Protocol::Udp, ports.0, ports.1)
                    }
                    _ => (Protocol::Other(hdr.next_header), 0, 0),
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
            })
        }
        _ => Err(ParserError::UnsupportedEtherType(ethernet.ethertype)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_packet_too_short() {
        let data = [0u8; 10];
        assert!(parse_packet(&data).is_err());
    }
}
