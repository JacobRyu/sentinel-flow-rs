use anyhow::Result;
use pnet::datalink;
use pnet::datalink::Channel::Ethernet;
use tokio::sync::mpsc;
use tracing::{error, info, warn};

use crate::config::CaptureConfig;
use sentinel_parser::parse_packet;

/// Packet capture using AF_PACKET via pnet
pub struct PacketCapture {
    interface: String,
    buffer_size: usize,
    snap_len: u32,
}

impl PacketCapture {
    /// Create a new packet capture instance
    pub fn new(config: &CaptureConfig) -> Result<Self> {
        Ok(Self {
            interface: config.interface.clone(),
            buffer_size: config.buffer_size,
            snap_len: config.snap_len,
        })
    }

    /// Run packet capture and send parsed packets to channel
    pub async fn run(&self, tx: mpsc::Sender<sentinel_parser::ParsedPacket>) -> Result<()> {
        info!("Starting packet capture on interface: {}", self.interface);

        // Find the network interface
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .iter()
            .find(|i| i.name == self.interface)
            .ok_or_else(|| anyhow::anyhow!("Interface not found: {}", self.interface))?;

        info!("Found interface: {} ({})", interface.name, interface.description);

        // Create datalink channel
        let (_, mut rx) = match datalink::channel(
            interface,
            datalink::Config {
                read_buffer_size: self.buffer_size,
                write_buffer_size: 0,
                read_timeout: Some(std::time::Duration::from_millis(100)),
                ..Default::default()
            },
        ) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => return Err(anyhow::anyhow!("Unexpected channel type")),
            Err(e) => return Err(anyhow::anyhow!("Failed to create datalink channel: {}", e)),
        };

        info!("Packet capture started. Waiting for packets...");

        // Process packets in a loop
        let mut packet_count = 0u64;
        let mut error_count = 0u64;

        loop {
            match rx.next() {
                Ok(packet) => {
                    packet_count += 1;

                    // Parse the packet
                    match parse_packet(packet) {
                        Ok(parsed) => {
                            // Send to channel
                            if tx.send(parsed).await.is_err() {
                                warn!("Failed to send packet to channel");
                                break;
                            }
                        }
                        Err(e) => {
                            error_count += 1;
                            if error_count <= 10 {
                                warn!("Failed to parse packet {}: {}", packet_count, e);
                            }
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading packet: {}", e);
                    // Continue reading after error
                }
            }

            // Periodic stats logging
            if packet_count.is_multiple_of(10000) {
                info!(
                    "Packet capture stats: {} packets processed, {} errors",
                    packet_count, error_count
                );
            }
        }

        info!("Packet capture stopped. Total: {} packets, {} errors", packet_count, error_count);

        Ok(())
    }
}

impl std::fmt::Display for PacketCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "PacketCapture(interface={}, buffer={}, snap_len={})",
            self.interface, self.buffer_size, self.snap_len
        )
    }
}
