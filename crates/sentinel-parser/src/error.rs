use thiserror::Error;

#[derive(Error, Debug)]
pub enum ParserError {
    #[error("Packet too short: need at least {0} bytes, got {1}")]
    PacketTooShort(usize, usize),

    #[error("Unsupported Ethernet type: 0x{0:04x}")]
    UnsupportedEtherType(u16),

    #[error("Invalid IP version: {0}")]
    InvalidIpVersion(u8),

    #[error("Invalid TCP data offset: {0}")]
    InvalidTcpDataOffset(u8),

    #[error("Parse error: {0}")]
    ParseError(String),
}

impl From<ParserError> for String {
    fn from(e: ParserError) -> Self {
        e.to_string()
    }
}
