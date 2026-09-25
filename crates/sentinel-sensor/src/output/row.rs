//! Row type mapping [`ExportedFlow`] onto the `network_flows` schema.

use std::net::{IpAddr, Ipv6Addr};

use chrono::{DateTime, Utc};
use clickhouse::Row;
use sentinel_flow::ExportedFlow;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

/// One row of `network_flows`, in the binary form ClickHouse expects.
///
/// Field names and types mirror the DDL in [`super::clickhouse`]; the
/// `Enum8` protocol tag is stored as `i8`, `IPv6` as 16 raw octets and
/// `DateTime64(3)` as milliseconds since the epoch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Row)]
pub struct FlowRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub flow_id: Uuid,
    #[serde(with = "datetime64_ms")]
    pub timestamp_start: DateTime<Utc>,
    #[serde(with = "datetime64_ms")]
    pub timestamp_end: DateTime<Utc>,
    #[serde(with = "ipv6")]
    pub source_ip: Ipv6Addr,
    #[serde(with = "ipv6")]
    pub destination_ip: Ipv6Addr,
    pub source_port: u16,
    pub destination_port: u16,
    /// `Enum8` tag: 1=TCP, 2=UDP, 3=ICMP, 4=OTHER.
    pub protocol: i8,
    pub packets_forward: u32,
    pub packets_reverse: u32,
    pub bytes_forward: u64,
    pub bytes_reverse: u64,
    pub duration_ms: u32,
    /// Observed TCP flag bits: FIN=1, SYN=2, RST=4, PSH=8, ACK=16, URG=32.
    pub tcp_flags_seen: Vec<u8>,
    pub sensor_node: String,
}

/// Reason a flow could not be converted into a [`FlowRow`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FlowConvertError {
    #[error("invalid flow_id: {0}")]
    FlowId(String),
    #[error("invalid timestamp: {0}")]
    Timestamp(String),
    #[error("invalid ip address: {0}")]
    Ip(String),
    #[error("duration_ms {0} exceeds UInt32")]
    Duration(u64),
}

impl TryFrom<&ExportedFlow> for FlowRow {
    type Error = FlowConvertError;

    fn try_from(flow: &ExportedFlow) -> Result<Self, Self::Error> {
        Ok(Self {
            flow_id: Uuid::parse_str(&flow.flow_id)
                .map_err(|_| FlowConvertError::FlowId(flow.flow_id.clone()))?,
            timestamp_start: parse_timestamp(&flow.timestamp_start)?,
            timestamp_end: parse_timestamp(&flow.timestamp_end)?,
            source_ip: parse_ip(&flow.source_ip)?,
            destination_ip: parse_ip(&flow.destination_ip)?,
            source_port: flow.source_port,
            destination_port: flow.destination_port,
            protocol: protocol_code(&flow.protocol),
            packets_forward: flow.packets_forward,
            packets_reverse: flow.packets_reverse,
            bytes_forward: flow.bytes_forward,
            bytes_reverse: flow.bytes_reverse,
            duration_ms: u32::try_from(flow.duration_ms)
                .map_err(|_| FlowConvertError::Duration(flow.duration_ms))?,
            tcp_flags_seen: flow.tcp_flags.iter().filter_map(|name| flag_bit(name)).collect(),
            sensor_node: flow.sensor_node.clone(),
        })
    }
}

/// Map a protocol name to its `Enum8` tag.
fn protocol_code(protocol: &str) -> i8 {
    match protocol {
        "TCP" => 1,
        "UDP" => 2,
        "ICMP" => 3,
        _ => 4,
    }
}

/// Map a TCP flag name to its bitmask value; unknown names are dropped.
fn flag_bit(name: &str) -> Option<u8> {
    match name {
        "FIN" => Some(0x01),
        "SYN" => Some(0x02),
        "RST" => Some(0x04),
        "PSH" => Some(0x08),
        "ACK" => Some(0x10),
        "URG" => Some(0x20),
        _ => None,
    }
}

fn parse_timestamp(timestamp: &str) -> Result<DateTime<Utc>, FlowConvertError> {
    DateTime::parse_from_rfc3339(timestamp)
        .map(|ts| ts.with_timezone(&Utc))
        .map_err(|_| FlowConvertError::Timestamp(timestamp.to_string()))
}

fn parse_ip(ip: &str) -> Result<Ipv6Addr, FlowConvertError> {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => Ok(v4.to_ipv6_mapped()),
        Ok(IpAddr::V6(v6)) => Ok(v6),
        Err(_) => Err(FlowConvertError::Ip(ip.to_string())),
    }
}

/// Ser/de `DateTime<Utc>` as `DateTime64(3)`: i64 milliseconds since epoch.
mod datetime64_ms {
    use super::*;

    pub fn serialize<S: Serializer>(
        timestamp: &DateTime<Utc>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_i64(timestamp.timestamp_millis())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<DateTime<Utc>, D::Error> {
        let millis = i64::deserialize(deserializer)?;
        DateTime::from_timestamp_millis(millis)
            .ok_or_else(|| serde::de::Error::custom(format!("timestamp out of range: {millis}")))
    }
}

/// Ser/de `Ipv6Addr` as `IPv6`: 16 raw octets with no length prefix.
mod ipv6 {
    use super::*;

    pub fn serialize<S: Serializer>(ip: &Ipv6Addr, serializer: S) -> Result<S::Ok, S::Error> {
        ip.octets().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Ipv6Addr, D::Error> {
        Ok(Ipv6Addr::from(<[u8; 16]>::deserialize(deserializer)?))
    }
}

/// Build a minimal convertible flow for tests.
#[cfg(test)]
pub(crate) fn sample_flow(flow_id: &str) -> ExportedFlow {
    ExportedFlow {
        flow_id: flow_id.to_string(),
        timestamp_start: "2026-09-25T10:00:00.123+00:00".to_string(),
        timestamp_end: "2026-09-25T10:00:01.456+00:00".to_string(),
        source_ip: "10.0.0.1".to_string(),
        destination_ip: "2001:db8::1".to_string(),
        source_port: 44321,
        destination_port: 443,
        protocol: "TCP".to_string(),
        packets_forward: 10,
        packets_reverse: 20,
        bytes_forward: 1000,
        bytes_reverse: 2000,
        duration_ms: 1333,
        tcp_flags: vec!["SYN".to_string(), "ACK".to_string(), "BOGUS".to_string()],
        sensor_node: "node-1".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn converts_exported_flow() {
        let flow = sample_flow("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e0f");
        let row = FlowRow::try_from(&flow).unwrap();

        assert_eq!(row.flow_id, Uuid::parse_str("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e0f").unwrap());
        assert_eq!(
            row.timestamp_start,
            DateTime::parse_from_rfc3339("2026-09-25T10:00:00.123+00:00")
                .unwrap()
                .with_timezone(&Utc)
        );
        assert_eq!(row.source_ip, Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert_eq!(row.destination_ip, "2001:db8::1".parse::<Ipv6Addr>().unwrap());
        assert_eq!(row.protocol, 1);
        assert_eq!(row.duration_ms, 1333);
        assert_eq!(row.tcp_flags_seen, vec![0x02, 0x10]);
        assert_eq!(row.sensor_node, "node-1");
    }

    #[test]
    fn maps_protocol_and_flags() {
        assert_eq!(protocol_code("TCP"), 1);
        assert_eq!(protocol_code("UDP"), 2);
        assert_eq!(protocol_code("ICMP"), 3);
        assert_eq!(protocol_code("GRE"), 4);

        assert_eq!(flag_bit("FIN"), Some(0x01));
        assert_eq!(flag_bit("URG"), Some(0x20));
        assert_eq!(flag_bit("BOGUS"), None);
    }

    #[test]
    fn rejects_invalid_flows() {
        let mut flow = sample_flow("not-a-uuid");
        assert_eq!(
            FlowRow::try_from(&flow).unwrap_err(),
            FlowConvertError::FlowId("not-a-uuid".to_string())
        );

        flow = sample_flow("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e0f");
        flow.timestamp_start = "yesterday".to_string();
        assert!(matches!(FlowRow::try_from(&flow).unwrap_err(), FlowConvertError::Timestamp(_)));

        flow = sample_flow("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e0f");
        flow.source_ip = "999.1.1.1".to_string();
        assert!(matches!(FlowRow::try_from(&flow).unwrap_err(), FlowConvertError::Ip(_)));

        flow = sample_flow("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e0f");
        flow.duration_ms = u64::from(u32::MAX) + 1;
        assert_eq!(
            FlowRow::try_from(&flow).unwrap_err(),
            FlowConvertError::Duration(u64::from(u32::MAX) + 1)
        );
    }
}
