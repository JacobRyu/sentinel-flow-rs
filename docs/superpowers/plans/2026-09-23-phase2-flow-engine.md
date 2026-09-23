# Phase 2: Flow Engine 統合 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** パケットキャプチャ済みの `ParsedPacket` を5タプルFlowに集計し、タイムアウト/FIN/RSTでエクスポート（ログ）するFlow Engineを sensor 本線に統合する。

**Architecture:** 単一 processor タスク内で `tokio::select!` によりパケット集計と1秒周期sweepを処理。`FlowTable` はタスクが単独所有。export先はログのみ（channel は Phase 3）。既存の双方向カウントバグを canonical キー正規化で修正する。

**Tech Stack:** Rust 2024 edition / tokio / dashmap / prometheus / 既存 path 依存 crate（sentinel-parser, sentinel-flow）

**Spec:** `docs/superpowers/specs/2026-09-23-phase2-flow-engine-design.md`

**Specとの明示的差異:** spec の `on_packet` は戻り値なしだが、FIN/RST 即export のログ出力を main 側の責務にするため `-> Option<ExportedFlow>` に精緻化した（計画時の_interface refinement）。

## Global Constraints

- export はログのみ。mpsc channel / `FlowSink` trait / ClickHouse 実装は禁止（Phase 3）
- sweep 間隔は固定1秒。設定項目の追加禁止
- 既存 Cargo.toml の依存追加禁止（path 依存の既存依存は使用可）
- 時間依存テストは `inactive_timeout_secs: 0` で実装し、sleep 禁止
- `cargo clippy --workspace --all-targets --all-features -- -D warnings` が全タスクでパスすること
- `cargo fmt --all` に従うこと（このリポジトリは `max_width=100`、`use_small_heuristics = "Max"`）
- コミットは Conventional Commits（`feat:` / `fix:` / `test:` / `refactor:`）
- spec の非スコープ（Detection 統合、Grafana、enrichment）は実装しない

---

### Task 1: parser — `tcp_flags` 抽出と `Protocol::ip_number()`

**Files:**
- Modify: `crates/sentinel-parser/src/packet.rs`
- Modify: `crates/sentinel-parser/src/lib.rs`
- Test: 各ファイル内の `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: 既存 `TcpHeader.flags: u8`（tcp.rs、変更なし）
- Produces:
  - `ParsedPacket.tcp_flags: Option<u8>` — TCP のとき `Some(flags)`、非TCPは `None`
  - `Protocol::ip_number(&self) -> u8` — Tcp=6, Udp=17, Icmp=1, Other(n)=n

- [ ] **Step 1: 失敗するテストを書く（packet.rs）**

`crates/sentinel-parser/src/packet.rs` の `mod tests` を置き換える:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protocol_display() {
        assert_eq!(Protocol::Tcp.to_string(), "TCP");
        assert_eq!(Protocol::Udp.to_string(), "UDP");
        assert_eq!(Protocol::Other(1).to_string(), "OTHER(1)");
    }

    #[test]
    fn test_protocol_ip_number() {
        assert_eq!(Protocol::Tcp.ip_number(), 6);
        assert_eq!(Protocol::Udp.ip_number(), 17);
        assert_eq!(Protocol::Icmp.ip_number(), 1);
        assert_eq!(Protocol::Other(47).ip_number(), 47);
    }
}
```

- [ ] **Step 2: テストが失敗することを確認**

Run: `cargo nextest run -p sentinel-parser`
Expected: FAIL — `no method named ip_number found for enum Protocol`

- [ ] **Step 3: `Protocol::ip_number` を実装**

`packet.rs` の `Protocol` enum 直下に追加:

```rust
impl Protocol {
    /// IP protocol number (for FlowKey)
    pub fn ip_number(&self) -> u8 {
        match self {
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Icmp => 1,
            Protocol::Other(n) => *n,
        }
    }
}
```

- [ ] **Step 4: `ParsedPacket` に `tcp_flags` フィールドを追加**

`packet.rs` の `ParsedPacket` struct を以下に変更（フィールド追加のみ）:

```rust
/// Parsed packet with all extracted fields
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub ethernet: EthernetFrame,
    pub ip: IpHeader,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: Protocol,
    pub payload_len: usize,
    /// TCP flags (raw byte) when protocol is TCP, otherwise None
    pub tcp_flags: Option<u8>,
}
```

この時点で `lib.rs` のコンストラクタがコンパイルエラーになる（Step 5 で修正）。

- [ ] **Step 5: `parse_packet` で flags をセット（lib.rs）**

`crates/sentinel-parser/src/lib.rs` の `parse_packet` 全体を以下に置き換える:

```rust
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
                            (Protocol::Tcp, ports.0, ports.1, remaining.len() - tcp_header_len, Some(tcp.flags))
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
```

注意: 上の IPv6 UDP アームの `udp.dst_port.min(u16::MAX)` は誤り。正しくは:

```rust
17 => {
    let udp = UdpHeader::parse(remaining)?;
    let ports = (udp.src_port, udp.dst_port);
    (Protocol::Udp, ports.0, ports.1, None)
}
```

- [ ] **Step 6: lib.rs に flags 経路のテストを追加**

`crates/sentinel-parser/src/lib.rs` の `mod tests` を以下に置き換える:

```rust
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
```

- [ ] **Step 7: テストがパスすることを確認**

Run: `cargo nextest run -p sentinel-parser`
Expected: PASS（既存を含む全テスト）

- [ ] **Step 8: clippy / fmt**

Run: `cargo clippy -p sentinel-parser --all-targets --all-features -- -D warnings && cargo fmt -p sentinel-parser`
Expected: clippy 通過、fmt による差分があれば自動修正

- [ ] **Step 9: コミット**

```bash
git add crates/sentinel-parser/src/packet.rs crates/sentinel-parser/src/lib.rs
git commit -m "feat(parser): extract TCP flags into ParsedPacket and add Protocol::ip_number"
```

---

### Task 2: flow crate — canonical 正規化・双方向カウント修正・`take_flow`

**Files:**
- Modify: `crates/sentinel-flow/src/entry.rs`
- Modify: `crates/sentinel-flow/src/table.rs`
- Modify: `crates/sentinel-flow/src/export.rs`（テストのみ。`FlowEntry::new` 呼び出し修正）

**Interfaces:**
- Consumes: Task 1 の成果物は不要（独立）。既存 `FlowKey::canonical(src, dst, sport, dport, proto) -> FlowKey`
- Produces:
  - `FlowEntry::new() -> FlowEntry`（引数なし。`is_forward` フィールド削除）
  - `FlowEntry::update(&mut self, bytes: u64, tcp_flags: Option<u8>, is_forward: bool)`
  - `FlowTable::update_flow(&self, key: FlowKey, bytes: u64, tcp_flags: Option<u8>) -> Result<(), FlowError>`（シグネチャ据え置き、内部で canonical 正規化）
  - `FlowTable::take_flow(&self, key: &FlowKey) -> Option<(FlowKey, FlowEntry)>`

**背景（既存バグ）:** `FlowEntry::new(true)` が常に forward 扱いで、リバースパケットも `packets_forward` に入る。またキーが正規化されておらず往復が別エントリになる。

- [ ] **Step 1: 失敗するテストを書く（table.rs）**

`crates/sentinel-flow/src/table.rs` の `mod tests` に既存テストを保持したまま**追記**:

```rust
    #[test]
    fn test_flow_table_bidirectional_counts() {
        let config = FlowTableConfig::default();
        let table = FlowTable::new(config);

        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];

        let fwd = FlowKey::new(ip1, ip2, 12345, 80, 6);
        let rev = FlowKey::new(ip2, ip1, 80, 12345, 6);

        table.update_flow(fwd, 100, Some(0x02)).unwrap(); // SYN
        table.update_flow(rev, 50, Some(0x10)).unwrap(); // ACK

        assert_eq!(table.len(), 1, "bidirectional packets must share one entry");

        let flows = table.get_active_flows();
        let (_, entry) = &flows[0];
        assert_eq!(entry.packets_forward, 1);
        assert_eq!(entry.bytes_forward, 100);
        assert_eq!(entry.packets_reverse, 1);
        assert_eq!(entry.bytes_reverse, 50);
        assert!(entry.tcp_flags.syn);
        assert!(entry.tcp_flags.ack);
    }

    #[test]
    fn test_flow_table_take_flow() {
        let config = FlowTableConfig::default();
        let table = FlowTable::new(config);

        let ip1 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 1];
        let ip2 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2];

        // 逆向きで登録
        let rev = FlowKey::new(ip2, ip1, 80, 12345, 6);
        table.update_flow(rev, 100, None).unwrap();

        // 正向きキーで take（canonical で同一エントリ）
        let fwd = FlowKey::new(ip1, ip2, 12345, 80, 6);
        let taken = table.take_flow(&fwd);
        assert!(taken.is_some());
        assert!(table.is_empty());

        let taken_again = table.take_flow(&fwd);
        assert!(taken_again.is_none());
    }
```

- [ ] **Step 2: テストが失敗することを確認**

Run: `cargo nextest run -p sentinel-flow`
Expected: FAIL — `test_flow_table_bidirectional_counts`（往復が2エントリ / forward計上バグ）、`take_flow` が存在しない

- [ ] **Step 3: `FlowEntry` を direction 対応に変更（entry.rs）**

entry.rs の変更点:

1. struct から `is_forward` フィールドを**削除**:

```rust
/// Flow entry with counters and metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowEntry {
    /// Flow ID (UUID)
    pub flow_id: String,

    /// Timestamps
    pub timestamp_start: DateTime<Utc>,
    pub timestamp_end: DateTime<Utc>,

    /// Packet counters
    pub packets_forward: u32,
    pub packets_reverse: u32,

    /// Byte counters
    pub bytes_forward: u64,
    pub bytes_reverse: u64,

    /// TCP flags observed
    pub tcp_flags: TcpFlags,

    /// Last activity timestamp (for timeout detection)
    pub last_activity: DateTime<Utc>,
}
```

2. コンストラクタを引数なしに:

```rust
    /// Create a new flow entry
    pub fn new() -> Self {
        let now = Utc::now();
        Self {
            flow_id: uuid::Uuid::new_v4().to_string(),
            timestamp_start: now,
            timestamp_end: now,
            packets_forward: 0,
            packets_reverse: 0,
            bytes_forward: 0,
            bytes_reverse: 0,
            tcp_flags: TcpFlags::default(),
            last_activity: now,
        }
    }
```

3. `update` に direction 引数を追加:

```rust
    /// Update flow with new packet.
    /// `is_forward` is true when the packet matches the canonical key orientation.
    pub fn update(&mut self, bytes: u64, tcp_flags: Option<u8>, is_forward: bool) {
        let now = Utc::now();
        self.timestamp_end = now;
        self.last_activity = now;

        if is_forward {
            self.packets_forward += 1;
            self.bytes_forward += bytes;
        } else {
            self.packets_reverse += 1;
            self.bytes_reverse += bytes;
        }

        if let Some(flags) = tcp_flags {
            self.tcp_flags.update(flags);
        }
    }
```

4. `Default` を追加（`new()` が引数なしだため conventional）:

```rust
impl Default for FlowEntry {
    fn default() -> Self {
        Self::new()
    }
}
```

5. entry.rs の tests を更新:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flow_entry_new() {
        let entry = FlowEntry::new();
        assert_eq!(entry.packets_forward, 0);
        assert_eq!(entry.bytes_forward, 0);
        assert_eq!(entry.packets_reverse, 0);
    }

    #[test]
    fn test_flow_entry_update_forward() {
        let mut entry = FlowEntry::new();
        entry.update(100, Some(0x02), true); // SYN

        assert_eq!(entry.packets_forward, 1);
        assert_eq!(entry.bytes_forward, 100);
        assert_eq!(entry.packets_reverse, 0);
        assert!(entry.tcp_flags.syn);
    }

    #[test]
    fn test_flow_entry_update_reverse() {
        let mut entry = FlowEntry::new();
        entry.update(50, Some(0x10), false); // ACK (reverse)

        assert_eq!(entry.packets_forward, 0);
        assert_eq!(entry.packets_reverse, 1);
        assert_eq!(entry.bytes_reverse, 50);
        assert!(entry.tcp_flags.ack);
    }

    #[test]
    fn test_flow_entry_duration() {
        let entry = FlowEntry::new();
        // Duration should be at least 0ms (u64 is always >= 0)
        let _ = entry.duration_ms();
    }
}
```

- [ ] **Step 4: `FlowTable` を canonical 正規化 + `take_flow` に変更（table.rs）**

`update_flow` を置き換え:

```rust
    /// Update or create a flow.
    /// The key is canonicalized internally so both directions map to one entry.
    pub fn update_flow(
        &self,
        key: FlowKey,
        bytes: u64,
        tcp_flags: Option<u8>,
    ) -> Result<(), crate::FlowError> {
        let canonical = FlowKey::canonical(
            key.src_ip,
            key.dst_ip,
            key.src_port,
            key.dst_port,
            key.protocol,
        );
        let is_forward = key == canonical;

        // Check if table is full
        if self.flows.len() >= self.config.max_flows && !self.flows.contains_key(&canonical) {
            return Err(crate::FlowError::TableFull(self.config.max_flows));
        }

        // Update existing flow or create new one
        if let Some(mut entry) = self.flows.get_mut(&canonical) {
            entry.update(bytes, tcp_flags, is_forward);
        } else {
            let mut entry = FlowEntry::new();
            entry.update(bytes, tcp_flags, is_forward);
            self.flows.insert(canonical, entry);
        }

        Ok(())
    }

    /// Take a flow out of the table (immediate export on FIN/RST).
    /// The key is canonicalized internally.
    pub fn take_flow(&self, key: &FlowKey) -> Option<(FlowKey, FlowEntry)> {
        let canonical = FlowKey::canonical(
            key.src_ip,
            key.dst_ip,
            key.src_port,
            key.dst_port,
            key.protocol,
        );
        self.flows.remove(&canonical)
    }
```

- [ ] **Step 5: export.rs のテスト修正**

`crates/sentinel-flow/src/export.rs` の `test_export_flow` 内、2行を修正:

```rust
        let mut entry = FlowEntry::new();
        entry.update(100, Some(0x02), true);
```

- [ ] **Step 6: テストがパスすることを確認**

Run: `cargo nextest run -p sentinel-flow`
Expected: PASS（全テスト。特に `test_flow_table_bidirectional_counts`, `test_flow_table_take_flow`）

- [ ] **Step 7: clippy / fmt**

Run: `cargo clippy -p sentinel-flow --all-targets --all-features -- -D warnings && cargo fmt -p sentinel-flow`
Expected: 通過

- [ ] **Step 8: コミット**

```bash
git add crates/sentinel-flow/src/entry.rs crates/sentinel-flow/src/table.rs crates/sentinel-flow/src/export.rs
git commit -m "fix(flow): canonicalize flow keys and count reverse direction correctly"
```

---

### Task 3: sensor — `FlowProcessor`（集計・sweep・FIN/RST即export）

**Files:**
- Create: `crates/sentinel-sensor/src/flow.rs`
- Modify: `crates/sentinel-sensor/src/main.rs`（`mod flow;` の追加のみ）

**Interfaces:**
- Consumes:
  - Task 1: `ParsedPacket.tcp_flags`, `Protocol::ip_number()`, `ParsedPacket::{src_ip_bytes, dst_ip_bytes, total_len, src_port, dst_port, protocol}`
  - Task 2: `FlowTable::new/update_flow/take_flow/get_expired_flows/len`, `FlowTableConfig`, `FlowExporter::new/export_flow/export_flows`, `ExportedFlow`, `FlowError::TableFull`
  - 既存: `crate::config::FlowConfig`, `crate::metrics::SensorMetrics`
- Produces:
  - `FlowProcessor::new(config: &FlowConfig, sensor_node: String, metrics: Arc<SensorMetrics>) -> Self`
  - `FlowProcessor::on_packet(&mut self, pkt: &ParsedPacket) -> Option<ExportedFlow>` — FIN/RST で即exportした場合 `Some`
  - `FlowProcessor::sweep(&mut self) -> Vec<ExportedFlow>` — 期限切れFlow（ログ副作用なし）
  - `FlowProcessor::active_flows(&self) -> usize`

- [ ] **Step 1: 失敗するテストを書く（flow.rs — テストのみ）**

`crates/sentinel-sensor/src/flow.rs` を以下で作成（`FlowProcessor` 実装はまだ書かない。存在しない型への参照がそのまま red になる）:

```rust
use std::sync::Arc;

use sentinel_parser::ParsedPacket;

use crate::config::FlowConfig;
use crate::metrics::SensorMetrics;

#[cfg(test)]
mod tests {
    use super::*;
    use sentinel_parser::parse_packet;

    fn test_metrics() -> Arc<SensorMetrics> {
        Arc::new(SensorMetrics::new().unwrap())
    }

    fn immediate_expiry_config() -> FlowConfig {
        FlowConfig {
            inactive_timeout_secs: 0,
            active_timeout_secs: 300,
            max_flows: 100,
        }
    }

    /// Build a minimal Ethernet+IPv4+TCP frame and parse it.
    fn make_tcp_packet(
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        flags: u8,
    ) -> ParsedPacket {
        let mut data = vec![0u8; 54];
        data[12] = 0x08;
        data[13] = 0x00;
        data[14] = 0x45;
        data[16..18].copy_from_slice(&40u16.to_be_bytes());
        data[22] = 64;
        data[23] = 6; // TCP
        data[26..30].copy_from_slice(&src);
        data[30..34].copy_from_slice(&dst);
        data[34..36].copy_from_slice(&sport.to_be_bytes());
        data[36..38].copy_from_slice(&dport.to_be_bytes());
        data[46] = 0x50;
        data[47] = flags;
        parse_packet(&data).unwrap()
    }

    #[test]
    fn test_on_packet_creates_flow_and_sweep_exports() {
        let metrics = test_metrics();
        let mut proc =
            FlowProcessor::new(&immediate_expiry_config(), "node-1".into(), metrics.clone());

        let pkt = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x02); // SYN
        assert!(proc.on_packet(&pkt).is_none());
        assert_eq!(proc.active_flows(), 1);

        // inactive_timeout_secs = 0 → すぐ期限切れ
        let exported = proc.sweep();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].source_ip, "10.0.0.1");
        assert_eq!(exported[0].destination_ip, "10.0.0.2");
        assert_eq!(exported[0].source_port, 12345);
        assert_eq!(exported[0].destination_port, 80);
        assert_eq!(exported[0].protocol, "TCP");
        assert_eq!(exported[0].packets_forward, 1);
        assert_eq!(exported[0].sensor_node, "node-1");
        assert_eq!(proc.active_flows(), 0);
        assert_eq!(metrics.flows_exported.get(), 1);
        assert_eq!(metrics.active_flows.get(), 0);
    }

    #[test]
    fn test_bidirectional_single_flow() {
        let mut proc =
            FlowProcessor::new(&immediate_expiry_config(), "node-1".into(), test_metrics());

        let fwd = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x02);
        let rev = make_tcp_packet([10, 0, 0, 2], [10, 0, 0, 1], 80, 12345, 0x10);
        proc.on_packet(&fwd);
        proc.on_packet(&rev);

        assert_eq!(proc.active_flows(), 1);

        let exported = proc.sweep();
        assert_eq!(exported.len(), 1);
        assert_eq!(exported[0].packets_forward, 1);
        assert_eq!(exported[0].packets_reverse, 1);
    }

    #[test]
    fn test_fin_triggers_immediate_export() {
        let mut proc =
            FlowProcessor::new(&immediate_expiry_config(), "node-1".into(), test_metrics());

        // FIN + ACK
        let pkt = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x11);
        let exported = proc.on_packet(&pkt);
        assert!(exported.is_some());
        assert_eq!(exported.unwrap().destination_port, 80);
        assert_eq!(proc.active_flows(), 0);
        // 既に export 済みなので sweep には出ない
        assert!(proc.sweep().is_empty());
    }

    #[test]
    fn test_rst_triggers_immediate_export() {
        let mut proc =
            FlowProcessor::new(&immediate_expiry_config(), "node-1".into(), test_metrics());

        let pkt = make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x04); // RST
        assert!(proc.on_packet(&pkt).is_some());
        assert_eq!(proc.active_flows(), 0);
    }

    #[test]
    fn test_table_full_drops_packet() {
        let config = FlowConfig { max_flows: 1, ..immediate_expiry_config() };
        let metrics = test_metrics();
        let mut proc = FlowProcessor::new(&config, "node-1".into(), metrics.clone());

        // 異なる2フロー、max_flows = 1
        proc.on_packet(&make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x10));
        proc.on_packet(&make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 3], 12345, 80, 0x10));

        assert_eq!(proc.active_flows(), 1);
        assert_eq!(metrics.packets_dropped.get(), 1);
    }
}
```

- [ ] **Step 2: `mod flow;` を main.rs に追加**

`crates/sentinel-sensor/src/main.rs` 冒頭のモジュール宣言を変更:

```rust
mod capture;
mod config;
mod flow;
mod metrics;
```

- [ ] **Step 3: テストが失敗することを確認（red）**

Run: `cargo nextest run -p sentinel-sensor`
Expected: FAIL — `cannot find struct FlowProcessor in this scope`（および `on_packet` / `sweep` / `active_flows` が見つからない）

- [ ] **Step 4: `FlowProcessor` を実装（green）**

`flow.rs` の先頭 import の直後（`mod tests` の前）に、以下の定数・構造体・`impl` を**追加**する:

```rust
use sentinel_flow::{ExportedFlow, FlowError, FlowExporter, FlowKey, FlowTable, FlowTableConfig};
use tracing::debug;

const TCP_FIN: u8 = 0x01;
const TCP_RST: u8 = 0x04;

/// Aggregates parsed packets into flows and exports them on timeout / FIN / RST.
pub struct FlowProcessor {
    table: FlowTable,
    exporter: FlowExporter,
    metrics: Arc<SensorMetrics>,
}

impl FlowProcessor {
    pub fn new(config: &FlowConfig, sensor_node: String, metrics: Arc<SensorMetrics>) -> Self {
        let table = FlowTable::new(FlowTableConfig {
            max_flows: config.max_flows,
            inactive_timeout_secs: config.inactive_timeout_secs,
            active_timeout_secs: config.active_timeout_secs,
        });
        Self { table, exporter: FlowExporter::new(sensor_node), metrics }
    }

    /// Process one packet into the flow table.
    /// Returns `Some(exported)` when FIN/RST triggered immediate export
    /// (architecture.md §5.4).
    pub fn on_packet(&mut self, pkt: &ParsedPacket) -> Option<ExportedFlow> {
        let key = FlowKey::new(
            pkt.src_ip_bytes(),
            pkt.dst_ip_bytes(),
            pkt.src_port,
            pkt.dst_port,
            pkt.protocol.ip_number(),
        );
        let bytes = pkt.total_len() as u64;

        match self.table.update_flow(key.clone(), bytes, pkt.tcp_flags) {
            Ok(()) => self.metrics.active_flows.set(self.table.len() as i64),
            Err(FlowError::TableFull(_)) => {
                self.metrics.packets_dropped.inc();
                debug!("flow table full, dropping packet");
            }
            Err(e) => debug!("flow update error: {}", e),
        }

        let fin_or_rst = pkt
            .tcp_flags
            .is_some_and(|f| f & TCP_FIN != 0 || f & TCP_RST != 0);
        if !fin_or_rst {
            return None;
        }

        let (key, entry) = self.table.take_flow(&key)?;
        let exported = self.exporter.export_flow(&key, &entry);
        self.metrics.flows_exported.inc();
        self.metrics.active_flows.set(self.table.len() as i64);
        Some(exported)
    }

    /// Collect expired flows (inactive / active timeout) and export them.
    /// Logging is the caller's responsibility.
    pub fn sweep(&mut self) -> Vec<ExportedFlow> {
        let expired = self.table.get_expired_flows();
        if expired.is_empty() {
            return Vec::new();
        }
        let flows = self.exporter.export_flows(&expired);
        self.metrics.flows_exported.inc_by(flows.len() as u64);
        self.metrics.active_flows.set(self.table.len() as i64);
        flows
    }

    /// Current number of active flows in the table.
    pub fn active_flows(&self) -> usize {
        self.table.len()
    }
}
```

完成後の `flow.rs` の構成順は「import → 定数 → struct → impl → mod tests」。

- [ ] **Step 5: テストがパスすることを確認**

Run: `cargo nextest run -p sentinel-sensor`
Expected: PASS（`flow::tests::*` 5件 + 既存 `config::tests` 1件）

- [ ] **Step 6: clippy / fmt**

Run: `cargo clippy -p sentinel-sensor --all-targets --all-features -- -D warnings && cargo fmt -p sentinel-sensor`
Expected: 通過（未使用 import があれば修正）

- [ ] **Step 7: コミット**

```bash
git add crates/sentinel-sensor/src/flow.rs crates/sentinel-sensor/src/main.rs
git commit -m "feat(sensor): add FlowProcessor for aggregation and timeout export"
```

---

### Task 4: main.rs 配線 — select! ループと graceful shutdown

**Files:**
- Modify: `crates/sentinel-sensor/src/main.rs`

**Interfaces:**
- Consumes: Task 3 の `FlowProcessor::{new, on_packet, sweep}`、既存 `PacketCapture::run(tx)`, `SensorMetrics`
- Produces: 完成した sensor バイナリ。以降の Phase 3 はこのループに export channel を差し込む

- [ ] **Step 1: main.rs 全文を置き換える**

`crates/sentinel-sensor/src/main.rs`:

```rust
mod capture;
mod config;
mod flow;
mod metrics;

use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{error, info};

use capture::PacketCapture;
use config::SensorConfig;
use flow::FlowProcessor;
use metrics::SensorMetrics;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    info!("Starting SentinelFlow Sensor...");

    // Parse command line arguments
    let args: Vec<String> = std::env::args().collect();
    let config_path = args
        .windows(2)
        .find(|w| w[0] == "--config")
        .map(|w| w[1].clone())
        .unwrap_or_else(|| "config/sensor.yaml".to_string());

    // Load configuration
    let config = SensorConfig::load(&config_path)?;
    info!("Loaded configuration from {}", config_path);

    // Initialize metrics
    let metrics = Arc::new(SensorMetrics::new()?);

    // Initialize packet capture
    let (tx, mut rx) = mpsc::channel(10000);
    let capture = PacketCapture::new(&config.capture)?;

    // Start packet capture in background
    let capture_handle = tokio::spawn(async move {
        if let Err(e) = capture.run(tx).await {
            error!("Packet capture error: {}", e);
        }
    });

    let sensor_node =
        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());

    // Process packets: flow aggregation + periodic sweep in one select! loop
    let flow_config = config.flow.clone();
    let processor_handle = tokio::spawn({
        let metrics = metrics.clone();
        async move {
            let mut processor = FlowProcessor::new(&flow_config, sensor_node, metrics.clone());
            let mut sweep_interval = tokio::time::interval(Duration::from_secs(1));
            let mut packet_count = 0u64;
            let mut byte_count = 0u64;

            loop {
                tokio::select! {
                    maybe = rx.recv() => {
                        let Some(packet) = maybe else { break };
                        packet_count += 1;
                        byte_count += packet.total_len() as u64;

                        // Log first few packets for debugging
                        if packet_count <= 10 {
                            info!("Packet {}: {}", packet_count, packet);
                        }

                        metrics.packets_captured.inc();
                        metrics.bytes_captured.inc_by(packet.total_len() as u64);

                        if let Some(exported) = processor.on_packet(&packet) {
                            info!("flow_export: {:?}", exported);
                        }
                    }
                    _ = sweep_interval.tick() => {
                        for exported in processor.sweep() {
                            info!("flow_export: {:?}", exported);
                        }
                    }
                }
            }

            // Flush remaining flows on shutdown (capture tx dropped → rx None)
            for exported in processor.sweep() {
                info!("flow_export: {:?}", exported);
            }

            info!(
                "Packet processing stopped. Total: {} packets, {} bytes",
                packet_count, byte_count
            );
        }
    });

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    info!("Shutdown signal received...");

    // Abort capture first: drops tx → processor drains → final sweep → exits
    capture_handle.abort();
    match tokio::time::timeout(Duration::from_secs(5), processor_handle).await {
        Ok(Ok(())) => info!("Flow processor stopped."),
        Ok(Err(e)) => error!("Flow processor task failed: {}", e),
        Err(_) => error!("Flow processor shutdown timed out"),
    }

    info!("SentinelFlow Sensor stopped.");
    Ok(())
}
```

- [ ] **Step 2: ワークスペース全体のテスト**

Run: `cargo nextest run --workspace`
Expected: PASS（全22件以上）

- [ ] **Step 3: clippy / fmt / check**

Run:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo check --workspace --all-targets
```

Expected: すべて通過。旧実装にあった `// TODO: Flow aggregation` / `// TODO: ClickHouse export` コメントが残っていないこと（Phase 3 の管理は spec 側）

- [ ] **Step 4: （任意）バイナリ起動の煙試験**

config が存在しないためエラーになるのは許容。存在確認:

Run: `cargo build --bin sentinel-sensor && ls target/debug/sentinel-sensor`
Expected: ビンド成功

- [ ] **Step 5: コミット**

```bash
git add crates/sentinel-sensor/src/main.rs
git commit -m "feat(sensor): wire flow engine into sensor main loop with graceful shutdown"
```

- [ ] **Step 6: 最終検証**

Run:

```bash
cargo nextest run --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
typos
```

Expected: 全て通過。spec の受入基準を満たすこと。
