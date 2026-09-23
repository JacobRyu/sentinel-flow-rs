# Phase 2: Flow Engine 統合 — 設計spec

> **Status**: Approved
> **Date**: 2026-09-23
> **Scope**: architecture.md Roadmap Phase 2 のみ（ClickHouse保存=Phase 3 は含まない）

## 目的

パケットキャプチャ済みの `ParsedPacket` を 5タプルFlowに集計し、タイムアウトでエクスポートする既存ライブラリ（`crates/sentinel-flow`）を sensor 本線に統合する。

**受入基準**

- パケットがFlowとして集計される（カウンタ・TCP flags・durationが正しい）
- 往復トラフィックが1つのFlowに集約され、forward/reverseカウンタが正しく分かれる
- inactive / active タイムアウトでFlowがエクスポートされる（ログ出力）
- TCP FIN/RST 観測時に即エクスポートされる
- `cargo nextest run --workspace` が全件パスする

**非スコープ（Phase 3以降）**

- ClickHouse 保存・export channel・`FlowSink` trait
- Grafana dashboard、Detection 統合、Kubernetes metadata enrichment

## 方針判断（brainstorming確定事項）

| 論点 | 決定 | 理由 |
|---|---|---|
| アプローチ | 単一processorタスク + `tokio::select!` | YAGNI。`Arc`共有・タスク分離・trait抽象は現時点で実需要なし |
| export先 | ログのみ（`info!`） | 消費者が存在しない今に channel を作らない。Phase 3 で ClickHouse writer と同時に導入 |
| 検証 | ユニットテスト中心 | 本環境は macOS（`eth0` も AF_PACKET もなく E2E 不可）。kind での E2E は Phase 3 以降 |

## データフロー

```text
capture タスク
    │ mpsc<ParsedPacket> (既存)
    ▼
processor タスク (tokio::select! 単一ループ)
    ├─ packet arm ──▶ FlowKey生成 → table.update_flow → metrics
    │                    └ FIN/RST 検知時 → take_flow → 即 export
    └─ tick arm (1秒固定) ─▶ get_expired_flows → exporter → ログ出力
```

- sweep 間隔は固定1秒。設定項目を追加しない
- `FlowProcessor` は processor タスクが単独所有（`Arc` 不要）

## コンポーネント設計

### 1. sentinel-parser（拡張）

- `ParsedPacket` に `tcp_flags: Option<u8>` を追加。TCP のとき `TcpHeader.flags`、非TCPは `None`
- `Protocol::ip_number(&self) -> u8` を追加（Tcp=6, Udp=17, Icmp=1, Other(n)=n）— FlowKey 生成用

### 2. sentinel-flow（バグ修正 + 追加API）

**既存バグ**: `FlowEntry::new(true)` で常に forward 扱いとなり、リバースパケットも `packets_forward` に入る。

修正:

- テーブルキーは `FlowKey::canonical`（小さいIP側）に正規化し、往復を1エントリに集約
- 各パケットで「パケットの生キーと正規キーの向きが一致するか」を都度判定し、forward/reverse カウンタを加算
- `FlowEntry.is_forward` フィールドを削除し、`update(bytes, tcp_flags, is_forward: bool)` の引数で毎回判定
- `FlowTable::take_flow(&key)` を追加（FIN/RST 即export用。key は内部で正規化）
- `update_flow` 内部で canonical 正規化を実施（呼び出し側は生キーを渡す）

### 3. sentinel-sensor（新規 flow.rs）

```rust
pub struct FlowProcessor { table: FlowTable, exporter: FlowExporter, metrics: Arc<SensorMetrics> }

impl FlowProcessor {
    fn new(flow: &FlowConfig, sensor_node: String, metrics: Arc<SensorMetrics>) -> Self;
    fn on_packet(&mut self, pkt: &ParsedPacket);   // 集計 + FIN/RST即export
    fn sweep(&mut self) -> Vec<ExportedFlow>;       // 期限切れ回収。ログ出力は呼び出し側(main)の責務
}
```

- `sweep()` はログ副作用を持たず戻り値で返す — ユニットテストから直接検証可能
- `sensor_node`: 環境変数 `HOSTNAME`（K8sがPod名を設定）、なければ `"unknown"`
- `FlowTableConfig` は既存 `FlowConfig` から変換（設定追加なし）
- FIN/RST 即export は architecture.md §5.4 の設計要求どおり（half-close でも export し、以降のパケットは新エントリになる。MVP では許容）

### 4. main.rs 配線

```rust
let mut interval = tokio::time::interval(Duration::from_secs(1));
loop {
    tokio::select! {
        maybe = rx.recv() => match maybe {
            Some(p) => processor.on_packet(&p),
            None => break,  // capture終了 → 最終sweepへ
        },
        _ = interval.tick() => {
            for f in processor.sweep() { info!("flow_export: {:?}", f); }
        }
    }
}
// break 後: 最終sweepを1回実行して終了（Ctrl-C時のFlowロス防止）
```

- シャットダウン: `capture_handle.abort()` で tx が破棄され → `rx.recv()==None` → processor が最終 sweep 後に自然終了。`processor_handle` は abort せず await（タイムアウト付き）

## エラーハンドリング

| ケース | 処理 |
|---|---|
| `FlowError::TableFull` | `packets_dropped` カウント + debugログ（arch doc の既存メトリクスを再利用） |
| export | `info!("flow_export: {:?}")` — Phase 2 は可視性優先 |
| パースエラー | 既存の capture 側で処理済み（変更なし） |

## テスト戦略

| 対象 | テスト内容 |
|---|---|
| parser | 合成TCPバイト列で `tcp_flags` 抽出、非TCPで `None`、`Protocol::ip_number()` |
| flow table | 往復パケットで forward/reverse 正確カウント、canonical で1エントリ化、`take_flow` |
| FlowProcessor | on_packet でFlow増加、`inactive_timeout_secs=0` でsweepが即export、FIN/RST 即export、TableFull |

時間依存挙動は `inactive_timeout_secs=0`（`>= 0` ですぐ期限切れ）で sleep なしに検証する。

## 変更ファイル一覧

| ファイル | 種別 |
|---|---|
| `crates/sentinel-parser/src/packet.rs` | 編集（`tcp_flags`, `Protocol::ip_number`） |
| `crates/sentinel-parser/src/lib.rs` | 編集（parse時に flags をセット） |
| `crates/sentinel-flow/src/entry.rs` | 編集（`update` シグネチャ変更、`is_forward` 削除） |
| `crates/sentinel-flow/src/table.rs` | 編集（canonical正規化、`take_flow`） |
| `crates/sentinel-sensor/src/flow.rs` | 新規 |
| `crates/sentinel-sensor/src/main.rs` | 編集（select!配線、シャットダウン） |

Cargo.toml 変更なし。

## 検証コマンド

```bash
cargo nextest run --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```
