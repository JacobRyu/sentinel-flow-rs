# Phase 5: Detection — 設計spec

> **Status**: Approved
> **Date**: 2026-11-10
> **Scope**: architecture.md Roadmap Phase 5 のみ（MVP 8ルールのうちベースライン不要の4ルール）

## 目的

sensor プロセス内でエクスポート済み連続 flow (`ExportedFlow`) をルール評価し、 anomalous なイベント (unknown external destination、unexpected port、port/network scanning) を検知して ClickHouse `security_events` テーブルへイベントを書き込む。手動レビューではなく、アラートとして俯瞰可能な形にする。

**受入基準**

- 4ルール (EXT-001 / EXT-002 / SCAN-001 / SCAN-002) がそれぞれ定義どおり発火する
- 発火したイベントが `info!` ログ + ClickHouse `security_events` に書き込まれる
- `config/detection-rules.yaml` の設定が起動時にロードされ、無効ルールはスキップされる
- `detection.enabled: false` で既存挙動から一切の変化が無い（無効の場合は通信経路に検知を介さない）
- `cargo nextest run --workspace` が全件パスする

**非スコープ**

- VOL-001 / VOL-002 / CONN-001 / CONN-002（ベースライン依存ルール、ベースライン学習は将来作業）
- ClickHouse を読み出してのバッチ評価（別プロセス/別成分としての分離含む）
- `FlowSink` trait / Kafka 出力（Phase 6 で扱う）
- kubernetes metadata enrichment（Phase 7）
- ルールのリロード・HMR（起動時ロードのみ）
- リスクスコアリング・ML検知（Phase 8/10）

## 方針判断（brainstorming確定事項）

| 論点 | 決定 | 理由 |
|---|---|---|
| アプローチ | プロセス内・イベント駆動（processor 直結評価） | ClickHouse 読み出し競合（dashboard クエリ競合、§9.2 既知の限界）を回避。Kafka と etc. として登場は不要 |
| ルール数 | ベースライン不要の4ルールのみ | baseline 学習は将来スコープ、vol/conn は baseline 依存のため除外 |
| 出力先 | ClickHouse `security_events` + `info!` ログ | 既存 storage pipeline (Phase 3 df267e5) のパターン踏襲 |
| 設定 | センサー側独立 `config/detection-rules.yaml` | 保守性。sensor.yaml にルールを埋め込まない |
| ウィンドウ | メモリ内固定ウィンドウ（source IP 単位）、再起動でリセット | 許容。分散永続ウィンドウは不要 |
| 有効化失敗時 | 設定エラーは fail-fast（起動時に停止） | 起動時後に検知が silently down するリスク回避 |

## データフロー

```text
on_packet → Some(ExportedFlow) ─┐
sweep()   → Vec<ExportedFlow> ──┴→ processor select! ループ内で
     ┌──────────────────────────── DetectionEngine::evaluate(&ExportedFlow)
     │                                └→ Vec<SecurityEvent>
     │                             events_tx (mpsc, cap=1000) へ push
     │                             out_tx (既存フローチャネル) へも引き続き push
     └ events_rx ◀── EventWriter (select! loop)
                        └→ ClickHouse security_events
```

- `DetectionEngine` は processor タスクから1箇所・同期的に呼び出されるため `Arc`/ロック不要
- EventWriter は processor と独立した tokio task、既存 FlowWriter と同じ配線パターン
- 既存 ExportedFlow の security クリティカルフローには影響しない

## コンポーネント設計

### 1. sentinel-detection クレート

#### ルール表現

```rust
pub struct RuleDef {
    id: String,
    name: String,
    rule_type: RuleType,          // Stateless | Window
    severity: Severity,           // Low | Medium | High | Critical （不明値は起動エラー）
    confidence: f32,
    enabled: bool,
    condition: Option<String>,    // architecture.md 互換用フィールド。MVPでは未使用
}

pub enum RuleAction {   // 起動時に parameters から型付き compile
    UnknownExternalDestination,              // EXT-001 (allowlist参照)
    UnexpectedPort { expected: HashMap<String, Vec<u16>> },  // EXT-002
    PortScan { window_secs: u64, threshold: u64 },           // SCAN-001
    NetworkScan { window_secs: u64, threshold: u64 },        // SCAN-002
}

pub struct CompiledRule { def: RuleDef, action: RuleAction, tags: Vec<String>,
                          description: String, mitigation: Vec<String> }
```

- `Rule::check` / `DetectionEngine::check_flow` 等の現 skeleton (`rules.rs`/`engine.rs`) は Phase 5 対象に基づき再構築する（`ExportedFlow` 単発の bool 評価でなく、Window 状態管理を備えた `evaluate` に統一）。
- パラメータ欠落・型不整合・未知 severity・未知 rule_type は起動時エラー (fail-fast)。

#### ウィンドウ状態

```rust
pub struct ScanWindow {
    destination_ips: HashSet<IpAddr>,
    destination_ports: HashSet<u16>,
    first_seen: Instant,
    fired: bool,       // 一度発火したら reset まで再発火しない
}
// DetectionEngine 内: HashMap<IpAddr /*source*/, ScanWindow>
```

- `evaluate(&ExportedFlow)` のたびに該当送信元IPウィンドウへ `(dst_ip, dst_port)` を追加
- プルーニング: `first_seen + window_secs <= now` のウィンドウを評価時に削除（アクティブでない場合も評価を通じて枯れる。バックグラウンドtask不要）
- 発火条件: SCAN-001 = `destination_ports.len() > threshold`、SCAN-002 = `destination_ips.len() > threshold`
- 重複アラート抑止: `fired: true` になったら同一ウィンドウ内で再発火しない
- 再起動で状態破棄（合意済み許容）

#### SecurityEvent

```rust
pub struct SecurityEvent {
    event_id: Uuid,
    timestamp: DateTime<Utc>,
    rule_id: String,
    rule_name: String,
    event_type: String,     // 例 "port_scanning"
    severity: Severity,
    confidence: f32,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    destination_port: u16,
    protocol: String,
    description: String,   // YAML rule の description テンプレートを threshold/window 値で埋める
    tags: Vec<String>,
    mitigation_suggestions: Vec<String>,
}
```

- `source_flow_ids`: MVP では空 `Array(UUID)`（FlowRow ↔ SecurityEvent 相関の解決は Phase 7 metadata強化とともに見直し）
- kubernetes metadata (source_pod 等) は Phase 3 の network_flows 前例と同様にカラム自体を Phase 7 まで追加しない（その時点で ALTER TABLE する）。

#### DetectionEngine

```rust
pub struct DetectionEngine {
    allowlist: Allowlist,          // external_ips: Vec<IpNet> (CIDR)
    private_ranges: Allowlist,     // RFC1918 + RFC4193 + loopback + link-local 静的
    rules: Vec<CompiledRule>,
    windows: HashMap<IpAddr, ScanWindow>,
}

impl DetectionEngine {
    pub fn load(path: &Path) -> Result<Self, DetectionError>;  // YAMLロード + compile + fail-fast
    pub fn evaluate(&mut self, flow: &ExportedFlow) -> Vec<SecurityEvent>;
}
```

- EXT-001: `dst_ip` が `allowlist.external_ips` に含まれない ∧ `private_ranges` に含まれない → High / confidence (YAML)
- EXT-002: MVP では k8s metadata が無いため、`source_service` の代わりに**送信元ポート番号（文字列キー）**を YAML `service_expected_ports` のキーと照合する。 送信元ポートが予約・登録ポート (1–1023) 以外 (特にエフェメラル範囲) の場合はクライアント起因フローとみなして **skip**（ノイズ防止）。 キーに一致した service の expected port リストに `dst_port` が含まれない → Medium
- `enabled: false` ルールは読み込むが評価 skip。

### 2. main.rs / flow.rs 配線

```rust
// 設定ロード:
if config.detection.enabled {
    let detection_engine = DetectionEngine::load(&config.detection.rules_path)?;
    // Arc 不使用: engine は processor タスクが単一所有する
    let (events_tx, events_rx) = mpsc::channel(config.detection.event_channel_capacity);
    let event_store = ClickHouseEventStore::new(&config.output)?;
    let event_writer = EventWriter::new(events_rx, event_store, ...);
    tokio::spawn(event_writer.run());
    // processor に detection_engine を渡す（processor タスクが単一所有者、Arc 不使用）
}
```

- processor の on_packet/sweep 実行後に `DetectionEngine::evaluate` を呼び出し、イベントを events_tx へ。`info!` ログにも出力
- 既存 flow 出力 (out_tx → FlowWriter → ClickHouse flows) と完全に並行
- `detection.enabled: false` の場合、events チャネル・Engine・writer は生成されない（既存パスのみ）

### 3. EventWriter

- 既存 FlowWriter と同じ select! ループ構造を継承 (batch buffer / flush interval / MAX_RETRIES=3 / RETRY_BACKOFF / WRITE_TIMEOUT=2s)
- 実装は MVP では flow writer とは分離（Task: `Writer<I,S>` 系のジェネリクス化はこのフェーズで行わない。Phase 6 Kafka の際の一般化とセットで検討）
- シャットダウン: processor 完了 → events_tx drop → ChannelClosed → drain → 終了（同じ headroom パターン 801593f に準拠）

### 4. config/detection-rules.yaml (新規)

```yaml
allowlist:
  external_ips:            # EXT-001: ここに含まれる宛先は「既知」扱い
    - "203.0.113.10"
    - "198.51.100.0/24"    # CIDR 記法を許可

rules:
  - id: EXT-001
    name: unknown_external_destination
    rule_type: stateless
    severity: high
    confidence: 0.8
    enabled: true
    parameters:
      description: "Unknown external destination"
      tags: ["outbound"]
      mitigation_suggestions:
        - "Verify destination legitimacy with the user."

  - id: EXT-002
    name: unexpected_port
    rule_type: stateless
    severity: medium
    confidence: 0.8
    enabled: true
    parameters:
      service_expected_ports:
        "8080": [443, 80]   # key = 送信元ポート番号。ローカル8080サービスは 443/80 へのみ許容
      description: "Unexpected destination port for local service on source port 8080."
      tags: ["outbound"]
      mitigation_suggestions:
        - "Verify the destination service is expected for this local service."

  - id: SCAN-001
    name: port_scanning
    rule_type: window
    severity: critical
    confidence: 0.9
    enabled: true
    parameters:
      window_secs: 60
      threshold: 50       # distinct destination_port 数
      description: "Port scanning detected: over {threshold} distinct ports in {window_secs}s."
      tags: ["scan", "outbound"]
      mitigation_suggestions:
        - "Verify source host activity; block or rate-limit if unauthorized."

  - id: SCAN-002
    name: network_scanning
    rule_type: window
    severity: critical
    confidence: 0.9
    enabled: true
    parameters:
      window_secs: 60
      threshold: 20       # distinct destination_ip 数
      description: "Network scanning detected: over {threshold} distinct destinations in {window_secs}s."
      tags: ["scan", "outbound"]
      mitigation_suggestions:
        - "Verify source host activity; block or rate-limit if unauthorized."
```

- severity / rule_type / confidence は型付き enum で検証（未知の severity は起動時エラー）
- 必須 parameters の欠落・型不整合も起動時 fail-fast

### 5. sensor.yaml 拡張 section（新規）

```yaml
detection:
  enabled: true
  rules_path: "config/detection-rules.yaml"   # 既定値
  event_channel_capacity: 1000
```

- `enabled: false` → 通信経路から detection 関連材料を全く生成しない
- rules ファイル不在 / parse error / パラメータ variants 亀裂も起動時 fail-fast

### 6. ClickHouse DDL (新規 migration)

- `security_events` テーブルを architecture.md §7.4 の DDL どおりで作成（既存 flows 用マイグレーションの方式に合わせる）
- key: `PARTITION BY toYYYYMM(timestamp)`, `ORDER BY (event_type, severity, timestamp)`, `TTL 365d`
- IPv6 型 (ip columns)、severity Enum8。	source_pod は含めない（Task 0-1 と同じ理由）。MergeTree()/LowCardinality 非使用は network_flows と同じ deliberate difference。

### 7. メトリクス (sentinel-sensor/src/metrics.rs)

| メトリクス | 説明 |
|---|---|
| `sentinel_detection_events_total{rule_id=}` | 発火イベント数 (rule_id label) |
| `sentinel_detection_windows_active` | SCAN ウィンドウの現在の source IP 数 (gauge) |
| `sentinel_detection_failed_writes_total` | 書き込み失敗回数 (writer retry 経過で増加) |
| sentinel_detection_events_written_total | security_events への書込成功行数 (writer) |

## エラーハンドリング

| ケース | 処理 |
|---|---|
| YAML ロード・パース・パラメータ無効 | 起動時 fail-fast（sensor 終了） |
| Severity / rule_type 未知値 | 起動時 fail-fast |
| 発火したが ClickHouse 書き込み失敗 | retry (3 回) → メトリクス++ + error ログ、イベントは drop（プロセスは継続） |
| 発火条件に合致しないフロー | 何もせず（既存 flow 出力のみ継続） |

## テスト戦略（TDD red→green）

| 対象 | テスト内容 |
|---|---|
| EXT-001 | allowlist 内 dst → no-op / private ranges → no-op / 未知外部 → Event 発火 |
| EXT-002 | expected port → no-op / 未使用 port → Event 発火 / 送信元ポートがマップに無い・エフェメラル範囲 → skip |
| SCAN-001/002 | 閾値未満 → no-op / 超過 → Event / window 経過後 reset / fired で再発火しない |
| DetectionEngine | 複数ルール同時発火で複数 Event 返却 / 無効ルール skip / allowlist 併用 |
| YAML ロード | 正常 YAML ロード / 必須パラメータ欠落 / 未知 severity / CIDR parse / enabled=false skip |
| 配線 (sensor) | `detection.enabled=false` で E2E を乱さない、processor → events channel へイベント通常輸送 |

- ClickHouse 実接続テストなし（Store trait モックで writer 挙動を検証、既存パターン踏襲）

## 変更ファイル一覧

| ファイル | 種別 |
|---|---|
| `crates/sentinel-detection/src/lib.rs` | 再構築（SecurityEvent / DetectionEngine 再エクスポート） |
| `crates/sentinel-detection/src/engine.rs` | 再構築（Windows 管理 + evaluate） |
| `crates/sentinel-detection/src/rules.rs` | 再構築（RuleDef / RuleAction / compiled rule / YAML parse） |
| `crates/sentinel-detection/src/event.rs` | 新規（SecurityEvent 型 + ClickHouse 行変換） |
| `crates/sentinel-flow/src/...` | 編集なし |
| `crates/sentinel-sensor/src/main.rs` | 編集（detection section 読み込み・配線、writer spawn） |
| `crates/sentinel-sensor/src/output/...` | 編集（event_row.rs / event_store.rs / event_writer.rs を追加、mod.rs 経由で公開） |
| `crates/sentinel-sensor/src/metrics.rs` | 編集（4メトリクス追加） |
| `crates/sentinel-sensor/src/config.rs` | 編集（detection section パース・検証） |
| `config/detection-rules.yaml` | 新規 |
| `config/sensor.yaml` | 編集（detection section） |
| （なし） | security_events DDL は起動時 ensure_schema で作成（network_flows と同じ方式） |

## 検証コマンド

```bash
cargo nextest run --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```
