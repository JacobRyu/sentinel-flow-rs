# Phase 5 Detection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** センサープロセス内でエクスポート済み flow (`ExportedFlow`) を 4 ルールで同期的に評価し、検知イベントを ClickHouse `security_events` テーブルへ書き込む（`info!` ログ併用）。

**Architecture:** イベント駆動。processor の select! ループが各エクスポート点で `DetectionEngine::evaluate(&ExportedFlow)` を同期的に呼ぶ。イベントは専用 mpsc チャネルを経由して `EventWriter`（既存 `FlowWriter` と同じバッチ/リトライ/タイムアウト パターン）へ流れ、`ClickHouseEventStore` が `security_events` に書き込む。ルール定義と外部 IP allowlist は `config/detection-rules.yaml` に置き、起動時に fail-fast ロードする。

**Tech Stack:** Rust 2024 workspace / tokio / serde_yaml / thiserror / prometheus / clickhouse crate (RowBinary) / chrono / uuid / cargo nextest

**Spec:** `docs/superpowers/specs/2026-11-10-phase5-detection-design.md` — 本 plan は spec に基づく。executor は両方を読むこと。

## Global Constraints

- ブランチ: `develop`。Conventional Commits (`feat:`/`docs:`)、AI 属性メタデータ禁止。
- 各タスク完了時に `cargo nextest run --workspace` 全緑をコミット前の必須条件とする。
- Lint バー: `cargo clippy --workspace --all-targets --all-features -- -D warnings`、`cargo fmt --all -- --check`（rustfmt `max_width = 100`、`use_small_heuristics = Max`）。
- テストは `#[cfg(test)] mod tests` で同居、TDD red→green。単一テストは `cargo nextest <name>`。
- 環境は macOS で datalink capture 不可: ライブキャプチャの E2E は不可。ClickHouse 統合テストは既存の probe-and-skip 形式（`crates/sentinel-sensor/src/output/clickhouse.rs` の `clickhouse_available` / `REQUIRE_CLICKHOUSE` と同じ）を踏襲。
- コミットフックは `cargo fmt`/`check`/`clippy`/`deny check`/空白 fixer を自動実行する（deny のため依存追加時は `[licenses]` 許可リスト確認）。

## Type map（タスク横断の型契約 — 各タスク実装者がこのシグネチャに従う）

```rust
// crates/sentinel-detection/src/rules.rs (Task 1)
pub enum Severity { Low, Medium, High, Critical }        // #[serde(rename_all = "lowercase")]
impl Severity { pub fn code(self) -> i8; pub fn as_str(self) -> &'static str; } // impl Display
pub enum RuleType { Stateless, Window }                   // as_str() -> "stateless" | "window"
pub struct RuleConfig { id: String, name: String, rule_type: RuleType, severity: Severity,
    confidence: f32, enabled: bool /* serde default true */, condition: Option<String> /* serde default */,
    parameters: serde_json::Map<String, serde_json::Value> /* serde default */ }
pub enum RuleParameters {        // 型付きコンパイル済みパラメータ
    UnknownExternalDestination,
    UnexpectedPort { ports_by_source: HashMap<u16, Vec<u16>> },
    PortScan { window_secs: u64, threshold: u64 },
    NetworkScan { window_secs: u64, threshold: u64 },
}
pub struct CompiledRule { id: String, name: String, severity: Severity, confidence: f32, enabled: bool,
    action: RuleParameters, description_template: String, tags: Vec<String>, mitigation_suggestions: Vec<String> }
pub fn compile(config: RuleConfig) -> Result<CompiledRule, DetectionConfigError>;
pub struct CidrRange { /* network/mask/v4 */ }
impl CidrRange { pub fn parse(entry: &str) -> Result<Self, DetectionConfigError>; pub fn contains(self, ip: IpAddr) -> bool; }
pub(crate) fn private_ranges() -> Vec<CidrRange>;
pub(crate) fn load_rules(path: &Path) -> Result<(Vec<CidrRange>, Vec<CompiledRule>), DetectionConfigError>;
pub enum DetectionConfigError {   // thiserror
    FileRead { path: String, source: std::io::Error }, Yaml(#[from] serde_yaml::Error),
    UnknownRuleId(String), RuleTypeMismatch { id: String, expected: &'static str, got: &'static str },
    MissingParameter { id: String, name: &'static str },
    InvalidParameter { id: String, name: &'static str, reason: String },
    ConfidenceOutOfRange { id: String, value: f32 },
    InvalidAllowlistEntry { entry: String, reason: String },
}

// crates/sentinel-detection/src/event.rs (Task 2)
pub struct SecurityEvent { event_id: Uuid, timestamp: DateTime<Utc>, rule_id: String, rule_name: String,
    event_type: String, severity: Severity, confidence: f32, source_ip: IpAddr, destination_ip: IpAddr,
    destination_port: u16, protocol: String, description: String, tags: Vec<String>, mitigation_suggestions: Vec<String> } // 全フィールド pub
pub(crate) fn build_event(rule_id: &str, rule_name: &str, severity: Severity, confidence: f32,
    source_ip: IpAddr, destination_ip: IpAddr, destination_port: u16, protocol: &str,
    description: String, tags: Vec<String>, mitigation_suggestions: Vec<String>) -> SecurityEvent;
pub(crate) fn fill_template(template: &str, values: &[(&str, u64)]) -> String;

// crates/sentinel-detection/src/engine.rs (Task 3/4)
impl DetectionEngine {
    pub fn new(allowlist: Vec<String>, rules: Vec<RuleConfig>) -> Result<Self, DetectionConfigError>;
    pub fn load(path: &Path) -> Result<Self, DetectionConfigError>;  // YAML + compile + fail-fast
    pub fn evaluate(&mut self, flow: &ExportedFlow) -> Vec<SecurityEvent>;
    pub fn rule_count(&self) -> usize;
    pub fn active_windows(&self) -> usize;
}

// 最終 lib.rs exports (Task 4 時点)
pub mod engine; pub mod event; pub mod rules;
pub use engine::DetectionEngine;
pub use event::SecurityEvent;
pub use rules::{CompiledRule, CidrRange, DetectionConfigError, RuleConfig, RuleParameters, RuleType, Severity};

// crates/sentinel-sensor/src/output/event_row.rs (Task 6)
pub struct EventRow { /* clickhouse_row; 下記 Task 6 参照 */ }
impl From<&SecurityEvent> for EventRow; // 変換は infallible

// crates/sentinel-sensor/src/output/event_store.rs (Task 7)
#[async_trait] pub trait EventStore: Send {
    type Error: std::fmt::Display + Send + Sync + 'static;
    async fn write_batch(&mut self, rows: &[EventRow]) -> Result<(), Self::Error>;
}
pub struct ClickHouseEventStore { /* admin, client, database, schema_ready */ }
impl ClickHouseEventStore { pub fn new(config: &OutputConfig) -> Self; }  // 失敗しない (Client 構築のみ)

// crates/sentinel-sensor/src/output/event_writer.rs (Task 8)
impl EventWriter<S: EventStore> {
    pub fn new(rx: Receiver<SecurityEvent>, store: S, batch_size: usize, batch_timeout: Duration,
        write_timeout: Duration, metrics: Arc<SensorMetrics>) -> Self;
    pub async fn run(self) -> S;  // チャネル切断で残余フラッシュ後 store を返す
}

// metrics.rs 追加フィールド (Task 8)
pub detection_events_total: IntCounterVec,         // labels ["rule_id"]
pub detection_windows_active: IntGauge,
pub detection_events_written: IntCounter,
pub detection_failed_writes_total: IntCounter,
```

---

### Task 0: spec 同期（計画作成中に確定した実装詳細の反映）

**Files:**
- Modify: `docs/superpowers/specs/2026-11-10-phase5-detection-design.md`

**Interfaces:**
- Consumes: なし
- Produces: 以下の箇所が削除された spec（実装タスクの根拠として一貫するドキュメント）

- [ ] **Step 1: spec の 5 か所を編集**

1. §2 SecurityEvent 箇条書き `kubernetes metadata (source_pod 等) ...` を次へ置換（network_flows 前例と揃える。column 自体を Phase 7 に追加）:
   `- kubernetes metadata (source_pod 等) は Phase 3 の network_flows 前例と同様にカラム自体を Phase 7 まで追加しない（その時点で ALTER TABLE する）。`
2. §6 DDL 箇条書き（`IPv6 型 ... Enum8` の行）を次へ置換:
   `- IPv6 型 (ip columns)、severity Enum8。	source_pod は含めない（Task 0-1 と同じ理由）。MergeTree()/LowCardinality 非使用は network_flows と同じ deliberate difference。`
3. `### 3. SecurityEventWriter` 見出しと本文中の `SecurityEventWriter` を 2 か所とも `EventWriter` に置換（実装は既存 FlowWriter の mirror、名前を揃える）。
4. 変更ファイル一覧テーブルの `crates/sentinel-sensor/src/flow.rs` 行を削除（evaluate 呼出しは main.rs の processor タスク内。flow.rs への変更はない）。
5. メトリクステーブルに 1 行追加:
   `| sentinel_detection_events_written_total | security_events への書込成功行数 (writer) |`

- [ ] **Step 2: 確認**

`grep -n "SecurityEventWriter\|source_pod" docs/superpowers/specs/2026-11-10-phase5-detection-design.md` がヒットしないこと（§2 の SecurityEvent 型定義自体の出現は除く）。

- [ ] **Step 3: Commit**

```bash
git add docs/superpowers/specs/2026-11-10-phase5-detection-design.md
git commit -m "docs: sync detection spec details with implementation plan"
```

---

### Task 1: sentinel-detection — ルール型・CIDR allowlist・コンパイル

**Files:**
- Modify: `crates/sentinel-detection/src/rules.rs`（全置換: 現行 46 行を下記で書き換え）
- Modify: `crates/sentinel-detection/src/engine.rs`（型付け前の撤去状態へ）
- Modify: `crates/sentinel-detection/src/lib.rs`
- Test: `#[cfg(test)] mod tests` 内（rules.rs 同居）

**Interfaces:**
- Consumes: `ExportedFlow`（crates/sentinel-flow、依存済み）、`serde_yaml`/`serde_json`/`thiserror`
- Produces: Type map §rules.rs の全型。Task 3 が `compile`, `load_rules`, `CidrRange::parse/contains`, `private_ranges`, `DetectionConfigError` を利用する。

注意: 現行の `Rule::check`（TODO を返す bool）とそのままの `Rule` ラッパーは削除。旧 `RuleConfig` は削除して型付きバージョンへ置換。旧 `rule_type: String` / `severity: String` フィールドは型付き enum で置換（未知の文字列は YAML アンパック時にエラーで fail-fast、デシリアライズ自体に任せる）。

- [ ] **Step 1: 失敗するテストを書く**

`crates/sentinel-detection/src/rules.rs` の末尾に下記 `#[cfg(test)] mod tests` をそのまま記述（実装は未着手のため、この時点で型未定義のコンパイルエラー=赤になる。Red フェーズは型が無い状態での検証失敗を期待する）:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn rule_config(id: &str, rule_type: RuleType, severity: Severity, confidence: f32) -> RuleConfig {
        RuleConfig {
            id: id.to_string(),
            name: "untested".to_string(),
            rule_type,
            severity,
            confidence,
            enabled: true,
            condition: None,
            parameters: serde_json::Map::new(),
        }
    }

    #[test]
    fn severity_parses_and_serializes_lowercase() {
        let severity: Severity = serde_yaml::from_str("critical").unwrap();
        assert_eq!(severity, Severity::Critical);
        assert_eq!(serde_yaml::to_string(&Severity::Medium).unwrap().trim(), "medium");
    }

    #[test]
    fn severity_tags_match_clickhouse_enum8() {
        assert_eq!(Severity::Low.code(), 1);
        assert_eq!(Severity::Medium.code(), 2);
        assert_eq!(Severity::High.code(), 3);
        assert_eq!(Severity::Critical.code(), 4);
        assert_eq!(Severity::Low.as_str(), "low");
        assert_eq!(Severity::Critical.to_string(), "critical");
    }

    #[test]
    fn rule_type_parses() {
        let stateless: RuleType = serde_yaml::from_str("stateless").unwrap();
        let window: RuleType = serde_yaml::from_str("window").unwrap();
        assert_eq!(stateless, RuleType::Stateless);
        assert_eq!(window, RuleType::Window);
        assert_eq!(serde_yaml::from_str::<RuleType>("threshold").unwrap_err().to_string(), "unknown variant `threshold`");
    }

    #[test]
    fn cidr_range_parses_exact_and_cidr() {
        let exact = CidrRange::parse("203.0.113.10").unwrap();
        assert!(exact.contains("203.0.113.10".parse().unwrap()));
        assert!(!exact.contains("203.0.113.11".parse().unwrap()));

        let cidr = CidrRange::parse("198.51.100.0/24").unwrap();
        assert!(cidr.contains("198.51.100.7".parse().unwrap()));
        assert!(!cidr.contains("198.51.101.7".parse().unwrap()));
    }

    #[test]
    fn cidr_range_v6_and_family_mismatch() {
        let range = CidrRange::parse("2001:db8::/32").unwrap();
        assert!(range.contains("2001:db8:1234::1".parse().unwrap()));
        assert!(!range.contains("2001:db9::1".parse().unwrap()));
        assert!(!range.contains("10.0.0.1".parse().unwrap())); // family mismatch
    }

    #[test]
    fn cidr_range_rejects_garbage() {
        assert!(CidrRange::parse("203.0.113.10/33").is_err());
        assert!(CidrRange::parse("nope").is_err());
        assert!(CidrRange::parse("2001:db8::/200").is_err());
        assert!(CidrRange::parse("10.0.0.0/8/more").is_err());
    }

    #[test]
    fn private_ranges_cover_both_families() {
        let ranges = private_ranges();
        let is_private = |ip: IpAddr| ranges.iter().any(|range| range.contains(ip));
        assert!(is_private("10.0.0.1".parse().unwrap()));
        assert!(is_private("192.168.5.5".parse().unwrap()));
        assert!(is_private("172.16.0.9".parse().unwrap()));
        assert!(is_private("127.0.0.1".parse().unwrap()));
        assert!(is_private("169.254.1.1".parse().unwrap()));
        assert!(is_private("fd00::1".parse().unwrap()));
        assert!(is_private("::1".parse().unwrap()));
        assert!(is_private("fe80::1".parse().unwrap()));
        assert!(!is_private("8.8.8.8".parse().unwrap()));
        assert!(!is_private("203.0.113.10".parse().unwrap()));
    }

    #[test]
    fn compile_ext001_minimal() {
        let rule = compile(rule_config("EXT-001", RuleType::Stateless, Severity::High, 0.8)).unwrap();
        assert!(rule.enabled);
        assert!(matches!(rule.action, RuleParameters::UnknownExternalDestination));
        assert!(rule.description_template.is_empty());
    }

    #[test]
    fn compile_ext002_builds_port_map() {
        let mut config = rule_config("EXT-002", RuleType::Stateless, Severity::Medium, 0.8);
        config.parameters = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
            r#"{"service_expected_ports": {"8080": [443, 80]}}"#,
        ).unwrap();
        let rule = compile(config).unwrap();
        let RuleParameters::UnexpectedPort { ports_by_source } = rule.action else {
            panic!("wrong action type: {:?}", rule.action);
        };
        assert_eq!(ports_by_source.get(&8080).unwrap(), &vec![443, 80]);
    }

    #[test]
    fn compile_rejects_bad_ext002_payloads() {
        // key must be a port number
        let mut config = rule_config("EXT-002", RuleType::Stateless, Severity::Medium, 0.8);
        config.parameters = serde_json::from_str(r#"{"service_expected_ports": {"http": [443]}}"#).unwrap();
        let err = compile(config).unwrap_err();
        assert!(matches!(err, DetectionConfigError::InvalidParameter { name: "service_expected_ports", .. }));

        // list items must be valid u16 ports
        let mut config = rule_config("EXT-002", RuleType::Stateless, Severity::Medium, 0.8);
        config.parameters = serde_json::from_str(r#"{"service_expected_ports": {"8080": [443, 70000]}}"#).unwrap();
        let err = compile(config).unwrap_err();
        assert!(matches!(err, DetectionConfigError::InvalidParameter { name: "service_expected_ports", .. }));
    }

    #[test]
    fn compile_scan_requires_window_and_threshold() {
        let mut config = rule_config("SCAN-001", RuleType::Window, Severity::Critical, 0.9);
        assert!(matches!(
            compile(config.clone()).unwrap_err(),
            DetectionConfigError::MissingParameter { name: "window_secs", .. }
        ));

        config.parameters = serde_json::from_str(r#"{"window_secs": 60}"#).unwrap();
        assert!(matches!(
            compile(config.clone()).unwrap_err(),
            DetectionConfigError::MissingParameter { name: "threshold", .. }
        ));

        config.parameters = serde_json::from_str(r#"{"window_secs": 60, "threshold": 0}"#).unwrap();
        assert!(matches!(
            compile(config).unwrap_err(),
            DetectionConfigError::InvalidParameter { name: "threshold", .. }
        ));
    }

    #[test]
    fn compile_scan002_parses_params_to_networkscan() {
        let mut config = rule_config("SCAN-002", RuleType::Window, Severity::Critical, 0.9);
        config.parameters = serde_json::from_str(r#"{"window_secs": 60, "threshold": 20}"#).unwrap();
        let rule = compile(config).unwrap();
        assert_eq!(rule.action, RuleParameters::NetworkScan { window_secs: 60, threshold: 20 });
    }

    #[test]
    fn compile_enforces_expected_rule_type_and_known_ids() {
        let err = compile(rule_config("SCAN-001", RuleType::Stateless, Severity::Critical, 0.9))
            .unwrap_err();
        assert!(matches!(
            err,
            DetectionConfigError::RuleTypeMismatch { expected: "window", got: "stateless", .. }
        ));

        let err = compile(rule_config("EXT-999", RuleType::Stateless, Severity::High, 0.8)).unwrap_err();
        assert!(matches!(err, DetectionConfigError::UnknownRuleId(id) if id == "EXT-999"));
    }

    #[test]
    fn compile_rejects_out_of_range_confidence() {
        let err = compile(rule_config("EXT-001", RuleType::Stateless, Severity::High, 1.5)).unwrap_err();
        assert!(matches!(err, DetectionConfigError::ConfidenceOutOfRange { value, .. } if value == 1.5));
    }

    const SAMPLE_RULES_YAML: &str = r#"
allowlist:
  external_ips:
    - "203.0.113.10"
    - "198.51.100.0/24"

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
        "8080": [443, 80]
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
      threshold: 50
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
      threshold: 20
      description: "Network scanning detected: over {threshold} distinct destinations in {window_secs}s."
      tags: ["scan", "outbound"]
      mitigation_suggestions:
        - "Verify source host activity; block or rate-limit if unauthorized."
"#;

    #[test]
    fn load_rules_parses_sample_document() {
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!("sentinel-rules-{}.yaml", std::process::id()));
        std::fs::write(&path, SAMPLE_RULES_YAML).unwrap();
        let (allowlist, rules) = load_rules(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(allowlist.len(), 2);
        assert_eq!(rules.len(), 4);
        assert_eq!(rules[0].id, "EXT-001");
        assert_eq!(rules[2].action, RuleParameters::PortScan { window_secs: 60, threshold: 50 });
    }

    #[test]
    fn load_rules_missing_file_is_file_read() {
        let err = load_rules(Path::new("/nonexistent/sentinel-detection-rules.yaml")).unwrap_err();
        assert!(matches!(err, DetectionConfigError::FileRead { .. }));
    }

    #[test]
    fn load_rules_invalid_allowlist_entry_is_invalid_entry() {
        let yaml = "allowlist:\n  external_ips: [ \"not a host\" ]\nrules: []\n";
        let temp_dir = std::env::temp_dir();
        let path = temp_dir.join(format!("sentinel-rules-bad-{}.yaml", std::process::id()));
        std::fs::write(&path, yaml).unwrap();
        let err = load_rules(&path).unwrap_err();
        std::fs::remove_file(&path).unwrap();
        assert!(matches!(err, DetectionConfigError::InvalidAllowlistEntry { .. }));
    }

    #[test]
    fn rule_config_defaults_apply() {
        let config: RuleConfig = serde_yaml::from_str(
            "id: EXT-001\nname: unknown_external_destination\nrule_type: stateless\nseverity: high\nconfidence: 0.8\n",
        ).unwrap();
        assert!(config.enabled);
        assert_eq!(config.condition, None);
        assert!(config.parameters.is_empty());
    }
}
```

- [ ] **Step 2: テストが失敗（赤）を確認**

```bash
cargo nextest -p sentinel-detection 2>&1 | tail -5
```
期待: 型未定義によるコンパイルエラー（`Severity`, `RuleType`, `CidrRange`, `compile`, `private_ranges`, `load_rules` が解決できず FAIL）。

- [ ] **Step 3: 実装以下を記述 (`rules.rs` 全体の置換コード)**

注意: `Rule::check` は「flow 単発の bool 評価」で window 管理に対応しないため廃止する。engine.rs が `DetectionEngine` の本体になり、rules.rs は設定/コンパイルの責務へ寄せる。

`rules.rs` 実装部（tests はそのまま・このパスでは置換全体を書き換え）:

```rust
//! ルール設定の型とコンパイル（YAML → 検証済み CompiledRule）。

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use serde::Deserialize;
use serde_json::{Map, Value};
use thiserror::Error;

/// イベントの重要度4段階。
/// code() は ClickHouse Enum8('low'=1,...'critical'=4) のタグ値。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn code(self) -> i8 {
        match self {
            Self::Low => 1,
            Self::Medium => 2,
            Self::High => 3,
            Self::Critical => 4,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// ルール種別。stateless = フローごと単発評価、window = 時間窓アキュムレータ付き評価。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleType {
    Stateless,
    Window,
}

impl RuleType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Stateless => "stateless",
            Self::Window => "window",
        }
    }
}

impl fmt::Display for RuleType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// YAML のルール定義（未検証）。as-is で受けて compile() でチェックする。
#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub id: String,
    pub name: String,
    pub rule_type: RuleType,
    pub severity: Severity,
    pub confidence: f32,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default)]
    pub condition: Option<String>,
    #[serde(default)]
    pub parameters: Map<String, Value>,
}

fn default_enabled() -> bool {
    true
}

/// 検証済みの型付きパラメータ。ルール評価 enum は match で対応する。
#[derive(Debug, Clone, PartialEq)]
pub enum RuleParameters {
    UnknownExternalDestination,                       // EXT-001
    UnexpectedPort { ports_by_source: HashMap<u16, Vec<u16>> }, // EXT-002: source port → 期待ポート群
    PortScan { window_secs: u64, threshold: u64 },    // SCAN-001: distinct destination_ports
    NetworkScan { window_secs: u64, threshold: u64 }, // SCAN-002: distinct destination_ips
}

/// YAML から検証・コンパイル済みのルール。
#[derive(Debug, Clone, PartialEq)]
pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub severity: Severity,
    pub confidence: f32,
    pub enabled: bool,
    pub action: RuleParameters,
    pub description_template: String,
    pub tags: Vec<String>,
    pub mitigation_suggestions: Vec<String>,
}

/// 設定ロード/コンパイル系のエラー。すべて起動時 fail-fast 対象。
#[derive(Debug, Error)]
pub enum DetectionConfigError {
    #[error("failed to read rules file {path}: {source}")]
    FileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error(transparent)]
    Yaml(#[from] serde_yaml::Error),

    #[error("unknown rule id `{0}` (expected EXT-001, EXT-002, SCAN-001, or SCAN-002)")]
    UnknownRuleId(String),

    #[error("rule {id}: expected rule_type `{expected}`, got `{got}`")]
    RuleTypeMismatch {
        id: String,
        expected: &'static str,
        got: &'static str,
    },

    #[error("rule {id}: missing required parameter `{name}`")]
    MissingParameter {
        id: String,
        name: &'static str,
    },

    #[error("rule {id}: invalid parameter `{name}`: {reason}")]
    InvalidParameter {
        id: String,
        name: &'static str,
        reason: String,
    },

    #[error("rule {id}: confidence {value} is not in 0.0..=1.0")]
    ConfidenceOutOfRange {
        id: String,
        value: f32,
    },

    #[error("invalid allowlist entry `{entry}`: {reason}")]
    InvalidAllowlistEntry {
        entry: String,
        reason: String,
    },
}

/// ``ExtConfig`` 系の各ルール id と rule_type を固定にして検証に通す。
fn expect_rule_type(id: &str, got: RuleType, want: RuleType) -> Result<(), DetectionConfigError> {
    if got == want {
        Ok(())
    } else {
        Err(DetectionConfigError::RuleTypeMismatch {
            id: id.to_string(),
            expected: want.as_str(),
            got: got.as_str(),
        })
    }
}

///
/// 1 つの RuleConfig を検証・型付き CompiledRule へコンパイルする。
/// unknown id / rule_type 不整合 / 必須パラメータ欠落 / confidence 範囲外はすべてエラー。
pub fn compile(config: RuleConfig) -> Result<CompiledRule, DetectionConfigError> {
    let RuleConfig {
        id,
        name,
        rule_type,
        severity,
        confidence,
        enabled,
        condition: _,
        parameters,
    } = config;
    if !(0.0..=1.0).contains(&confidence) {
        return Err(DetectionConfigError::ConfidenceOutOfRange { id: id.clone(), value: confidence });
    }

    let action = match id.as_str() {
        "EXT-001" => {
            expect_rule_type(&id, rule_type, RuleType::Stateless)?;
            RuleParameters::UnknownExternalDestination
        }
        "EXT-002" => {
            expect_rule_type(&id, rule_type, RuleType::Stateless)?;
            RuleParameters::UnexpectedPort {
                ports_by_source: extract_ports_map(&id, &parameters)?,
            }
        }
        "SCAN-001" => {
            expect_rule_type(&id, rule_type, RuleType::Window)?;
            let (window_secs, threshold, _) = extract_window_params(&id, &parameters, "distinct destination ports")?;
            RuleParameters::PortScan { window_secs, threshold }
        }
        "SCAN-002" => {
            expect_rule_type(&id, rule_type, RuleType::Window)?;
            let (window_secs, threshold, _) = extract_window_params(&id, &parameters, "distinct destination IPs")?;
            RuleParameters::NetworkScan { window_secs, threshold }
        }
        _ => return Err(DetectionConfigError::UnknownRuleId(id)),
    };

    let description_template = string_param(&parameters, "description").unwrap_or_default().to_string();
    let tags = string_list(&parameters, "tags");
    let mitigation_suggestions = string_list(&parameters, "mitigation_suggestions");

    Ok(CompiledRule {
        id,
        name,
        severity,
        confidence,
        enabled,
        action,
        description_template,
        tags,
        mitigation_suggestions,
    })
}

/// parameters から service_expected_ports 地図を抽出し検証する。
fn extract_ports_map(
    id: &str,
    parameters: &Map<String, Value>,
) -> Result<HashMap<u16, Vec<u16>>, DetectionConfigError> {
    let name = "service_expected_ports";
    let Some(value) = parameters.get(name) else {
        return Err(DetectionConfigError::MissingParameter { id: id.to_string(), name });
    };
    let Some(map) = value.as_object() else {
        return Err(send(id, name, "must be a map from source port number to expected ports".to_string()));
    };

    let mut ports_by_source = HashMap::new();
    for (key, expected) in map {
        let source_port = key.parse::<u16>().map_err(|_| {
            send(id, name, format!("key `{key}` must be a source port number"))
        })?;
        let Some(expected_list) = expected.as_array() else {
            return Err(send(id, name, format!("value for source port {source_port} must be a list")));
        };
        let mut ports = Vec::with_capacity(expected_list.len());
        for port_value in expected_list {
            let Some(port) = port_value.as_u64().and_then(|port| u16::try_from(port).ok()) else {
                return Err(send(id, name, format!("port value `{port_value}` must be a valid TCP/UDP port")));
            };
            ports.push(port);
        }
        ports_by_source.insert(source_port, ports);
    }

    if ports_by_source.is_empty() {
        return Err(send(id, name, "must contain at least one source-port entry".to_string()));
    }
    Ok(ports_by_source)
}

fn send(id: &str, name: &str, reason: String) -> DetectionConfigError {
    DetectionConfigError::InvalidParameter {
        id: id.to_string(),
        name,
        reason,
    }
}

/// scan 系ルール (SCAN-001/002) 共通の必須パラメータ抽出。
/// threshold はイベント発火条件 `count > threshold` で使う、0 は無意味なので禁止。
fn extract_window_params(
    id: &str,
    parameters: &Map<String, Value>,
    threshold_noun: &'static str,
) -> Result<(u64, u64, &'static str), DetectionConfigError> {
    let Some(window_value) = parameters.get("window_secs") else {
        return Err(DetectionConfigError::MissingParameter { id: id.to_string(), name: "window_secs" });
    };
    let Some(window_secs) = window_value.as_u64().and_then(|value| if value >= 1 { Some(value) } else { None }) else {
        return Err(send(id, "window_secs", "must be an integer >= 1".to_string()));
    };

    let Some(threshold_value) = parameters.get("threshold") else {
        return Err(DetectionConfigError::MissingParameter { id: id.to_string(), name: "threshold" });
    };
    let Some(threshold) = threshold_value.as_u64().and_then(|value| if value >= 1 { Some(value) } else { None }) else {
        return Err(send(id, "threshold", format!("must be an integer >= 1 ({threshold_noun} count)")));
    };

    Ok((window_secs, threshold, threshold_noun))
}

/// 文字列パラメータ取得、なければ空文字。
fn string_param<'a>(parameters: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    parameters.get(key).and_then(Value::as_str)
}

/// 文字列リスト取得、なければ空（tags / mitigation_suggestions は必須ではない）。
fn string_list(parameters: &Map<String, Value>, key: &str) -> Vec<String> {
    let Some(list) = parameters.get(key).and_then(Value::as_array) else { return Vec::new() };
    list.iter().filter_map(Value::as_str).map(ToOwned::to_owned).collect()
}

/// EXT-001 からみて「既知/許可」とみなす宛先の IP/CIDR 範囲。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CidrRange {
    network: u128,
    mask: u128,
    v4: bool,
}

impl CidrRange {
    /// 単一 IP (`203.0.113.10`) または CIDR (`198.51.100.0/24`) を 1 つの範囲として扱う。
    pub fn parse(entry: &str) -> Result<Self, DetectionConfigError> {
        let invalid = |reason: &str| DetectionConfigError::InvalidAllowlistEntry {
            entry: entry.to_string(),
            reason: reason.to_string(),
        };
        let (addr_part, prefix_part) = match entry.split_once('/') {
            Some(parts) => parts,
            None => match entry.trim().parse::<IpAddr>() {
                Ok(addr) => return Ok(Self {
                    network: value_of(addr),
                    mask: if addr.is_ipv4() { u128::from(u32::MAX) } else { u128::MAX },
                    v4: addr.is_ipv4(),
                }),
                Err(_) => return Err(invalid("must be an IP address or `ip/prefix` CIDR")),
            },
        };
        let addr = addr_part.trim().parse::<IpAddr>().map_err(|_| invalid("`ip/prefix` : IP part is invalid"))?;
        let prefix = prefix_part.trim().parse::<u32>().map_err(|_| invalid("`ip/prefix` : prefix is invalid"))?;

        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(invalid("prefix length exceeds the address family limit"));
        }
        let addr_value = value_of(addr);
        let mask = if prefix == 0 { 0 } else if addr.is_ipv4() {
            u128::from(u32::MAX) << (32 - prefix)
        } else {
            u128::MAX << (128 - prefix)
        };
        Ok(Self { network: addr_value & mask, mask, v4: addr.is_ipv4() })
    }

    /// `ip` が範囲内なら true。v4/v6 の family mismatch は常に false。
    pub fn contains(self, ip: IpAddr) -> bool {
        if self.v4 != ip.is_ipv4() {
            return false;
        }
        (value_of(ip) & self.mask) == self.network
    }
}

fn value_of(addr: IpAddr) -> u128 {
    match addr {
        IpAddr::V4(v4) => u128::from(u32::from(v4)),
        IpAddr::V6(v6) => u128::from(v6),
    }
}

/// RFC1918/4193 + loopback + link-local。EXT-001 のノイズ除去用静的レンジ。
pub(crate) fn private_ranges() -> Vec<CidrRange> {
    ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "fd00::/8", "fc00::/7", "::1/128", "fe80::/10"]
        .iter()
        .map(|entry| CidrRange::parse(entry).expect("static private range parses fine"))
        .collect()
}

#[derive(Debug, Deserialize)]
struct Allowlist {
    #[serde(default)]
    external_ips: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct RulesDocument {
    #[serde(default)]
    allowlist: Allowlist,
    #[serde(default)]
    rules: Vec<RuleConfig>,
}

/// rules ファイルをロードして (allowlist, compiled rules) を返す。
pub(crate) fn load_rules(path: &Path) -> Result<(Vec<CidrRange>, Vec<CompiledRule>), DetectionConfigError> {
    let text = std::fs::read_to_string(path).map_err(|source| DetectionConfigError::FileRead {
        path: path.display().to_string(),
        source,
    })?;
    let document: RulesDocument = serde_yaml::from_str(&text)?;

    let allowlist = document
        .allowlist
        .external_ips
        .iter()
        .map(|entry| CidrRange::parse(entry))
        .collect::<Result<Vec<_>, _>>()?;
    let rules = document
        .rules
        .into_iter()
        .map(compile)
        .collect::<Result<Vec<_>, _>>()?;

    Ok((allowlist, rules))
}
```

HashSet import note: rules.rs の本実装では `HashSet` を import しない（v4/v6 判定は `is_ipv4`）。上記 `use std::collections::{HashMap, HashSet};` を置き替え: `use std::collections::HashMap;`。

ポイント:
- `expect static` : `private_ranges()` は内部実装で、呼び出しは engine.rs (Task 3)。
- `load_rules` は compiled rule リストを返すだけ。engine 側で disabled filter & windows map を組み立てる（Task 3 で統合）。
- 旧 `RuleConfig` (String severity 等) の利用者は 0（grep 済み）のため置換して問題なし。

- [ ] **Step 4: nextest 全件を緑に**

```bash
cargo nextest -p sentinel-detection
```
期待: PASS。

- [ ] **Step 5: engine.rs / lib.rs トリアージ**

engine.rs は Task 3 で全置換するため、この時点では旧 `DetectionEngine{rules: Vec<Rule>}` API を「Task 3 の型に合わせた最小スタブ」へ詰め替え（`DetectionEngine` は構造体だけ先行定義、`new()` と `load()` は `load_rules` を利用して合成まで行い、`evaluate` は空 Vec を返す TODO コメント付きスタブ）。`lib.rs` は以下に更新:

```rust
pub mod engine;
pub mod event;
pub mod rules;

pub use engine::DetectionEngine;
pub use event::SecurityEvent;
pub use rules::{CompiledRule, CidrRange, DetectionConfigError, RuleConfig, RuleParameters, RuleType, Severity};
```

注: `pub mod event;` と `SecurityEvent` は Task 2 で追加するため、この時点では engine と rules の export のみで先に進める。Task 2/3 完了時に本セクションの最終形にする。

- [ ] **Step 6: ワークスペース緑確認**

```bash
cargo nextest run --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

- [ ] **Step 7: Commit**

```bash
git add crates/sentinel-detection
git commit -m "feat(detection): typed rule configs with CIDR allowlist"
```

---

### Task 2: sentinel-detection — SecurityEvent 型

**Files:**
- Modify: `crates/sentinel-detection/Cargo.toml`（依存追加）
- Modify: `crates/sentinel-detection/src/lib.rs`
- Create: `crates/sentinel-detection/src/event.rs`
- Test: `crates/sentinel-detection/src/event.rs` の `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: Task 1 の `Severity`（`crates/sentinel-detection/src/rules.rs`）、workspace `chrono`/`uuid` 依存
- Produces: Type map §event.rs の `SecurityEvent`（全フィールド pub）、`build_event`、`fill_template`。Task 3/4 が `build_event`/`fill_template`、Task 6/T8 が `SecurityEvent` を利用する。

- [ ] **Step 1: 依存追加**

`crates/sentinel-detection/Cargo.toml` の `[dependencies]` に追記:

```toml
chrono = { workspace = true }
uuid = { workspace = true }
```

- [ ] **Step 2: 失敗するテストを書く（新規ファイルにテスト付き）**

`crates/sentinel-detection/src/event.rs` を新規作成し、まずテストのみ（実装なしで赤）:

```rust
#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use super::*;

    fn sample_rule_fields() -> (&'static str, Severity, f32) {
        ("SCAN-001", Severity::Critical, 0.9)
    }

    #[test]
    fn fill_template_replaces_known_placeholders() {
        let out = fill_template("over {threshold} distinct ports in {window_secs}s", &[("threshold", 50), ("window_secs", 60), ("source_port", 8080)]);
        assert_eq!(out, "over 50 distinct ports in 60s");
    }

    #[test]
    fn fill_template_keeps_unknown_placeholders() {
        let out = fill_template("Port scanning detected: {unknown}", &[]);
        assert_eq!(out, "Port scanning detected: {unknown}");
    }

    #[test]
    fn build_event_sets_type_from_rule_name() {
        let (rule_id, severity, confidence) = sample_rule_fields();
        let event = build_event(
            rule_id,
            "port_scanning",
            severity,
            confidence,
            IpAddr::from([10, 0, 0, 9]),
            IpAddr::from([203, 0, 113, 10]),
            443,
            "TCP",
            "Port scanning detected".to_string(),
            vec!["scan".to_string()],
            vec!["Rate-limit the source.".to_string()],
        );
        assert_eq!(event.rule_id, "SCAN-001");
        assert_eq!(event.rule_name, "port_scanning");
        assert_eq!(event.event_type, "port_scanning");
        assert_eq!(event.destination_port, 443);
        assert_eq!(event.protocol, "TCP");
        assert!(!event.event_id.is_nil());
        assert!(event.timestamp <= chrono::Utc::now());
    }
}
```

- [ ] **Step 3: 赤を確認**

```bash
cargo nextest -p sentinel-detection 2>&1 | tail -3
```
期待: `fill_template` / `build_event` 未定義でコンパイルエラー。

- [ ] **Step 4: 実装（event.rs の tests 以外）**

```rust
//! 検知イベント。detection 側で生成され、sensor の EventWriter が ClickHouse へ書き込む。

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::rules::Severity;

/// ClickHouse `security_events` テーブル (architecture.md §7.4) に対応するイベント。
#[derive(Debug, Clone, PartialEq)]
pub struct SecurityEvent {
    pub event_id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub rule_id: String,
    pub rule_name: String,
    pub event_type: String, // 例: "port_scanning" (= rule_name)
    pub severity: Severity,
    pub confidence: f32,
    pub source_ip: IpAddr,
    pub destination_ip: IpAddr,
    pub destination_port: u16,
    pub protocol: String,
    pub description: String,
    pub tags: Vec<String>,
    pub mitigation_suggestions: Vec<String>,
}

/// 需要 fields から 1 つの SecurityEvent を発行する（timestamp/uuid はここで採番）。
pub(crate) fn build_event(
    rule_id: &str,
    rule_name: &str,
    severity: Severity,
    confidence: f32,
    source_ip: IpAddr,
    destination_ip: IpAddr,
    destination_port: u16,
    protocol: &str,
    description: String,
    tags: Vec<String>,
    mitigation_suggestions: Vec<String>,
) -> SecurityEvent {
    SecurityEvent {
        event_id: Uuid::new_v4(),
        timestamp: Utc::now(),
        rule_id: rule_id.to_owned(),
        rule_name: rule_name.to_owned(),
        event_type: rule_name.to_owned(),
        severity,
        confidence,
        source_ip,
        destination_ip,
        destination_port,
        protocol: protocol.to_owned(),
        description,
        tags,
        mitigation_suggestions,
    }
}

/// `{key}` プレースホルダを埋める。未知の key はそのまま残す（EXT 系ルールの説明文など）。
pub(crate) fn fill_template(template: &str, values: &[(&str, u64)]) -> String {
    let mut out = template.to_owned();
    for (key, value) in values {
        let placeholder = format!("{{{key}}}");
        if out.contains(&placeholder) {
            out = out.replace(&placeholder, value.to_string().as_str());
        }
    }
    out
}
```

`lib.rs` に `pub mod event;` と `pub use event::SecurityEvent;` を追加（Task 1 Step 5 の最終形)。

- [ ] **Step 5: 緑確認**

```bash
cargo nextest -p sentinel-detection
```

- [ ] **Step 6: Commit**

```bash
git add crates/sentinel-detection
git commit -m "feat(detection): security event type"
```

---

### Task 3: sentinel-detection — ステートレスルール (EXT-001/EXT-002) + エンジン骨格

**Files:**
- Modify: `crates/sentinel-detection/src/engine.rs`（全置換）

**Interfaces:**
- Consumes: Task 1 の `compile`/`load_rules`/`CidrRange`/`private_ranges`/`DetectionConfigError`/`RuleConfig`/`RuleParameters`/`Severity`、Task 2 の `build_event`/`fill_template`/`SecurityEvent`、`ExportedFlow`
- Produces: Type map §engine.rs。Task 4 が scan arm を追加し、Task 9 が `DetectionEngine::load` と `evaluate` を利用する。

実装の核心: `windows` のエントリは `(source_ip, window_secs)` を key にする。Task 3 では scan arm を `None` のスタブにし、Task 4 で有効化する。

- [ ] **Step 1: 失敗するテストを書く (engine.rs に tests module 追加)**

```rust
#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use sentinel_flow::ExportedFlow;

    use crate::rules::{RuleConfig, RuleType, Severity};

    use super::*;

    fn flow(source_ip: &str, source_port: u16, destination_ip: &str, destination_port: u16) -> ExportedFlow {
        ExportedFlow {
            flow_id: format!("t-{}", destination_port),
            timestamp_start: "2026-11-10T10:00:00.000+00:00".to_string(),
            timestamp_end: "2026-11-10T10:00:01.000+00:00".to_string(),
            source_ip: source_ip.to_string(),
            destination_ip: destination_ip.to_string(),
            source_port,
            destination_port,
            protocol: "TCP".to_string(),
            packets_forward: 1,
            packets_reverse: 0,
            bytes_forward: 100,
            bytes_reverse: 0,
            duration_ms: 1000,
            tcp_flags: vec![],
            sensor_node: "node-1".to_string(),
        }
    }

    fn rule(id: &str, name: &str, rule_type: RuleType, parameters: &str) -> RuleConfig {
        serde_yaml::from_str(&format!(
            "id: {id}\nname: {name}\nrule_type: {}\nseverity: high\nconfidence: 0.8\nparameters: {}\n",
            serde_yaml::to_string(&rule_type).unwrap().trim(),
            parameters
        )).unwrap()
    }

    fn ext001() -> RuleConfig {
        rule("EXT-001", "unknown_external_destination", RuleType::Stateless, "{}")
    }

    fn ext002() -> RuleConfig {
        rule("EXT-002", "unexpected_port", RuleType::Stateless, r#"{service_expected_ports: {"8080": [443, 80]}}"#)
    }

    fn window_rule(id: &'static str, name: &'static str, window_secs: u64, threshold: u64) -> RuleConfig {
        serde_yaml::from_str(&format!(
            "id: {id}\nname: {name}\nrule_type: window\nseverity: critical\nconfidence: 0.9\nparameters: {{window_secs: {window_secs}, threshold: {threshold}, description: \"over {threshold} in {window_secs}s\"}}\n"
        )).unwrap()
    }

    fn ext001_engine() -> DetectionEngine {
        DetectionEngine::new(Vec::new(), vec![ext001()]).unwrap()
    }

    #[test]
    fn allowlisted_exact_and_cidr_destinations_are_skipped() {
        let mut engine = DetectionEngine::new(
            vec!["203.0.113.10".to_owned(), "198.51.100.0/24".to_owned()],
            vec![ext001()],
        ).unwrap();
        assert!(engine.evaluate(&flow("10.0.0.9", 44321, "203.0.113.10", 443)).is_empty());
        assert!(engine.evaluate(&flow("10.0.0.9", 44321, "198.51.100.7", 443)).is_empty());
    }

    #[test]
    fn private_destination_ranges_are_skipped() {
        let mut engine = ext001_engine();
        assert!(engine.evaluate(&flow("10.0.0.9", 44321, "10.1.2.3", 443)).is_empty());
        assert!(engine.evaluate(&flow("10.0.0.9", 44321, "172.16.0.1", 443)).is_empty());
        assert!(engine.evaluate(&flow("10.0.0.9", 44321, "192.168.1.1", 443)).is_empty());
        assert!(engine.evaluate(&flow("10.0.0.9", 44321, "fd00::1", 443)).is_empty());
    }

    #[test]
    fn unknown_external_destination_fires_per_flow() {
        let mut engine = ext001_engine();
        let events = engine.evaluate(&flow("10.0.0.9", 44321, "8.8.8.8", 443));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].rule_id, "EXT-001");
        assert_eq!(events[0].event_type, "unknown_external_destination");
        assert_eq!(events[0].severity, Severity::High);
        assert_eq!(events[0].destination_port, 443);
        assert_eq!(events[0].protocol, "TCP");
        // ルールが stateless なので同じ宛先でも各 flow で再発火する。
        assert_eq!(engine.evaluate(&flow("10.0.0.9", 44321, "8.8.8.8", 443)).len(), 1);
    }

    #[test]
    fn expected_port_is_allowed() {
        let mut engine = DetectionEngine::new(Vec::new(), vec![ext002()]).unwrap();
        assert!(engine.evaluate(&flow("10.0.0.9", 8080, "8.8.8.8", 443)).is_empty());
        assert!(engine.evaluate(&flow("10.0.0.9", 8080, "8.8.8.8", 80)).is_empty());
    }

    #[test]
    fn unexpected_port_fires() {
        let mut engine = DetectionEngine::new(Vec::new(), vec![ext002()]).unwrap();
        let events = engine.evaluate(&flow("10.0.0.9", 8080, "8.8.8.8", 22));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].rule_id, "EXT-002");
        assert_eq!(events[0].destination_port, 22);
    }

    #[test]
    fn unknown_source_port_is_skipped() {
        // 送信元ポート 49152 は service_expected_ports に無い: k8s metadata のない MVP では
        // クライアント起因のノイズを避けるため skip (spec §1 EXT-002)。
        let mut engine = DetectionEngine::new(Vec::new(), vec![ext002()]).unwrap();
        assert!(engine.evaluate(&flow("10.0.0.9", 49152, "8.8.8.8", 22)).is_empty());
    }

    #[test]
    fn disabled_rules_are_filtered_out() {
        let disabled = serde_yaml::from_str::<RuleConfig>(
            "id: EXT-001\nname: unknown_external_destination\nrule_type: stateless\nseverity: high\nconfidence: 0.8\nenabled: false\n",
        ).unwrap();
        let engine = DetectionEngine::new(Vec::new(), vec![disabled]).unwrap();
        assert_eq!(engine.rule_count(), 0);
    }

    #[test]
    fn invalid_ip_addresses_produce_no_events() {
        let mut engine = ext001_engine();
        assert!(engine.evaluate(&flow("bad-ip", 1, "8.8.8.8", 443)).is_empty());
        assert!(engine.evaluate(&flow("10.0.0.9", 1, "", 443)).is_empty());
    }

    #[test]
    fn windows_stay_empty_for_stateless_rules() {
        let engine = ext001_engine();
        assert_eq!(engine.active_windows(), 0);
    }

    #[test]
    fn mixed_stateless_rules_emit_rule_order() {
        let mut engine = DetectionEngine::new(Vec::new(), vec![ext001(), ext002()]).unwrap();
        // 送信元 8080 は EXT-002 の key 有り、宛先 8.8.8.8 は未知の外部先 → 両方のルールが発火。EXT-001 → EXT-002 の順。
        let events = engine.evaluate(&flow("10.0.0.9", 8080, "8.8.8.8", 22));
        let rule_ids: Vec<&str> = events.iter().map(|event| event.rule_id.as_str()).collect();
        assert_eq!(rule_ids, vec!["EXT-001", "EXT-002"]);
    }
}
```

- [ ] **Step 2: 赤を確認**

```bash
cargo nextest -p sentinel-detection 2>&1 | tail -3
```
期待: `DetectionEngine::new/load/evaluate` が未実装のためコンパイルエラー。

- [ ] **Step 3: engine.rs 実装（スキャン ルール arm なしのスタブ）**

```rust
//! 検知エンジン: ExportedFlow をルール群で評価し SecurityEvent を生成する。
//!
//! singleton ownership: processor タスクが 1 つだけ所有し、`&mut evaluate` で
//! window 更新する。Arc/ロックは不要 (spec「配線」節)。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use sentinel_flow::ExportedFlow;

use crate::event::{build_event, fill_template, SecurityEvent};
use crate::rules::{
    compile, load_rules, private_ranges, CidrRange, DetectionConfigError, RuleConfig, RuleParameters, Severity,
};

/// SCAN ウィンドウ (source IP × window_secs 単位)。再起動で捨てる仕様 (spec 合意)。
#[derive(Debug)]
struct ScanWindow {
    destination_ips: HashSet<IpAddr>,
    destination_ports: HashSet<u16>,
    first_seen: Instant,
    fired: bool, // fires once per window life
}

impl ScanWindow {
    fn new() -> Self {
        Self {
            destination_ips: HashSet::new(),
            destination_ports: HashSet::new(),
            first_seen: Instant::now(),
            fired: false,
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum ScanMarker {
    Ports,
    Addresses,
}

/// gateway がルール群を所有する。
#[derive(Debug)]
pub struct DetectionEngine {
    allowlist: Vec<CidrRange>,
    private_ranges: Vec<CidrRange>,
    rules: Vec<crate::rules::CompiledRule>,
    windows: HashMap<(IpAddr, u64), ScanWindow>, // (source_ip, window_secs) → window
}

impl DetectionEngine {
    /// テスト/手動構築用。allowlist はテキスト (ip / cidr) のリスト。
    pub fn new(allowlist: Vec<String>, rules: Vec<RuleConfig>) -> Result<Self, DetectionConfigError> {
        let allowlist = parse_allowlist(&allowlist)?;
        let mut rules = rules.into_iter().map(compile).collect::<Result<Vec<_>, _>>()?;
        rules.retain(|rule| rule.enabled); // 無効ルールは検証対象外 (Task 1 で検証済み)
        Ok(Self {
            allowlist,
            private_ranges: private_ranges(),
            rules,
            windows: HashMap::new(),
        })
    }

    /// YAML ルールファイルから構築。パース・コンパイルで全エラーを fail-fast。
    pub fn load(path: &Path) -> Result<Self, DetectionConfigError> {
        let (allowlist, mut rules) = load_rules(path)?;
        rules.retain(|rule| rule.enabled);
        Ok(Self {
            allowlist,
            private_ranges: private_ranges(),
            rules,
            windows: HashMap::new(),
        })
    }

    /// 有効なルール数（無効入りを除く）。
    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    /// 現在生存している SCAN ウィンドウ数（gauge 用）。
    pub fn active_windows(&self) -> usize {
        self.windows.len()
    }

    /// 1 つの ExportedFlow を全有効ルールで評価する。生成したイベントを返す。
    ///
    /// IP parse 失敗は 0 件扱い（不正レコードは上流の異常だが評価 pipeline を止めない）。
    pub fn evaluate(&mut self, flow: &ExportedFlow) -> Vec<SecurityEvent> {
        let Ok(source_ip) = flow.source_ip.parse::<IpAddr>() else {
            return Vec::new();
        };
        let Ok(destination_ip) = flow.destination_ip.parse::<IpAddr>() else {
            return Vec::new();
        };

        // while-index loop: scan arm 内で `&mut self.windows` と `&self.rules` を
        // while-index loop: scan arm が `&mut self.windows` を更新するため、`for` で
        // rule を借用したまま windows を触れず、for だと排他借用エラーになるため。Task 4 の
        // scan arm もこの構造に乗る。ルール順序を YAML 定義順に保持するため Spec どおりに並べる。
        let mut events = Vec::new();
        let mut index = 0;
        while index < self.rules.len() {
            index += 1;
            if let Some(event) = self.evaluate_rule(index - 1, flow, source_ip, destination_ip) {
                events.push(event);
            }
        }
        events
    }

    fn evaluate_rule(
        &mut self,
        index: usize,
        flow: &ExportedFlow,
        source_ip: IpAddr,
        destination_ip: IpAddr,
    ) -> Option<SecurityEvent> {
        // 判別は action 側で: scan 系は Task 4 実装まで None。
        let rule = &self.rules[index];
        match &rule.action {
            RuleParameters::UnknownExternalDestination => {
                if self.is_private(destination_ip) || self.is_allowed(destination_ip) {
                    return None;
                }
                Some(build_event(
                    &rule.id,
                    &rule.name,
                    rule.severity,
                    rule.confidence,
                    source_ip,
                    destination_ip,
                    flow.destination_port,
                    &flow.protocol,
                    fill_template(&rule.description_template, &[]),
                    rule.tags.clone(),
                    rule.mitigation_suggestions.clone(),
                ))
            }
            RuleParameters::UnexpectedPort { ports_by_source } => {
                let Some(expected) = ports_by_source.get(&flow.source_port) else {
                    return None;
                };
                if expected.contains(&flow.destination_port) {
                    return None;
                }
                Some(build_event(
                    &rule.id,
                    &rule.name,
                    rule.severity,
                    rule.confidence,
                    source_ip,
                    destination_ip,
                    flow.destination_port,
                    &flow.protocol,
                    fill_template(&rule.description_template, &[]),
                    rule.tags.clone(),
                    rule.mitigation_suggestions.clone(),
                ))
            }
            // Task 4 で置き換え: PortScan / NetworkScan arms
            _ => None,
        }
    }

    fn is_allowed(&self, ip: IpAddr) -> bool {
        self.allowlist.iter().any(|range| range.contains(ip))
    }

    fn is_private(&self, ip: IpAddr) -> bool {
        self.private_ranges.iter().any(|range| range.contains(ip))
    }
}

fn parse_allowlist(entries: &[String]) -> Result<Vec<CidrRange>, DetectionConfigError> {
    entries.iter().map(String::as_str).map(CidrRange::parse).collect()
}
```

注: engine.rs の `use std::collections::HashSet;` は Task 4 で必要になる。Task 3 時点では未使用のため `windows` の型のみ活用し (HashMap), HashSet import は Task 4 追加時に整理。

- [ ] **Step 4: 緑確認**

```bash
cargo nextest -p sentinel-detection
```

- [ ] **Step 5: Commit**

```bash
git add crates/sentinel-detection
git commit -m "feat(detection): stateless rules EXT-001 and EXT-002"
```

---

### Task 4: sentinel-detection — SCAN ウィンドウ ルール (SCAN-001/SCAN-002)

**Files:**
- Modify: `crates/sentinel-detection/src/engine.rs`（scan arms を本実装に）

**Interfaces:**
- Consumes: Task 3 の `DetectionEngine` 骨格 / `ScanWindow` / `ScanMarker`
- Produces: 完全な `evaluate` 動作。Task 9 の受入テストが spec の6パターンを通る。

仕様: SCAN-001 = `window_secs` 内の distinct `destination_port` 数 > `threshold` で発火、SCAN-002 は distinct `destination_ip` 数。発火は window につき 1 回（`fired: true` 後は reset まで再発火しない）。窓切れ（`first_seen + window_secs <= now`）で window を消去し次の評価で作り直す。`windows` key は `(source_ip, window_secs)`。

- [ ] **Step 1: 失敗するテストを書く (engine.rs tests module に追加)**

```rust
#[test]
fn scan001_fires_once_threshold_crossed() {
    let mut engine = DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)]).unwrap();
    assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
    assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 80)).is_empty());
    let events = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 22));
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].rule_id, "SCAN-001");
    assert_eq!(events[0].event_type, "port_scanning");
    assert_eq!(events[0].severity, Severity::Critical);
}

#[test]
fn scan001_stays_silent_below_threshold() {
    // flows: 80, 443, 22 (3 distinct) with threshold 2 → 3rd fires... above; below test uses threshold 5:
    let mut engine = DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 5)]).unwrap();
    for port in [80u16, 443, 22, 1433] {
        assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", port)).is_empty());
    }
}

#[test]
fn scan001_repeated_destination_port_does_not_grow_window() {
    let mut engine = DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)]).unwrap();
    assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
    assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
    // window count = 1 distinct port ( threshold 2 → 2nd) so 3 flows on same port never fire
    assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
}

#[test]
fn scan001_does_not_refire_within_window() {
    let mut engine = DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)]).unwrap();
    for port in [443u16, 80, 22] {
        engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", port));
    }
    let events = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 33));
    assert_eq!(events.len(), 1, "flow 4 should not fire (fired=true in window)");
    assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 55)).is_empty());
}

#[test]
fn scan001_window_reset_after_expiry() {
    let mut engine = DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)]).unwrap();
    // 1st window fires
    dump_support::freshen_stale_windows(engine.windows.values_mut(), 61, &mut engine.anchor);  // helper: backdate first_seen
    ...
}
```

計略が無駄に複雑なので簡潔に: backdating テストは struct 直触り。tests module 内ユーティリティとして:

```rust
    /// 接触できない engine.windows の first_seen を窓切れギリギリに戻す。
    fn expire_window(engine: &mut DetectionEngine, seconds_back: u64) {
        for window in engine.windows.values_mut() {
            window.first_seen = Instant::now() - Duration::from_secs(seconds_back);
        }
    }
```
（tests と impl が同 crate 同 file なので private field に触れる。）

`scan001_window_reset_after_expiry` の本体:

```rust
#[test]
fn scan001_window_reset_after_expiry() {
    let mut engine = DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)]).unwrap();
    assert_eq!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).len(), 0);
    expire_window(&mut engine, 61);
    // 新しい window で再評価 (thr 2, count=1) → 発火しない、window は新しく作り直し
    let events = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443));
    assert!(events.is_empty());
    assert_eq!(engine.active_windows(), 1);
}

#[test]
fn scan002_counts_distinct_destination_ips() {
    let mut engine = DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-002", "network_scanning", 60, 2)]).unwrap();
    assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
    assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.2", 443)).is_empty());
    let events = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.3", 443)); // same port, 3 distinct ips
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].rule_id, "SCAN-002");
}

#[test]
fn scan_windows_are_per_source_ip() {
    let mut engine = DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)]).unwrap();
    for port in [443u16, 80, 22] {
        let _ = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", port));
    }
    assert_eq!(engine.active_windows(), 1);
    // different source IP → 別 window (same window_secs)
    let _ = engine.evaluate(&flow("10.0.0.20", 49152, "203.0.113.1", 443));
    assert_eq!(engine.active_windows(), 2);
}

#[test]
fn scan001_renders_description_template() {
    let rule = serde_yaml::from_str::<RuleConfig>(
        "id: SCAN-001\nname: port_scanning\nrule_type: window\nseverity: critical\nconfidence: 0.9\n\
         parameters: {window_secs: 60, threshold: 2, description: \"Port scanning detected: over {threshold} distinct ports in {window_secs}s.\"}\n",
    ).unwrap();
    let mut engine = DetectionEngine::new(Vec::new(), vec![rule]).unwrap();
    let _ = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443));
    let _ = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 80));
    let events = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 22));
    assert_eq!(events[0].description, "Port scanning detected: over 2 distinct ports in 60s.");
}

#[test]
fn mixed_rules_emit_in_order_and_delay_window() {
    let mut engine = DetectionEngine::new(Vec::new(), vec![ext001(), window_rule("SCAN-001", "port_scanning", 60, 2)]).unwrap();
    let first = engine.evaluate(&flow("10.0.0.9", 49152, "8.8.8.8", 443)); // EXT-001 fires now
    assert_eq!(first.len(), 1);
    let second = engine.evaluate(&flow("10.0.0.9", 49152, "8.8.8.8", 80)); // EXT-001 fires; scan count 2 (未超)
    assert_eq!(second.len(), 1);
    let third = engine.evaluate(&flow("10.0.0.9", 49152, "8.8.8.8", 22)); // EXT-001 + SCAN-001
    let rule_ids: Vec<&str> = third.iter().map(|event| event.rule_id.as_str()).collect();
    assert_eq!(rule_ids, vec!["EXT-001", "SCAN-001"]);
}
```

- [ ] **Step 2: 赤を確認**

```bash
cargo nextest -p sentinel-detection 2>&1 | tail -3
```
期待: scan arm は `None` スタブなので window ルールのテスト群が FAIL (`active_windows()==0`、`fired` 認識なしなど)。

- [ ] **Step 3: scan arm 本実装**

`engine.rs` の `RuleParameters::UnknownExternalDestination` / `UnexpectedPort` arms の下の `% ...`; catch-all `_ => None,` を以下に置換:

```rust
            RuleParameters::PortScan { window_secs, threshold } => {
                self.scan_evaluation(rule, flow, source_ip, destination_ip, ScanMarker::Ports, window_secs, threshold)
            }
            RuleParameters::NetworkScan { window_secs, threshold } => {
                self.scan_evaluation(rule, flow, source_ip, destination_ip, ScanMarker::Addresses, window_secs, threshold)
            }
```

さらに impl に追加（private_windows 保留: `(window_secs)` で key 打切り timestamp の効果確認, 再起動で捨てる仕様）:

```rust
    /// SCAN ルール共通: window 更新 → 閾値チェック → fired 制御 → イベント生成。
    fn scan_evaluation(
        &mut self,
        rule: &crate::rules::CompiledRule,
        flow: &ExportedFlow,
        source_ip: IpAddr,
        destination_ip: IpAddr,
        marker: ScanMarker,
        window_secs: u64,
        threshold: u64,
    ) -> Option<SecurityEvent> {
        // 期限切れ window は掃除 (spec: 評価を通じて prune する、背景 task 無し)
        self.prune_windows();

        let window = self.windows.entry((source_ip, window_secs)).or_insert_with(ScanWindow::new);
        match marker {
            ScanMarker::Ports => { window.destination_ports.insert(flow.destination_port); }
            ScanMarker::Addresses => { window.destination_ips.insert(destination_ip); }
        }
        let count = match marker {
            ScanMarker::Ports => window.destination_ports.len(),
            ScanMarker::Addresses => window.destination_ips.len(),
        } as u64;

        if count <= threshold || window.fired {
            return None;
        }
        window.fired = true;
        let description = fill_template(&rule.description_template, &[("threshold", threshold), ("window_secs", window_secs)]);
        Some(build_event(
            &rule.id,
            &rule.name,
            rule.severity,
            rule.confidence,
            source_ip,
            destination_ip,
            flow.destination_port,
            &flow.protocol,
            description,
            rule.tags.clone(),
            rule.mitigation_suggestions.clone(),
        ))
    }

    /// first_seen + window_secs が elapsed した window を落とす (スキャン評価毎に呼ばれる)。
    fn prune_windows(&mut self) {
        self.windows
            .retain(|(_source_ip, window_secs), window| window.first_seen.elapsed() < Duration::from_secs(*window_secs));
    }
```

借用チェッカーの注記: `evaluate_rule` は `let rule = &self.rules[index]` の借用を保ったまま `&mut self.windows` を更新するため、単純 `for` ではコンパイル不可。呼び出しに disambiguate されるのは field-pointer の split borrow（`self.rules` の読み出しと `self.windows` の書き込みが field 次元で離れている）で合法。書けない場合は `rule` のデータをローカルに clone して `rule` 借用を切ってから window を更新する（この冗長 clone は SCAN arm で複数参照型でないため許容)。実装としては上記の通り rule borrow + windows 借用が並存する形が可能 (Rust 2024 field-projected)。動かなければ上記 fallback 方針。

- [ ] **Step 4: 緑確認**

```bash
cargo nextest -p sentinel-detection
```
期待: 全部 PASS（stateless + window + mixed）。

- [ ] **Step 5: Commit**

```bash
git add crates/sentinel-detection
git commit -m "feat(detection): SCAN-001/SCAN-002 window rules"
```

---

### Task 5: sentinel-sensor — DetectionConfig 拡張 + rules YAML 作成

**Files:**
- Modify: `crates/sentinel-sensor/src/config.rs`
- Modify: `config/sensor.yaml`
- Create: `config/detection-rules.yaml`
- Test: `crates/sentinel-sensor/src/config.rs` の `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: `SensorConfig::validate()`（既存 anyhow::ensure! 形式）
- Produces: `DetectionConfig { enabled, rules_path: Option<String>, event_channel_capacity: usize }`。Task 9 が `config.detection.event_channel_capacity` と `rules_path` を利用する。

- [ ] **Step 1: 失敗するテストを書く (config.rs tests module に追加)**

```rust
#[test]
fn rejects_zero_event_channel_capacity() {
    let mut config = SensorConfig::default();
    config.detection.event_channel_capacity = 0;
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("event_channel_capacity"),
    );
}
```

既存の test モジュール内にネット用のテスト。この時点では `event_channel_capacity` フィールドが無くコンパイルエラー（赤）。

- [ ] **Step 2: 赤を確認**

```bash
cargo nextest -p sentinel-sensor 2>&1 | tail -3
```

- [ ] **Step 3: DetectionConfig に event_channel_capacity を追加**

`config.rs` 内の `DetectionConfig` 定義と `Default` 実装を下記に置換（struct 定義自体はフィールド追加のみ）:

```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectionConfig {
    pub enabled: bool,
    pub rules_path: Option<String>,
    /// 検知イベントの mpsc チャネル容量。EventWriter (Task 8) 導入の flow で使用。
    #[serde(default = "default_event_channel_capacity")]
    pub event_channel_capacity: usize,
}

fn default_event_channel_capacity() -> usize {
    1000
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            rules_path: None,
            event_channel_capacity: default_event_channel_capacity(),
        }
    }
}
```

`SensorConfig::validate()` に次を追記:

```rust
    ensure!(
        config.detection.event_channel_capacity >= 1,
        "detection.event_channel_capacity must be >= 1 (EventWriter sizing)",
    );
```

- [ ] **Step 4: sensor.yaml と rules ファイル**

`config/sensor.yaml` の detection セクションを以下に置換:

```yaml
detection:
  enabled: true
  rules_path: "config/detection-rules.yaml"
  event_channel_capacity: 1000
```

`config/detection-rules.yaml` を新規作成（spec §4、EXT-002 key = "8080" 送信元ポート）:

```yaml
allowlist:
  external_ips:
    - "203.0.113.10"
    - "198.51.100.0/24"

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
        "8080": [443, 80]
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
      threshold: 50
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
      threshold: 20
      description: "Network scanning detected: over {threshold} distinct destinations in {window_secs}s."
      tags: ["scan", "outbound"]
      mitigation_suggestions:
        - "Verify source host activity; block or rate-limit if unauthorized."
```

- [ ] **Step 5: 緑確認**

```bash
cargo nextest -p sentinel-sensor
```

- [ ] **Step 6: Commit**

```bash
git add crates/sentinel-sensor/src/config.rs config/sensor.yaml config/detection-rules.yaml
git commit -m "feat(sensor): detection config and default rules file"
```

### Task 6: sentinel-sensor — EventRow（ClickHouse 行変換）

**Files:**

- Modify: `crates/sentinel-sensor/src/output/row.rs`（共有 serde ヘルパーの可視性）
- Create: `crates/sentinel-sensor/src/output/event_row.rs`
- Modify: `crates/sentinel-sensor/src/output/mod.rs`（`mod event_row;` を追加）
- Test: `crates/sentinel-sensor/src/output/event_row.rs` の tests モジュール

**Interfaces:**

- Consumes: `SecurityEvent`（Task 2）、`row.rs` の `ipv6`/`datetime64_ms` serde ヘルパーと `protocol_code`。
- Produces: `EventRow`（`clickhouse::Row` derive、全フィールド同名で Task 7 の DDL に対応）+ `impl From<&SecurityEvent> for EventRow`（列挙可能な不変変換）。

- [ ] **Step 1: row.rs のヘルパーを `pub(crate)` に公開**

`output/row.rs` で次の3つを可視化するだけ:

```rust
// `mod datetime64_ms` → `pub(crate) mod datetime64_ms`
pub(crate) mod datetime64_ms { /* 変更なし */ }

// `mod ipv6` → `pub(crate) mod ipv6`
pub(crate) mod ipv6 { /* 変更なし */ }

// `fn protocol_code` → `pub(crate) fn protocol_code`
pub(crate) fn protocol_code(protocol: &str) -> i8 { /* 変更なし */ }
```

`protocol_code` に `#[allow(dead_code)]` が付いていたら、ビルドが通ることを確認して削除する（event_row から利用されるため警告が消えるはず。残るようなら属性を保持）。

- [ ] **Step 2: 変換実装（赤→緑崩壊型: 新ファイルのためまず実装を書く）**

新ファイル `output/event_row.rs` — テストを前に書きたくなるが、このタスクは型自体が新規の初回定義なので「テスト先行で型未定義のコンパイルエラー」を確認する手順は Task 1 と同様に赤確認だけを挟む（Step 2 実装 → Step 3 テスト → Step 4 全緑）。`FlowRow`（`row.rs`）と同じエンコーディング規約に従う:

```rust
//! Security-event ClickHouse row mapping (`security_events` schema).

use std::net::{IpAddr, Ipv6Addr};

use chrono::{DateTime, Utc};
use clickhouse::Row;
use sentinel_detection::{SecurityEvent, Severity};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::row::{datetime64_ms, ipv6, protocol_code};

/// One `security_events` row. Encoding mirrors `FlowRow`: `DateTime64(3)` as
/// epoch milliseconds, `IPv6` as 16 raw octets (IPv4 as v4-mapped), `Enum8`
/// protocol/severity as numeric tags.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Row)]
pub struct EventRow {
    #[serde(with = "clickhouse::serde::uuid")]
    pub event_id: Uuid,
    #[serde(with = "datetime64_ms")]
    pub timestamp: DateTime<Utc>,
    /// MVP emits no flow correlation (Phase 7 metadata enrichment adds it).
    pub source_flow_ids: Vec<Uuid>,
    pub event_type: String,
    pub severity: i8,
    pub confidence: f32,
    #[serde(with = "ipv6")]
    pub source_ip: Ipv6Addr,
    #[serde(with = "ipv6")]
    pub destination_ip: Ipv6Addr,
    pub destination_port: u16,
    pub protocol: i8,
    pub description: String,
    pub rule_id: String,
    pub rule_name: String,
    pub tags: Vec<String>,
    pub mitigation_suggestions: Vec<String>,
}

impl From<&SecurityEvent> for EventRow {
    fn from(event: &SecurityEvent) -> Self {
        Self {
            event_id: event.event_id,
            timestamp: event.timestamp,
            source_flow_ids: Vec::new(),
            event_type: event.event_type.clone(),
            severity: event.severity.code(),
            confidence: event.confidence,
            source_ip: to_ipv6(event.source_ip),
            destination_ip: to_ipv6(event.destination_ip),
            destination_port: event.destination_port,
            protocol: protocol_code(&event.protocol),
            description: event.description.clone(),
            rule_id: event.rule_id.clone(),
            rule_name: event.rule_name.clone(),
            tags: event.tags.clone(),
            mitigation_suggestions: event.mitigation_suggestions.clone(),
        }
    }
}

/// Map a family-tagged IP onto the schema's IPv6 column (v4-mapped for IPv4).
fn to_ipv6(ip: IpAddr) -> Ipv6Addr {
    match ip {
        IpAddr::V4(v4) => v4.to_ipv6_mapped(),
        IpAddr::V6(v6) => v6,
    }
}

/// Shared sample event for the output-module test suites (row/store/writer).
#[cfg(test)]
pub(crate) fn sample_event(rule_id: &str, port: u16) -> SecurityEvent {
    use chrono::TimeZone;

    let timestamp = Utc.with_ymd_and_hms(2026, 11, 10, 10, 0, 0).unwrap();
    SecurityEvent {
        event_id: Uuid::from_u128(0xf00d + u128::from(port)),
        timestamp,
        rule_id: rule_id.to_string(),
        rule_name: "port_scanning".to_string(),
        event_type: "port_scanning".to_string(),
        severity: Severity::High,
        confidence: 0.8,
        source_ip: "10.0.0.9".parse().unwrap(),
        destination_ip: "198.51.100.7".parse().unwrap(),
        destination_port: port,
        protocol: "TCP".to_string(),
        description: "Unknown external destination".to_string(),
        tags: vec!["outbound".to_string()],
        mitigation_suggestions: vec!["Verify destination legitimacy with the user.".to_string()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn security_event_converts_to_clickhouse_row() {
        let event = sample_event("EXT-001", 443);
        let row = EventRow::from(&event);
        assert_eq!(row.event_id, event.event_id);
        assert_eq!(row.timestamp, event.timestamp);
        assert_eq!(row.severity, 3); // high → Enum8 tag
        assert_eq!(row.source_ip, Ipv6Addr::from(std::net::Ipv4Addr::new(10, 0, 0, 9)));
        assert_eq!(row.destination_ip, Ipv6Addr::from(std::net::Ipv4Addr::new(198, 51, 100, 7)));
        assert!(row.source_flow_ids.is_empty());
        assert_eq!(row.protocol, 1); // TCP → Enum8 tag
        assert_eq!(row.tags, vec!["outbound".to_string()]);
        assert!(!row.description.is_empty());
    }
}
```

注記: `row.rs` 側の `datetime64_ms`/`ipv6` ヘルパーと完全に同じ `serde(with = ...)` 使用であること（このタスク固有の serde パスを新規に作らない）。

- [ ] **Step 3: mod.rs 登録**

`output/mod.rs`:

```rust
mod event_row;
```

（`pub(crate) use` は不要。`event_store.rs`/`event_writer.rs` が `super::event_row::…` で参照するため）

- [ ] **Step 4: 全緑確認**

```bash
cargo nextest run -p sentinel-sensor
```

Expected: PASS（既存 flow 系テストに影響なし）。

- [ ] **Step 5: clippy + fmt + commit**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
git add crates/sentinel-sensor/src/output/row.rs crates/sentinel-sensor/src/output/event_row.rs crates/sentinel-sensor/src/output/mod.rs
git commit -m "feat(sensor): security event row mapping"
```

### Task 7: sentinel-sensor — security_events ClickHouse ストア

**Files:**

- Create: `crates/sentinel-sensor/src/output/event_store.rs`
- Modify: `crates/sentinel-sensor/src/output/mod.rs`（`mod event_store;` + `pub(crate) use event_store::ClickHouseEventStore;`）
- Test: `crates/sentinel-sensor/src/output/event_store.rs` の tests モジュール

**Interfaces:**

- Consumes: `EventRow`（Task 6）、`crate::config::OutputConfig`、`clickhouse.rs`（`ClickHouseStore`）と同じクライアント/識別子パターン。
- Produces: `EventStore` trait + `ClickHouseEventStore::new(&OutputConfig) -> Self`（クライアント構築はエラーを返さない。ネットワーク接続は書き込み時のみ発生する）。

- [ ] **Step 1: 実装（新規体系のため、まず本体を書く）**

`output/event_store.rs` 全文:

```rust
//! ClickHouse storage for security events `security_events`.

use async_trait::async_trait;
use clickhouse::{Client, sql::Identifier};

use super::event_row::EventRow;
use crate::config::OutputConfig;

const TABLE: &str = "security_events";

/// Storage sink for security-event rows. `Send` so the writer task can own it.
#[async_trait]
pub trait EventStore: Send {
    type Error: std::fmt::Display + Send + Sync + 'static;
    async fn write_batch(&mut self, rows: &[EventRow]) -> Result<(), Self::Error>;
}

/// `security_events` DDL. Deliberate differences mirror `network_flows`
/// (Phase 3 precedent, see clickhouse.rs comments): `MergeTree()` instead of
/// `ReplicatedMergeTree()` for the single-node deployment, plain `String` /
/// `Array(String)` instead of `LowCardinality` aliases, and no Kubernetes
/// metadata columns yet (extended by `ALTER TABLE` in Phase 7).
fn create_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {TABLE}
(
    event_id UUID,
    timestamp DateTime64(3, 'UTC'),
    event_type String,
    severity Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    confidence Float32,
    source_flow_ids Array(UUID),
    source_ip IPv6,
    destination_ip IPv6,
    destination_port UInt16,
    protocol Enum8('TCP' = 1, 'UDP' = 2, 'ICMP' = 3, 'OTHER' = 4),
    description String,
    rule_id String,
    rule_name String,
    tags Array(String),
    mitigation_suggestions Array(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (event_type, severity, timestamp)
TTL toDateTime(timestamp) + INTERVAL 365 DAY
"#
    )
}

/// ClickHouse-backed event store; schema creation is lazy on first write.
pub struct ClickHouseEventStore {
    admin: Client,
    client: Client,
    database: String,
    schema_ready: bool,
}

impl ClickHouseEventStore {
    pub fn new(config: &OutputConfig) -> Self {
        let mut admin = Client::default().with_url(&config.clickhouse_url);
        if let Some(user) = &config.clickhouse_user {
            admin = admin.with_user(user);
        }
        if let Some(password) = &config.clickhouse_password {
            admin = admin.with_password(password);
        }
        let database = config.clickhouse_database.clone();
        let client = admin.clone().with_database(&database);
        Self {
            admin,
            client,
            database,
            schema_ready: false,
        }
    }

    async fn ensure_schema(&mut self) -> Result<(), clickhouse::error::Error> {
        if self.schema_ready {
            return Ok(());
        }
        self.admin
            .query("CREATE DATABASE IF NOT EXISTS ?")
            .with_bind(Identifier(&self.database))
            .execute()
            .await?;
        self.client.query(&create_table_sql()).execute().await?;
        self.schema_ready = true;
        Ok(())
    }
}

#[async_trait]
impl EventStore for ClickHouseEventStore {
    type Error = clickhouse::error::Error;

    async fn write_batch(&mut self, rows: &[EventRow]) -> Result<(), Self::Error> {
        if rows.is_empty() {
            return Ok(());
        }
        if let Err(err) = self.ensure_schema().await {
            self.schema_ready = false;
            return Err(err);
        }
        let mut insert = self.client.insert(TABLE)?;
        for row in rows {
            insert.write(row).await?;
        }
        if let Err(err) = insert.end().await {
            self.schema_ready = false;
            return Err(err);
        }
        Ok(())
    }
}
```

- [ ] **Step 2: テスト（probe-skip 形式）**

`event_store.rs` の末尾に tests モジュールを追加:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::event_row::sample_event;

    /// Probe the ClickHouse server; tests skip unless `REQUIRE_CLICKHOUSE`
    /// is set and the server answers within 2s (same gating pattern as the
    /// `network_flows` integration tests in `clickhouse.rs`).
    async fn clickhouse_available() -> bool {
        if std::env::var("REQUIRE_CLICKHOUSE").is_err() {
            return false;
        }
        let url =
            std::env::var("SENTINEL_CH_TEST_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            Client::default().with_url(&url).query("SELECT 1").execute(),
        )
        .await
        .is_ok()
    }

    async fn reset_test_table(store: &ClickHouseEventStore) {
        store
            .admin
            .query(&format!("DROP TABLE IF EXISTS {}.{}", store.database, TABLE))
            .execute()
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn empty_batch_is_a_noop() {
        if !clickhouse_available().await {
            eprintln!("skipping: ClickHouse not available");
            return;
        }
        let mut store = ClickHouseEventStore::new(&OutputConfig::default());
        // No traffic at all: must not panic or touch the network.
        store.write_batch(&[]).await.unwrap();
    }

    #[tokio::test]
    async fn roundtrips_security_events() {
        if !clickhouse_available().await {
            eprintln!("skipping: ClickHouse not available");
            return;
        }
        let config = OutputConfig::default();
        let mut store = ClickHouseEventStore::new(&config);
        reset_test_table(&store).await;

        let event = sample_event("EXT-001", 443);
        store.write_batch(&[EventRow::from(&event)]).await.unwrap();

        let selected: Vec<EventRow> = store
            .client
            .query("SELECT ?fields FROM security_events WHERE event_id = toUUID(?)")
            .with_bind(event.event_id)
            .fetch_all()
            .await
            .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], EventRow::from(&event));
    }

    #[test]
    fn table_ddl_covers_row_columns() {
        let ddl = create_table_sql();
        for column in <EventRow as clickhouse::Row>::COLUMN_NAMES {
            assert!(
                ddl.contains(&format!("\n    {column} ")),
                "column {column} missing from DDL:\n{ddl}"
            );
        }
        assert!(ddl.contains("ENGINE = MergeTree()"));
        assert!(ddl.contains("PARTITION BY toYYYYMM(timestamp)"));
        assert!(ddl.contains("TTL toDateTime(timestamp) + INTERVAL 365 DAY"));
    }
}
```

注記: env var 名（`REQUIRE_CLICKHOUSE` / `SENTINEL_CH_TEST_URL`）は `clickhouse.rs` の tests と同じ実名に揃える。実装時に `clickhouse.rs` tests の実装を確認し、名称・probe 形式が異なればそちらに合わせること（テスト間の粒度を統一する意図で、ここでは記述を標準化した）。

- [ ] **Step 3: mod.rs 登録**

```rust
mod event_store;

pub(crate) use event_store::ClickHouseEventStore;
```

- [ ] **Step 4: 全緑確認**

```bash
cargo nextest run -p sentinel-sensor
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

- [ ] **Step 5: Commit**

```bash
git add crates/sentinel-sensor/src/output/event_store.rs crates/sentinel-sensor/src/output/mod.rs
git commit -m "feat(sensor): security_events ClickHouse store"
```

### Task 8: `crates/sentinel-sensor/src/output/event_writer.rs` + `metrics.rs` — event writer pipeline

**Files:**

- Create: `crates/sentinel-sensor/src/output/event_writer.rs`
- Modify: `crates/sentinel-sensor/src/output/mod.rs` (add `mod event_writer;` + `pub(crate) use event_writer::EventWriter;`)
- Modify: `crates/sentinel-sensor/src/metrics.rs` (add 4 detection metrics)

**Interfaces:**

- Consumes: `EventStore` (Task 7), `EventRow::from(&SecurityEvent)` (Task 6), `WRITE_TIMEOUT` (`crate::output::writer`), `SecurityEvent` (Task 2).
- Produces: `EventWriter<S: EventStore>::new(rx: mpsc::Receiver<SecurityEvent>, store: S, batch_size: usize, batch_timeout: Duration, write_timeout: Duration, metrics: Arc<SensorMetrics>) -> Self` + `pub async fn run(self) -> S`; metrics fields `detection_events_total: IntCounterVec`, `detection_windows_active: IntGauge`, `detection_events_written: IntCounter`, `detection_failed_writes_total: IntCounter` (Task 9 uses all four names).

- [ ] **Step 1: metrics.rs — write the failing test**

Append to the `#[cfg(test)] mod tests` at the bottom of `metrics.rs` (create the module if it has no tests yet):

```rust
    #[test]
    fn detection_metrics_registered() {
        let metrics = SensorMetrics::new().unwrap();
        // Fire the label-bearing counter once so the series materializes.
        metrics.detection_events_total.with_label_values(&["SCAN-001"]).inc();
        let exported = metrics.export().unwrap();
        assert!(exported.contains("sentinel_detection_events_total"));
        assert!(exported.contains("sentinel_detection_windows_active"));
        assert!(exported.contains("sentinel_detection_events_written_total"));
        assert!(exported.contains("sentinel_detection_failed_writes_total"));
    }
```

- [ ] **Step 2: Run to verify it fails**

```bash
cargo nextest run -p sentinel-sensor detection_metrics_registered
```

Expected: FAIL — struct has no field `detection_events_total`.

- [ ] **Step 3: metrics.rs minimal implementation**

Add to imports: `prometheus::{..., IntCounterVec, ...}`. Add 4 fields to `SensorMetrics` (after `clickhouse_write_duration`), construct + register them in `new()` following the exact existing pattern (`IntCounter::with_opts(prometheus::opts!(...))?`, `registry.register(Box::new(x.clone()))?`, return them in `Ok(Self { ... })`):

```rust
    pub detection_events_total: IntCounterVec,
    pub detection_windows_active: IntGauge,
    pub detection_events_written: IntCounter,
    pub detection_failed_writes_total: IntCounter,
```

```rust
        let detection_events_total = IntCounterVec::new(
            prometheus::opts!(
                "sentinel_detection_events_total",
                "Total security events emitted by the detection engine"
            ),
            &["rule_id"],
        )?;

        let detection_windows_active = IntGauge::with_opts(prometheus::opts!(
            "sentinel_detection_windows_active",
            "Live per-source scan windows in the detection engine"
        ))?;

        let detection_events_written = IntCounter::with_opts(prometheus::opts!(
            "sentinel_detection_events_written_total",
            "Security events successfully written to ClickHouse"
        ))?;

        let detection_failed_writes_total = IntCounter::with_opts(prometheus::opts!(
            "sentinel_detection_failed_writes_total",
            "Security events dropped after exhausting the write retry budget"
        ))?;
```

（注記として書いていた「誤記テンプレート」は正誤ペアを残す意味が無いので、正しい値一本に統一してある。）

- [ ] **Step 4: Run metrics test to green**

```bash
cargo nextest run -p sentinel-sensor detection_metrics_registered
```

Expected: PASS.

- [ ] **Step 5: event_writer.rs — write the failing tests**

Create `crates/sentinel-sensor/src/output/event_writer.rs` starting with the test module (operators see only this task, so the full harness is inline):

```rust
//! Security-event writer: same batch/retry pipeline discipline as
//! `writer::FlowWriter`, but for `SecurityEvent` rows into `security_events`.

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use chrono::{DateTime, Utc};
    use sentinel_detection::{SecurityEvent, Severity};
    use tokio::sync::mpsc;
    use uuid::Uuid;

    use super::*;
    use crate::metrics::SensorMetrics;

    struct MockEventStore {
        batches: Vec<Vec<EventRow>>,
        failures_left: usize,
        hang: bool,
    }

    impl MockEventStore {
        fn returning_ok() -> Self {
            Self { batches: Vec::new(), failures_left: 0, hang: false }
        }

        fn failing(times: usize) -> Self {
            Self { batches: Vec::new(), failures_left: times, hang: false }
        }

        fn hanging() -> Self {
            Self { batches: Vec::new(), failures_left: usize::MAX, hang: true }
        }
    }

    #[async_trait::async_trait]
    impl EventStore for MockEventStore {
        type Error = std::io::Error;

        async fn write_batch(&mut self, rows: &[EventRow]) -> Result<(), Self::Error> {
            if self.hang {
                std::future::pending::<()>().await;
            }
            if self.failures_left > 0 {
                self.failures_left -= 1;
                return Err(std::io::Error::other("injected write failure"));
            }
            self.batches.push(rows.to_vec());
            Ok(())
        }
    }

    fn sample_event(rule_id: &str, port: u16) -> SecurityEvent {
        SecurityEvent {
            event_id: Uuid::from_u128(0xf00d + u128::from(port)),
            timestamp: DateTime::parse_from_rfc3339("2026-11-10T10:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            rule_id: rule_id.to_string(),
            rule_name: "port_scanning".to_string(),
            event_type: "port_scanning".to_string(),
            severity: Severity::Critical,
            confidence: 0.9,
            source_ip: "10.0.0.9".parse().unwrap(),
            destination_ip: "203.0.113.10".parse().unwrap(),
            destination_port: port,
            protocol: "TCP".to_string(),
            description: "Port scanning detected".to_string(),
            tags: vec!["scan".to_string()],
            mitigation_suggestions: vec!["Verify source host activity; block or rate-limit if unauthorized.".to_string()],
        }
    }

    struct WriterHandle {
        tx: mpsc::Sender<SecurityEvent>,
        task: tokio::task::JoinHandle<MockEventStore>,
        metrics: Arc<SensorMetrics>,
    }

    async fn spawn_writer(store: MockEventStore, batch_size: usize) -> WriterHandle {
        let (tx, rx) = mpsc::channel(64);
        let metrics = Arc::new(SensorMetrics::new().unwrap());
        let writer = EventWriter::new(
            rx,
            store,
            batch_size,
            Duration::from_millis(50),
            WRITE_TIMEOUT,
            metrics.clone(),
        );
        let task = tokio::spawn(writer.run());
        WriterHandle { tx, task, metrics }
    }

    /// Poll until `cond()` is true or ~2s elapse (CI scheduling tolerance).
    async fn wait_until(mut cond: impl FnMut() -> bool) {
        for _ in 0..400 {
            if cond() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    }

    #[tokio::test]
    async fn flushes_when_batch_is_full() {
        let handle = spawn_writer(MockEventStore::returning_ok(), 2).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        handle.tx.send(sample_event("SCAN-001", 22)).await.unwrap();
        handle.tx.send(sample_event("SCAN-001", 23)).await.unwrap(); // stays buffered
        drop(handle.tx);
        let store = handle.task.await.unwrap();
        assert_eq!(store.batches.len(), 2);
        assert_eq!(store.batches[0].len(), 2);
        assert_eq!(store.batches[1].len(), 1);
    }

    #[tokio::test]
    async fn flushes_on_batch_timeout() {
        let handle = spawn_writer(MockEventStore::returning_ok(), 8).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        wait_until(|| handle.metrics.detection_events_written.get() == 1).await;
        assert_eq!(handle.metrics.detection_events_written.get(), 1);
    }
    }

    #[tokio::test]
    async fn drains_remainder_on_channel_close() {
        let handle = spawn_writer(MockEventStore::returning_ok(), 8).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        drop(handle.tx);
        let store = handle.task.await.unwrap();
        assert_eq!(store.batches.len(), 1);
        assert_eq!(store.batches[0].len(), 1);
    }

    #[tokio::test]
    async fn retries_until_ok() {
        let handle = spawn_writer(MockEventStore::failing(1), 2).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        handle.tx.send(sample_event("SCAN-001", 22)).await.unwrap();
        drop(handle.tx);
        let store = handle.task.await.unwrap();
        assert_eq!(store.batches.len(), 1);
        assert_eq!(handle.metrics.detection_failed_writes_total.get(), 0);
    }

    #[tokio::test]
    async fn drops_after_retry_budget() {
        let handle = spawn_writer(MockEventStore::failing(usize::MAX), 2).await;
        handle.tx.send(sample_event("SCAN-001", 443)).await.unwrap();
        handle.tx.send(sample_event("SCAN-001", 22)).await.unwrap();
        drop(handle.tx);
        let store = handle.task.await.unwrap();
        assert!(store.batches.is_empty());
        assert_eq!(handle.metrics.detection_failed_writes_total.get(), 2);
    }
}
```

注記: `flushes_on_batch_timeout` の最終 assert 行は自明の `|| true` で冗長になっている。実装する際は、次のように待機とゲージの一致だけで完結させる:

```rust
        wait_until(|| handle.metrics.detection_events_written.get() == 1).await;
        assert_eq!(handle.metrics.detection_events_written.get(), 1);
```

- [ ] **Step 6: Run to verify the tests fail**

```bash
cargo nextest run -p sentinel-sensor event_writer
```

Expected: FAIL — `EventWriter` undefined.

- [ ] **Step 7: Implement event_writer.rs**

Append to the file (tests stay at the bottom):

```rust
use std::sync::Arc;
use std::time::{Duration, Instant};

use sentinel_detection::SecurityEvent;
use tokio::sync::mpsc;
use tokio::time::MissedTickBehavior;
use tracing::{debug, error, warn};

use super::event_row::EventRow;
use super::event_store::EventStore;
use super::writer::WRITE_TIMEOUT;
use crate::metrics::SensorMetrics;

/// Write attempts per batch before it is dropped.
const MAX_RETRIES: usize = 3;
/// Linear backoff base between write attempts (attempt n waits n × base).
const RETRY_BACKOFF: Duration = Duration::from_millis(100);

/// Batches security events and flushes them to the event store.
///
/// Structural mirror of `writer::FlowWriter`; deliberately separate (spec
/// 方針:ジェネリクス化は Phase 6 Kafka 一般化とセットで検討する).
pub struct EventWriter<S: EventStore> {
    rx: mpsc::Receiver<SecurityEvent>,
    store: S,
    buffer: Vec<EventRow>,
    batch_size: usize,
    batch_timeout: Duration,
    write_timeout: Duration,
    metrics: Arc<SensorMetrics>,
}

impl<S: EventStore> EventWriter<S> {
    pub fn new(
        rx: mpsc::Receiver<SecurityEvent>,
        store: S,
        batch_size: usize,
        batch_timeout: Duration,
        write_timeout: Duration,
        metrics: Arc<SensorMetrics>,
    ) -> Self {
        Self {
            rx,
            store,
            buffer: Vec::with_capacity(batch_size),
            batch_size,
            batch_timeout,
            write_timeout,
            metrics,
        }
    }

    /// Consume events, flush on batch-full or timeout, and drain on close.
    pub async fn run(mut self) -> S {
        let mut ticker = tokio::time::interval(self.batch_timeout);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        ticker.tick().await; // consume the immediate first tick

        loop {
            tokio::select! {
                maybe = self.rx.recv() => match maybe {
                    Some(event) => {
                        self.buffer.push(EventRow::from(&event));
                        if self.buffer.len() >= self.batch_size {
                            self.flush().await;
                        }
                    }
                    None => break,
                },
                _ = ticker.tick() => self.flush().await,
            }
        }

        self.flush().await;
        self.store
    }

    async fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let rows = std::mem::take(&mut self.buffer);
        for attempt in 0..=MAX_RETRIES {
            match tokio::time::timeout(self.write_timeout, self.store.write_batch(&rows)).await {
                Ok(Ok(())) => {
                    self.metrics.detection_events_written.inc_by(rows.len() as u64);
                    return;
                }
                Ok(Err(err)) => {
                    error!("event batch write failed (attempt {}): {}", attempt + 1, err);
                }
                Err(_elapsed) => {
                    error!("event batch write timed out after {:?}", self.write_timeout);
                }
            }
                warn!(attempt = attempt + 1, "event batch write failed; retrying");
                tokio::time::sleep(RETRY_BACKOFF * (attempt as u32 + 1)).await;
            }
        }
        self.metrics.detection_failed_writes_total.inc_by(rows.len() as u64);
        error!(
            "dropped {} security events after {} write attempts",
            rows.len(),
            MAX_RETRIES + 1
        );
    }
}
```

注記: 上の `flush()` にある冗長な `debug!("attempt {} failed, retrying", ...)` 行は、その下の `warn!` と重複している。実装の際は `debug!` 行を取り除き、`warn!` だけを残すこと。

- [ ] **Step 8: Run all event_writer + metrics tests green**

```bash
cargo nextest run -p sentinel-sensor
```

Expected: PASS (all, including writer/flow tests untouched).

- [ ] **Step 9: mod.rs exports**

`crates/sentinel-sensor/src/output/mod.rs` gets:

```rust
mod event_writer;

pub(crate) use event_writer::EventWriter;
```

- [ ] **Step 10: clippy + fmt**

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
```

- [ ] **Step 11: Commit**

```bash
git add crates/sentinel-sensor/src/output/event_writer.rs crates/sentinel-sensor/src/output/mod.rs crates/sentinel-sensor/src/metrics.rs
git commit -m "feat(sensor): event writer with detection metrics"
```

### Task 9: `crates/sentinel-sensor/src/main.rs` — route exported flows through detection

**Files:**

- Modify: `crates/sentinel-sensor/src/main.rs`
- Test: existing suites must stay green (runtime wiring; covered by workspace tests + manual startup note)

**Interfaces:**

- Consumes: everything above (`DetectionEngine::load`, `evaluate`, `rule_count`, `active_windows`, `SecurityEvent`, `EventWriter`, `ClickHouseEventStore`, 4 metrics).
- Produces: runtime behavior only. `detection.enabled: false` changes nothing observable in the flow path.

- [ ] **Step 1: Imports + constant**

At the top of `main.rs` adjust the imports to:

```rust
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use capture::PacketCapture;
use config::SensorConfig;
use flow::FlowProcessor;
use metrics::SensorMetrics;
use output::{ClickHouseEventStore, EventWriter, FlowWriter, WRITE_TIMEOUT};
use sentinel_detection::{DetectionEngine, SecurityEvent};
use sentinel_flow::ExportedFlow;
```

And below the imports:

```rust
/// Fallback rules file when `detection.rules_path` is not set.
const DEFAULT_RULES_PATH: &str = "config/detection-rules.yaml";
```

- [ ] **Step 2: Detection bootstrap (before the processor spawn)**

Insert between the flow writer spawn and the processor spawn:

```rust
    // Detection: loaded before capture so rule defects fail fast at startup.
    let detection = if config.detection.enabled {
        let rules_path = config
            .detection
            .rules_path
            .clone()
            .unwrap_or_else(|| DEFAULT_RULES_PATH.to_string());
        let engine = DetectionEngine::load(Path::new(&rules_path))?;
        info!(rules = engine.rule_count(), rules_path = %rules_path, "detection enabled");
        Some(engine)
    } else {
        info!("detection disabled");
        None
    };

    let (events_tx, events_rx) = mpsc::channel(config.detection.event_channel_capacity);
    let event_writer_handle = if config.detection.enabled {
        let event_writer = EventWriter::new(
            events_rx,
            ClickHouseEventStore::new(&config.output),
            config.output.batch_size,
            Duration::from_millis(config.output.batch_timeout_ms),
            WRITE_TIMEOUT,
            metrics.clone(),
        );
        Some(tokio::spawn(event_writer.run()))
    } else {
        // No consumer will drain this receiver; drop it so any stray send is
        // observed as a closed channel instead of buffering silently.
        drop(events_rx);
        None
    };
```

- [ ] **Step 3: Processor loop call sites**

Inside the processor spawn block, first line after `async move {`:

```rust
            let mut detection = detection;
```

Then at the packet arm:

```rust
                        if let Some(exported) = processor.on_packet(&packet) {
                            info!("flow_export: {:?}", exported);
                            handle_export(&exported, &mut detection, &events_tx, &metrics);
                            forward(&out_tx, &metrics, exported);
                        }
```

At the sweep arm and the final drain sweep:

```rust
                        for exported in processor.sweep() {
                            info!("flow_export: {:?}", exported);
                            handle_export(&exported, &mut detection, &events_tx, &metrics);
                            forward(&out_tx, &metrics, exported);
                        }
```

(Database note: `&metrics` deref-coerces from `Arc<SensorMetrics>` exactly like the existing `forward` calls.)

- [ ] **Step 4: handle_export + forward_event functions**

Add beside the existing `forward` function:

```rust
/// Evaluate one exported flow against the detection engine, announce and
/// forward every produced event. A no-op when detection is disabled.
fn handle_export(
    exported: &ExportedFlow,
    detection: &mut Option<DetectionEngine>,
    events_tx: &mpsc::Sender<SecurityEvent>,
    metrics: &SensorMetrics,
) {
    let Some(engine) = detection.as_mut() else { return };
    metrics.detection_windows_active.set(i64::try_from(engine.active_windows()).unwrap_or(i64::MAX));
    for event in engine.evaluate(exported) {
        metrics.detection_events_total.with_label_values(&[&event.rule_id]).inc();
        info!(rule_id = %event.rule_id, severity = %event.severity, "detection event: {}", event.description);
        forward_event(events_tx, event);
    }
}

/// Hand a security event to the event writer without blocking the flow path.
fn forward_event(events_tx: &mpsc::Sender<SecurityEvent>, event: SecurityEvent) {
    if let Err(err) = events_tx.try_send(event) {
        match err {
            mpsc::error::TrySendError::Full(_) => warn!("events channel full, dropping event"),
            mpsc::error::TrySendError::Closed(_) => debug!("events channel closed, dropping event"),
        }
    }
}
```

- [ ] **Step 5: Shutdown drain for the event writer**

After the existing `writer_handle` await block, add:

```rust
    if let Some(handle) = event_writer_handle {
        match tokio::time::timeout(Duration::from_secs(30), handle).await {
            Ok(Ok(_)) => info!("Detection event writer stopped."),
            Ok(Err(e)) => error!("Detection event writer task failed: {}", e),
            Err(_) => error!("Detection event writer shutdown timed out"),
        }
    }
```

- [ ] **Step 6: Full workspace verification**

```bash
cargo nextest run --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo deny check
```

Expected: all green.

**Known runtime caveat (documented, not fixable here):** macOS has no datalink capture, so the processor loop cannot run end-to-end locally; wiring is exercised by tests only (config parsing + engine/store/writer unit tests) and live on Linux later.

- [ ] **Step 7: Commit**

```bash
git add crates/sentinel-sensor/src/main.rs
git commit -m "feat(sensor): route exported flows through detection engine"
```

---

## Self-Review (executed when writing this plan)

1. **Spec coverage:** 4ルール（EXT-001/002 → Task 3、SCAN-001/002 → Task 4）、発火ログ（Task 9 `info!`）、security_events 書き込み（Task 7+8+9）、ClickHouse 行変換（Task 6）、`config/detection-rules.yaml` 起動ロード・fail-fast（Task 1/5/9 Step 2）、`detection.enabled: false` は経路非生成（Task 9 分岐）、YAML ロード系の fail-fast 仕様（Task 1 テスト群）、ClickHouse 実接続なしのモック検証（Task 8）。
2. **Placeholder scan:** TBD/TODO なし。「実装は Task N 同様」のような省略はなし（writer/store はコード全文提示）。
3. **Type consistency:** `CompiledRule` のフィールド名、`load_rules` の戻り値 `(Vec<CidrRange>, Vec<CompiledRule>)`、`EventWriter::new` 引数順、metrics 名（`…_written_total` / `…failed_writes_total`）は Type map と各 Task で一致。

