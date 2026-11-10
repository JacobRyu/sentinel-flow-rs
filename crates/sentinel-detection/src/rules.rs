//! ルール設定の型とコンパイル（YAML → 検証済み CompiledRule）。

use std::collections::HashMap;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

/// イベントの重要度4段階。
/// code() は ClickHouse Enum8('low'=1,...'critical'=4) のタグ値。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    UnknownExternalDestination, // EXT-001
    UnexpectedPort {
        ports_by_source: HashMap<u16, Vec<u16>>, // EXT-002: source port → 期待ポート群
    },
    PortScan {
        window_secs: u64,
        threshold: u64, // SCAN-001: distinct destination_ports
    },
    NetworkScan {
        window_secs: u64,
        threshold: u64, // SCAN-002: distinct destination_ips
    },
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
    RuleTypeMismatch { id: String, expected: &'static str, got: &'static str },

    #[error("rule {id}: missing required parameter `{name}`")]
    MissingParameter { id: String, name: &'static str },

    #[error("rule {id}: invalid parameter `{name}`: {reason}")]
    InvalidParameter { id: String, name: &'static str, reason: String },

    #[error("rule {id}: confidence {value} is not in 0.0..=1.0")]
    ConfidenceOutOfRange { id: String, value: f32 },

    #[error("invalid allowlist entry `{entry}`: {reason}")]
    InvalidAllowlistEntry { entry: String, reason: String },
}

/// ルール id ごとに固定された rule_type と一致するか検証する。
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

/// 1 つの RuleConfig を検証・型付き CompiledRule へコンパイルする。
/// unknown id / rule_type 不整合 / 必須パラメータ欠落 / confidence 範囲外はすべてエラー。
pub fn compile(config: RuleConfig) -> Result<CompiledRule, DetectionConfigError> {
    let RuleConfig { id, name, rule_type, severity, confidence, enabled, condition: _, parameters } =
        config;
    if !(0.0..=1.0).contains(&confidence) {
        return Err(DetectionConfigError::ConfidenceOutOfRange {
            id: id.clone(),
            value: confidence,
        });
    }

    let action = match id.as_str() {
        "EXT-001" => {
            expect_rule_type(&id, rule_type, RuleType::Stateless)?;
            RuleParameters::UnknownExternalDestination
        }
        "EXT-002" => {
            expect_rule_type(&id, rule_type, RuleType::Stateless)?;
            RuleParameters::UnexpectedPort { ports_by_source: extract_ports_map(&id, &parameters)? }
        }
        "SCAN-001" => {
            expect_rule_type(&id, rule_type, RuleType::Window)?;
            let (window_secs, threshold, _) =
                extract_window_params(&id, &parameters, "distinct destination ports")?;
            RuleParameters::PortScan { window_secs, threshold }
        }
        "SCAN-002" => {
            expect_rule_type(&id, rule_type, RuleType::Window)?;
            let (window_secs, threshold, _) =
                extract_window_params(&id, &parameters, "distinct destination IPs")?;
            RuleParameters::NetworkScan { window_secs, threshold }
        }
        _ => return Err(DetectionConfigError::UnknownRuleId(id)),
    };

    let description_template =
        string_param(&parameters, "description").unwrap_or_default().to_string();
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
        return Err(send(
            id,
            name,
            "must be a map from source port number to expected ports".to_string(),
        ));
    };

    let mut ports_by_source = HashMap::new();
    for (key, expected) in map {
        let source_port = key
            .parse::<u16>()
            .map_err(|_| send(id, name, format!("key `{key}` must be a source port number")))?;
        let Some(expected_list) = expected.as_array() else {
            return Err(send(
                id,
                name,
                format!("value for source port {source_port} must be a list"),
            ));
        };
        let mut ports = Vec::with_capacity(expected_list.len());
        for port_value in expected_list {
            let Some(port) = port_value.as_u64().and_then(|port| u16::try_from(port).ok()) else {
                return Err(send(
                    id,
                    name,
                    format!("port value `{port_value}` must be a valid TCP/UDP port"),
                ));
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

fn send(id: &str, name: &'static str, reason: String) -> DetectionConfigError {
    DetectionConfigError::InvalidParameter { id: id.to_string(), name, reason }
}

/// scan 系ルール (SCAN-001/002) 共通の必須パラメータ抽出。
/// threshold はイベント発火条件 `count > threshold` で使う、0 は無意味なので禁止。
fn extract_window_params(
    id: &str,
    parameters: &Map<String, Value>,
    threshold_noun: &'static str,
) -> Result<(u64, u64, &'static str), DetectionConfigError> {
    let Some(window_value) = parameters.get("window_secs") else {
        return Err(DetectionConfigError::MissingParameter {
            id: id.to_string(),
            name: "window_secs",
        });
    };
    let Some(window_secs) =
        window_value.as_u64().and_then(|value| if value >= 1 { Some(value) } else { None })
    else {
        return Err(send(id, "window_secs", "must be an integer >= 1".to_string()));
    };

    let Some(threshold_value) = parameters.get("threshold") else {
        return Err(DetectionConfigError::MissingParameter {
            id: id.to_string(),
            name: "threshold",
        });
    };
    let Some(threshold) =
        threshold_value.as_u64().and_then(|value| if value >= 1 { Some(value) } else { None })
    else {
        return Err(send(
            id,
            "threshold",
            format!("must be an integer >= 1 ({threshold_noun} count)"),
        ));
    };

    Ok((window_secs, threshold, threshold_noun))
}

/// 文字列パラメータ取得、なければ空文字。
fn string_param<'a>(parameters: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    parameters.get(key).and_then(Value::as_str)
}

/// 文字列リスト取得、なければ空（tags / mitigation_suggestions は必須ではない）。
fn string_list(parameters: &Map<String, Value>, key: &str) -> Vec<String> {
    let Some(list) = parameters.get(key).and_then(Value::as_array) else {
        return Vec::new();
    };
    list.iter().filter_map(Value::as_str).map(ToOwned::to_owned).collect()
}

/// 既知/許可とみなす宛先の IP/CIDR 範囲。
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
                Ok(addr) => {
                    return Ok(Self {
                        network: value_of(addr),
                        mask: if addr.is_ipv4() { u128::from(u32::MAX) } else { u128::MAX },
                        v4: addr.is_ipv4(),
                    });
                }
                Err(_) => return Err(invalid("must be an IP address or `ip/prefix` CIDR")),
            },
        };
        let addr = addr_part
            .trim()
            .parse::<IpAddr>()
            .map_err(|_| invalid("`ip/prefix` : IP part is invalid"))?;
        let prefix = prefix_part
            .trim()
            .parse::<u32>()
            .map_err(|_| invalid("`ip/prefix` : prefix is invalid"))?;

        let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max_prefix {
            return Err(invalid("prefix length exceeds the address family limit"));
        }
        let addr_value = value_of(addr);
        let mask = if prefix == 0 {
            0
        } else if addr.is_ipv4() {
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
#[allow(dead_code)] // wired into DetectionEngine in Task 3
pub(crate) fn private_ranges() -> Vec<CidrRange> {
    [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "fd00::/8",
        "fc00::/7",
        "::1/128",
        "fe80::/10",
    ]
    .iter()
    .map(|entry| CidrRange::parse(entry).expect("static private range parses fine"))
    .collect()
}

#[derive(Debug, Default, Deserialize)]
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
#[allow(dead_code)] // wired into DetectionEngine in Task 3
pub(crate) fn load_rules(
    path: &Path,
) -> Result<(Vec<CidrRange>, Vec<CompiledRule>), DetectionConfigError> {
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
    let rules = document.rules.into_iter().map(compile).collect::<Result<Vec<_>, _>>()?;

    Ok((allowlist, rules))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_config(
        id: &str,
        rule_type: RuleType,
        severity: Severity,
        confidence: f32,
    ) -> RuleConfig {
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
        assert_eq!(
            serde_yaml::from_str::<RuleType>("threshold").unwrap_err().to_string(),
            "unknown variant `threshold`, expected `stateless` or `window`"
        );
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
        let rule =
            compile(rule_config("EXT-001", RuleType::Stateless, Severity::High, 0.8)).unwrap();
        assert!(rule.enabled);
        assert!(matches!(rule.action, RuleParameters::UnknownExternalDestination));
        assert!(rule.description_template.is_empty());
    }

    #[test]
    fn compile_ext002_builds_port_map() {
        let mut config = rule_config("EXT-002", RuleType::Stateless, Severity::Medium, 0.8);
        config.parameters = serde_json::from_str::<serde_json::Map<String, serde_json::Value>>(
            r#"{"service_expected_ports": {"8080": [443, 80]}}"#,
        )
        .unwrap();
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
        config.parameters =
            serde_json::from_str(r#"{"service_expected_ports": {"http": [443]}}"#).unwrap();
        let err = compile(config).unwrap_err();
        assert!(matches!(
            err,
            DetectionConfigError::InvalidParameter { name: "service_expected_ports", .. }
        ));

        // list items must be valid u16 ports
        let mut config = rule_config("EXT-002", RuleType::Stateless, Severity::Medium, 0.8);
        config.parameters =
            serde_json::from_str(r#"{"service_expected_ports": {"8080": [443, 70000]}}"#).unwrap();
        let err = compile(config).unwrap_err();
        assert!(matches!(
            err,
            DetectionConfigError::InvalidParameter { name: "service_expected_ports", .. }
        ));
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
        config.parameters =
            serde_json::from_str(r#"{"window_secs": 60, "threshold": 20}"#).unwrap();
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

        let err =
            compile(rule_config("EXT-999", RuleType::Stateless, Severity::High, 0.8)).unwrap_err();
        assert!(matches!(err, DetectionConfigError::UnknownRuleId(id) if id == "EXT-999"));
    }

    #[test]
    fn compile_rejects_out_of_range_confidence() {
        let err =
            compile(rule_config("EXT-001", RuleType::Stateless, Severity::High, 1.5)).unwrap_err();
        assert!(
            matches!(err, DetectionConfigError::ConfidenceOutOfRange { value, .. } if value == 1.5)
        );
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
