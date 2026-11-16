//! 検知エンジン: ExportedFlow をルール群で評価し SecurityEvent を生成する。
//!
//! singleton ownership: processor タスクが 1 つだけ所有し、`&mut evaluate` で
//! window 更新する。Arc/ロックは不要 (spec「配線」節)。

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use sentinel_flow::ExportedFlow;

use crate::event::{SecurityEvent, build_event, fill_template};
use crate::rules::{
    CidrRange, DetectionConfigError, RuleConfig, RuleParameters, compile, load_rules,
    private_ranges,
};

/// SCAN ウィンドウ (rule id × source IP × window_secs 単位)。再起動で捨てる仕様 (spec 合意)。
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
    windows: HashMap<(String, IpAddr, u64), ScanWindow>, // (rule_id, source_ip, window_secs) → window
}

impl DetectionEngine {
    /// テスト/手動構築用。allowlist はテキスト (ip / cidr) のリスト。
    pub fn new(
        allowlist: Vec<String>,
        rules: Vec<RuleConfig>,
    ) -> Result<Self, DetectionConfigError> {
        let allowlist = parse_allowlist(&allowlist)?;
        let mut rules = rules.into_iter().map(compile).collect::<Result<Vec<_>, _>>()?;
        rules.retain(|rule| rule.enabled); // 無効ルールは検証対象外 (Task 1 で検証済み)
        Ok(Self { allowlist, private_ranges: private_ranges(), rules, windows: HashMap::new() })
    }

    /// YAML ルールファイルから構築。パース・コンパイルで全エラーを fail-fast。
    pub fn load(path: &Path) -> Result<Self, DetectionConfigError> {
        let (allowlist, mut rules) = load_rules(path)?;
        rules.retain(|rule| rule.enabled);
        Ok(Self { allowlist, private_ranges: private_ranges(), rules, windows: HashMap::new() })
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
        // 同時に触るため。`for` だと rule を借用したまま windows を更新できず排他借用エラーに
        // なる。Task 4 の scan arm もこの構造に乗る。ルール順序を YAML 定義順に保持する。
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
                let expected = ports_by_source.get(&flow.source_port)?;
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
            RuleParameters::PortScan { window_secs, threshold } => {
                let (window_secs, threshold) = (*window_secs, *threshold);
                // `rule` は `self.rules` を借用したまま。scan 評価は `&mut self` を必要とし
                // method 呼び出しでは field 分割が効かないため、clone して借用を切る
                // (brief Step 3 の fallback 方針)。
                let rule = rule.clone();
                self.scan_evaluation(
                    &rule,
                    flow,
                    source_ip,
                    destination_ip,
                    ScanMarker::Ports,
                    window_secs,
                    threshold,
                )
            }
            RuleParameters::NetworkScan { window_secs, threshold } => {
                let (window_secs, threshold) = (*window_secs, *threshold);
                let rule = rule.clone();
                self.scan_evaluation(
                    &rule,
                    flow,
                    source_ip,
                    destination_ip,
                    ScanMarker::Addresses,
                    window_secs,
                    threshold,
                )
            }
        }
    }

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

        let window = self
            .windows
            .entry((rule.id.clone(), source_ip, window_secs))
            .or_insert_with(ScanWindow::new);
        match marker {
            ScanMarker::Ports => {
                window.destination_ports.insert(flow.destination_port);
            }
            ScanMarker::Addresses => {
                window.destination_ips.insert(destination_ip);
            }
        }
        let count = match marker {
            ScanMarker::Ports => window.destination_ports.len(),
            ScanMarker::Addresses => window.destination_ips.len(),
        } as u64;

        if count <= threshold || window.fired {
            return None;
        }
        window.fired = true;
        let description = fill_template(
            &rule.description_template,
            &[("threshold", threshold), ("window_secs", window_secs)],
        );
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
        self.windows.retain(|(_rule_id, _source_ip, window_secs), window| {
            window.first_seen.elapsed() < Duration::from_secs(*window_secs)
        });
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

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use sentinel_flow::ExportedFlow;

    use crate::rules::{RuleConfig, RuleType, Severity};

    use super::*;

    fn flow(
        source_ip: &str,
        source_port: u16,
        destination_ip: &str,
        destination_port: u16,
    ) -> ExportedFlow {
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
            source_namespace: None,
            source_pod: None,
            source_deployment: None,
            source_service: None,
            source_app: None,
            destination_namespace: None,
            destination_pod: None,
            destination_deployment: None,
            destination_service: None,
            destination_app: None,
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
        rule(
            "EXT-002",
            "unexpected_port",
            RuleType::Stateless,
            r#"{service_expected_ports: {"8080": [443, 80]}}"#,
        )
    }

    fn window_rule(
        id: &'static str,
        name: &'static str,
        window_secs: u64,
        threshold: u64,
    ) -> RuleConfig {
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
        )
        .unwrap();
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
        // build_event の pass-through フィールドも検証する。
        assert_eq!(events[0].rule_name, "unknown_external_destination");
        assert_eq!(events[0].confidence, 0.8);
        assert_eq!(events[0].source_ip, "10.0.0.9".parse::<IpAddr>().unwrap());
        assert_eq!(events[0].destination_ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert!(!events[0].event_id.is_nil());
        assert!(events[0].timestamp <= chrono::Utc::now());
        // ルールが stateless なので同じ宛先でも各 flow で再発火する。
        assert_eq!(engine.evaluate(&flow("10.0.0.9", 44321, "8.8.8.8", 443)).len(), 1);
    }

    #[test]
    fn event_carries_rule_metadata_and_template() {
        let configured = rule(
            "EXT-001",
            "unknown_external_destination",
            RuleType::Stateless,
            r#"{description: "Outbound to unknown external {destination_port}", tags: ["outbound"], mitigation_suggestions: ["Verify destination."]}"#,
        );
        let mut engine = DetectionEngine::new(Vec::new(), vec![configured]).unwrap();
        let events = engine.evaluate(&flow("10.0.0.9", 44321, "8.8.8.8", 443));
        assert_eq!(events.len(), 1);
        let event = &events[0];
        assert!(!event.event_id.is_nil());
        assert!(event.timestamp <= chrono::Utc::now());
        assert_eq!(event.severity, Severity::High);
        assert_eq!(event.confidence, 0.8);
        assert_eq!(event.source_ip, "10.0.0.9".parse::<IpAddr>().unwrap());
        assert_eq!(event.destination_ip, "8.8.8.8".parse::<IpAddr>().unwrap());
        assert_eq!(event.destination_port, 443);
        assert_eq!(event.protocol, "TCP");
        // fill_template は未知プレースホルダを残す (EXT 系の説明文は実値を持たない)。
        assert_eq!(event.description, "Outbound to unknown external {destination_port}");
        assert_eq!(event.tags, vec!["outbound".to_string()]);
        assert_eq!(event.mitigation_suggestions, vec!["Verify destination.".to_string()]);
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

    /// 接触できない engine.windows の first_seen を窓切れギリギリに戻す。
    fn expire_window(engine: &mut DetectionEngine, seconds_back: u64) {
        for window in engine.windows.values_mut() {
            window.first_seen = Instant::now() - Duration::from_secs(seconds_back);
        }
    }

    #[test]
    fn scan001_fires_once_threshold_crossed() {
        let mut engine =
            DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)])
                .unwrap();
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
        let mut engine =
            DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 5)])
                .unwrap();
        for port in [80u16, 443, 22, 1433] {
            assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", port)).is_empty());
        }
    }

    #[test]
    fn scan001_repeated_destination_port_does_not_grow_window() {
        let mut engine =
            DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)])
                .unwrap();
        assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
        assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
        // window count = 1 distinct port (threshold 2) so repeated flows on the same port never fire
        assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
    }

    #[test]
    fn scan001_does_not_refire_within_window() {
        let mut engine =
            DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)])
                .unwrap();
        let mut fired = 0;
        for port in [443u16, 80, 22] {
            fired += engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", port)).len();
        }
        assert_eq!(fired, 1, "third distinct port crosses the threshold exactly once");
        assert!(
            engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 33)).is_empty(),
            "flow 4 should not fire (fired=true in window)"
        );
        assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 55)).is_empty());
    }

    #[test]
    fn scan001_window_reset_after_expiry() {
        let mut engine =
            DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)])
                .unwrap();
        assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
        expire_window(&mut engine, 61);
        // 新しい window で再評価 (threshold 2, count=1) → 発火しない、window は新しく作り直し
        let events = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443));
        assert!(events.is_empty());
        assert_eq!(engine.active_windows(), 1);
    }

    #[test]
    fn scan002_counts_distinct_destination_ips() {
        let mut engine = DetectionEngine::new(
            Vec::new(),
            vec![window_rule("SCAN-002", "network_scanning", 60, 2)],
        )
        .unwrap();
        assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty());
        assert!(engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.2", 443)).is_empty());
        let events = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.3", 443));
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].rule_id, "SCAN-002");
    }

    #[test]
    fn scan_windows_are_per_source_ip() {
        let mut engine =
            DetectionEngine::new(Vec::new(), vec![window_rule("SCAN-001", "port_scanning", 60, 2)])
                .unwrap();
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
        let mut engine = DetectionEngine::new(
            Vec::new(),
            vec![ext001(), window_rule("SCAN-001", "port_scanning", 60, 2)],
        )
        .unwrap();
        let first = engine.evaluate(&flow("10.0.0.9", 49152, "8.8.8.8", 443)); // EXT-001 fires now
        assert_eq!(first.len(), 1);
        let second = engine.evaluate(&flow("10.0.0.9", 49152, "8.8.8.8", 80)); // EXT-001 fires; scan count 2 (未超)
        assert_eq!(second.len(), 1);
        let third = engine.evaluate(&flow("10.0.0.9", 49152, "8.8.8.8", 22)); // EXT-001 + SCAN-001
        let rule_ids: Vec<&str> = third.iter().map(|event| event.rule_id.as_str()).collect();
        assert_eq!(rule_ids, vec!["EXT-001", "SCAN-001"]);
    }

    #[test]
    fn scan001_and_scan002_with_same_window_secs_fire_independently() {
        let mut engine = DetectionEngine::new(
            Vec::new(),
            vec![
                window_rule("SCAN-001", "port_scanning", 60, 2),
                window_rule("SCAN-002", "network_scanning", 60, 2),
            ],
        )
        .unwrap();
        assert!(
            engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.1", 443)).is_empty(),
            "1 distinct port/ip does not cross threshold 2"
        );
        assert!(
            engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.2", 80)).is_empty(),
            "2 distinct ports/ips do not cross threshold 2"
        );
        // 3 distinct ports and 3 distinct IPs → both rules cross threshold 2 in the same
        // flow. With a shared (source_ip, window_secs) key the first rule's `fired` flag
        // would suppress the second until expiry.
        let events = engine.evaluate(&flow("10.0.0.9", 49152, "203.0.113.3", 22));
        let rule_ids: Vec<&str> = events.iter().map(|event| event.rule_id.as_str()).collect();
        assert_eq!(rule_ids, vec!["SCAN-001", "SCAN-002"]);
    }
}
