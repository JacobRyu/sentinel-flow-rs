# Role

あなたは Staff Software Engineer / Principal Engineer / Security Architect として振る舞ってください。

Rust、Network Security、Distributed Systems、Cloud Native、Kubernetes、Kafka、Observability、Zero Trust Architecture に精通している前提で、技術的に妥当性の高いシステム設計を行ってください。

# Project

Project name:

`sentinel-flow-rs`

Concept:

Rustで実装するNetwork Security Visibility & Detection Platform。

自社サービスのネットワーク通信を観測し、Network Flowを生成・分析することで、通常とは異なる通信やSecurity Eventを検知する。

将来的には以下へ拡張する。

```text
Network Visibility
    ↓
Asset Discovery
    ↓
Traffic Analysis
    ↓
Security Detection
    ↓
Risk Analysis
    ↓
Zero Trust
    ↓
AI-assisted Security Analysis
```

ただし、現在は最小構成のInternal Security Monitoring Platformを対象とし、SaaS化やMulti-Tenantは将来構想として扱う。

# Primary Goal

以下を満たす設計ドキュメントを作成してください。

1. 自社サービスに導入可能な最小構成を定義する
2. Rust Security Sensorの責務を明確にする
3. Network PacketからNetwork Flow / Security Eventへ変換する設計を定義する
4. 既存のPrometheus / GrafanaなどのObservability基盤との責務分担を明確にする
5. Security Monitoringとしてどのような価値を提供するか明確にする
6. 将来的なKafka / Kubernetes / ClickHouse / Zero Trust / AIへの拡張性を考慮する
7. 過剰設計を避け、MVPとして実装可能な範囲を明確にする

# Important Design Principle

「パケットを大量に保存するシステム」を作ることを目的にしない。

以下を重視する。

```text
Raw Packet
    ↓
Packet Parsing
    ↓
Flow Aggregation
    ↓
Security-relevant Telemetry
    ↓
Detection
    ↓
Security Event
```

最終的に価値を持つのはPacketそのものではなく、

- 誰が
- どこから
- どこへ
- どのProtocolで
- どのPortを使い
- どれくらい通信し
- 通常と比べて異常か

を判断できる情報である。

# Architecture Scope

最低限、以下のコンポーネントを検討する。

```text
Application / Kubernetes
        ↓
Rust Security Sensor
        ↓
Network Flow
        ↓
Storage / Stream
        ↓
Detection Engine
        ↓
Dashboard / Alert
```

将来的な構成として、

```text
Rust Sensor
    ↓
Kafka
    ↓
Stream Processing
    ↓
ClickHouse
    ↓
Detection Engine
    ↓
Security Dashboard
    ↓
AI Security Analyst
```

を検討する。

# Required Sections

設計ドキュメントには以下の章を含めること。

## 1. Overview

- Project purpose
- Problem statement
- Target users
- Expected value
- Non-goals
- Current MVP scope
- Future scope

## 2. Problem Definition

既存のPrometheus / Grafana / Application Logs / Distributed Tracingでは取得しにくい情報を明確にする。

特に、

```text
Application Observability
vs
Network Security Visibility
```

の違いを説明する。

「Prometheusを置き換える」のではなく、既存Observability基盤を補完することを基本方針とする。

## 3. Use Cases

最低限、以下を検討する。

- Unexpected external communication
- Unexpected port communication
- Unusual traffic volume
- Connection spike
- Port scanning
- Unknown destination
- Unexpected service-to-service communication
- Network topology discovery
- Kubernetes workload communication analysis

各Use Caseについて、

- Detection method
- Required data
- False positive risk
- Detection limitations

を説明する。

## 4. System Architecture

システム構成図を作成する。

最低限、

```text
Customer/Internal Service
        ↓
Rust Sensor
        ↓
Flow
        ↓
Kafka or direct storage
        ↓
Detection
        ↓
Storage
        ↓
Dashboard
```

を示す。

MVP ArchitectureとFuture Architectureを分ける。

## 5. Rust Security Sensor

Sensorの責務を詳細に定義する。

検討対象:

- Packet Capture
- Ethernet parsing
- IPv4 / IPv6
- TCP / UDP
- Flow identification
- Flow aggregation
- Packet counters
- Byte counters
- Connection duration
- TCP flags
- Timestamp
- Local buffering
- Backpressure
- Filtering
- Sampling
- Serialization
- Secure transmission

pnetを採用する場合は、

- pnetを採用する理由
- pnetの限界
- libpcap
- AF_PACKET
- eBPF
- XDP

などの代替技術との比較を行う。

「pnetを使うこと自体」が目的にならないようにする。

## 6. Network Flow Model

Flowのデータモデルを定義する。

例:

```json
{
  "timestamp": "...",
  "source_ip": "...",
  "destination_ip": "...",
  "source_port": 12345,
  "destination_port": 443,
  "protocol": "TCP",
  "packets": 120,
  "bytes": 182034,
  "duration_ms": 1200
}
```

必要に応じて、

- service identity
- pod
- namespace
- node
- application
- environment

などのMetadataを追加する。

Raw PacketとFlow/Eventの使い分けも説明する。

## 7. Storage Design

以下を比較する。

- PostgreSQL
- Elasticsearch / OpenSearch
- ClickHouse
- S3
- Kafka retention

特に、

- Write throughput
- Query performance
- Storage cost
- Retention
- Aggregation
- Time-series workload
- Security investigation workload

を比較し、MVPで採用するStorageを決定する。

## 8. Kafka Design

Kafkaを導入する場合、

- Topic design
- Partition key
- Ordering
- Consumer groups
- Retention
- Replay
- Backpressure
- Delivery semantics
- Failure handling

を設計する。

ただし、「Kafkaを使うことが目的」にならないようにする。

MVPでKafkaが本当に必要かも評価する。

## 9. Detection Engine

Rule-based Detectionを最初の実装とする。

例:

```text
IF destination is unknown
AND outbound_bytes > threshold
THEN security_event = suspicious_external_communication
```

検討するDetection:

- Static rules
- Threshold rules
- Baseline-based detection
- Anomaly detection

AI/MLを初期MVPに入れるべきかについても判断する。

## 10. Kubernetes Integration

Kubernetes環境でのDeployment方式を設計する。

候補:

- DaemonSet
- Sidecar
- Host process
- eBPF-based collector

特に、

```text
Pod
Service
Namespace
Deployment
Node
IP
```

をNetwork Flowに関連付ける方法を検討する。

## 11. Observability Integration

既存Observabilityとの関係を明確にする。

```text
Prometheus
    ↓
Application / Infrastructure Metrics

Logs
    ↓
Application Events

Tracing
    ↓
Request Flow

SentinelFlow
    ↓
Network Flow / Security Events
```

さらに、

```text
Metrics
+
Logs
+
Traces
+
Network Flow
        ↓
Correlation
        ↓
Security Investigation
```

という将来構想を検討する。

## 12. Security Architecture

Security Sensor自身のSecurityを設計する。

最低限、

- TLS / mTLS
- Authentication
- Authorization
- Secret management
- Data encryption
- Sensitive data handling
- IP anonymization
- Payload handling
- Log security
- Sensor tampering
- Least privilege

を検討する。

## 13. Privacy / Data Protection

Network trafficには機密情報が含まれる可能性があるため、

- Raw packetを保存するか
- Payloadを保存するか
- IP addressの扱い
- User information
- TLS encrypted traffic
- Data retention

について明確な方針を決める。

## 14. Performance

以下を設計する。

- Packets/sec
- Network throughput
- CPU usage
- Memory usage
- Flow aggregation memory
- GCではなくRust ownershipによるmemory management
- Backpressure
- Packet loss
- Sampling
- Batch processing

特に、

> Sensor自身が監視対象サービスの性能を悪化させる

という問題を防ぐ設計を検討する。

## 15. Reliability

Failure scenarioを整理する。

最低限、

```text
Sensor Down
Kafka Down
Storage Down
Network Disconnected
Detection Engine Down
High Traffic
Memory Pressure
Packet Loss
```

について、

- Detection impact
- Data loss
- Recovery
- Buffering
- Retry
- Backpressure

を設計する。

## 16. Zero Trust Relationship

Zero Trustとの関係を正確に整理する。

重要:

SentinelFlowそのものを「Zero Trust Architecture」と表現しない。

現在は、

```text
Network Visibility
        ↓
Continuous Monitoring
        ↓
Risk Context
```

としてZero Trustを支援する基盤と位置付ける。

将来的には、

```text
Identity
+
Device
+
Application
+
Resource
+
Network
        ↓
Risk Evaluation
        ↓
Policy Decision
```

へ拡張する可能性を検討する。

## 17. Threat Model

STRIDEなどの観点を利用し、

- Sensor compromise
- False data injection
- Data exfiltration
- Sensor bypass
- Log tampering
- Kafka compromise
- Dashboard compromise

などを分析する。

## 18. Alternatives / Trade-offs

最低限、以下を比較する。

### Capture

- pnet
- libpcap
- AF_PACKET
- eBPF
- XDP

### Processing

- Rust local processing
- Kafka
- Flink
- Kafka Streams

### Storage

- PostgreSQL
- OpenSearch
- ClickHouse
- S3

### Deployment

- DaemonSet
- Sidecar
- Dedicated host sensor

各比較について、

- Pros
- Cons
- Performance
- Complexity
- Cost
- Operational burden
- Recommended use case

を説明する。

## 19. MVP Definition

「最初に何を作るか」を明確にする。

MVPでは以下を優先する。

```text
Packet Capture
    ↓
TCP/IP Parsing
    ↓
Flow Aggregation
    ↓
ClickHouse
    ↓
Basic Detection
    ↓
Dashboard
```

Kafka / Kubernetes integration / AI / Zero Trust Policy Enforcementなどは、MVPに必須かどうかを判断する。

## 20. Implementation Roadmap

以下の順番で段階化する。

```text
Phase 1
Rust Packet Capture

Phase 2
Flow Engine

Phase 3
Storage

Phase 4
Dashboard

Phase 5
Detection

Phase 6
Kafka

Phase 7
Kubernetes Metadata

Phase 8
Risk Analysis

Phase 9
Zero Trust Integration

Phase 10
AI Security Analyst
```

各Phaseについて、

- Goal
- Deliverables
- Technical challenges
- Acceptance criteria

を定義する。

## 21. Repository Architecture

GitHub repository:

`sentinel-flow-rs`

Rust Workspaceを前提に、適切なディレクトリ構成を提案する。

例:

```text
sentinel-flow-rs/
├── crates/
│   ├── sensor/
│   ├── packet-parser/
│   ├── flow-engine/
│   └── detection/
├── docs/
├── deploy/
├── tests/
├── Cargo.toml
└── README.md
```

ただし、これは例であり、設計上より良い構成があれば変更する。

## 22. Architecture Decision Records

重要な技術選定についてADRを作成する。

最低限、

- ADR-001: Packet capture technology
- ADR-002: Flow data model
- ADR-003: Storage selection
- ADR-004: Kafka adoption
- ADR-005: Kubernetes deployment model

を提案する。

# Architecture Review Requirements

設計を作る際は、単に「この構成が良い」と結論付けない。

各重要な意思決定について、

```text
Problem
↓
Options
↓
Constraints
↓
Trade-offs
↓
Decision
↓
Consequences
```

の順番で説明する。

特に以下を厳しくレビューする。

- Over-engineering
- Premature Kafka adoption
- Excessive raw packet storage
- Excessive CPU / memory usage
- False positives
- Security/privacy risks
- Operational complexity
- Kubernetes privilege requirements
- Vendor lock-in
- Future scalability

# Important Constraints

以下を守る。

1. 現在の目的は「自社サービスのInternal Security Monitoring」
2. SaaS化はFuture Scope
3. Multi-TenantはMVP対象外
4. Zero Trust Policy EnforcementはMVP対象外
5. AIはMVP対象外
6. Prometheus/Grafanaを置き換えない
7. Packet captureそのものを目的にしない
8. Security Event / Flowを中心に設計する
9. 実装可能性を優先する
10. Rustを使う理由を明確にする

# Expected Output

最終的に、GitHub repository `sentinel-flow-rs` の `docs/architecture.md` としてそのまま利用できる品質の設計ドキュメントを作成してください。

最後に必ず以下をまとめてください。

### Architecture Decision Summary

| Decision | Choice | Reason |
|---|---|---|

### MVP Architecture

```text
[Architecture Diagram]
```

### Future Architecture

```text
[Architecture Diagram]
```

### Main Risks

| Risk | Impact | Mitigation |
|---|---|---|

### Future Evolution

```text
Network Visibility
        ↓
Security Detection
        ↓
Risk Analysis
        ↓
Zero Trust
        ↓
AI Security Analyst
```

また、設計上まだ決定できない事項については勝手に決定せず、

`Open Questions`

として最後に列挙してください。

# Quality Bar

この設計は単なるRust学習用サンプルではなく、

**Staff Engineer / Security Architectが実際のProduction Systemを設計する際のArchitecture Design Document**

としてレビューしてください。

特に「なぜこの設計なのか」「他の設計ではなぜないのか」「どの条件で設計を変更すべきか」を明確にしてください。