# SentinelFlow-rs Architecture Design Document

> **Version**: 0.1.0
> **Status**: Draft
> **Last Updated**: 2026-09-16
> **Author**: Architecture Team

---

## Table of Contents

1. [Overview](#1-overview)
2. [Problem Definition](#2-problem-definition)
3. [Use Cases](#3-use-cases)
4. [System Architecture](#4-system-architecture)
5. [Rust Security Sensor](#5-rust-security-sensor)
6. [Network Flow Model](#6-network-flow-model)
7. [Storage Design](#7-storage-design)
8. [Kafka Design](#8-kafka-design)
9. [Detection Engine](#9-detection-engine)
10. [Kubernetes Integration](#10-kubernetes-integration)
11. [Observability Integration](#11-observability-integration)
12. [Security Architecture](#12-security-architecture)
13. [Privacy / Data Protection](#13-privacy--data-protection)
14. [Performance](#14-performance)
15. [Reliability](#15-reliability)
16. [Zero Trust Relationship](#16-zero-trust-relationship)
17. [Threat Model](#17-threat-model)
18. [Alternatives / Trade-offs](#18-alternatives--trade-offs)
19. [MVP Definition](#19-mvp-definition)
20. [Implementation Roadmap](#20-implementation-roadmap)
21. [Repository Architecture](#21-repository-architecture)
22. [Architecture Decision Records](#22-architecture-decision-records)

---

## 1. Overview

### 1.1 Project Purpose

SentinelFlow-rs is a **Network Security Visibility & Detection Platform** implemented in Rust. It captures network traffic at the host level, transforms raw packets into structured Network Flow telemetry, and applies detection logic to identify security-relevant anomalies in real time.

The system answers a fundamental question that existing application-level observability cannot:

> **"What is actually happening on the network, independent of what applications report?"**

### 1.2 Problem Statement

Modern cloud-native infrastructure relies heavily on application-level observability (Prometheus metrics, application logs, distributed tracing). While these provide deep insight into application behavior, they share a critical blind spot:

- **Applications only report what they choose to.** Malware, compromised containers, misconfigured sidecars, and layer-7 exploits can communicate freely without generating application-level telemetry.
- **Network-level truth is independent.** A TCP connection exists regardless of whether either endpoint logs it. DNS queries happen regardless of application tracing.
- **East-west traffic in Kubernetes is largely unmonitored.** Pod-to-pod communication within a cluster generates minimal application-level security signals.
- **Existing network monitoring tools are either too heavy (full packet capture) or too shallow (NetFlow exporters on routers).** There is no lightweight, host-level, programmable network visibility tool designed for cloud-native environments.

### 1.3 Target Users

| User Role | Primary Concern |
|---|---|
| Security Engineers | Detect unauthorized communication, lateral movement, data exfiltration |
| Platform Engineers | Validate network policies, discover service topology, troubleshoot connectivity |
| SRE / DevOps | Correlate network anomalies with application incidents |
| Compliance / Audit | Prove network segmentation, maintain network activity records |

### 1.4 Expected Value

- **Detection of blind spots**: Identify communication paths that application-level observability cannot see
- **Network-level asset discovery**: Automatically discover what services communicate, how, and how much
- **Security baseline establishment**: Learn normal network behavior to detect deviations
- **Compliance support**: Maintain auditable network flow records
- **Zero Trust enablement**: Provide the network visibility layer required for Zero Trust risk evaluation

### 1.5 Non-Goals

| Non-Goal | Reason |
|---|---|
| Full packet capture / PCAP storage | Storage cost prohibitive; privacy concerns; use existing tools for packet-level forensics |
| SaaS offering | Current scope is internal deployment only |
| Multi-tenant architecture | Not needed for internal platform |
| Zero Trust policy enforcement | SentinelFlow provides visibility; policy enforcement is a separate system |
| AI/ML-based detection in MVP | Rule-based detection is sufficient for initial deployment; ML adds operational complexity |
| Replacing Prometheus/Grafana | Complementary system; does not replace application-level observability |
| Deep packet inspection (L7) | Out of scope for MVP; encrypted traffic makes DPI limited in value |
| Real-time packet modification / blocking | Observation-only system; does not alter traffic |

### 1.6 Current MVP Scope

The MVP delivers:

```
Packet Capture (AF_PACKET)
    ↓
TCP/IP Parsing (Ethernet → IPv4/IPv6 → TCP/UDP)
    ↓
Flow Aggregation (5-tuple + counters + duration)
    ↓
ClickHouse Storage
    ↓
Rule-based Detection
    ↓
Grafana Dashboard
```

### 1.7 Future Scope

```
Kafka (event streaming)
    ↓
Kubernetes Metadata Enrichment
    ↓
Stream Processing (Flink / Kafka Streams)
    ↓
ClickHouse (expanded retention + analytics)
    ↓
Anomaly Detection / ML
    ↓
Zero Trust Risk Evaluation
    ↓
AI-assisted Security Analysis
```

---

## 2. Problem Definition

### 2.1 Application Observability vs. Network Security Visibility

| Dimension | Application Observability (Prometheus/Grafana) | Network Security Visibility (SentinelFlow) |
|---|---|---|
| **Data Source** | Application-instrumented code | Network interface (raw packets) |
| **Trust Model** | Application is the source of truth | Network is the source of truth |
| **Coverage** | Only instrumented code paths | All traffic on the interface |
| **Blind Spots** | Malware, compromised processes, misconfigurations | Encrypted payload content, application intent |
| **Latency Insight** | Excellent (tracing) | Connection-level only |
| **Security Relevance** | Indirect (error rates, latency anomalies) | Direct (unauthorized connections, scanning) |
| **East-West Traffic** | Requires per-service instrumentation | Captures all traffic on the host |
| **Spoofability** | Application can lie | Network packets are harder to fake (kernel-level) |

### 2.2 What Application Observability Misses

1. **Compromised process communication**: A process that has been compromised can open arbitrary TCP/UDP connections. Application metrics will not reflect this unless the process has specific instrumentation for connection tracking.

2. **DNS-based exfiltration**: Malware frequently uses DNS tunneling or DNS-based C2 channels. Application-level observability rarely monitors DNS queries at the host level.

3. **Port scanning and reconnaissance**: Internal reconnaissance (port scanning within the cluster) generates network traffic but no application-level signals on the scanning host.

4. **Unauthorized external communication**: A container connecting to an unexpected external IP generates no application-level alert unless an egress policy is explicitly enforced and monitored.

5. **Network policy validation**: Kubernetes NetworkPolicies define allowed traffic patterns, but there is no built-in mechanism to verify that actual traffic matches policy intent.

6. **Service mesh blind spots**: Even with a service mesh (Istio/Linkerd), traffic between non-meshed workloads or traffic that bypasses the proxy is invisible.

### 2.3 Complementary Positioning

SentinelFlow does **not** replace Prometheus, Grafana, or application logging. It adds a new data source:

```text
Prometheus     → Application / Infrastructure Metrics (what applications report)
Logs           → Application Events (what applications write)
Tracing        → Request Flow (what applications trace)
SentinelFlow   → Network Flow / Security Events (what actually happens on the wire)
```

The combination of all four provides defense-in-depth observability. If an application stops reporting correctly (crash, compromise, misconfiguration), the network layer continues to provide visibility.

---

## 3. Use Cases

### 3.1 Unexpected External Communication

| Aspect | Detail |
|---|---|
| **Description** | A service communicates with an IP address outside the expected external dependency list |
| **Detection Method** | Flow matching against allowlist of known external destinations; alert on unmatched outbound flows |
| **Required Data** | Source IP, destination IP, destination port, protocol, byte count |
| **False Positive Risk** | Medium — new legitimate dependencies (SDK updates, CDN changes) may trigger alerts. Mitigated by allowlist maintenance workflow |
| **Detection Limitations** | Cannot determine application intent; encrypted payloads prevent content-based validation |

### 3.2 Unexpected Port Communication

| Aspect | Detail |
|---|---|
| **Description** | A service uses a port outside its declared/expected port set |
| **Detection Method** | Per-service port profile baseline; alert on ports not in the baseline |
| **Required Data** | Source IP, destination port, protocol, service identity (via Kubernetes metadata) |
| **False Positive Risk** | Low-Medium — dynamic port allocation (gRPC, ephemeral ports) may cause noise |
| **Detection Limitations** | Requires accurate service-to-IP mapping; Kubernetes metadata enrichment is critical |

### 3.3 Unusual Traffic Volume

| Aspect | Detail |
|---|---|
| **Description** | A service generates significantly more (or less) traffic than its historical baseline |
| **Detection Method** | Rolling average + standard deviation per service pair; alert when current volume exceeds N standard deviations |
| **Required Data** | Byte counters, packet counters, flow duration, timestamp |
| **False Positive Risk** | Medium — legitimate traffic spikes (deployments, batch jobs, marketing events) may trigger alerts |
| **Detection Limitations** | Requires baseline establishment period; seasonal patterns need longer observation windows |

### 3.4 Connection Spike

| Aspect | Detail |
|---|---|
| **Description** | A service opens an abnormally high number of new connections in a short time window |
| **Detection Method** | Connection rate per source IP; sliding window count with threshold |
| **Required Data** | Flow start timestamps, source IP, destination IP/port |
| **False Positive Risk** | Medium — connection pooling, service restarts, and load spikes are legitimate causes |
| **Detection Limitations** | Short-lived connections may be aggregated away if flow timeout is too long |

### 3.5 Port Scanning

| Aspect | Detail |
|---|---|
| **Description** | A source IP probes multiple destination ports on one or more hosts in rapid succession |
| **Detection Method** | Count unique destination ports per source IP within a time window; threshold-based alert |
| **Required Data** | Source IP, destination IP, destination port, timestamp |
| **False Positive Risk** | Low — legitimate port scanning is rare in production; security scanning tools should be allowlisted |
| **Detection Limitations** | Slow scanning (low-and-slow) evades time-window-based detection; distributed scanning across multiple sources is harder to detect |

### 3.6 Unknown Destination

| Aspect | Detail |
|---|---|
| **Description** | A service connects to an IP not seen before in the baseline or not in the known inventory |
| **Detection Method** | Destination IP allowlist / asset inventory comparison; alert on unknown destinations |
| **Required Data** | Source IP, destination IP, DNS resolution (if available), byte count |
| **False Positive Risk** | Medium — new infrastructure, cloud service IPs, CDN edge servers |
| **Detection Limitations** | IP-based identification is imprecise for cloud services behind shared IPs; requires regular inventory updates |

### 3.7 Unexpected Service-to-Service Communication

| Aspect | Detail |
|---|---|
| **Description** | Two internal services communicate that have no defined dependency in the service catalog |
| **Detection Method** | Service dependency graph baseline; alert on edges not in the graph |
| **Required Data** | Source service identity, destination service identity, port, protocol |
| **False Positive Risk** | Low-Medium — new service integrations need graph updates |
| **Detection Limitations** | Requires accurate service identity resolution (Kubernetes metadata enrichment) |

### 3.8 Network Topology Discovery

| Aspect | Detail |
|---|---|
| **Description** | Automatically discover the communication topology of the cluster from network flow data |
| **Detection Method** | Aggregate flows into a directed graph of service-to-service communication |
| **Required Data** | All flows with Kubernetes metadata enrichment |
| **False Positive Risk** | N/A — this is a discovery feature, not a detection feature |
| **Detection Limitations** | Visibility is limited to the nodes where sensors are deployed; cross-node flows require sensor coverage on both endpoints |

### 3.9 Kubernetes Workload Communication Analysis

| Aspect | Detail |
|---|---|
| **Description** | Analyze communication patterns between Kubernetes workloads (Pods, Deployments, Namespaces) |
| **Detection Method** | Flow aggregation with Kubernetes metadata; namespace-level and deployment-level traffic analysis |
| **Required Data** | Flows enriched with Pod name, Namespace, Deployment, Node, Service labels |
| **False Positive Risk** | N/A — analytical feature |
| **Detection Limitations** | Requires Kubernetes API access for metadata; metadata staleness during rapid scaling events |

---

## 4. System Architecture

### 4.1 MVP Architecture

```text
┌─────────────────────────────────────────────────────┐
│                  Kubernetes Cluster                  │
│                                                     │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐          │
│  │   Pod A   │  │   Pod B   │  │   Pod C   │         │
│  │  (App)    │  │  (App)    │  │  (App)    │         │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘          │
│       │              │              │                │
│  ┌────┴──────────────┴──────────────┴────┐          │
│  │          Linux Network Stack           │          │
│  │       (eth0 / veth pairs)             │          │
│  └────────────────┬──────────────────────┘          │
│                   │                                 │
│  ┌────────────────┴──────────────────────┐          │
│  │       Rust Security Sensor            │          │
│  │   (DaemonSet - one per node)          │          │
│  │                                       │          │
│  │   ┌─────────────┐  ┌──────────────┐  │          │
│  │   │   Packet     │  │    Flow      │  │          │
│  │   │   Capture    │→ │   Engine     │  │          │
│  │   │  (AF_PACKET) │  │              │  │          │
│  │   └─────────────┘  └──────┬───────┘  │          │
│  │                           │           │          │
│  │   ┌───────────────────────┴────────┐  │          │
│  │   │   Kubernetes Metadata          │  │          │
│  │   │   Enricher (optional)          │  │          │
│  │   └───────────────────────┬────────┘  │          │
│  │                           │           │          │
│  │   ┌───────────────────────┴────────┐  │          │
│  │   │   ClickHouse Writer            │  │          │
│  │   │   (Batch + Async)              │  │          │
│  │   └───────────────────────┬────────┘  │          │
│  └───────────────────────────┼──────────┘          │
└──────────────────────────────┼──────────────────────┘
                               │
                    ┌──────────┴──────────┐
                    │    ClickHouse        │
                    │  (Single Node MVP)   │
                    └──────────┬──────────┘
                               │
                    ┌──────────┴──────────┐
                    │   Grafana Dashboard  │
                    │   + Alert Rules      │
                    └─────────────────────┘
```

### 4.2 Future Architecture

```text
┌──────────────────────────────────────────────────────────┐
│                    Kubernetes Cluster                     │
│                                                          │
│  ┌──────────────────────────────────────────┐           │
│  │       Rust Security Sensor (DaemonSet)    │           │
│  │   Packet Capture → Flow Engine → Batch    │           │
│  └──────────────────────┬───────────────────┘           │
└─────────────────────────┼────────────────────────────────┘
                          │
               ┌──────────┴──────────┐
               │      Kafka           │
               │  (Event Streaming)   │
               │                      │
               │  Topic: netflow.raw  │
               │  Topic: events.sec   │
               └──────────┬──────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
    ┌─────────┴──────────┐  ┌────────┴─────────┐
    │  Stream Processing  │  │   ClickHouse      │
    │  (Flink / Kafka     │  │   (Cluster)       │
    │   Streams)          │  │                    │
    │                     │  │   - Flow data      │
    │  - Enrichment       │  │   - Security events│
    │  - Aggregation      │  │   - Aggregations   │
    │  - Windowed detect  │  │                    │
    └─────────┬──────────┘  └────────┬─────────┘
              │                      │
              └──────────┬───────────┘
                         │
              ┌──────────┴──────────┐
              │  Detection Engine    │
              │                      │
              │  - Rule-based        │
              │  - Threshold         │
              │  - Baseline/ML       │
              └──────────┬──────────┘
                         │
              ┌──────────┴──────────┐
              │  Security Dashboard  │
              │  + Alert Manager     │
              └──────────┬──────────┘
                         │
              ┌──────────┴──────────┐
              │  Zero Trust Context  │
              │  (Future)            │
              └──────────┬──────────┘
                         │
              ┌──────────┴──────────┐
              │  AI Security Analyst │
              │  (Future)            │
              └─────────────────────┘
```

### 4.3 Data Flow

```text
Raw Packet (AF_PACKET socket)
    ↓
Ethernet Frame Parsing (pnet)
    ↓
IPv4/IPv6 Header Extraction
    ↓
TCP/UDP Header Extraction
    ↓
5-Tuple Construction (src_ip, dst_ip, src_port, dst_port, protocol)
    ↓
Flow Key Hashing (consistent hash of 5-tuple)
    ↓
Flow Table Lookup (HashMap in memory)
    ↓
  [Flow exists?] → Update counters (packets, bytes, duration, flags)
  [Flow new?]    → Insert new flow entry
    ↓
Flow Timeout Check (inactive timeout: 30s, active timeout: 5min)
    ↓
  [Timeout expired?] → Export flow record, remove from table
    ↓
Kubernetes Metadata Enrichment (IP → Pod/Namespace/Service mapping)
    ↓
Serialization (Protocol Buffers or JSON)
    ↓
Batch Write to ClickHouse (async, buffered)
    ↓
Detection Engine (periodic scan of recent flows)
    ↓
Security Event Generation (on rule match)
    ↓
Alert (webhook / Grafana alerting)
```

### 4.4 Timing Considerations

The flow timeout values directly impact detection latency:

| Detection Rule | Window | Flow Export Delay | Total Detection Latency |
|---|---|---|---|
| CONN-001 (Connection Spike) | 1 min | Up to 30s | Up to 90s |
| SCAN-001 (Port Scanning) | 60s | Up to 30s | Up to 90s |
| VOL-001 (High Volume) | 5 min | Up to 30s | Up to 5.5 min |

**Impact**: Short-lived connections (e.g., port scans completing within seconds) will not appear in ClickHouse until the inactive timeout expires. For time-critical detection, the sensor can emit flow records early when TCP FIN/RST is observed, bypassing the inactive timeout.

---

## 5. Rust Security Sensor

### 5.1 Responsibilities

The Rust Security Sensor is the core component deployed on each node. Its responsibilities are:

| Responsibility | Description |
|---|---|
| **Packet Capture** | Capture raw network packets from the host network interface |
| **Protocol Parsing** | Parse Ethernet, IPv4/IPv6, TCP, UDP, ICMP headers |
| **Flow Identification** | Identify network flows using 5-tuple hashing |
| **Flow Aggregation** | Maintain in-memory flow table; aggregate packet/byte counters |
| **Flow Export** | Export completed flows (by timeout or termination) |
| **Metadata Enrichment** | Enrich flows with Kubernetes metadata (Pod, Namespace, Service) |
| **Local Buffering** | Buffer flow records before batch write |
| **Backpressure** | Apply backpressure when downstream is slow |
| **Filtering** | Optional: filter traffic by interface, protocol, or IP range |
| **Sampling** | Optional: sample flows under high traffic load |
| **Serialization** | Serialize flow records for storage |
| **Secure Transmission** | Transmit flow records securely to storage backend |
| **Self-Monitoring** | Report own health metrics (packet drop rate, flow table size, write latency) |

### 5.2 Packet Capture Technology Selection

#### Problem

We need to capture network packets at the host level in a cloud-native (Kubernetes) environment. The capture mechanism must:

- Run in a container with minimal privileges
- Handle high throughput without excessive CPU usage
- Support both ingress and egress traffic
- Work on Linux (primary target)

#### Options

| Technology | Description | Privilege Level | Performance | Complexity |
|---|---|---|---|---|
| **pnet** | Rust library for packet manipulation | CAP_NET_RAW (via AF_PACKET) | Medium | Low |
| **libpcap (via pcap crate)** | C library wrapper | CAP_NET_RAW | Medium-High | Low |
| **AF_PACKET (raw socket)** | Direct kernel API | CAP_NET_RAW | High | Medium |
| **eBPF (XDP/TC)** | Kernel-level packet processing | CAP_BPF + CAP_NET_ADMIN | Very High | High |
| **XDP** | eBPF at the driver level | CAP_BPF + CAP_NET_ADMIN | Highest | Very High |

#### Constraints

- Must run in a Kubernetes DaemonSet container
- Must not require host network namespace compromise beyond what is necessary
- Must be implementable by a small team in reasonable time
- Must be debuggable and maintainable

#### Trade-offs

**pnet** provides the simplest Rust API for packet parsing but wraps AF_PACKET internally. It is well-suited for the parsing layer but should not be the sole abstraction for capture — raw AF_PACKET socket access provides better control over buffer sizes and capture parameters.

**libpcap** is battle-tested but introduces a C dependency, which complicates cross-compilation and container builds. Rust-native alternatives are preferable.

**AF_PACKET** gives direct access to the kernel's packet capture mechanism with configurable buffer sizes. This is the right capture layer for a Rust sensor.

**eBPF/XDP** offers the highest performance and lowest overhead but requires significant kernel version requirements, BPF CO-RE compilation toolchain, and debugging complexity that is not justified for MVP.

#### Decision

Use **AF_PACKET raw sockets** as the capture mechanism, with **pnet** used only for packet parsing (header extraction). This gives us:

- Direct control over capture buffer sizing
- Zero-copy potential via AF_PACKET ring buffer
- No C dependencies
- Clean separation between capture and parsing layers

eBPF/XDP is a future optimization path for high-throughput environments.

### 5.3 Internal Architecture

```rust
// Conceptual module structure (not final API)

sensor/
├── capture/
│   ├── af_packet.rs      // AF_PACKET socket management
│   ├── buffer.rs         // Ring buffer / zero-copy buffer
│   └── stats.rs          // Capture statistics
├── parser/
│   ├── ethernet.rs       // Ethernet frame parsing
│   ├── ip.rs             // IPv4/IPv6 header parsing
│   ├── tcp.rs            // TCP header parsing
│   ├── udp.rs            // UDP header parsing
│   └── icmp.rs           // ICMP header parsing
├── flow/
│   ├── key.rs            // Flow key (5-tuple)
│   ├── table.rs          // In-memory flow table
│   ├── entry.rs          // Flow entry (counters, timestamps)
│   └── export.rs         // Flow export logic
├── enrichment/
│   └── kubernetes.rs     // Kubernetes metadata resolution
├── output/
│   ├── clickhouse.rs     // ClickHouse writer
│   ├── buffer.rs         // Output buffering
│   └── batch.rs          // Batch assembly
├── config.rs             // Configuration
└── metrics.rs            // Self-monitoring metrics
```

### 5.4 Key Design Decisions

1. **Zero-copy where possible**: AF_PACKET ring buffer allows zero-copy packet capture. Parsing operates on borrowed slices.

2. **Flow table as HashMap**: In-memory flow table using `HashMap<FlowKey, FlowEntry>`. FlowKey is a compact 5-tuple. FlowEntry contains counters and timestamps.

3. **Timeout-based flow export**: Flows are exported when:
   - Inactive timeout (default: 30s) — no packets seen for 30 seconds
   - Active timeout (default: 5 minutes) — long-lived flow periodic export
   - TCP FIN/RST — connection termination detected

4. **Batched writes**: Flow records are batched (default: 1000 records or 1 second) before writing to ClickHouse to amortize write overhead.

5. **Backpressure**: If ClickHouse writes fall behind, the sensor applies backpressure by:
   - Increasing batch sizes
   - Dropping oldest flow records (with metrics)
   - Under extreme pressure: sampling flows

---

## 6. Network Flow Model

### 6.1 Core Flow Record

The fundamental data unit is a Network Flow record, derived from the 5-tuple model used by network monitoring standards (IPFIX/NetFlow):

**IPv4/IPv6 Handling**: IP addresses are stored as `IPv6` type in ClickHouse, supporting dual-stack. IPv4 addresses are mapped to IPv4-mapped IPv6 addresses (::ffff:0:0/96) automatically. The parser handles IPv6 extension headers for flow identification.

```json
{
  "flow_id": "uuid-v4",
  "timestamp_start": "2026-09-16T10:00:00.000Z",
  "timestamp_end": "2026-09-16T10:05:00.000Z",
  "source_ip": "10.244.1.5",
  "destination_ip": "10.244.2.10",
  "source_port": 43210,
  "destination_port": 8080,
  "protocol": "TCP",
  "packets_forward": 120,
  "packets_reverse": 100,
  "bytes_forward": 182034,
  "bytes_reverse": 54321,
  "duration_ms": 300000,
  "tcp_flags_seen": ["SYN", "ACK", "PSH", "FIN"],
  "sensor_node": "node-1",
  "sensor_timestamp": "2026-09-16T10:05:00.100Z"
}
```

### 6.2 Kubernetes Metadata Enrichment

When deployed in Kubernetes, flows are enriched with pod and service metadata:

```json
{
  "flow_id": "uuid-v4",
  "timestamp_start": "2026-09-16T10:00:00.000Z",
  "timestamp_end": "2026-09-16T10:05:00.000Z",
  "source_ip": "10.244.1.5",
  "destination_ip": "10.244.2.10",
  "source_port": 43210,
  "destination_port": 8080,
  "protocol": "TCP",
  "packets_forward": 120,
  "packets_reverse": 100,
  "bytes_forward": 182034,
  "bytes_reverse": 54321,
  "duration_ms": 300000,
  "tcp_flags_seen": ["SYN", "ACK", "PSH", "FIN"],
  "sensor_node": "node-1",

  "source_namespace": "production",
  "source_pod": "api-server-7b8d9f4c5-x2k9m",
  "source_deployment": "api-server",
  "source_service": "api-server",
  "source_app": "api-server",
  "source_labels": {
    "app.kubernetes.io/name": "api-server",
    "app.kubernetes.io/version": "1.2.0"
  },

  "destination_namespace": "production",
  "destination_pod": "database-5c6d7e8f9-a1b2c",
  "destination_deployment": "database",
  "destination_service": "database",
  "destination_app": "postgres",
  "destination_labels": {
    "app.kubernetes.io/name": "database",
    "app.kubernetes.io/version": "14.0"
  }
}
```

### 6.3 Security Event Record

When the detection engine identifies suspicious activity, it generates a Security Event:

```json
{
  "event_id": "uuid-v4",
  "timestamp": "2026-09-16T10:05:00.100Z",
  "event_type": "unexpected_external_communication",
  "severity": "high",
  "confidence": 0.85,
  "source_flow_ids": ["flow-uuid-1", "flow-uuid-2"],
  "source_ip": "10.244.1.5",
  "source_pod": "api-server-7b8d9f4c5-x2k9m",
  "destination_ip": "203.0.113.50",
  "destination_port": 4444,
  "protocol": "TCP",
  "description": "Unexpected outbound connection to unknown external IP on non-standard port",
  "rule_id": "EXT-001",
  "rule_name": "unknown_external_destination",
  "tags": ["exfiltration-suspected", "unauthorized-egress"],
  "mitigation_suggestions": [
    "Verify if 203.0.113.50 is a known dependency",
    "Check NetworkPolicy for egress rules",
    "Inspect pod for compromise indicators"
  ]
}
```

### 6.4 Raw Packet vs. Flow/Event

| Aspect | Raw Packet | Flow Record | Security Event |
|---|---|---|---|
| **Content** | Full packet bytes | Aggregated metadata | Alert with context |
| **Storage Cost** | Very High (~100 bytes/packet) | Low (~200 bytes/flow) | Very Low (~1 KB/event) |
| **Retention** | Minutes to hours | Days to months | Months to years |
| **Use Case** | Forensic packet analysis | Traffic analysis, baseline | Incident response |
| **MVP** | Not stored | Stored | Stored |

**Decision**: The MVP stores **Flow Records** and **Security Events** only. Raw packets are not stored. This is a deliberate design decision driven by storage cost, privacy concerns, and the principle that "the value is in the telemetry, not the packet."

---

## 7. Storage Design

### 7.1 Requirements

| Requirement | Priority |
|---|---|
| High write throughput (thousands of flows/sec per node) | Critical |
| Time-series optimization (flows are inherently time-ordered) | Critical |
| Aggregation queries (GROUP BY source, destination, port, namespace) | High |
| Compression (flow data is highly compressible) | High |
| Reasonable retention (30-90 days for flows, 1 year for events) | High |
| SQL query interface | Medium |
| Operational simplicity (MVP) | Critical |

### 7.2 Options Comparison

| Criteria | PostgreSQL | Elasticsearch/OpenSearch | ClickHouse | S3 (Parquet) |
|---|---|---|---|---|
| **Write Throughput** | Medium (~50K rows/s) | High (~100K docs/s) | Very High (~1M rows/s) | N/A (batch) |
| **Query Performance (aggregation)** | Medium | Medium | Very High | Low |
| **Storage Cost** | High | Very High | Low (10:1 compression) | Very Low |
| **Compression** | None (row-based) | Moderate | Excellent (columnar) | Excellent |
| **Time-Series Workload** | Poor | Moderate | Excellent | Moderate |
| **Security Investigation** | Good (joins) | Good (full-text) | Good (analytics) | Poor |
| **Operational Complexity** | Low | High | Medium | Low |
| **Retention Management** | Manual | ILM policies | TTL / Tiered | Lifecycle policies |
| **Kubernetes Deployment** | StatefulSet | StatefulSet (complex) | Single node / StatefulSet | Managed service |

### 7.3 Decision: ClickHouse

**ClickHouse** is selected for the MVP for the following reasons:

1. **Columnar storage**: Network flow data is highly structured with a fixed schema. Columnar storage provides excellent compression (typically 10:1 or better for flow data) and fast aggregation queries.

2. **Time-series native**: ClickHouse is designed for time-series analytics. Flow data is inherently time-ordered, and ClickHouse's `MergeTree` engine with `ORDER BY (timestamp, source_ip, destination_ip)` provides optimal query patterns.

3. **SQL interface**: ClickHouse supports SQL, making it accessible for Grafana dashboards and ad-hoc investigation queries.

4. **Single-node simplicity**: For MVP, ClickHouse can run as a single-node deployment with `ReplicatedMergeTree` ready for future scaling.

5. **Proven for network telemetry**: ClickHouse is widely used for NetFlow/IPFIX storage in production network monitoring systems.

6. **Low operational burden**: Compared to Elasticsearch (JVM tuning, shard management) or PostgreSQL (VACUUM, index bloat), ClickHouse has lower operational overhead for this use case.

### 7.4 ClickHouse Schema

```sql
CREATE TABLE IF NOT EXISTS network_flows
(
    flow_id           UUID,
    timestamp_start   DateTime64(3, 'UTC'),
    timestamp_end     DateTime64(3, 'UTC'),
    source_ip         IPv6,
    destination_ip    IPv6,
    source_port       UInt16,
    destination_port  UInt16,
    protocol          Enum8('TCP' = 1, 'UDP' = 2, 'ICMP' = 3, 'OTHER' = 4),
    packets_forward   UInt32,
    packets_reverse   UInt32,
    bytes_forward     UInt64,
    bytes_reverse     UInt64,
    duration_ms       UInt32,
    tcp_flags_seen    Array(UInt8),
    sensor_node       LowCardinality(String),

    -- Kubernetes metadata (nullable for non-K8s environments)
    source_namespace      Nullable(LowCardinality(String)),
    source_pod            Nullable(LowCardinality(String)),
    source_deployment     Nullable(LowCardinality(String)),
    source_service        Nullable(LowCardinality(String)),
    source_app            Nullable(LowCardinality(String)),
    destination_namespace Nullable(LowCardinality(String)),
    destination_pod       Nullable(LowCardinality(String)),
    destination_deployment Nullable(LowCardinality(String)),
    destination_service   Nullable(LowCardinality(String)),
    destination_app       Nullable(LowCardinality(String))
)
ENGINE = ReplicatedMergeTree()
PARTITION BY toYYYYMM(timestamp_start)
ORDER BY (source_ip, destination_ip, timestamp_start, source_port, destination_port, protocol)
TTL timestamp_start + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

CREATE TABLE IF NOT EXISTS security_events
(
    event_id          UUID,
    timestamp         DateTime64(3, 'UTC'),
    event_type        LowCardinality(String),
    severity          Enum8('low' = 1, 'medium' = 2, 'high' = 3, 'critical' = 4),
    confidence        Float32,
    source_flow_ids   Array(UUID),
    source_ip         IPv6,
    source_pod        Nullable(LowCardinality(String)),
    destination_ip    IPv6,
    destination_port  UInt16,
    protocol          LowCardinality(String),
    description       String,
    rule_id           LowCardinality(String),
    rule_name         LowCardinality(String),
    tags              Array(LowCardinality(String)),
    mitigation_suggestions Array(String)
)
ENGINE = ReplicatedMergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (event_type, severity, timestamp)
TTL timestamp + INTERVAL 365 DAY
SETTINGS index_granularity = 8192;
```

---

## 8. Kafka Design

### 8.1 Evaluation

#### Problem

Should we introduce Kafka as an intermediate message bus between the sensor and ClickHouse?

#### Options

| Approach | Pros | Cons |
|---|---|---|
| **Direct to ClickHouse** | Simple, low latency, fewer components | Tight coupling, no replay, single point of failure |
| **Kafka in between** | Decoupling, replay, backpressure, fan-out | Added complexity, operational burden, latency |

#### Constraints

- MVP must be deployable and operable by a small team
- Operational complexity must be minimized
- Current expected throughput: ~5K-50K flows/sec cluster-wide

#### Trade-offs

Kafka provides significant value in production-scale deployments:
- **Decoupling**: Sensor and storage can be upgraded independently
- **Replay**: Re-process historical flows for new detection rules
- **Fan-out**: Multiple consumers (ClickHouse, detection engine, archival) without sensor changes
- **Backpressure**: Natural buffer between producers and consumers

However, for MVP:
- **Throughput is manageable**: 5K-50K flows/sec can be handled by ClickHouse directly
- **Operational burden**: Kafka is a distributed system requiring its own monitoring, tuning, and maintenance
- **No immediate replay need**: MVP detection rules are static; reprocessing is not yet a requirement
- **Added failure mode**: Kafka failure would block all flow ingestion

#### Decision

**Do not include Kafka in the MVP.** The sensor writes directly to ClickHouse via HTTP interface with batched inserts.

Kafka is introduced in **Phase 6** of the roadmap when:
- Throughput exceeds ClickHouse direct-write capacity
- Multiple consumers need the same flow stream
- Replay capability is required for detection rule development
- The team has operational capacity for Kafka

### 8.2 Future Kafka Design

When Kafka is adopted, the design follows:

**Topic Design:**
```text
netflow.raw          → Raw flow records from sensors
netflow.enriched     → Flows enriched with K8s metadata
security.events      → Detection engine outputs
```

**Partition Key:** `xxhash3(source_ip, destination_ip, source_port, destination_port, protocol)` — distributes flows evenly across partitions while ensuring all packets of a single flow go to the same partition. Flow-level ordering is not required across flows, so even distribution is prioritized.

**Consumer Groups:**
- `clickhouse-sinker` — writes flows to ClickHouse
- `detection-engine` — reads flows for real-time detection
- `archival` — writes to long-term storage (S3/Parquet)

**Retention:** 7 days (sufficient for replay and reprocessing)

---

## 9. Detection Engine

### 9.1 Architecture

The detection engine operates as a periodic batch process within the sensor (MVP) or as a separate service (future). It evaluates recent flow records against a set of rules.

```text
┌──────────────────┐
│  Flow Records     │
│  (ClickHouse)     │
└────────┬─────────┘
         │
         ↓
┌──────────────────┐
│  Rule Evaluator   │
│                   │
│  ┌─────────────┐  │
│  │ Static Rules│  │
│  └─────────────┘  │
│  ┌─────────────┐  │
│  │Threshold    │  │
│  │Rules        │  │
│  └─────────────┘  │
│  ┌─────────────┐  │
│  │Baseline     │  │
│  │Rules (future)│ │
│  └─────────────┘  │
└────────┬─────────┘
         │
         ↓
┌──────────────────┐
│  Security Events  │
│  (ClickHouse)     │
└───────────────────┘
```

### 9.2 Detection Rules

**Known Limitation**: In the MVP, the detection engine reads from ClickHouse, which means detection queries compete with dashboard/ad-hoc queries for ClickHouse resources. Under high flow volume, this can cause detection latency. Mitigation: use separate ClickHouse user profiles with resource pools, or schedule detection queries during low-traffic periods.

#### Static Rules (MVP)

| Rule ID | Rule Name | Logic | Severity |
|---|---|---|---|
| EXT-001 | Unknown External Destination | `destination_ip NOT IN known_external_ips AND destination_ip NOT IN private_ranges` | High |
| EXT-002 | Unexpected Port | `destination_port NOT IN service_expected_ports[source_service]` | Medium |
| VOL-001 | High Outbound Volume | `SUM(bytes_forward) OVER 5min > threshold * baseline[source_service]` | Medium |
| VOL-002 | Volume Drop | `SUM(bytes_forward) OVER 5min < baseline[source_service] * 0.1` | Low |
| SCAN-001 | Port Scanning | `COUNT(DISTINCT destination_port) > 50 AND time_window < 60s` | Critical |
| SCAN-002 | Network Scanning | `COUNT(DISTINCT destination_ip) > 20 AND time_window < 60s` | Critical |
| CONN-001 | Connection Spike | `COUNT(new_flows) OVER 1min > threshold * baseline[source_ip]` | Medium |
| CONN-002 | Unusual Destination Count | `COUNT(DISTINCT destination_ip) > threshold * baseline[source_service]` | Medium |

#### Threshold Rules (MVP)

Rules with configurable thresholds defined in YAML:

```yaml
rules:
  - id: EXT-001
    name: unknown_external_destination
    type: static
    condition: "destination_ip NOT IN allowlist.external_ips"
    severity: high
    confidence: 0.8

  - id: SCAN-001
    name: port_scanning
    type: threshold
    condition: "COUNT(DISTINCT destination_port) > {{ threshold }}"
    parameters:
      threshold: 50
      time_window_seconds: 60
    severity: critical
    confidence: 0.9

  - id: VOL-001
    name: high_outbound_volume
    type: threshold
    condition: "SUM(bytes_forward) OVER {{ time_window }} > {{ multiplier }} * baseline"
    parameters:
      time_window_seconds: 300
      multiplier: 3.0
    severity: medium
    confidence: 0.7
```

### 9.3 Baseline-Based Detection (Future)

Phase 5+ introduces baseline learning:
- Per-service traffic profiles (byte volume, connection count, destination set)
- Rolling 7-day / 30-day baselines
- Standard deviation-based anomaly detection
- Requires historical flow data in ClickHouse

### 9.4 AI/ML Detection (Not MVP)

AI/ML-based detection is explicitly **not included** in the MVP. Reasons:

1. **Operational complexity**: ML models require training infrastructure, monitoring, and retraining pipelines
2. **Insufficient data**: MVP does not yet have enough historical data for meaningful model training
3. **Explainability**: Rule-based alerts are immediately actionable; ML alerts require additional context
4. **Maintenance burden**: Model drift, feature engineering, and A/B testing add significant overhead

ML is introduced in the roadmap as Phase 10, after sufficient operational data and team maturity.

---

## 10. Kubernetes Integration

### 10.1 Deployment Model

**DaemonSet** is the recommended deployment model for the sensor.

| Option | Pros | Cons | Recommended |
|---|---|---|---|
| **DaemonSet** | One sensor per node; covers all pod traffic; minimal resource overhead | Requires host-level packet access; node-level visibility only | Yes (MVP) |
| **Sidecar** | Per-pod visibility; no host access needed | High resource overhead; deployment complexity; must be added to every pod | No |
| **Host Process** | Direct host access; no container overhead | Not Kubernetes-native; harder to manage | No |
| **eBPF-based** | Kernel-level visibility; very low overhead | Requires BPF-capable kernel; high complexity | Future |

#### Problem

Deploy a packet capture sensor in Kubernetes that can observe all pod traffic on a node with minimal privilege escalation and resource overhead.

#### Options

| Deployment | Privilege | Coverage | Resource Overhead | Operational Complexity |
|---|---|---|---|---|
| DaemonSet | CAP_NET_RAW + hostNetwork (optional) | All pods on node | Low (single process) | Low |
| Sidecar | None (per-pod) | Single pod only | High (per-pod) | High |
| Dedicated Host | CAP_NET_RAW + hostPID | All pods on node | Low | Medium |

#### Constraints

- Must observe all pod-to-pod traffic on the node
- Must not require modifications to existing pod specs
- Must have predictable, bounded resource usage
- Must be deployable via standard Kubernetes manifests

#### Decision

**DaemonSet with CAP_NET_RAW.** This provides node-wide visibility with a single process per node. The sensor uses `hostNetwork: false` by default and captures via `veth` pair traffic. If full node visibility is needed, `hostNetwork: true` can be enabled.

### 10.2 Kubernetes Metadata Resolution

The sensor enriches flow records with Kubernetes metadata by maintaining a local cache of the Pod IP → metadata mapping:

```text
Kubernetes API Server
        ↓
Informer (Watch API)
        ↓
Local Cache (HashMap<IP, PodMetadata>)
        ↓
Flow Enrichment (IP lookup at flow export time)
```

**Key design decisions:**
- Use **Informer** pattern (list + watch) to maintain a local cache, avoiding per-flow API calls
- Cache is refreshed via watch events; staleness is bounded by watch reconnection timeout
- Pod metadata includes: name, namespace, deployment, service, labels, node
- If enrichment fails (cache miss), flows are exported without metadata (nullable fields)

### 10.3 RBAC Requirements

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sentinel-flow-sensor
rules:
  - apiGroups: [""]
    resources: ["pods", "services", "namespaces", "nodes"]
    verbs: ["get", "list", "watch"]
  - apiGroups: ["apps"]
    resources: ["deployments", "replicasets", "daemonsets", "statefulsets"]
    verbs: ["get", "list", "watch"]
```

The sensor requires **read-only** access to the Kubernetes API. No write operations are needed.

---

## 11. Observability Integration

### 11.1 Existing Observability Stack

```text
┌─────────────────────────────────────────────────────┐
│              Application Observability               │
│                                                     │
│  Prometheus     → Application / Infrastructure       │
│                   Metrics (what applications report) │
│                                                     │
│  Logs           → Application Events                 │
│                   (what applications write)          │
│                                                     │
│  Tracing        → Request Flow                       │
│                   (what applications trace)          │
└─────────────────────────────────────────────────────┘
```

### 11.2 SentinelFlow Addition

```text
┌─────────────────────────────────────────────────────┐
│              Network Security Visibility             │
│                                                     │
│  SentinelFlow   → Network Flow / Security Events    │
│                   (what actually happens on wire)    │
└─────────────────────────────────────────────────────┘
```

### 11.3 Correlation Vision (Future)

```text
Metrics + Logs + Traces + Network Flow
            ↓
    Correlation Engine
            ↓
    Security Investigation
```

Example correlation:
- **Prometheus**: "api-server latency spiked to 5s"
- **Logs**: "api-server: connection refused to database:5432"
- **Network Flow**: "api-server opened 500 new connections to unknown IP 203.0.113.50"
- **Conclusion**: api-server may be compromised and exfiltrating data

This correlation is a future capability. For MVP, SentinelFlow operates independently and alerts are investigated separately.

### 11.4 Self-Monitoring via Prometheus

The sensor itself exposes Prometheus metrics for operational monitoring:

```text
sentinel_flows_active          → Current active flows in memory
sentinel_flows_exported_total  → Total exported flows
sentinel_packets_captured_total → Total captured packets
sentinel_packets_dropped_total  → Dropped packets (buffer full)
sentinel_flow_export_duration_seconds → Flow export latency
sentinel_clickhouse_write_duration_seconds → ClickHouse write latency
sentinel_clickhouse_write_errors_total → ClickHouse write errors
sentinel_kubernetes_cache_size → Kubernetes metadata cache size
sentinel_detection_events_total → Total security events generated
```

---

## 12. Security Architecture

### 12.1 Sensor Security Requirements

The sensor operates with elevated privileges (CAP_NET_RAW) and processes sensitive network data. Its own security is critical.

### 12.2 Transport Security

| Component | Mechanism | MVP |
|---|---|---|
| Sensor → ClickHouse | TLS (HTTPS) with certificate verification | Yes |
| Sensor → Kubernetes API | Service account token (in-cluster) | Yes |
| Sensor → Kafka (future) | mTLS | Future |
| Grafana → ClickHouse | TLS with read-only credentials | Yes |

### 12.3 Authentication & Authorization

| Interface | Mechanism |
|---|---|
| ClickHouse | Username/password with minimal privileges (INSERT on flow table, INSERT on event table) |
| Kubernetes API | Service account with read-only RBAC |
| Grafana | OAuth / SSO integration with ClickHouse data source |

### 12.4 Secret Management

| Secret | Storage | MVP |
|---|---|---|
| ClickHouse credentials | Kubernetes Secret → mounted as env vars or files | Yes |
| TLS certificates | Kubernetes Secret or cert-manager | Yes |
| API tokens | Kubernetes Secret | Yes |

Secrets are **never** stored in:
- Source code
- Configuration files committed to git
- Container images
- Log output

### 12.5 Data Sensitivity

| Data Type | Sensitivity | Handling |
|---|---|---|
| IP addresses | Medium | Stored as-is; not anonymized in MVP (internal IPs only) |
| Port numbers | Low | Stored as-is |
| Byte/packet counts | Low | Stored as-is |
| TCP flags | Low | Stored as-is |
| DNS queries | High | Not captured in MVP |
| HTTP headers/payloads | Critical | Not captured (observation is flow-level only) |
| TLS certificates | Medium | Not inspected in MVP |

### 12.6 Sensor Tampering Prevention

- Sensor runs as a **DaemonSet** with immutable container image
- Container runs as **non-root** where possible (CAP_NET_RAW is the only capability)
- **Read-only root filesystem** with tmpfs for writable paths
- **No shell access** in production container image (distroless or scratch-based)
- Sensor health is monitored via Prometheus; absence triggers alert
- Container image is signed and verified via admission controller (future)

### 12.7 Least Privilege

```yaml
securityContext:
  capabilities:
    add:
      - NET_RAW
    drop:
      - ALL
  readOnlyRootFilesystem: true
  runAsNonRoot: true
  runAsUser: 65534  # nobody
  seccompProfile:
    type: RuntimeDefault
```

### 12.8 Resource Limits

```yaml
resources:
  requests:
    cpu: 100m
    memory: 128Mi
  limits:
    cpu: 500m
    memory: 256Mi
```

| Resource | Request | Limit | Rationale |
|---|---|---|---|
| **CPU** | 100m | 500m | Packet capture is bursty; limit prevents CPU starvation of application pods |
| **Memory** | 128Mi | 256Mi | Flow table bounded by capacity; prevents OOM kill under normal load |

The sensor must **never** consume unbounded resources. Under extreme traffic, the sensor degrades gracefully (drops packets, reduces sampling) rather than consuming resources needed by application workloads.

---

## 13. Privacy / Data Protection

### 13.1 Data Policy

| Data Type | Policy | Rationale |
|---|---|---|
| **Raw packets** | **NOT stored** | Privacy risk; storage cost; flow metadata is sufficient |
| **Packet payloads** | **NOT captured** | DPI is out of scope; encrypted payloads are opaque anyway |
| **IP addresses** | Stored as-is (internal networks only) | Required for flow identification; no external IP anonymization in MVP |
| **Port numbers** | Stored as-is | Required for flow identification |
| **Byte/packet counts** | Stored as-is | Required for traffic analysis |
| **TCP flags** | Stored as-is | Required for connection state analysis |
| **Kubernetes metadata** | Stored as-is | Required for service identity |

### 13.2 Future Privacy Considerations

When deployed in environments with stricter privacy requirements:

- **IP anonymization**: HMAC-based one-way hash of IP addresses (preserves uniqueness, destroys reversibility)
- **External IP masking**: Truncate or hash external IP addresses for compliance
- **Data retention tiers**: Hot (7 days), Warm (30 days), Cold (90 days), Archive (1 year)
- **GDPR/CCPA compliance**: If flows can be associated with individual users, additional anonymization is required

### 13.3 TLS Encrypted Traffic

TLS-encrypted traffic is observed at the **flow level only**:
- We see source IP, destination IP, port, protocol, byte count
- We **cannot** see HTTP headers, DNS query names, or application content
- This is sufficient for most security use cases (unauthorized connections, traffic anomalies)
- Deep packet inspection of encrypted traffic is not feasible and not attempted

---

## 14. Performance

### 14.1 Performance Requirements

| Metric | Target | Notes |
|---|---|---|
| **Packets/sec per sensor** | 100K pps sustained | Sufficient for most node-level traffic |
| **Network throughput** | 1 Gbps sustained | Covers most application workloads |
| **CPU usage** | < 10% of one core | Must not impact application performance |
| **Memory usage** | < 256 MB RSS | Bounded by flow table size |
| **Flow table capacity** | 100K active flows | Sufficient for node-level visibility |
| **Flow export latency** | < 1 second | Time from last packet to flow record creation |
| **ClickHouse write latency** | < 500ms per batch | End-to-end from flow export to storage |
| **Packet loss** | < 0.01% under normal load | Monitored via AF_PACKET statistics |

### 14.2 Memory Management

Rust's ownership model provides deterministic memory management without GC pauses. This is critical for a packet processing system:

- **Zero-copy packet capture**: AF_PACKET ring buffer provides kernel-to-user zero-copy
- **Borrowed slices**: Parsed headers are borrowed from the packet buffer, no allocation
- **Flow table**: Pre-allocated HashMap with bounded capacity; eviction on capacity overflow
- **Batch buffering**: Fixed-size batch buffers; reused across batches

### 14.3 Backpressure Design

```text
Traffic Rate ↑
    │
    ├─ Normal: Process all packets → All flows exported
    │
    ├─ High: Increase batch size → Reduce per-flow overhead
    │
    ├─ Very High: Enable sampling → Process N% of flows
    │
    └─ Critical: Drop packets (with metrics) → Alert on packet loss
```

### 14.4 Sensor Impact Mitigation

The sensor must **never** degrade the monitored application's performance:

1. **Bounded CPU**: cgroup limits on the sensor container
2. **Bounded memory**: Flow table has hard capacity limit
3. **Bounded I/O**: ClickHouse writes are batched and async
4. **No application interference**: Sensor does not interact with application containers
5. **Graceful degradation**: Under pressure, the sensor drops its own work (packets/flows), not application work

---

## 15. Reliability

### 15.1 Failure Scenarios

| Scenario | Detection Impact | Data Loss | Recovery | Mitigation |
|---|---|---|---|---|
| **Sensor Down** | No flow capture on node | Flows during downtime lost | Restart via DaemonSet | Health monitoring + alerting; DaemonSet auto-restart |
| **ClickHouse Down** | Flows buffered locally | None (buffered, subject to buffer capacity) | ClickHouse restart | Local buffer with configurable capacity; retry with backoff |
| **Network Disconnected** | No flow export | Buffer overflow if prolonged | Network recovery | Local buffer + alert on buffer capacity |
| **Detection Engine Down** | No security events | Flows still stored | Engine restart | Detection runs as sensor thread; restart is automatic |
| **High Traffic** | Sampling may activate | Sampled flows not stored | Traffic normalization | Adaptive sampling with alerting |
| **Memory Pressure** | Flow table eviction | Evicted flows not exported | Memory recovery | Hard capacity limit; alert on high utilization |
| **Packet Loss** | Incomplete flow data | Packets dropped at kernel level | Monitor and alert | Increase AF_PACKET buffer size; alert on loss rate |

### 15.2 Reliability Design Principles

1. **Fail-safe**: Sensor failure results in no data, not corrupt data
2. **Local buffering**: ClickHouse unavailability does not cause immediate data loss
3. **Self-healing**: DaemonSet ensures sensor restart; health checks ensure liveness
4. **Observable**: All failure modes produce metrics and alerts
5. **Graceful degradation**: Under pressure, reduce fidelity rather than crash

### 15.3 Health Checks

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 10
  periodSeconds: 10
  failureThreshold: 3

readinessProbe:
  httpGet:
    path: /readyz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 5
  failureThreshold: 2
```

Health endpoints report:
- `/healthz`: Process is alive, AF_PACKET socket is valid, flow table is responsive
- `/readyz`: All subsystems initialized, ClickHouse connection established, Kubernetes cache loaded

---

## 16. Zero Trust Relationship

### 16.1 Positioning

SentinelFlow is **not** a Zero Trust Architecture implementation. It is a **Network Visibility** layer that **supports** Zero Trust by providing the continuous monitoring data required for risk evaluation.

```text
Current:
    Network Visibility (SentinelFlow)
            ↓
    Continuous Monitoring
            ↓
    Risk Context

Future:
    Identity + Device + Application + Resource + Network
            ↓
    Risk Evaluation
            ↓
    Policy Decision
```

### 16.2 How SentinelFlow Supports Zero Trust

| Zero Trust Principle | SentinelFlow Contribution |
|---|---|
| **Verify explicitly** | Network flow data verifies that actual communication matches expected patterns |
| **Least privilege access** | Detect when services communicate beyond their defined scope |
| **Assume breach** | Detect lateral movement, unusual internal communication, data exfiltration |
| **Continuous monitoring** | Real-time network flow analysis provides continuous verification |

### 16.3 Future Integration Points

In future phases, SentinelFlow data feeds into Zero Trust components:

- **Policy Engine** (e.g., Open Policy Agent): Network flow context informs policy decisions
- **Risk Scoring**: Traffic anomalies contribute to dynamic risk scores
- **Access Control**: Network-level signals complement identity-based access decisions
- **Microsegmentation Validation**: Verify that network policies produce expected traffic patterns

---

## 17. Threat Model

### 17.1 STRIDE Analysis

| Threat | Category | Impact | Likelihood | Mitigation |
|---|---|---|---|---|
| **Sensor compromise** | Tampering | Attacker controls what flows are reported | Low | Read-only root filesystem; signed images; health monitoring; minimal capabilities |
| **False data injection** | Tampering | Attacker injects fake flow records | Low | Flow records are derived from kernel-captured packets; not user-input; integrity checks |
| **Data exfiltration** | Information Disclosure | Attacker extracts network flow data | Medium | TLS for transport; ClickHouse auth; RBAC; flow data is metadata only (no payloads) |
| **Sensor bypass** | Elevation of Privilege | Attacker evades sensor detection | Medium | DaemonSet deployment ensures sensor presence; monitoring for sensor gaps |
| **Log tampering** | Tampering | Attacker modifies security events | Low | ClickHouse access controls; append-only flow; audit logging |
| **Kafka compromise** (future) | Tampering | Attacker modifies flow stream | Medium | mTLS; SASL authentication; ACLs; schema validation |
| **Dashboard compromise** | Information Disclosure | Attacker views security alerts | Medium | OAuth/SSO; RBAC; TLS |

### 17.2 Sensor as Attack Surface

The sensor is a high-value target because it has:
- CAP_NET_RAW capability (packet capture)
- Read access to Kubernetes API (pod metadata)
- Network connectivity to storage backend

**Mitigations:**
- Minimal container image (distroless/scratch)
- No shell, no package manager
- Read-only root filesystem
- Network policy restricting sensor egress to ClickHouse and K8s API only
- Runtime security monitoring (Falco or similar)

### 17.3 Data Integrity

Flow records are derived from kernel-level packet capture, making them harder to tamper with than application-level logs. However:

- A compromised sensor can selectively drop flows
- **Mitigation**: Deploy multiple sensors per node (future); cross-validate with application-level metrics
- **Mitigation**: Monitor sensor health metrics; absence of expected flow volume triggers alert

---

## 18. Alternatives / Trade-offs

### 18.1 Packet Capture Technologies

| Technology | Pros | Cons | Performance | Complexity | Cost | Recommended Use Case |
|---|---|---|---|---|---|---|
| **pnet** | Pure Rust; easy API; good for parsing | Limited capture control; abstraction over AF_PACKET | Medium | Low | Free | Packet parsing layer |
| **libpcap** | Battle-tested; portable | C dependency; FFI overhead | Medium-High | Low | Free | Cross-platform capture |
| **AF_PACKET** | Direct kernel API; zero-copy; configurable buffers | Linux-only; requires understanding of socket options | High | Medium | Free | **MVP primary capture** |
| **eBPF (TC)** | Kernel-level; programmable filters | Kernel version requirements; BPF complexity | Very High | High | Free | Future optimization |
| **XDP** | Driver-level; highest performance | Requires NIC driver support; limited programability at MVP complexity | Highest | Very High | Free | Future high-throughput |

### 18.2 Processing Approaches

| Approach | Pros | Cons | Recommended |
|---|---|---|---|
| **Rust local processing** | Simple; low latency; no external dependency | Single-node; no replay | Yes (MVP) |
| **Kafka + Flink** | Scalable; replay; complex event processing | High operational complexity | Future |
| **Kafka Streams** | Kafka-native; Java ecosystem | JVM overhead; Java ecosystem | Future |

### 18.3 Storage Technologies

| Technology | Pros | Cons | Recommended |
|---|---|---|---|
| **PostgreSQL** | ACID; joins; familiar | Poor time-series performance; no compression | No |
| **OpenSearch** | Full-text search; flexible schema | High storage cost; JVM overhead; complex operations | No |
| **ClickHouse** | Columnar; fast aggregation; excellent compression; SQL | Newer; smaller community than PostgreSQL | Yes (MVP) |
| **S3 (Parquet)** | Cheapest storage; excellent compression | Batch-only; no real-time query | Future archival |

### 18.4 Deployment Models

| Model | Pros | Cons | Recommended |
|---|---|---|---|
| **DaemonSet** | One per node; covers all pods; minimal overhead | Requires host access; node-level only | Yes (MVP) |
| **Sidecar** | Per-pod visibility; no host access | High overhead; must be added to every pod | No |
| **Dedicated host sensor** | Direct host access; no K8s overhead | Not K8s-native; harder to manage | No |

---

## 19. MVP Definition

### 19.1 What We Build First

```text
┌─────────────────────────────────────────────────┐
│                   MVP Scope                      │
│                                                  │
│  ✅ AF_PACKET capture (Rust)                     │
│  ✅ TCP/IP/UDP parsing                           │
│  ✅ Flow aggregation (5-tuple + counters)        │
│  ✅ Kubernetes metadata enrichment               │
│  ✅ ClickHouse storage (single node)            │
│  ✅ Rule-based detection (8 core rules)         │
│  ✅ Grafana dashboard                            │
│  ✅ Prometheus self-monitoring                   │
│                                                  │
│  ❌ Kafka (not MVP)                              │
│  ❌ AI/ML detection (not MVP)                    │
│  ❌ Zero Trust policy enforcement (not MVP)      │
│  ❌ Multi-tenant (not MVP)                       │
│  ❌ SaaS (not MVP)                               │
│  ❌ eBPF/XDP (not MVP)                           │
│  ❌ Raw packet storage (not MVP)                 │
│  ❌ Deep packet inspection (not MVP)             │
└─────────────────────────────────────────────────┘
```

### 19.2 MVP Deliverables

| Deliverable | Description |
|---|---|
| Rust sensor binary | Packet capture + flow engine + ClickHouse writer |
| Kubernetes manifests | DaemonSet, ServiceAccount, RBAC, ConfigMap |
| ClickHouse schema | Flow and event tables |
| Grafana dashboard | Flow overview, top talkers, security events |
| Detection rules | 8 core rules in YAML format |
| Prometheus metrics | Self-monitoring metrics endpoint |
| Documentation | Architecture doc (this), deployment guide, configuration reference |

### 19.3 MVP Validation Criteria

| Criterion | How Verified |
|---|---|
| Sensor captures packets on all cluster nodes | Deploy DaemonSet; verify flow records in ClickHouse |
| Flows are correctly aggregated | Compare flow byte counts with `tcpdump` capture |
| Kubernetes metadata is enriched | Verify pod/namespace fields in ClickHouse queries |
| Detection rules fire correctly | Simulate test scenarios (port scan, external connection) |
| Dashboard shows flow data | Grafana panels display real-time flow data |
| Sensor does not degrade application performance | Benchmark application latency with/without sensor |
| Sensor self-reports health | Prometheus scrape shows all sentinel_* metrics |

---

## 20. Implementation Roadmap

### Phase 1: Packet Capture

| Item | Detail |
|---|---|
| **Goal** | Capture raw packets from a network interface using AF_PACKET |
| **Deliverables** | AF_PACKET socket setup; ring buffer configuration; packet reading loop; basic statistics |
| **Technical Challenges** | Buffer sizing; handling ring buffer overflow; working within container constraints |
| **Acceptance Criteria** | Captures all packets on specified interface; reports packet count and drop count |

### Phase 2: Flow Engine

| Item | Detail |
|---|---|
| **Goal** | Parse packets and aggregate into network flows |
| **Deliverables** | Ethernet/IP/TCP/UDP parsing; 5-tuple flow key; flow table; timeout-based export |
| **Technical Challenges** | Flow table memory management; timeout tuning; handling out-of-order packets |
| **Acceptance Criteria** | Correctly identifies and exports flows; handles 100K concurrent flows |

### Phase 3: Storage

| Item | Detail |
|---|---|
| **Goal** | Store flow records in ClickHouse |
| **Deliverables** | ClickHouse HTTP writer; batch assembly; schema creation; async writes |
| **Technical Challenges** | Batch sizing; error handling; retry logic; connection pooling |
| **Acceptance Criteria** | Flows written to ClickHouse with < 1s end-to-end latency; handles ClickHouse restart gracefully |

### Phase 4: Dashboard

| Item | Detail |
|---|---|
| **Goal** | Visualize flow data and sensor health |
| **Deliverables** | Grafana data source; flow overview dashboard; top talkers; sensor health panels |
| **Technical Challenges** | ClickHouse query optimization; dashboard performance with large datasets |
| **Acceptance Criteria** | Dashboard displays real-time flow data; refresh interval < 30 seconds |

### Phase 5: Detection

| Item | Detail |
|---|---|
| **Goal** | Detect security-relevant anomalies from flow data |
| **Deliverables** | Rule engine; 8 core rules; alert generation; security event storage |
| **Technical Challenges** | Rule evaluation performance; false positive management; alert fatigue |
| **Acceptance Criteria** | Each rule fires correctly in test scenarios; false positive rate < 10% |

### Phase 6: Kafka

| Item | Detail |
|---|---|
| **Goal** | Introduce event streaming for decoupling and replay |
| **Deliverables** | Kafka producer in sensor; topic configuration; consumer for ClickHouse sink |
| **Technical Challenges** | Partition key selection; consumer group management; exactly-once semantics |
| **Acceptance Criteria** | Flows flow through Kafka to ClickHouse; replay capability demonstrated |

### Phase 7: Kubernetes Metadata

| Item | Detail |
|---|---|
| **Goal** | Enrich flows with full Kubernetes metadata |
| **Deliverables** | Informer-based cache; IP→Pod resolution; service/deployment mapping |
| **Technical Challenges** | Cache consistency during scaling; handling IP reuse; memory footprint |
| **Acceptance Criteria** | 95%+ of flows enriched with pod/namespace/service metadata |

### Phase 8: Risk Analysis

| Item | Detail |
|---|---|
| **Goal** | Establish traffic baselines and detect deviations |
| **Deliverables** | Baseline computation; anomaly scoring; adaptive thresholds |
| **Technical Challenges** | Baseline accuracy; handling seasonality; cold start |
| **Acceptance Criteria** | Detects 30% traffic deviation reliably; < 5% false positive rate |

### Phase 9: Zero Trust Integration

| Item | Detail |
|---|---|
| **Goal** | Feed network visibility data into Zero Trust risk evaluation |
| **Deliverables** | Risk context API; network segment validation; policy compliance reporting |
| **Technical Challenges** | Risk scoring accuracy; policy definition; integration with policy engines |
| **Acceptance Criteria** | Network risk signals integrated with identity/device risk signals |

### Phase 10: AI Security Analyst

| Item | Detail |
|---|---|
| **Goal** | AI-assisted analysis of security events and network anomalies |
| **Deliverables** | ML-based anomaly detection; natural language event summaries; investigation assistance |
| **Training data** | Requires 6+ months of operational flow data |
| **Technical Challenges** | Model training infrastructure; drift detection; explainability |
| **Acceptance Criteria** | ML detection outperforms rule-based on held-out test data |

---

## 21. Repository Architecture

### 21.1 Directory Structure

```text
sentinel-flow-rs/
├── Cargo.toml                    # Workspace root
├── rust-toolchain.toml           # Rust toolchain version
├── .cargo/
│   └── config.toml               # Cargo configuration
│
├── crates/
│   ├── sentinel-sensor/          # Main sensor binary
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── main.rs
│   │       ├── capture/
│   │       │   ├── mod.rs
│   │       │   ├── af_packet.rs
│   │       │   └── stats.rs
│   │       ├── parser/
│   │       │   ├── mod.rs
│   │       │   ├── ethernet.rs
│   │       │   ├── ip.rs
│   │       │   ├── tcp.rs
│   │       │   └── udp.rs
│   │       ├── flow/
│   │       │   ├── mod.rs
│   │       │   ├── key.rs
│   │       │   ├── table.rs
│   │       │   ├── entry.rs
│   │       │   └── export.rs
│   │       ├── enrichment/
│   │       │   ├── mod.rs
│   │       │   └── kubernetes.rs
│   │       ├── output/
│   │       │   ├── mod.rs
│   │       │   ├── clickhouse.rs
│   │       │   └── batch.rs
│   │       ├── detection/
│   │       │   ├── mod.rs
│   │       │   ├── engine.rs
│   │       │   └── rules.rs
│   │       ├── config.rs
│   │       ├── metrics.rs
│   │       └── error.rs
│   │
│   ├── sentinel-parser/          # Packet parsing library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── ethernet.rs
│   │       ├── ip.rs
│   │       ├── tcp.rs
│   │       └── udp.rs
│   │
│   ├── sentinel-flow/            # Flow engine library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── key.rs
│   │       ├── table.rs
│   │       ├── entry.rs
│   │       └── export.rs
│   │
│   ├── sentinel-detection/       # Detection engine library
│   │   ├── Cargo.toml
│   │   └── src/
│   │       ├── lib.rs
│   │       ├── engine.rs
│   │       └── rules.rs
│   │
│   └── sentinel-enrichment/      # Metadata enrichment library
│       ├── Cargo.toml
│       └── src/
│           ├── lib.rs
│           └── kubernetes.rs
│
├── config/
│   ├── sensor.yaml               # Sensor configuration
│   ├── detection-rules.yaml      # Detection rule definitions
│   └── clickhouse/
│       └── schema.sql            # ClickHouse DDL
│
├── deploy/
│   ├── kubernetes/
│   │   ├── daemonset.yaml
│   │   ├── serviceaccount.yaml
│   │   ├── clusterrole.yaml
│   │   ├── clusterrolebinding.yaml
│   │   ├── configmap.yaml
│   │   └── secret.yaml
│   ├── grafana/
│   │   ├── dashboard.json
│   │   └── datasource.yaml
│   └── clickhouse/
│       └── statefulset.yaml
│
├── docs/
│   ├── architecture.md           # This document
│   ├── deployment.md             # Deployment guide
│   ├── configuration.md          # Configuration reference
│   └── adr/                      # Architecture Decision Records
│       ├── ADR-001-packet-capture.md
│       ├── ADR-002-flow-model.md
│       ├── ADR-003-storage.md
│       ├── ADR-004-kafka.md
│       └── ADR-005-k8s-deployment.md
│
├── tests/
│   ├── integration/
│   │   ├── capture_test.rs
│   │   ├── flow_test.rs
│   │   └── clickhouse_test.rs
│   └── fixtures/
│       ├── sample_packets.pcap
│       └── expected_flows.json
│
├── .github/
│   └── workflows/
│       ├── ci.yml
│       └── release.yml
│
├── Dockerfile                    # Multi-stage build
├── Dockerfile.sensor             # Minimal sensor image
├── deny.toml                     # cargo-deny configuration
├── clippy.toml                   # Clippy configuration
├── rustfmt.toml                  # rustfmt configuration
├── README.md
├── LICENSE
└── sentinel-flow-rs.md           # Original design prompt
```

### 21.2 Workspace Dependency Graph

```text
sentinel-sensor (binary)
    ├── sentinel-parser (library)
    ├── sentinel-flow (library)
    ├── sentinel-detection (library)
    └── sentinel-enrichment (library)
```

Each crate is independently testable and has a focused responsibility.

---

## 22. Architecture Decision Records

### ADR-001: Packet Capture Technology

**Status**: Accepted

**Problem**: How to capture network packets in a Kubernetes container?

**Options**: pnet, libpcap, AF_PACKET, eBPF, XDP

**Constraints**: Must run in container; must observe all node traffic; must be maintainable

**Trade-offs**: pnet simplifies parsing but abstracts capture; eBPF/XDP offer highest performance but highest complexity; AF_PACKET provides the right balance of control and simplicity.

**Decision**: Use AF_PACKET for capture, pnet for parsing only.

**Consequences**: We maintain direct control over capture parameters while leveraging Rust's parsing ecosystem. eBPF/XDP is available as a future optimization.

### ADR-002: Flow Data Model

**Status**: Accepted

**Problem**: What data model captures sufficient network security information without storing raw packets?

**Options**: Fixed 5-tuple model, IPFIX-compliant model, custom enriched model

**Constraints**: Must be storage-efficient; must support security detection; must be enrichable with K8s metadata

**Trade-offs**: Fixed models are simpler but less extensible; IPFIX is standard but complex; custom models are flexible but non-standard.

**Decision**: Custom 5-tuple model with nullable Kubernetes metadata fields.

**Consequences**: Simple, focused on security use cases. Non-standard but easily mapped to IPFIX if interop is needed.

### ADR-003: Storage Selection

**Status**: Accepted

**Problem**: Where to store network flow data for analysis and detection?

**Options**: PostgreSQL, Elasticsearch/OpenSearch, ClickHouse, S3

**Constraints**: Must handle high write throughput; must support time-series queries; must be operable by small team

**Trade-offs**: PostgreSQL is familiar but poor for time-series; Elasticsearch is powerful but operationally heavy; ClickHouse is optimal for analytics but newer; S3 is cheapest but batch-only.

**Decision**: ClickHouse (single node for MVP, clustered for production).

**Consequences**: Excellent performance for flow analytics. Requires ClickHouse expertise but operational burden is manageable.

### ADR-004: Kafka Adoption

**Status**: Deferred

**Problem**: Should Kafka be introduced between sensor and storage?

**Options**: Direct to ClickHouse, Kafka intermediate

**Constraints**: MVP simplicity; small team; moderate throughput

**Trade-offs**: Kafka adds decoupling and replay but increases operational complexity. Direct write is simpler but couples sensor to storage.

**Decision**: Do not use Kafka in MVP. Introduce in Phase 6 when throughput and replay requirements justify it.

**Consequences**: Simpler MVP. May require sensor changes when Kafka is introduced. Acceptable trade-off.

### ADR-005: Kubernetes Deployment Model

**Status**: Accepted

**Problem**: How to deploy the sensor in Kubernetes for node-wide network visibility?

**Options**: DaemonSet, Sidecar, Dedicated host, eBPF collector

**Constraints**: Must observe all pod traffic; must not require pod spec changes; must have bounded resource usage

**Trade-offs**: DaemonSet is simple and comprehensive but requires host access; Sidecar is per-pod but high overhead; Dedicated host is non-K8s-native.

**Decision**: DaemonSet with CAP_NET_RAW capability.

**Consequences**: One sensor per node. Node-wide visibility. Requires RBAC for K8s API read access. Resource usage is bounded and predictable.

---

## Architecture Decision Summary

| Decision | Choice | Reason |
|---|---|---|
| Packet Capture | AF_PACKET + pnet parsing | Balance of control, simplicity, and Rust-native implementation |
| Flow Model | Custom 5-tuple with K8s metadata | Focused on security use cases, storage-efficient, enrichable |
| Storage | ClickHouse | Best fit for time-series network flow analytics; excellent compression |
| Kafka | Deferred (Phase 6) | Not needed for MVP throughput; adds operational complexity |
| K8s Deployment | DaemonSet | Node-wide visibility with single process; bounded overhead |
| Detection | Rule-based (YAML rules) | Simple, explainable, immediately actionable; ML deferred |
| Language | Rust | Zero-cost abstractions; memory safety; performance; no GC pauses |
| Dashboard | Grafana | Existing tooling; no new infrastructure; rich visualization |

---

## Main Risks

| Risk | Impact | Mitigation |
|---|---|---|
| ClickHouse single point of failure | Flow data unavailable; detection paused | Local buffering in sensor; alert on ClickHouse health; plan for replication |
| AF_PACKET privilege escalation risk | Container escape via CAP_NET_RAW | Minimal container image; seccomp profile; network policy; runtime monitoring |
| Flow table memory exhaustion under high traffic | Flow records dropped; incomplete visibility | Hard capacity limit with LRU eviction; adaptive sampling; alert on utilization |
| False positive alert fatigue | Security team ignores alerts | Conservative rule thresholds; allowlist mechanism; phased rollout of detection rules |
| Kubernetes metadata staleness | Incorrect service attribution during scaling | Watch-based cache with bounded staleness; export flows without metadata on cache miss |
| ClickHouse write performance under high throughput | Sensor buffer overflow; data loss | Batch optimization; backpressure; sampling; vertical scaling |
| Sensor impact on application performance | Application latency degradation | Bounded CPU/memory via cgroups; profiling; benchmarking before production rollout |

---

## Future Evolution

```text
Phase 1-5:  Network Visibility → Security Detection
Phase 6-7:  Event Streaming → Kubernetes Metadata
Phase 8:    Risk Analysis (baseline + anomaly detection)
Phase 9:    Zero Trust Integration (risk context for policy decisions)
Phase 10:   AI Security Analyst (ML-based detection + investigation assistance)
```

---

## Open Questions

| ID | Question | Impact | Target Resolution |
|---|---|---|---|
| OQ-002 | What is the maximum cluster size (nodes) for single-node ClickHouse before requiring sharding? | Deployment planning | Load testing in Phase 3 |
| OQ-003 | Should detection rules be hot-reloadable (configmap watch) or require sensor restart? | Operational flexibility | Phase 5 design review |
| OQ-004 | What Grafana alerting integration is preferred: Grafana native alerts, PagerDuty, or Slack webhook? | Incident response workflow | Phase 4 design review |
| OQ-005 | Should the sensor generate a self-signed TLS certificate for ClickHouse communication, or require cert-manager? | Deployment simplicity | Phase 3 design review |
| OQ-006 | Is DNS query monitoring (from /proc/net or conntrack) in scope for Phase 7+? | Detection capability | Phase 7 planning |
| OQ-007 | What is the expected retention period for flow data in production? Regulatory/compliance requirements? | Storage capacity planning | Requirements gathering |
| OQ-008 | Should the sensor support non-Kubernetes (bare-metal / VM) deployment, or Kubernetes-only? | Deployment scope | Product requirements |
