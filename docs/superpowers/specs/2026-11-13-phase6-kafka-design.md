# Phase 6: Kafka トランスポート — 設計spec

> **Status**: Approved
> **Date**: 2026-11-13
> **Scope**: architecture.md Roadmap Phase 6 のみ（sensor→Kafka→ClickHouse の flow トランスポート）

## 目的

フロー出力をセンサープロセスから切り離し、Kafka 経由で ClickHouse に到達させる選択肢を追加する。DB 障害時のバッファリング（7日保持）、停止したセンサーの読み替え（replay）、独立したスケール（sensor/sink を別プロセスで再起動）を実現する。**direct モード（Phase 3 の直接書き込み）は現行のまま残し、`output.mode` で選択可能にする**（既存テスト・既存経路は一切変更しない）。

**受入基準**

- `output.mode: direct`（既定）で Phase 5 時点の動作が完全に変わらない（既存テスト全件パス、追加の結線なし）
- `output.mode: kafka` で sensor がフローを Kafka トピック `netflow.raw` に JSON で送出し、パーティションキーが 5-tuple の xxhash3 になる
- 新規クレート `sentinel-sink` が `netflow.raw` を消費し、既存の FlowWriter + ClickHouseStore パターンで `network_flows` に書き込む（consumer group `clickhouse-sinker`、手動コミット）
- sensor と sink を別々に停止・再起動しても、sink は Kafka の保持期間内（7日）のデータを読み戻せる（replay 動作確認を手順書に文書化）
- `cargo nextest run --workspace` 全件パス（Kafka E2E は CI 外の docker-compose + 手動確認）

**非スコープ**

- `security.events` の Kafka 化（Phase 7 以降で再検討）
- `netflow.enriched` トピック / k8s enrichment（Phase 7）
- Kafka トランザクションによる exactly-once（at-least-once + 重複許容で十分。ClickHouse 側の重複は許容済み）
- archival（S3/Parquet エクスポート、consumer group `archival`）
- Grafana ダッシュボードの拡張

## 方針判断（brainstorming確定事項）

| 論点 | 決定 | 理由 |
|---|---|---|
| トランスポート | config 切替 `output.mode: direct \| kafka` | direct 経路を温存（Phase 5 実装・テストがそのまま生きる）。リスク最小 |
| Kafka クライアント | **rdkafka**（librdkafka バインディング） | 実績・tokio async 対応。pure-Rust 実装は未成熟 |
| 対象トピック | `netflow.raw` のみ | security_events は in-sensor 検知（Phase 5）のまま direct 書き込み。需要が出てから Kafka 化 |
| シリアライズ | JSON（serde）1行=1メッセージ | FlowRow は Serialize 済み。protobuf/avro は運用コスト過大（YAGNI） |
| パーティションキー | 5-tuple 文字列の xxhash3 | architecture.md §8.2 準拠。同一フローは同一パーティション、分散は均等 |
| コンシューマ配置 | 新規ワークスペースクレート `sentinel-sink` | sensor バイナリから独立。個別再起動・スケール・リリースが可能 |
| テスト/リプレイ | docker-compose + 手動 replay 手順書 | Kafka E2E を CI に入れない（flaky リスク・実行時間）。手順書で再現可能にする |

## データフロー

```text
[direct モード（現行、変更なし）]
processor → out_tx → FlowWriter → ClickHouseStore → network_flows

[kafka モード（新規）]
processor → out_tx → FlowWriter → KafkaFlowStore (rdkafka FutureProducer)
      → topic netflow.raw (key = xxhash3(5-tuple), value = FlowRow JSON)
      → sentinel-sink (StreamConsumer, group clickhouse-sinker)
      → FlowWriter → ClickHouseStore → network_flows
```

- モード切替は **FlowStore 実装の差し替えのみ**。FlowWriter（batch/retry/timeout/metrics）は両モードで同一
- 検知パス（Phase 5 の DetectionEngine → EventWriter → security_events）は kafka/direct どちらのモードでも direct 書き込みのまま
- sink の書き込みは既存 FlowWriter を再利用するため、`network_flows` DDL・行変換・リトライ挙動は Phase 3 と完全同一

## コンポーネント設計

### 1. sensor 側: `KafkaFlowStore`（crates/sentinel-sensor/src/output/kafka_store.rs 新規）

```rust
/// `FlowStore` の Kafka 実装。1 FlowRow = 1 メッセージ。
pub struct KafkaFlowStore {
    producer: FutureProducer,          // rdkafka
    topic: String,
    brokers: Vec<String>,              // 設定ログ用に保持
}
```

- `FlowStore` trait を実装（`write_batch(&[FlowRow])`）。既存 FlowWriter からそのまま呼ばれる
- メッセージ本体: `FlowRow` の JSON（serde_json::to_string）。FlowRow は既に Serialize
- パーティションキー: `format!("{source_ip},{destination_ip},{source_port},{destination_port},{protocol}")` の **xxhash3（64bit）を 16進文字列化**したもの。実装は XXH3 系クレート（`twox-hash` の `xxh3_64`）
- 送信: `producer.send_result(FutureRecord { key, payload }, timeout)`。配信完了を待つ（acks=all）。`FutureProducer::send` 相当の完了待ち + `WRITE_TIMEOUT` でタイムアウト
- 失敗時: `Result<(), KafkaProduceError>` を返す → 既存 FlowWriter のリトライ3回 → 最終失敗で `flows_dropped`（既存挙動踏襲）
- producer 設定: `acks=all`, `enable.idempotence=true`（順序・重複の乱れを最小化）, `compression.type=lz4`, `bootstrap.servers` は設定から
- `ClickHouseStore::new` と同様に非 fallible コンストラクタ。`KafkaFlowStore::new(&OutputConfig)` は producer 生成に失敗した場合のみ `anyhow::Result` を返す（設定ミスの起動時 fail-fast 用。ネットワーク接続は書き込み時のみ発生するため、コンストラクタ自体は通常成功する）

### 2. 新規クレート `sentinel-sink`

```text
crates/sentinel-sink/
├── Cargo.toml        # rdkafka, tokio, serde/serde_json, clickhouse, anyhow, tracing, prometheus
└── src/
    ├── main.rs       # 設定ロード → consumer 生成 → 消費ループ spawn → シャットダウン
    ├── config.rs     # SinkConfig { kafka: {brokers, topic, group_id}, clickhouse: {url, database, user?, password?, batch_size, batch_timeout_ms}, metrics: {enabled, port} }
    ├── consumer.rs   # KafkaEventSource 抽象 + rdkafka StreamConsumer 実装
    └── output/       # sensor の output/ から必要な部分を再利用 or 参照
```

- **再利用方針**: `FlowWriter`・`ClickHouseStore`・`FlowRow`・`BatchBuffer` は sensor クレート内にあるため、これらを `sentinel-flow` または共通クレートへ移動せず、**sensor 側を `pub` 可視化した上で sink から path 依存**する（ワークスペース内クレート依存）。sensor の output module のうち sink が必要なのは `FlowWriter`/`ClickHouseStore`/`FlowRow`/`WRITE_TIMEOUT` のみ → `output` module を `pub` にし、`pub use` を追加（既存 `pub(crate)` は温存し、追加のみ）
- 消費ループ: `StreamConsumer::subscribe(&[topic])` → `stream()` でメッセージ受信 → JSON → `FlowRow` → FlowWriter へ `mpsc` チャネルで送信 → FlowWriter タスクが既存手順で ClickHouse へ書き込み
- オフセットコミット: **手動コミット（enable.auto.commit=false）**。ClickHouse バッチ書き込み成功後に `consumer.commit` を呼ぶ方針（厳密にはバッチ単位でコミット。at-least-once、重複は許容 — Phase 5 時の network_flows at-least-once 判断と整合）
- デシリアライズ失敗: `sentinel_sink_failed_messages_total++` + warn ログ + スキップ（poison message で停止しない）
- シャットダウン: ctrl_c → consumer 停止 → FlowWriter drain → プロセス終了（sensor と同じ headroom パターン）

### 3. 設定ファイル

```yaml
# config/sensor.yaml — output section 拡張（既存キーは温存）
output:
  mode: direct                # direct | kafka（既定 direct）
  clickhouse_url: "http://localhost:8123"
  clickhouse_database: "sentinel"
  batch_size: 1000
  batch_timeout_ms: 500
  kafka:                      # mode=kafka 時のみ使用
    brokers: ["localhost:9092"]
    topic: "netflow.raw"
```

```yaml
# config/sink.yaml — 新規（sentinel-sink 用）
kafka:
  brokers: ["localhost:9092"]
  topic: "netflow.raw"
  group_id: "clickhouse-sinker"

clickhouse:
  url: "http://localhost:8123"
  database: "sentinel"
  batch_size: 1000
  batch_timeout_ms: 500

metrics:
  enabled: true
  port: 9091
```

- `OutputConfig` に `mode` と `kafka` を追加（`mode` は serde default `direct`、未知値は fail-fast）。kafka サブ設定は `mode=kafka` でない限り未使用（値がなくても validate を通す）
- `mode: kafka` かつ `kafka.brokers` 空は起動時 fail-fast

### 4. docker-compose（ローカル開発・リプレイ用）

```yaml
# docker-compose.kafka.yml（新規）
services:
  kafka:
    image: bitnami/kafka:3.7            # KRaft モード（ZooKeeper 不要）
    ports: ["9092:9092"]
    environment:
      KAFKA_CFG_AUTO_CREATE_TOPICS_ENABLE: "false"
      KAFKA_CFG_GROUP_INITIAL_REBALANCE_DELAY_MS: "0"
    # トピック作成は起動後手動コマンドで行う（保持期間7日の明示）
  clickhouse:
    image: clickhouse/clickhouse-server:24.8
    ports: ["8123:8123"]
```

- トピック作成コマンド（手順書に含める）: `kafka-topics.sh --create --topic netflow.raw --partitions 4 --retention-ms 604800000`
- 既存の local-infrastructure.md に kafka セクションを追記するか、別途手順書（`docs/runbooks/kafka-replay.md`）に集約。**決定: `docs/runbooks/kafka-replay.md` に手順書を新規作成する**（local-infrastructure.md は既存の内容を壊さない。ファイル一覧は runbooks を採用）

### 5. メトリクス

| メトリクス | 発行元 | 説明 |
|---|---|---|
| `sentinel_kafka_produced_total` | sensor | Kafka 送信成功メッセージ数 |
| `sentinel_kafka_produce_errors_total` | sensor | 送信失敗（リトライ込み試行回数） |
| `sentinel_sink_consumed_total` | sink | 消費メッセージ数（デシリアライズ成功） |
| `sentinel_sink_failed_messages_total` | sink | デシリアライズ失敗数 |
| 既存 `flows_written_total` / `flows_dropped_total` | 両側 | FlowWriter 経由なので sensor でも sink でも既存のまま機能 |

- sink は独立プロセスのため `SensorMetrics` と同構造の `SinkMetrics` を sink クレート内に作る（prometheus 直使用。スコープ: 上の2メトリクスのみ、共通化はしない）

### 6. エラーハンドリング

| ケース | 処理 |
|---|---|
| Kafka ブローカ不在（sensor） | write_batch 失敗 → FlowWriter リトライ3 → `flows_dropped` 増加 + error ログ、プロセス継続 |
| 送信タイムアウト | WRITE_TIMEOUT（2s）で timeout エラー → 同上リトライ |
| sink: トピック不在 | consumer 生成失敗 → 起動 fail-fast |
| sink: デシリアライズ失敗 | counter++ + warn、スキップ（停止しない） |
| sink: ClickHouse 書き込み失敗 | 既存 FlowWriter リトライ3 → `flows_dropped`、オフセットはコミットされず次回再消費（at-least-once） |
| 重複書き込み | 許容（network_flows は at-least-once、既存判断と同一） |

### 7. リプレイ手順（手順書に文書化）

1. `docker compose -f docker-compose.kafka.yml up -d`
2. トピック作成（保持期間 7 日明示）
3. sensor を `mode: kafka` で起動 → データ投入
4. sink 起動 → `network_flows` に書き込み確認
5. sink 停止 → sensor 続けてデータ投入 → sink 再起動 → 停止中の分が読み戻されることを確認（consumer group オフセットから再開）
6. （任意）`--from-beginning` 相当のオフセットリセットで全件再読取 → ClickHouse 側の重複行を確認（許容動作）

## テスト戦略

| 対象 | テスト内容 |
|---|---|
| 設定 | `mode` デフォルト direct / kafka ブローカ空 fail-fast / sink.yaml パース |
| KafkaFlowStore | モック producer（FlowStore 契約: JSON 化・キー化・失敗伝播）単体テスト。rdkafka のモックは薄く、JSON/キー生成を関数に切り出してテスト |
| sink 消費ループ | テスト用 `KafkaEventSource` trait を抽象化し、モックソースで JSON→FlowRow→FlowWriter 連携・デシリアライズ失敗スキップ・オフセットコミット呼び出しを検証 |
| FlowWriter 再利用 | 既存テストがそのまま sink でも成立することを、`pub` 可視化後に 1 回確認（重複テストは書かない） |
| E2E/replay | docker-compose + 手動手順書（CI 外）。CI は既存ユニットテストのみ |

## 検証コマンド

```bash
cargo nextest run --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
docker compose -f docker-compose.kafka.yml up -d   # 手動 E2E
```

## 変更ファイル一覧（概算）

| ファイル | 種別 |
|---|---|
| `crates/sentinel-sensor/src/output/kafka_store.rs` | 新規（KafkaFlowStore） |
| `crates/sentinel-sensor/src/output/mod.rs` | 編集（sink からの再利用に必要な pub 化） |
| `crates/sentinel-sensor/src/config.rs` | 編集（OutputConfig: mode + kafka サブ設定） |
| `crates/sentinel-sensor/src/main.rs` | 編集（mode による FlowStore 選択） |
| `crates/sentinel-sensor/src/metrics.rs` | 編集（kafka producer メトリクス 2 本） |
| `crates/sentinel-sink/**` | 新規クレート（config/consumer/main/metrics） |
| `config/sensor.yaml` / `config/sink.yaml` | 編集/新規 |
| `docker-compose.kafka.yml` | 新規 |
| `docs/runbooks/kafka-replay.md` | 新規（replay 手順書。docker-compose 起動〜全件再読取確認まで） |
| `Cargo.toml`（workspace） | 編集（rdkafka/twox-hash/serde_json 追加、sentinel-sink member 追加） |
