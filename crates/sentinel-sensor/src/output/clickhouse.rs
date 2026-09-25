//! ClickHouse-backed flow store: schema creation and batched inserts.
//!
//! Inserts are at-least-once: a retried batch whose predecessor actually
//! committed can land duplicate rows, and the `MergeTree` engine does not
//! deduplicate on `flow_id`.

use async_trait::async_trait;
use clickhouse::{Client, sql::Identifier};

use super::row::FlowRow;
use crate::config::OutputConfig;

/// Table name; the database comes from the client, so no qualification here.
const TABLE: &str = "network_flows";

/// Storage sink for converted flow rows.
///
/// Implementations must be safe to call repeatedly: the writer retries a
/// failed batch against the same store.
#[async_trait]
pub trait FlowStore: Send {
    /// Error type surfaced to the writer for logging and retry.
    type Error: std::fmt::Display + Send + Sync + 'static;

    /// Write one batch of rows. An empty slice must be a no-op.
    async fn write_batch(&mut self, rows: &[FlowRow]) -> Result<(), Self::Error>;
}

/// Idempotent DDL for the `network_flows` table.
///
/// Matches the schema in `docs/architecture.md` with two deliberate
/// differences: `MergeTree()` instead of `ReplicatedMergeTree()` (single-node
/// deployment; switch on HA with a Keeper-backed replica path) and no
/// Kubernetes metadata columns yet (added by `ALTER TABLE` in Phase 7).
fn create_table_sql() -> String {
    format!(
        r#"CREATE TABLE IF NOT EXISTS {TABLE}
(
    flow_id UUID,
    timestamp_start DateTime64(3, 'UTC'),
    timestamp_end DateTime64(3, 'UTC'),
    source_ip IPv6,
    destination_ip IPv6,
    source_port UInt16,
    destination_port UInt16,
    protocol Enum8('TCP' = 1, 'UDP' = 2, 'ICMP' = 3, 'OTHER' = 4),
    packets_forward UInt32,
    packets_reverse UInt32,
    bytes_forward UInt64,
    bytes_reverse UInt64,
    duration_ms UInt32,
    tcp_flags_seen Array(UInt8),
    sensor_node LowCardinality(String)
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp_start)
ORDER BY (source_ip, destination_ip, timestamp_start, source_port, destination_port, protocol)
TTL toDateTime(timestamp_start) + INTERVAL 90 DAY
"#
    )
}

/// ClickHouse implementation of [`FlowStore`].
pub struct ClickHouseStore {
    /// Database-less client: `CREATE DATABASE` cannot run through a client
    /// that already selects a database that may not exist yet.
    admin: Client,
    client: Client,
    database: String,
    schema_ready: bool,
}

impl ClickHouseStore {
    /// Build a store from configuration. The schema is created lazily on the
    /// first write, so a ClickHouse that starts (or restarts) late is retried.
    pub fn new(config: &OutputConfig) -> Self {
        let mut admin = Client::default().with_url(&config.clickhouse_url);
        if let Some(user) = &config.clickhouse_user {
            admin = admin.with_user(user);
        }
        if let Some(password) = &config.clickhouse_password {
            admin = admin.with_password(password);
        }
        let client = admin.clone().with_database(&config.clickhouse_database);
        Self { admin, client, database: config.clickhouse_database.clone(), schema_ready: false }
    }

    /// Create database and table if missing; records readiness until a write
    /// fails (a restart with wiped state re-runs the same idempotent DDL).
    async fn ensure_schema(&mut self) -> clickhouse::error::Result<()> {
        if self.schema_ready {
            return Ok(());
        }
        self.admin
            .query("CREATE DATABASE IF NOT EXISTS ?")
            .bind(Identifier(&self.database))
            .execute()
            .await?;
        self.client.query(&create_table_sql()).execute().await?;
        self.schema_ready = true;
        Ok(())
    }

    async fn do_write(&mut self, rows: &[FlowRow]) -> clickhouse::error::Result<()> {
        self.ensure_schema().await?;
        let mut insert = self.client.insert(TABLE)?;
        for row in rows {
            insert.write(row).await?;
        }
        insert.end().await
    }
}

#[async_trait]
impl FlowStore for ClickHouseStore {
    type Error = clickhouse::error::Error;

    async fn write_batch(&mut self, rows: &[FlowRow]) -> Result<(), Self::Error> {
        if rows.is_empty() {
            return Ok(());
        }
        let result = self.do_write(rows).await;
        if result.is_err() {
            // Re-run DDL on the next attempt: covers restarts that wiped the schema.
            self.schema_ready = false;
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::row::{FlowRow, sample_flow};
    use std::net::Ipv4Addr;
    use std::sync::Arc;
    use std::time::Duration;

    /// Integration test against a real ClickHouse (see `CLAUDE.md` Phase 3):
    /// skipped with a notice when no server is reachable, e.g. on developer
    /// machines without Docker or the `sentinel-flow` CI unit-test job.
    /// Probe the server; when `REQUIRE_CLICKHOUSE` is set (CI) an
    /// unreachable server fails the test instead of skipping it.
    async fn clickhouse_available(url: &str) -> bool {
        let probe = Client::default().with_url(url).query("SELECT 1").execute();
        let result = match tokio::time::timeout(Duration::from_secs(2), probe).await {
            Ok(Ok(())) => true,
            Ok(Err(err)) => {
                eprintln!("clickhouse probe failed: {err}");
                false
            }
            Err(_) => {
                eprintln!("clickhouse probe timed out at {url}");
                false
            }
        };
        if !result && std::env::var_os("REQUIRE_CLICKHOUSE").is_some() {
            panic!("REQUIRE_CLICKHOUSE is set but no server answered at {url}");
        }
        result
    }

    fn test_config(url: &str, database: &str) -> OutputConfig {
        OutputConfig {
            clickhouse_url: url.to_string(),
            clickhouse_database: database.to_string(),
            ..OutputConfig::default()
        }
    }

    /// Ensure the test database exists, then clear last run's rows.
    /// Each test owns a database so parallel runs cannot interfere.
    async fn reset_test_table(store: &mut ClickHouseStore, database: &str) {
        store
            .admin
            .query("CREATE DATABASE IF NOT EXISTS ?")
            .bind(Identifier(database))
            .execute()
            .await
            .expect("create test database");
        store
            .admin
            .query("DROP TABLE IF EXISTS ?.?")
            .bind(Identifier(database))
            .bind(Identifier(TABLE))
            .execute()
            .await
            .expect("drop test table");
        store.ensure_schema().await.expect("create test table");
    }

    fn sample_row(flow_id: &str) -> FlowRow {
        FlowRow::try_from(&sample_flow(flow_id)).unwrap()
    }

    async fn count_rows(store: &ClickHouseStore) -> u64 {
        store
            .client
            .query("SELECT count() FROM network_flows")
            .fetch_one::<u64>()
            .await
            .expect("count query")
    }

    #[tokio::test]
    async fn schema_and_writes_roundtrip() {
        let url =
            std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
        if !clickhouse_available(&url).await {
            eprintln!("skipping ClickHouse integration test: no server at {url}");
            return;
        }

        let config = test_config(&url, "sentinel_it_roundtrip");
        let mut store = ClickHouseStore::new(&config);

        // Deterministic counts across runs.
        reset_test_table(&mut store, "sentinel_it_roundtrip").await;

        // Schema creation is idempotent across writes.
        let row_a = sample_row("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e01");
        let row_b = sample_row("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e02");
        store.write_batch(std::slice::from_ref(&row_a)).await.expect("first batch");
        store.write_batch(std::slice::from_ref(&row_b)).await.expect("second batch");
        assert_eq!(count_rows(&store).await, 2);

        // Round-trip the stored row through the same binary format.
        let fetched: FlowRow = store
            .client
            .query("SELECT ?fields FROM network_flows WHERE flow_id = toUUID(?)")
            .bind(row_b.flow_id.to_string())
            .fetch_one()
            .await
            .expect("select row");
        assert_eq!(fetched, row_b);
    }

    #[tokio::test]
    async fn writer_flushes_batches_to_clickhouse() {
        let url =
            std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
        if !clickhouse_available(&url).await {
            eprintln!("skipping ClickHouse integration test: no server at {url}");
            return;
        }

        let config = test_config(&url, "sentinel_it_writer");
        let mut store = ClickHouseStore::new(&config);
        reset_test_table(&mut store, "sentinel_it_writer").await;

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let metrics = Arc::new(crate::metrics::SensorMetrics::new().unwrap());
        let writer = crate::output::writer::FlowWriter::new(
            rx,
            store,
            2,
            Duration::from_millis(50),
            crate::output::WRITE_TIMEOUT,
            metrics.clone(),
        );
        let handle = tokio::spawn(writer.run());

        for i in 1..=5u8 {
            let flow = sample_flow(&format!("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e{i:02}"));
            tx.send(flow).await.expect("send flow");
        }
        drop(tx);
        handle.await.expect("writer task");

        // 5 flows: batch-size flushes of 2 + 2, final flush of 1.
        assert_eq!(metrics.flows_written.get(), 5);
        let store = ClickHouseStore::new(&config);
        assert_eq!(count_rows(&store).await, 5);
    }

    #[tokio::test]
    async fn packets_reach_clickhouse_through_pipeline() {
        let url =
            std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
        if !clickhouse_available(&url).await {
            eprintln!("skipping ClickHouse integration test: no server at {url}");
            return;
        }

        let config = test_config(&url, "sentinel_it_pipeline");
        let mut store = ClickHouseStore::new(&config);
        reset_test_table(&mut store, "sentinel_it_pipeline").await;

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let metrics = Arc::new(crate::metrics::SensorMetrics::new().unwrap());
        let writer = crate::output::writer::FlowWriter::new(
            rx,
            store,
            10,
            Duration::from_millis(50),
            crate::output::WRITE_TIMEOUT,
            metrics.clone(),
        );
        let writer_task = tokio::spawn(writer.run());

        // SYN then FIN: the flow engine exports immediately on FIN.
        let mut processor = crate::flow::FlowProcessor::new(
            &crate::config::FlowConfig::default(),
            "node-1".into(),
            metrics.clone(),
        );
        let syn = crate::flow::make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x02);
        assert!(processor.on_packet(&syn).is_none());
        let fin = crate::flow::make_tcp_packet([10, 0, 0, 1], [10, 0, 0, 2], 12345, 80, 0x11);
        let exported = processor.on_packet(&fin).expect("FIN exports the flow");
        tx.send(exported).await.expect("writer running");
        drop(tx);
        writer_task.await.expect("writer task");

        let store = ClickHouseStore::new(&config);
        assert_eq!(count_rows(&store).await, 1);
        let rows: Vec<FlowRow> = store
            .client
            .query("SELECT ?fields FROM network_flows")
            .fetch_all()
            .await
            .expect("select flows");
        let row = &rows[0];
        assert_eq!(row.source_ip, Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert_eq!(row.destination_ip, Ipv4Addr::new(10, 0, 0, 2).to_ipv6_mapped());
        assert_eq!(row.source_port, 12345);
        assert_eq!(row.destination_port, 80);
        assert_eq!(row.protocol, 1);
        // SYN|FIN|ACK observed across both packets, in TcpFlags::to_vec order.
        assert_eq!(row.tcp_flags_seen, vec![0x02, 0x10, 0x01]);
        assert_eq!(row.sensor_node, "node-1");
        assert_eq!(metrics.flows_written.get(), 1);
    }

    #[tokio::test]
    async fn default_batching_meets_latency_budget() {
        let url =
            std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
        if !clickhouse_available(&url).await {
            eprintln!("skipping ClickHouse integration test: no server at {url}");
            return;
        }

        // Defaults from OutputConfig: batch_size 1000, timeout 500ms.
        let config = test_config(&url, "sentinel_it_latency");
        let mut store = ClickHouseStore::new(&config);
        reset_test_table(&mut store, "sentinel_it_latency").await;

        let (tx, rx) = tokio::sync::mpsc::channel(16);
        let metrics = Arc::new(crate::metrics::SensorMetrics::new().unwrap());
        let writer = crate::output::writer::FlowWriter::new(
            rx,
            store,
            config.batch_size,
            Duration::from_millis(config.batch_timeout_ms),
            crate::output::WRITE_TIMEOUT,
            metrics,
        );
        let writer_task = tokio::spawn(writer.run());

        // Keep the sender open: only the timeout flush can write this row.
        let started = std::time::Instant::now();
        tx.send(sample_flow("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e09")).await.expect("writer running");
        let probe = ClickHouseStore::new(&config);
        loop {
            let elapsed = started.elapsed();
            assert!(
                elapsed < Duration::from_millis(950),
                "row not written within the <1s budget ({elapsed:?})"
            );
            if count_rows(&probe).await == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        let elapsed = started.elapsed();
        eprintln!("export-to-ClickHouse latency: {elapsed:?}");
        assert!(elapsed >= Duration::from_millis(400));

        drop(tx);
        writer_task.await.expect("writer task");
    }

    #[test]
    fn table_ddl_covers_row_columns() {
        let ddl = create_table_sql();
        for column in <FlowRow as clickhouse::Row>::COLUMN_NAMES {
            assert!(
                ddl.contains(&format!(" {column} ")),
                "column {column} missing from DDL:\n{ddl}"
            );
        }
        assert!(ddl.contains("ENGINE = MergeTree()"));
        assert!(ddl.contains("PARTITION BY toYYYYMM(timestamp_start)"));
    }
}
