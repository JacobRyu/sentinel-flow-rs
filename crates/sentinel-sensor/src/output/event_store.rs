//! ClickHouse storage for security events `security_events`.
//!
//! Not yet wired into the event writer (task 8), so the whole module is
//! unreachable from `main` today and would trip `-D warnings` on dead code.

#![allow(dead_code)] // removed in task 8 with the writer wiring + mod.rs's unused_imports allowance

use async_trait::async_trait;
use clickhouse::{Client, sql::Identifier};

use super::event_row::EventRow;
use crate::config::OutputConfig;

/// Table name; the database comes from the client, so no qualification here.
const TABLE: &str = "security_events";

/// Storage sink for security-event rows. `Send` so the writer task can own it.
#[async_trait]
pub trait EventStore: Send {
    /// Error type surfaced to the writer for logging and retry.
    type Error: std::fmt::Display + Send + Sync + 'static;

    /// Write one batch of rows. An empty slice must be a no-op.
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
    /// Database-less client: `CREATE DATABASE` cannot run through a client
    /// that already selects a database that may not exist yet.
    admin: Client,
    client: Client,
    database: String,
    schema_ready: bool,
}

impl ClickHouseEventStore {
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
        let database = config.clickhouse_database.clone();
        let client = admin.clone().with_database(&database);
        Self { admin, client, database, schema_ready: false }
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
}

#[async_trait]
impl EventStore for ClickHouseEventStore {
    type Error = clickhouse::error::Error;

    async fn write_batch(&mut self, rows: &[EventRow]) -> Result<(), Self::Error> {
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

impl ClickHouseEventStore {
    async fn do_write(&mut self, rows: &[EventRow]) -> clickhouse::error::Result<()> {
        self.ensure_schema().await?;
        let mut insert = self.client.insert(TABLE)?;
        for row in rows {
            insert.write(row).await?;
        }
        insert.end().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::event_row::sample_event;
    use std::time::Duration;

    /// Probe the ClickHouse server; when `REQUIRE_CLICKHOUSE` is set (CI) an
    /// unreachable server fails the test instead of skipping it. Same gating
    /// as the `network_flows` integration tests in `clickhouse.rs`.
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
    async fn reset_test_table(store: &mut ClickHouseEventStore, database: &str) {
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

    #[tokio::test]
    async fn empty_batch_is_a_noop() {
        let url =
            std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
        if !clickhouse_available(&url).await {
            eprintln!("skipping ClickHouse integration test: no server at {url}");
            return;
        }
        let mut store = ClickHouseEventStore::new(&OutputConfig::default());
        // No traffic at all: must not panic or touch the network.
        store.write_batch(&[]).await.unwrap();
    }

    #[tokio::test]
    async fn roundtrips_security_events() {
        let url =
            std::env::var("CLICKHOUSE_URL").unwrap_or_else(|_| "http://localhost:8123".to_string());
        if !clickhouse_available(&url).await {
            eprintln!("skipping ClickHouse integration test: no server at {url}");
            return;
        }

        let config = test_config(&url, "sentinel_it_events");
        let mut store = ClickHouseEventStore::new(&config);
        reset_test_table(&mut store, "sentinel_it_events").await;

        let event = sample_event("EXT-001", 443);
        let row = EventRow::from(&event);
        store.write_batch(std::slice::from_ref(&row)).await.expect("write event");

        let selected: Vec<EventRow> = store
            .client
            .query("SELECT ?fields FROM security_events WHERE event_id = toUUID(?)")
            .bind(row.event_id.to_string())
            .fetch_all()
            .await
            .expect("select event");
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0], row);
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
