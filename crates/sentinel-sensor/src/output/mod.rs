//! Flow output: batch assembly, ClickHouse storage, and the writer loop.

mod batch;
mod clickhouse;
mod event_row;
mod event_store;
mod row;
mod writer;

pub(crate) use clickhouse::ClickHouseStore;
#[allow(unused_imports)] // re-exported for the event writer (task 8)
pub(crate) use event_store::ClickHouseEventStore;
pub(crate) use writer::{FlowWriter, WRITE_TIMEOUT};
