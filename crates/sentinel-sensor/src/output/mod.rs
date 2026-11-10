//! Flow output: batch assembly, ClickHouse storage, and the writer loop.

mod batch;
mod clickhouse;
mod event_row;
// The event pipeline is not reachable from `main` until task 9 wires it;
// these allowances go away with that wiring.
#[cfg_attr(not(test), allow(dead_code))]
mod event_store;
#[cfg_attr(not(test), allow(dead_code))]
mod event_writer;
mod row;
mod writer;

pub(crate) use clickhouse::ClickHouseStore;
#[allow(unused_imports)] // consumed by the pipeline wiring in task 9
pub(crate) use event_store::ClickHouseEventStore;
#[allow(unused_imports)] // consumed by the pipeline wiring in task 9
pub(crate) use event_writer::EventWriter;
pub(crate) use writer::{FlowWriter, WRITE_TIMEOUT};
