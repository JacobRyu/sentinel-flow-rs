//! Sentinel sensor library.
//!
//! `config`, `metrics`, `flow`, and `output` are compiled into this lib so
//! that `sentinel-sink` can reuse the flow writer and ClickHouse store, and so
//! that the `output` tests can drive the flow engine. The `capture` and
//! `server` modules stay private to the binary.

pub mod config;
pub mod flow;
pub mod metrics;
pub mod output;
