use thiserror::Error;

#[derive(Error, Debug)]
pub enum FlowError {
    #[error("Flow table full: max capacity {0}")]
    TableFull(usize),

    #[error("Flow not found: {0}")]
    NotFound(String),

    #[error("Export error: {0}")]
    ExportError(String),
}
