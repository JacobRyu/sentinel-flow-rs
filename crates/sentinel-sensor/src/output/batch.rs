//! Batch assembly: a bounded buffer of rows awaiting one write.

use super::row::FlowRow;

/// Bounded buffer of [`FlowRow`]s awaiting a batched write.
#[derive(Debug)]
pub struct BatchBuffer {
    rows: Vec<FlowRow>,
    capacity: usize,
}

impl BatchBuffer {
    /// Create a buffer that flushes once it holds `capacity` rows.
    pub fn new(capacity: usize) -> Self {
        assert!(capacity > 0, "batch capacity must be greater than zero");
        Self { rows: Vec::with_capacity(capacity), capacity }
    }

    /// Push a row, returning `true` when the batch is full and should be written.
    pub fn push(&mut self, row: FlowRow) -> bool {
        self.rows.push(row);
        self.rows.len() >= self.capacity
    }

    /// Whether no rows are buffered.
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Number of buffered rows.
    #[allow(dead_code)] // used by tests
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Take all buffered rows, leaving the buffer empty.
    pub fn take(&mut self) -> Vec<FlowRow> {
        std::mem::take(&mut self.rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(i: u8) -> FlowRow {
        let mut flow =
            crate::output::row::sample_flow(&format!("0c9d8e7f-1a2b-4c3d-8e4f-5a6b7c8d9e{i:02}"));
        flow.source_port = 10_000 + u16::from(i);
        FlowRow::try_from(&flow).unwrap()
    }

    #[test]
    fn pushes_until_capacity() {
        let mut buffer = BatchBuffer::new(2);
        assert!(buffer.is_empty());

        assert!(!buffer.push(row(1)));
        assert_eq!(buffer.len(), 1);

        assert!(buffer.push(row(2)));
        assert_eq!(buffer.len(), 2);

        let taken = buffer.take();
        assert_eq!(taken.len(), 2);
        assert!(buffer.is_empty());
        assert!(buffer.take().is_empty());
    }

    #[test]
    fn rejects_zero_capacity() {
        let result = std::panic::catch_unwind(|| BatchBuffer::new(0));
        assert!(result.is_err());
    }
}
