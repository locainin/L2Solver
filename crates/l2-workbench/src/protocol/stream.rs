//! Incremental source-mapped framing candidates over reconstructed TCP bytes

mod checkpoint;
mod gaps;
mod lifecycle;
mod mapping;
mod model;
mod origin_index;
mod parser;
mod planning;
mod report_budget;

pub use model::{
    MessageOrigin, MessageRecord, StreamExtractionReport, StreamMessageParser, StreamTransition,
    StreamTransitionState,
};
pub use parser::validate_stream_framings;

#[cfg(test)]
#[path = "../../tests/protocol/stream/memory.rs"]
mod memory_tests;
