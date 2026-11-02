// The classic PCAP reader suite is grouped by format, limits, and I/O
// behavior so failures point directly at the contract under test
#[path = "../../../tests/fixtures/captures.rs"]
pub mod captures;

#[path = "reader/boundaries.rs"]
mod boundaries;
#[path = "reader/common.rs"]
mod common;
#[path = "reader/endian.rs"]
mod endian;
#[path = "reader/errors.rs"]
mod errors;
#[path = "reader/format.rs"]
mod format;
#[path = "reader/limits.rs"]
mod limits;
#[path = "reader/stream.rs"]
mod stream;
