//! Shared JSONL record framing for snapshots and published evidence

use serde::Serialize;

#[derive(Serialize)]
pub(super) struct RecordRef<'a, T: ?Sized> {
    pub(super) record: &'static str,
    pub(super) value: &'a T,
}
