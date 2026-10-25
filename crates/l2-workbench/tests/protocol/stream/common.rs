use l2_workbench::protocol::{Direction, MessageContext, MessageOrigin, StreamTransition};
use std::error::Error;

pub(super) fn context() -> MessageContext {
    MessageContext {
        source: "sha256:source".to_owned(),
        scope: "scope-1".to_owned(),
        session: 9,
        direction: Direction::FirstToSecond,
    }
}

pub(super) const fn transition_metadata_bytes(
    context: &MessageContext,
    origin_count: usize,
    digest_bytes: usize,
) -> usize {
    std::mem::size_of::<StreamTransition>()
        + origin_count * std::mem::size_of::<MessageOrigin>()
        + context.source.len()
        + context.scope.len()
        + "candidate_framing".len()
        + digest_bytes
}

pub(super) fn set_checkpoint_field(
    checkpoint: &mut serde_json::Value,
    field: &str,
    value: serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    checkpoint
        .as_object_mut()
        .ok_or("checkpoint is not an object")?
        .insert(field.to_owned(), value);
    Ok(())
}
