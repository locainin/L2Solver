use super::super::super::RecoveryExecutionError;
use super::super::DecodedFrameOutput;
use super::super::{invalid_policy, operational};
use l2_workbench::protocol::{Direction, RelationalSessionId, RelationalTransformReport};

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub(super) struct SchemaLayoutKey {
    discovery_sessions: Vec<u64>,
    heldout_sessions: Vec<u64>,
    frames: Vec<FrameLayoutKey>,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FrameLayoutKey {
    input_node_id: u64,
    source: String,
    scope: String,
    session: u64,
    direction: u8,
    session_order: u64,
    frame_length: usize,
    transformed_payload_start: usize,
    unchanged_prefix: Vec<u8>,
    transformed_content_sha256: Option<String>,
}

pub(super) fn schema_layout_key(
    frames: &[DecodedFrameOutput],
    report: &RelationalTransformReport,
) -> Result<SchemaLayoutKey, RecoveryExecutionError> {
    let mut frame_keys = Vec::new();
    frame_keys
        .try_reserve_exact(frames.len())
        .map_err(|source| operational("record gate layout key allocation failed", source))?;
    for frame in frames {
        let prefix_end = frame.preserved_header_end.unwrap_or(0);
        let prefix = frame
            .bytes
            .get(..prefix_end)
            .ok_or_else(|| invalid_policy("record gate preserved header ends outside frame"))?;
        if frame.payload_range.end != frame.bytes.len() {
            return Err(invalid_policy(
                "record gate transformed payload does not cover the frame tail",
            ));
        }
        let mut unchanged_prefix = Vec::new();
        unchanged_prefix
            .try_reserve_exact(prefix.len())
            .map_err(|source| operational("record gate prefix key allocation failed", source))?;
        unchanged_prefix.extend_from_slice(prefix);
        frame_keys.push(FrameLayoutKey {
            input_node_id: frame.input_node_id,
            source: frame.context.source.clone(),
            scope: frame.context.scope.clone(),
            session: frame.context.session,
            direction: match frame.context.direction {
                Direction::FirstToSecond => 0,
                Direction::SecondToFirst => 1,
            },
            session_order: frame.session_order,
            frame_length: frame.bytes.len(),
            transformed_payload_start: frame.payload_range.start,
            unchanged_prefix,
            // A held header constrains layout; other frames key their full transformed bytes
            transformed_content_sha256: frame
                .preserved_header_end
                .is_none()
                .then(|| l2_workbench::sha256(&frame.bytes)),
        });
    }
    Ok(SchemaLayoutKey {
        discovery_sessions: session_ids(&report.discovery_sessions),
        heldout_sessions: session_ids(&report.heldout_sessions),
        frames: frame_keys,
    })
}

fn session_ids(sessions: &[RelationalSessionId]) -> Vec<u64> {
    sessions.iter().map(|session| session.session).collect()
}
