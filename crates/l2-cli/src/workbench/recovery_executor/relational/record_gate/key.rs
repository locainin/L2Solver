use super::super::super::RecoveryExecutionError;
use super::super::DecodedFrameOutput;
use super::super::{invalid_policy, operational};
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    protocol::{
        Direction, RecordSchemaProposalLimits, RelationalSessionId, RelationalTransformReport,
    },
};
use std::hash::{Hash, Hasher};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SchemaLayoutKey {
    discovery_sessions: Vec<u64>,
    heldout_sessions: Vec<u64>,
    frames: Vec<FrameLayoutKey>,
    validation_format: ArtifactValidationFormat,
    validation_policy: ArtifactValidationPolicy,
    schema_limits: RecordSchemaProposalLimits,
    work_limit: usize,
}

impl Hash for SchemaLayoutKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.discovery_sessions.hash(state);
        self.heldout_sessions.hash(state);
        self.frames.hash(state);
        validation_format_key(self.validation_format).hash(state);
        self.work_limit.hash(state);
    }
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
    preserved_header_end: Option<usize>,
    transformed_output_sha256: String,
}

pub(super) fn schema_layout_key(
    frames: &[DecodedFrameOutput],
    report: &RelationalTransformReport,
    parser_format: ArtifactValidationFormat,
    artifact_policy: ArtifactValidationPolicy,
    schema_limits: RecordSchemaProposalLimits,
    work_limit: usize,
) -> Result<SchemaLayoutKey, RecoveryExecutionError> {
    let mut frame_keys = Vec::new();
    frame_keys
        .try_reserve_exact(frames.len())
        .map_err(|source| operational("record gate layout key allocation failed", source))?;
    for frame in frames {
        if let Some(prefix_end) = frame.preserved_header_end
            && frame.bytes.get(..prefix_end).is_none()
        {
            return Err(invalid_policy(
                "record gate preserved header ends outside frame",
            ));
        }
        if frame
            .bytes
            .get(frame.payload_range.start..frame.payload_range.end)
            .is_none()
        {
            return Err(invalid_policy(
                "record gate transformed payload is outside frame",
            ));
        }
        if frame.payload_range.end != frame.bytes.len() {
            return Err(invalid_policy(
                "record gate transformed payload does not cover the frame tail",
            ));
        }
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
            preserved_header_end: frame.preserved_header_end,
            transformed_output_sha256: frame.transformed_output_sha256.clone(),
        });
    }
    Ok(SchemaLayoutKey {
        discovery_sessions: session_ids(&report.discovery_sessions),
        heldout_sessions: session_ids(&report.heldout_sessions),
        frames: frame_keys,
        validation_format: parser_format,
        validation_policy: artifact_policy,
        schema_limits,
        work_limit,
    })
}

const fn validation_format_key(format: ArtifactValidationFormat) -> u8 {
    match format {
        ArtifactValidationFormat::Der => 0,
        ArtifactValidationFormat::Elf => 1,
        ArtifactValidationFormat::PortableExecutable => 2,
        ArtifactValidationFormat::Png => 3,
        ArtifactValidationFormat::Zip => 4,
    }
}

fn session_ids(sessions: &[RelationalSessionId]) -> Vec<u64> {
    sessions.iter().map(|session| session.session).collect()
}
