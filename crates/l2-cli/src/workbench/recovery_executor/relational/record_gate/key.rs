use super::super::super::RecoveryExecutionError;
use super::super::DecodedFrameOutput;
use super::super::{invalid_policy, operational};
use l2_workbench::{
    artifact::{ArtifactValidationFormat, ArtifactValidationPolicy},
    protocol::{
        Direction, HoldoutBasis, RecordSchemaProposalLimits, RelationalSessionId,
        RelationalTransformReport,
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SchemaHeaderKey {
    split_basis: u8,
    discovery_sessions: Vec<u64>,
    heldout_sessions: Vec<u64>,
    frames: Vec<FrameHeaderKey>,
    validation_format: ArtifactValidationFormat,
    validation_policy: ArtifactValidationPolicy,
    schema_limits: RecordSchemaProposalLimits,
    retained_bytes: usize,
}

impl SchemaHeaderKey {
    pub(super) const fn retained_bytes(&self) -> usize {
        self.retained_bytes
    }
}

impl Hash for SchemaHeaderKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.split_basis.hash(state);
        self.discovery_sessions.hash(state);
        self.heldout_sessions.hash(state);
        self.frames.hash(state);
        validation_format_key(self.validation_format).hash(state);
    }
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

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct FrameHeaderKey {
    input_node_id: u64,
    seed_sample: u64,
    direction_node_id: u64,
    episode_node_id: u64,
    source: String,
    scope: String,
    session: u64,
    direction: u8,
    session_order: u64,
    expected_session_orders: Vec<u64>,
    stream_offset: usize,
    frame_length: usize,
    parser_format: u8,
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

pub(super) fn schema_header_key(
    frames: &[DecodedFrameOutput],
    report: &RelationalTransformReport,
    parser_format: ArtifactValidationFormat,
    artifact_policy: ArtifactValidationPolicy,
    schema_limits: RecordSchemaProposalLimits,
    maximum_retained_bytes: usize,
) -> Result<Option<SchemaHeaderKey>, RecoveryExecutionError> {
    if frames.is_empty() {
        return Ok(None);
    }
    // A cache hit selects partial models; binding still checks the current bytes and lengths
    let Some(retained_bytes) = header_key_size(frames, report, maximum_retained_bytes) else {
        return Ok(None);
    };

    let mut frame_keys = Vec::new();
    frame_keys
        .try_reserve_exact(frames.len())
        .map_err(|source| operational("record gate header key allocation failed", source))?;
    for frame in frames {
        frame_keys.push(frame_header_key(frame)?);
    }
    Ok(Some(SchemaHeaderKey {
        split_basis: match report.split_basis {
            HoldoutBasis::SampleOrder => 0,
            HoldoutBasis::CompleteSessions => 1,
        },
        discovery_sessions: try_session_ids(&report.discovery_sessions)?,
        heldout_sessions: try_session_ids(&report.heldout_sessions)?,
        frames: frame_keys,
        validation_format: parser_format,
        validation_policy: artifact_policy,
        schema_limits,
        retained_bytes,
    }))
}

fn header_key_size(
    frames: &[DecodedFrameOutput],
    report: &RelationalTransformReport,
    maximum_retained_bytes: usize,
) -> Option<usize> {
    let session_bytes = report
        .discovery_sessions
        .len()
        .saturating_add(report.heldout_sessions.len())
        .saturating_mul(std::mem::size_of::<u64>());
    let mut retained_bytes = std::mem::size_of::<SchemaHeaderKey>()
        .saturating_add(
            frames
                .len()
                .saturating_mul(std::mem::size_of::<FrameHeaderKey>()),
        )
        .saturating_add(session_bytes);
    for frame in frames {
        retained_bytes = retained_bytes
            .saturating_add(frame.context.source.len())
            .saturating_add(frame.context.scope.len())
            .saturating_add(
                frame
                    .expected_session_orders
                    .len()
                    .saturating_mul(std::mem::size_of::<u64>()),
            );
        if retained_bytes > maximum_retained_bytes {
            return None;
        }
    }
    if retained_bytes > maximum_retained_bytes {
        return None;
    }
    Some(retained_bytes)
}

fn frame_header_key(frame: &DecodedFrameOutput) -> Result<FrameHeaderKey, RecoveryExecutionError> {
    Ok(FrameHeaderKey {
        input_node_id: frame.input_node_id,
        seed_sample: frame.seed_sample,
        direction_node_id: frame.direction_node_id,
        episode_node_id: frame.episode_node_id,
        source: try_clone_string(&frame.context.source)?,
        scope: try_clone_string(&frame.context.scope)?,
        session: frame.context.session,
        direction: match frame.context.direction {
            Direction::FirstToSecond => 0,
            Direction::SecondToFirst => 1,
        },
        session_order: frame.session_order,
        expected_session_orders: try_copy_slice(&frame.expected_session_orders)?,
        stream_offset: frame.stream_offset,
        frame_length: frame.bytes.len(),
        parser_format: validation_format_key(frame.parser_format),
    })
}

fn try_clone_string(value: &str) -> Result<String, RecoveryExecutionError> {
    super::super::try_clone_string(value)
        .map_err(|source| operational("record gate header key text allocation failed", source))
}

fn try_copy_slice<T: Copy>(values: &[T]) -> Result<Vec<T>, RecoveryExecutionError> {
    let mut copy = Vec::new();
    copy.try_reserve_exact(values.len()).map_err(|source| {
        operational("record gate header key metadata allocation failed", source)
    })?;
    copy.extend_from_slice(values);
    Ok(copy)
}

fn try_session_ids(sessions: &[RelationalSessionId]) -> Result<Vec<u64>, RecoveryExecutionError> {
    let mut ids = Vec::new();
    ids.try_reserve_exact(sessions.len())
        .map_err(|source| operational("record gate session key allocation failed", source))?;
    ids.extend(sessions.iter().map(|session| session.session));
    Ok(ids)
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
