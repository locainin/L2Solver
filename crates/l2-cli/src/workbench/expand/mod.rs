//! Recursive artifact expansion with explicit budgets and evidence relationships

mod archive;
mod der;
mod png;

#[cfg(test)]
#[path = "../../../tests/workbench/expand_memory.rs"]
mod memory_tests;
#[cfg(test)]
#[path = "../../../tests/workbench/expand_service.rs"]
mod service_tests;

use super::{file_signatures, load, selected};
use crate::arguments::ExpandArgs;
use l2_workbench::{
    artifact::{PNG_SIGNATURE, zip::has_zip_end_record},
    evidence::{Case, Edge, EvidenceError, EvidenceStatus, MAX_NODES},
    job::{MemoryBudget, MemoryClass, MemoryError, MemoryLease},
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    error::Error,
    fmt,
    io::Write,
};

const ZIP_LOCAL_MAGIC: &[u8; 4] = b"PK\x03\x04";
const ZIP_EMPTY_MAGIC: &[u8; 4] = b"PK\x05\x06";
const ZIP64_MAGIC: &[u8; 4] = b"PK\x06\x06";
pub(super) const ZIP_MEMBER_NAME_PREVIEW_BYTES: usize = 128;

#[derive(Clone, Copy)]
struct WorkItem {
    node: u64,
    depth: usize,
    root: bool,
}

struct NodeInput {
    blob: String,
    bytes: Option<ChargedInput>,
    length: usize,
}

struct ChargedInput {
    bytes: Vec<u8>,
    _memory: Option<MemoryLease>,
}

// One service owns shared budgets while candidate-local parser state resets
pub(super) struct ExpansionService<'a> {
    case: &'a mut Case,
    memory: Option<&'a MemoryBudget>,
    limits: ExpansionLimits,
    queue: VecDeque<WorkItem>,
    parsed_blobs: HashMap<String, u64>,
    created_objects: usize,
    max_objects: usize,
    retained_bytes: usize,
    zip_work_remaining: usize,
    work_remaining: Option<usize>,
    work_used: usize,
    case_blob_bytes: usize,
    complete: bool,
    rejections: Vec<CandidateRejection>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ExpansionLimits {
    pub(super) depth: usize,
    pub(super) objects: usize,
    pub(super) input_bytes: usize,
    pub(super) archive_entries: usize,
    pub(super) member_bytes: usize,
    pub(super) zip_work_bytes: usize,
    pub(super) retained_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum CandidateMode {
    StrictSelected,
    SpeculativeProbe,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct CandidateRejection {
    pub(super) node: u64,
    pub(super) format: &'static str,
    pub(super) message: String,
}

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ExpansionOutcome {
    pub(super) created_nodes: Vec<u64>,
    pub(super) complete: bool,
    pub(super) rejections: Vec<CandidateRejection>,
    pub(super) work_bytes: usize,
}

#[derive(Debug)]
pub(super) enum ExpansionError {
    Rejected(CandidateRejection),
    Failure(ExpansionFailure),
    Memory(MemoryError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ExpansionFailureKind {
    Invariant,
    Io,
    Resource,
}

#[derive(Debug)]
pub(super) struct ExpansionFailure {
    pub(super) kind: ExpansionFailureKind,
    source: Box<dyn Error>,
}

impl ExpansionError {
    pub(super) fn invariant(error: impl Error + 'static) -> Self {
        Self::failure(ExpansionFailureKind::Invariant, Box::new(error))
    }

    pub(super) fn resource(error: impl Error + 'static) -> Self {
        Self::failure(ExpansionFailureKind::Resource, Box::new(error))
    }

    fn failure(kind: ExpansionFailureKind, source: Box<dyn Error>) -> Self {
        Self::Failure(ExpansionFailure { kind, source })
    }
}

impl fmt::Display for ExpansionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected(rejection) => write!(
                formatter,
                "candidate node {} was rejected as {}: {}",
                rejection.node, rejection.format, rejection.message
            ),
            Self::Failure(failure) => {
                let category = match failure.kind {
                    ExpansionFailureKind::Invariant => "invariant",
                    ExpansionFailureKind::Io => "I/O",
                    ExpansionFailureKind::Resource => "resource",
                };
                write!(formatter, "{category} failure: {}", failure.source)
            }
            Self::Memory(error) => write!(formatter, "expansion memory admission failed: {error}"),
        }
    }
}

impl Error for ExpansionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Rejected(_) => None,
            Self::Failure(failure) => Some(failure.source.as_ref()),
            Self::Memory(error) => Some(error),
        }
    }
}

impl From<Box<dyn Error>> for ExpansionError {
    fn from(error: Box<dyn Error>) -> Self {
        if let Some(memory) = error.downcast_ref::<MemoryError>() {
            return Self::Memory(*memory);
        }
        if let Some(EvidenceError::Memory(memory)) = error.downcast_ref::<EvidenceError>() {
            return Self::Memory(*memory);
        }
        let kind = error.downcast_ref::<EvidenceError>().map_or_else(
            || {
                if error.downcast_ref::<std::io::Error>().is_some() {
                    ExpansionFailureKind::Io
                } else if error
                    .downcast_ref::<std::collections::TryReserveError>()
                    .is_some()
                {
                    ExpansionFailureKind::Resource
                } else {
                    ExpansionFailureKind::Invariant
                }
            },
            evidence_failure_kind,
        );
        Self::failure(kind, error)
    }
}

impl From<EvidenceError> for ExpansionError {
    fn from(error: EvidenceError) -> Self {
        if let EvidenceError::Memory(memory) = error {
            return Self::Memory(memory);
        }
        let kind = evidence_failure_kind(&error);
        Self::failure(kind, Box::new(error))
    }
}

impl From<MemoryError> for ExpansionError {
    fn from(error: MemoryError) -> Self {
        Self::Memory(error)
    }
}

impl From<std::io::Error> for ExpansionError {
    fn from(error: std::io::Error) -> Self {
        Self::failure(ExpansionFailureKind::Io, Box::new(error))
    }
}

impl From<&'static str> for ExpansionError {
    fn from(message: &'static str) -> Self {
        Self::failure(ExpansionFailureKind::Invariant, Box::from(message))
    }
}

const fn evidence_failure_kind(error: &EvidenceError) -> ExpansionFailureKind {
    match error {
        EvidenceError::WriteFailed => ExpansionFailureKind::Io,
        EvidenceError::CaseTooLarge { .. }
        | EvidenceError::QuotaExceeded { .. }
        | EvidenceError::NodeDetailsTooLarge { .. }
        | EvidenceError::TotalDetailsTooLarge { .. }
        | EvidenceError::AllocationFailed { .. } => ExpansionFailureKind::Resource,
        _ => ExpansionFailureKind::Invariant,
    }
}

pub(super) fn run(args: &ExpandArgs, output: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let mut case = load(&args.case)?;
    let input_length = selected::bytes(&case, args.node)?.1.len();
    if input_length > args.max_input_bytes.get() {
        return Err(format!(
            "selected artifact has {input_length} bytes; maximum is {}",
            args.max_input_bytes
        )
        .into());
    }
    let complete = {
        let mut expansion = ExpansionService::new(&mut case, ExpansionLimits::from(args), None);
        let outcome = expansion.expand_selected(args.node)?;
        outcome.complete && expansion.case().collection_complete()
    };
    case.write_json(output)?;
    Ok(complete)
}

impl From<&ExpandArgs> for ExpansionLimits {
    fn from(args: &ExpandArgs) -> Self {
        Self {
            depth: args.max_depth as usize,
            objects: args.max_objects.get(),
            input_bytes: args.max_input_bytes.get(),
            archive_entries: args.max_archive_entries.get(),
            member_bytes: args.max_member_bytes.get(),
            zip_work_bytes: args.max_zip_work_bytes.get(),
            retained_bytes: args.max_retained_bytes.get(),
        }
    }
}

impl<'a> ExpansionService<'a> {
    pub(super) fn new(
        case: &'a mut Case,
        limits: ExpansionLimits,
        memory: Option<&'a MemoryBudget>,
    ) -> Self {
        let case_blob_bytes = case.blobs().iter().map(|blob| blob.bytes.len()).sum();
        let available_nodes = MAX_NODES.saturating_sub(case.nodes().len());
        Self {
            case,
            memory,
            limits,
            queue: VecDeque::new(),
            parsed_blobs: HashMap::new(),
            created_objects: 0,
            max_objects: limits.objects.min(available_nodes),
            retained_bytes: 0,
            zip_work_remaining: limits.zip_work_bytes,
            work_remaining: None,
            work_used: 0,
            case_blob_bytes,
            complete: true,
            rejections: Vec::new(),
        }
    }

    pub(super) const fn case(&self) -> &Case {
        self.case
    }

    pub(super) fn expand_selected(
        &mut self,
        node: u64,
    ) -> Result<ExpansionOutcome, ExpansionError> {
        self.expand_candidate(node, CandidateMode::StrictSelected, 0, None, true)
    }

    #[cfg(test)]
    pub fn probe_candidate(&mut self, node: u64) -> Result<ExpansionOutcome, ExpansionError> {
        self.probe_candidate_at(node, 0)
    }

    /// Probe an artifact at its absolute recovery depth
    #[cfg(test)]
    pub(super) fn probe_candidate_at(
        &mut self,
        node: u64,
        start_depth: usize,
    ) -> Result<ExpansionOutcome, ExpansionError> {
        self.expand_candidate(
            node,
            CandidateMode::SpeculativeProbe,
            start_depth,
            None,
            true,
        )
    }

    /// Expand one candidate layer within the coordinator's remaining work allowance
    pub(super) fn probe_candidate_at_with_work(
        &mut self,
        node: u64,
        start_depth: usize,
        work_bytes: usize,
    ) -> Result<ExpansionOutcome, ExpansionError> {
        self.expand_candidate(
            node,
            CandidateMode::SpeculativeProbe,
            start_depth,
            Some(work_bytes),
            false,
        )
    }

    fn expand_candidate(
        &mut self,
        node: u64,
        mode: CandidateMode,
        start_depth: usize,
        work_limit: Option<usize>,
        recursive: bool,
    ) -> Result<ExpansionOutcome, ExpansionError> {
        let initial_node_count = self.case.nodes().len();
        // Keep cumulative limits while clearing the previous candidate's worklist
        self.queue.clear();
        self.parsed_blobs.clear();
        self.rejections.clear();
        self.work_remaining = work_limit;
        self.work_used = 0;
        self.complete = true;
        self.queue.push_back(WorkItem {
            node,
            depth: start_depth,
            root: true,
        });
        self.execute(mode, recursive)?;

        // New evidence is appended, so this suffix is the exact result of this call
        let added_nodes = self
            .case
            .nodes()
            .get(initial_node_count..)
            .ok_or("case node count decreased during expansion")?;
        let mut created_nodes = Vec::new();
        created_nodes
            .try_reserve(added_nodes.len())
            .map_err(ExpansionError::resource)?;
        created_nodes.extend(added_nodes.iter().map(|node| node.id));
        Ok(ExpansionOutcome {
            created_nodes,
            complete: self.complete,
            rejections: std::mem::take(&mut self.rejections),
            work_bytes: self.work_used,
        })
    }

    fn execute(&mut self, mode: CandidateMode, recursive: bool) -> Result<(), ExpansionError> {
        while let Some(item) = self.queue.pop_front() {
            self.execute_item(item, mode, recursive)?;
        }
        Ok(())
    }

    fn execute_item(
        &mut self,
        item: WorkItem,
        mode: CandidateMode,
        recursive: bool,
    ) -> Result<(), ExpansionError> {
        if !recursive && !item.root {
            return Ok(());
        }
        let Some((blob, bytes)) = self.input_for_item(item)? else {
            return Ok(());
        };
        if !item.root && !self.spend_work(bytes.bytes.len())? {
            self.omit(
                item.node,
                "work_byte_limit",
                &json!({"requested":bytes.bytes.len()}),
            )?;
            return Ok(());
        }
        self.parsed_blobs.insert(blob, item.node);
        self.parse_item(item, mode, &bytes.bytes)
    }

    fn input_for_item(
        &mut self,
        item: WorkItem,
    ) -> Result<Option<(String, ChargedInput)>, ExpansionError> {
        if item.depth > self.limits.depth {
            self.omit(
                item.node,
                "depth_limit",
                &json!({"depth":item.depth,"maximum":self.limits.depth}),
            )?;
            return Ok(None);
        }
        let input = self.node_blob_and_bytes(item.node)?;
        let Some(bytes) = input.bytes else {
            self.omit(
                item.node,
                "input_byte_limit",
                &json!({"length":input.length,"maximum":self.limits.input_bytes}),
            )?;
            return Ok(None);
        };
        if let Some(canonical) = self.parsed_blobs.get(&input.blob).copied() {
            if canonical != item.node {
                self.edge(
                    item.node,
                    canonical,
                    "same_bytes_as",
                    EvidenceStatus::Observed,
                    "Both nodes reference the same content-addressed byte blob",
                )?;
            }
            return Ok(None);
        }
        Ok(Some((input.blob, bytes)))
    }

    fn parse_item(
        &mut self,
        item: WorkItem,
        mode: CandidateMode,
        bytes: &[u8],
    ) -> Result<(), ExpansionError> {
        let parsed = if bytes.starts_with(&PNG_SIGNATURE) {
            png::expand(self, item, bytes)
        } else if is_zip(bytes) {
            archive::expand(self, item, bytes)
        } else if der::try_expand(self, item, bytes)? {
            Ok(())
        } else {
            if item.root {
                self.reference_node(
                    "artifact_structure_unresolved",
                    item.node,
                    json!({
                        "input_node":item.node,
                        "length":bytes.len(),
                        "sha256":l2_workbench::sha256(bytes),
                        "reason":"no supported complete structure matched at byte zero"
                    }),
                )?;
            }
            Ok(())
        };
        self.record_parse_result(item, mode, parsed)?;
        self.add_signature_observations(item.node, bytes)?;
        Ok(())
    }

    fn record_parse_result(
        &mut self,
        item: WorkItem,
        mode: CandidateMode,
        parsed: Result<(), ExpansionError>,
    ) -> Result<(), ExpansionError> {
        match parsed {
            Ok(()) => Ok(()),
            Err(ExpansionError::Rejected(rejection)) => {
                // Explicit selection propagates a root rejection; probes retain it as evidence
                if item.root && mode == CandidateMode::StrictSelected {
                    return Err(ExpansionError::Rejected(rejection));
                }
                self.parse_issue(&rejection)?;
                self.rejections
                    .try_reserve(1)
                    .map_err(ExpansionError::resource)?;
                self.rejections.push(rejection);
                Ok(())
            }
            Err(error @ (ExpansionError::Failure(_) | ExpansionError::Memory(_))) => Err(error),
        }
    }

    pub(super) fn enqueue(&mut self, node: u64, depth: usize) {
        self.queue.push_back(WorkItem {
            node,
            depth,
            root: false,
        });
    }

    pub(super) fn reference_node(
        &mut self,
        kind: &str,
        parent: u64,
        details: Value,
    ) -> Result<Option<u64>, Box<dyn Error>> {
        if !self.reserve_object()? {
            return Ok(None);
        }
        let blob = self
            .case
            .node(parent)
            .and_then(|node| node.blob.as_deref())
            .map(str::to_owned)
            .ok_or("artifact parent has no retained byte blob")?;
        Ok(Some(self.case.add_node(
            kind,
            Some(&blob),
            Vec::new(),
            details,
        )?))
    }

    pub(super) fn byte_node(
        &mut self,
        kind: &str,
        parent: u64,
        bytes: &[u8],
        details: Value,
    ) -> Result<Option<u64>, Box<dyn Error>> {
        if !self.reserve_object()? {
            return Ok(None);
        }
        let blob_id = format!("sha256:{}", l2_workbench::sha256(bytes));
        let already_retained = self.case.blob(&blob_id).is_some();
        if !already_retained {
            let next_operation_bytes = self
                .retained_bytes
                .checked_add(bytes.len())
                .ok_or("artifact retained-byte accounting overflow")?;
            let next_case_bytes = self
                .case_blob_bytes
                .checked_add(bytes.len())
                .ok_or("case blob-byte accounting overflow")?;
            if next_operation_bytes > self.limits.retained_bytes
                || self
                    .case
                    .blob_byte_limit()
                    .is_some_and(|maximum| next_case_bytes > maximum)
            {
                // Give the reserved object slot to the omission record
                self.created_objects = self.created_objects.saturating_sub(1);
                self.omit(
                    parent,
                    "retained_byte_limit",
                    &json!({
                        "candidate_length":bytes.len(),
                        "operation_bytes_before":self.retained_bytes,
                        "operation_maximum":self.limits.retained_bytes,
                        "case_bytes_before":self.case_blob_bytes,
                        "case_maximum":self.case.blob_byte_limit()
                    }),
                )?;
                return Ok(None);
            }
            if !self.spend_work(bytes.len())? {
                // Give the reserved object slot to the omission record
                self.created_objects = self.created_objects.saturating_sub(1);
                self.omit(parent, "work_byte_limit", &json!({"requested":bytes.len()}))?;
                return Ok(None);
            }
            self.retained_bytes = next_operation_bytes;
            self.case_blob_bytes = next_case_bytes;
        }
        Ok(Some(self.case.add_bytes_node(
            kind,
            bytes,
            Vec::new(),
            details,
        )?))
    }

    pub(super) fn limit_zip_work(&self) -> usize {
        self.work_remaining
            .map_or(self.zip_work_remaining, |remaining| {
                self.zip_work_remaining.min(remaining)
            })
    }

    pub(super) fn retain_zip_work(&mut self, used: usize) -> Result<(), ExpansionError> {
        self.zip_work_remaining = self
            .zip_work_remaining
            .checked_sub(used)
            .ok_or("ZIP operation exceeded its remaining work budget")?;
        if !self.spend_work(used)? {
            return Err("ZIP parser exceeded its shared recovery work allowance".into());
        }
        Ok(())
    }

    fn spend_work(&mut self, bytes: usize) -> Result<bool, ExpansionError> {
        if let Some(remaining) = self.work_remaining.as_mut() {
            if bytes > *remaining {
                return Ok(false);
            }
            *remaining -= bytes;
        }
        self.work_used = self
            .work_used
            .checked_add(bytes)
            .ok_or("expansion work byte count overflowed")?;
        Ok(true)
    }

    pub(super) fn edge(
        &mut self,
        from: u64,
        to: u64,
        relation: &str,
        status: EvidenceStatus,
        reason: &str,
    ) -> Result<(), Box<dyn Error>> {
        self.case.add_edge(Edge {
            from,
            to,
            relation: relation.to_owned(),
            status,
            reason: reason.to_owned(),
        })?;
        Ok(())
    }

    pub(super) fn omit(
        &mut self,
        parent: u64,
        reason: &str,
        facts: &Value,
    ) -> Result<(), Box<dyn Error>> {
        self.complete = false;
        self.case.mark_incomplete(
            "Artifact expansion omitted one or more objects under an explicit resource or format limit",
        )?;
        let Some(issue) = self.reference_node(
            "artifact_expansion_omission",
            parent,
            json!({"parent_node":parent,"reason":reason,"facts":facts}),
        )?
        else {
            return Ok(());
        };
        self.edge(
            parent,
            issue,
            "omitted_child",
            EvidenceStatus::Unresolved,
            "The retained parent establishes the candidate bytes, but the recorded limit prevented complete expansion",
        )
    }

    fn parse_issue(&mut self, rejection: &CandidateRejection) -> Result<(), Box<dyn Error>> {
        let bounded_message: String = rejection.message.chars().take(512).collect();
        let Some(issue) = self.reference_node(
            "artifact_parse_issue",
            rejection.node,
            json!({
                "parent_node":rejection.node,
                "format":rejection.format,
                "error":bounded_message
            }),
        )?
        else {
            return Ok(());
        };
        self.edge(
            rejection.node,
            issue,
            "failed_to_parse",
            EvidenceStatus::ConstraintFailed,
            "Candidate bytes begin with the format marker but fail that format's structural checks",
        )
    }

    fn reserve_object(&mut self) -> Result<bool, Box<dyn Error>> {
        if self.created_objects < self.max_objects {
            self.created_objects += 1;
            return Ok(true);
        }
        self.complete = false;
        self.case.mark_incomplete(
            "Artifact expansion stopped after the configured derived-object budget",
        )?;
        Ok(false)
    }

    fn add_signature_observations(
        &mut self,
        input_node: u64,
        bytes: &[u8],
    ) -> Result<(), Box<dyn Error>> {
        let available = self.max_objects.saturating_sub(self.created_objects);
        let report = file_signatures::add_limited(self.case, input_node, bytes, available)?;
        self.created_objects = self
            .created_objects
            .checked_add(report.retained)
            .ok_or("artifact object count overflow")?;
        if report.omitted != 0 {
            self.complete = false;
            self.case.mark_incomplete(
                "One or more artifact signature observations were omitted after the configured derived-object budget",
            )?;
        }
        Ok(())
    }

    fn node_blob_and_bytes(&self, id: u64) -> Result<NodeInput, ExpansionError> {
        let (node, bytes) = selected::bytes(self.case, id)?;
        let blob = node
            .blob
            .clone()
            .ok_or("artifact input node has no retained byte blob")?;
        if bytes.len() > self.limits.input_bytes {
            return Ok(NodeInput {
                blob,
                bytes: None,
                length: bytes.len(),
            });
        }
        let requested = u64::try_from(bytes.len()).map_err(ExpansionError::invariant)?;
        let mut memory = self
            .memory
            .map(|budget| budget.try_reserve(MemoryClass::Executor, requested))
            .transpose()?;
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(ExpansionError::resource)?;
        if let Some(memory) = &mut memory {
            memory.try_resize(
                u64::try_from(retained.capacity()).map_err(ExpansionError::invariant)?,
            )?;
        }
        retained.extend_from_slice(bytes);
        Ok(NodeInput {
            blob,
            bytes: Some(ChargedInput {
                bytes: retained,
                _memory: memory,
            }),
            length: bytes.len(),
        })
    }
}

fn is_zip(bytes: &[u8]) -> bool {
    bytes.starts_with(ZIP_LOCAL_MAGIC)
        || bytes.starts_with(ZIP_EMPTY_MAGIC)
        || bytes.starts_with(ZIP64_MAGIC)
        || has_zip_end_record(bytes)
}

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(hex_digit(byte >> 4)));
        output.push(char::from(hex_digit(byte & 0x0f)));
    }
    output
}

const fn hex_digit(nibble: u8) -> u8 {
    match nibble {
        0..=9 => b'0' + nibble,
        10..=15 => b'a' + (nibble - 10),
        _ => b'?',
    }
}
