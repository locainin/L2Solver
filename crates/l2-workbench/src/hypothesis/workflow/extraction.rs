use super::{ReconstructionReceipt, StreamReceipt, WorkflowError, WorkflowLimits, WorkflowPlan};
use crate::{
    protocol::{
        Direction, MessageContext, MessageRecord, ProtocolError, StreamExtractionReport,
        StreamMessageParser, StreamTransition, report_size,
    },
    reconstruction::{ReconstructionReport, Stream, TcpSession},
};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct Extraction {
    pub(super) reconstruction: ReconstructionReceipt,
    pub(super) frames: Vec<MessageRecord>,
    pub(super) streams: Vec<StreamReceipt>,
    pub(super) transitions: Vec<StreamTransition>,
    pub(super) omitted_streams: usize,
    pub(super) partial_streams: usize,
}

pub(super) fn session_split(
    sessions: &[TcpSession],
) -> Result<(BTreeSet<u32>, BTreeSet<u32>, bool), WorkflowError> {
    let mut known_groups = Vec::new();
    let mut ambiguous_group = BTreeMap::<AmbiguousGroupKey, BTreeSet<u32>>::new();
    for session in sessions {
        if session.first_packet == 0 {
            return Err(WorkflowError::InvalidPlan(
                "reconstruction contains a zero TCP session identity",
            ));
        }
        let scope = serde_json::to_string(&session.scope)?;
        if session.generation_ambiguous {
            ambiguous_group
                .entry(AmbiguousGroupKey {
                    scope,
                    endpoints: session.endpoints.clone(),
                })
                .or_default()
                .insert(session.first_packet);
        } else {
            known_groups.push(session.first_packet);
        }
    }
    known_groups.sort_unstable();
    if known_groups.len() < 2 {
        return Ok((
            sessions
                .iter()
                .map(|session| session.first_packet)
                .collect(),
            BTreeSet::new(),
            false,
        ));
    }
    let heldout = known_groups.split_off(known_groups.len() / 2);
    let mut discovery = known_groups.into_iter().collect::<BTreeSet<_>>();
    // Ambiguous tuple generations stay with discovery and cannot supply a held-out group
    discovery.extend(ambiguous_group.into_values().flatten());
    Ok((discovery, heldout.into_iter().collect(), true))
}

pub(super) fn extract_sessions(
    source_id: &str,
    reconstruction: &ReconstructionReport,
    plan: &WorkflowPlan,
    limits: WorkflowLimits,
) -> Result<Extraction, WorkflowError> {
    let receipt = ReconstructionReceipt {
        frames: reconstruction.frames,
        input_selection: reconstruction.input_selection,
        complete: reconstruction.complete,
        omitted_frames: reconstruction.omitted_frames,
        unsupported_frames: reconstruction.unsupported_frames,
        omitted_fragments: reconstruction.omitted_fragments,
        omitted_tcp_records: reconstruction.omitted_tcp_records,
        omitted_ranges: reconstruction.omitted_ranges,
        omitted_state_observations: reconstruction.omitted_state_observations,
    };
    let mut output = ExtractionBuilder::new(limits);
    for session in &reconstruction.sessions {
        for (direction_index, stream) in session.directions.iter().enumerate() {
            output.extract_stream(source_id, session, direction_index, stream, plan)?;
        }
    }
    Ok(output.finish(receipt))
}

struct ExtractionBuilder {
    limits: WorkflowLimits,
    frames: Vec<MessageRecord>,
    streams: Vec<StreamReceipt>,
    transitions: Vec<StreamTransition>,
    omitted_streams: usize,
    partial_streams: usize,
    total_input_bytes: usize,
    estimated_report_bytes: usize,
    remaining_samples: usize,
}

impl ExtractionBuilder {
    const fn new(limits: WorkflowLimits) -> Self {
        Self {
            limits,
            frames: Vec::new(),
            streams: Vec::new(),
            transitions: Vec::new(),
            omitted_streams: 0,
            partial_streams: 0,
            total_input_bytes: 0,
            estimated_report_bytes: 0,
            remaining_samples: limits.protocol.max_samples,
        }
    }

    fn extract_stream(
        &mut self,
        source_id: &str,
        session: &TcpSession,
        direction_index: usize,
        stream: &Stream,
        plan: &WorkflowPlan,
    ) -> Result<(), WorkflowError> {
        let runs = stream.runs();
        self.account_input(&runs)?;
        if self.remaining_samples == 0 {
            self.omitted_streams = self.omitted_streams.saturating_add(1);
            return Ok(());
        }
        let context = MessageContext {
            source: source_id.to_owned(),
            scope: serde_json::to_string(&session.scope)?,
            session: u64::from(session.first_packet),
            direction: if direction_index == 0 {
                Direction::FirstToSecond
            } else {
                Direction::SecondToFirst
            },
        };
        let extracted = self.parse_stream(context, session, stream, &runs, plan)?;
        self.retain_report(extracted)
    }

    fn account_input(
        &mut self,
        runs: &[crate::reconstruction::ByteRun],
    ) -> Result<(), WorkflowError> {
        let stream_bytes = runs.iter().try_fold(0_usize, |total, run| {
            total
                .checked_add(run.bytes.len())
                .ok_or(ProtocolError::TotalBytesTooLarge {
                    total: usize::MAX,
                    maximum: self.limits.protocol.max_total_bytes,
                })
        })?;
        self.total_input_bytes = self.total_input_bytes.checked_add(stream_bytes).ok_or(
            ProtocolError::TotalBytesTooLarge {
                total: usize::MAX,
                maximum: self.limits.protocol.max_total_bytes,
            },
        )?;
        if self.total_input_bytes > self.limits.protocol.max_total_bytes {
            return Err(WorkflowError::Protocol(ProtocolError::TotalBytesTooLarge {
                total: self.total_input_bytes,
                maximum: self.limits.protocol.max_total_bytes,
            }));
        }
        Ok(())
    }

    fn parse_stream(
        &self,
        context: MessageContext,
        session: &TcpSession,
        stream: &Stream,
        runs: &[crate::reconstruction::ByteRun],
        plan: &WorkflowPlan,
    ) -> Result<StreamExtractionReport, WorkflowError> {
        let mut parser_limits = self.limits.protocol;
        parser_limits.max_samples = self.remaining_samples;
        parser_limits.max_report_bytes = self
            .limits
            .protocol
            .max_report_bytes
            .saturating_sub(self.estimated_report_bytes)
            .max(1);
        let mut parser = StreamMessageParser::new(
            context,
            session.generation_ambiguous,
            stream.sequence_ambiguous,
            plan.framing_candidates.clone(),
            parser_limits,
        )?;
        for run in runs {
            parser.push_chunk(run.offset, run.bytes, &stream.origins)?;
        }
        Ok(parser.into_report()?)
    }

    fn retain_report(&mut self, extracted: StreamExtractionReport) -> Result<(), WorkflowError> {
        self.remaining_samples = self
            .remaining_samples
            .saturating_sub(extracted.messages.len());
        self.estimated_report_bytes = self
            .estimated_report_bytes
            .checked_add(extraction_size_estimate(
                &extracted,
                self.limits.protocol.max_report_bytes,
            )?)
            .ok_or(ProtocolError::TotalBytesTooLarge {
                total: usize::MAX,
                maximum: self.limits.protocol.max_report_bytes,
            })?;
        if self.estimated_report_bytes > self.limits.protocol.max_report_bytes {
            return Err(WorkflowError::Protocol(ProtocolError::TotalBytesTooLarge {
                total: self.estimated_report_bytes,
                maximum: self.limits.protocol.max_report_bytes,
            }));
        }
        self.partial_streams = self
            .partial_streams
            .saturating_add(usize::from(extracted.partial));
        self.streams.push(stream_receipt(&extracted));
        self.frames.extend(extracted.messages);
        self.transitions.extend(extracted.transitions);
        Ok(())
    }

    fn finish(self, reconstruction: ReconstructionReceipt) -> Extraction {
        Extraction {
            reconstruction,
            frames: self.frames,
            streams: self.streams,
            transitions: self.transitions,
            omitted_streams: self.omitted_streams,
            partial_streams: self.partial_streams,
        }
    }
}

fn stream_receipt(extracted: &StreamExtractionReport) -> StreamReceipt {
    StreamReceipt {
        context: extracted.context.clone(),
        generation_ambiguous: extracted.generation_ambiguous,
        sequence_ambiguous: extracted.sequence_ambiguous,
        input_bytes: extracted.input_bytes,
        omitted_candidates: extracted.omitted_candidates,
        partial: extracted.partial,
    }
}

fn extraction_size_estimate(
    extracted: &StreamExtractionReport,
    maximum: usize,
) -> Result<usize, WorkflowError> {
    let records =
        report_size::estimate_records(&extracted.messages, &extracted.transitions, maximum)?;
    let stream_receipt = std::mem::size_of::<StreamReceipt>()
        .checked_add(report_size::context_owned_bytes(
            &extracted.context,
            maximum,
        )?)
        .ok_or(ProtocolError::TotalBytesTooLarge {
            total: usize::MAX,
            maximum,
        })?;
    records
        .total(maximum)?
        .checked_add(stream_receipt)
        .ok_or(ProtocolError::TotalBytesTooLarge {
            total: usize::MAX,
            maximum,
        })
        .map_err(WorkflowError::from)
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AmbiguousGroupKey {
    scope: String,
    endpoints: [crate::reconstruction::Endpoint; 2],
}
