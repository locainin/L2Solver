use super::{
    ByteRange, FramingBootstrapReport, FramingBootstrapRunReport, MessageContext, ProtocolError,
    ProtocolLimits, bootstrap_framing_with_limits, sampling::validate_limits,
};
use crate::reconstruction::{InputSelection, Origin, ReconstructionReport, Stream};
use serde::Serialize;

const MAX_INPUT_OMISSION_EXAMPLES: usize = 32;

/// Discover framing candidates directly over retained reconstructed TCP byte runs
///
/// The result borrows exact run bytes, stream coverage, and source origins from the
/// reconstruction report. Candidate frame ranges can be mapped back to capture bytes
/// without copying or reinterpreting the reconstructed data
///
/// # Errors
/// Rejects empty source identities, invalid protocol limits, or inconsistent reconstructed contexts
pub fn discover_reconstructed_framing_with_limits<'a>(
    source_id: &str,
    reconstruction: &'a ReconstructionReport,
    limits: ProtocolLimits,
) -> Result<ReconstructedFramingReport<'a>, ProtocolError> {
    validate_limits(limits)?;
    if source_id.is_empty() {
        return Err(ProtocolError::InvalidSourceIdentity);
    }

    let inputs = collect_reconstructed_inputs(source_id, reconstruction, limits)?;
    let bootstrap = if inputs.byte_samples.is_empty() {
        None
    } else {
        Some(bootstrap_framing_with_limits(&inputs.byte_samples, limits)?)
    };
    Ok(ReconstructedFramingReport {
        reconstruction,
        bootstrap,
        streams: inputs.streams,
        runs: inputs.runs,
        input_omissions: inputs.input_omissions,
    })
}

struct ReconstructedInputs<'a> {
    streams: Vec<ReconstructedFramingStream<'a>>,
    runs: Vec<ReconstructedFramingRun<'a>>,
    byte_samples: Vec<super::ByteRunSample<'a>>,
    input_omissions: ReconstructedFramingInputOmissions,
    sample: u64,
    retained_bytes: usize,
}

impl<'a> ReconstructedInputs<'a> {
    fn new(session_count: usize) -> Result<Self, ProtocolError> {
        let capacity = session_count
            .checked_mul(2)
            .ok_or(ProtocolError::InvalidLimits)?;
        let mut streams = Vec::new();
        streams
            .try_reserve_exact(capacity)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        Ok(Self {
            streams,
            runs: Vec::new(),
            byte_samples: Vec::new(),
            input_omissions: ReconstructedFramingInputOmissions::default(),
            sample: 1,
            retained_bytes: 0,
        })
    }

    fn append_session(
        &mut self,
        source_id: &str,
        session: &'a crate::reconstruction::TcpSession,
        limits: ProtocolLimits,
    ) -> Result<(), ProtocolError> {
        if session.first_packet == 0 {
            return Err(ProtocolError::InvalidContext {
                sample: self.sample,
            });
        }
        let scope =
            serde_json::to_string(&session.scope).map_err(|_| ProtocolError::InvalidContext {
                sample: self.sample,
            })?;
        for (direction_index, stream) in session.directions.iter().enumerate() {
            let context = MessageContext {
                source: source_id.to_owned(),
                scope: scope.clone(),
                session: u64::from(session.first_packet),
                direction: if direction_index == 0 {
                    super::Direction::FirstToSecond
                } else {
                    super::Direction::SecondToFirst
                },
            };
            self.append_stream(session, stream, &context, limits)?;
        }
        Ok(())
    }

    fn append_stream(
        &mut self,
        session: &'a crate::reconstruction::TcpSession,
        stream: &'a Stream,
        context: &MessageContext,
        limits: ProtocolLimits,
    ) -> Result<(), ProtocolError> {
        self.streams
            .try_reserve(1)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        let stream_index = self.streams.len();
        self.streams.push(ReconstructedFramingStream {
            context: context.to_owned(),
            session_first_packet: session.first_packet,
            generation_ambiguous: session.generation_ambiguous,
            stream,
        });
        for run in stream.runs() {
            let sample = self.sample;
            self.sample = sample
                .checked_add(1)
                .ok_or(ProtocolError::InvalidSampleId { sample })?;
            let reason = self.omission_reason(run.bytes.len(), limits);
            if let Some(reason) = reason {
                self.input_omissions
                    .record(ReconstructedFramingInputOmission {
                        sample,
                        stream_index,
                        length: run.bytes.len(),
                        reason,
                    })?;
                continue;
            }
            self.retain_run(
                sample,
                stream_index,
                &run,
                stream,
                context.to_owned(),
                limits,
            )?;
        }
        Ok(())
    }

    const fn omission_reason(
        &self,
        length: usize,
        limits: ProtocolLimits,
    ) -> Option<ReconstructedFramingInputOmissionReason> {
        if length > limits.max_run_bytes {
            Some(ReconstructedFramingInputOmissionReason::RunByteLimit)
        } else if self.byte_samples.len() == limits.max_samples {
            Some(ReconstructedFramingInputOmissionReason::SampleLimit)
        } else if length > limits.max_total_bytes - self.retained_bytes {
            Some(ReconstructedFramingInputOmissionReason::TotalByteLimit)
        } else {
            None
        }
    }

    fn retain_run(
        &mut self,
        sample: u64,
        stream_index: usize,
        run: &crate::reconstruction::ByteRun<'a>,
        stream: &'a Stream,
        context: MessageContext,
        limits: ProtocolLimits,
    ) -> Result<(), ProtocolError> {
        self.retained_bytes = self.retained_bytes.checked_add(run.bytes.len()).ok_or(
            ProtocolError::TotalBytesTooLarge {
                total: usize::MAX,
                maximum: limits.max_total_bytes,
            },
        )?;
        self.byte_samples
            .try_reserve(1)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        self.runs
            .try_reserve(1)
            .map_err(|_| ProtocolError::AllocationFailed)?;
        self.byte_samples.push(super::ByteRunSample {
            sample,
            context: Some(context),
            bytes: run.bytes,
        });
        self.runs.push(ReconstructedFramingRun {
            sample,
            stream_index,
            stream_offset: run.offset,
            bytes: run.bytes,
            origins: &stream.origins,
        });
        Ok(())
    }
}

fn collect_reconstructed_inputs<'a>(
    source_id: &str,
    reconstruction: &'a ReconstructionReport,
    limits: ProtocolLimits,
) -> Result<ReconstructedInputs<'a>, ProtocolError> {
    let mut sessions = Vec::new();
    sessions
        .try_reserve_exact(reconstruction.sessions.len())
        .map_err(|_| ProtocolError::AllocationFailed)?;
    sessions.extend(reconstruction.sessions.iter());
    sessions.sort_by(|left, right| {
        left.scope
            .cmp(&right.scope)
            .then_with(|| left.first_packet.cmp(&right.first_packet))
            .then_with(|| left.endpoints.cmp(&right.endpoints))
    });
    let mut inputs = ReconstructedInputs::new(sessions.len())?;
    for session in sessions {
        inputs.append_session(source_id, session, limits)?;
    }
    Ok(inputs)
}

/// Bootstrap results and exact borrowed provenance for reconstructed byte runs
pub struct ReconstructedFramingReport<'a> {
    /// Original retention, capture completeness, and gap facts
    pub reconstruction: &'a ReconstructionReport,
    /// Candidate generation and boundary materialization from the shared protocol service
    pub bootstrap: Option<FramingBootstrapReport>,
    /// Both directions for every retained TCP session, including directions without bytes
    pub streams: Vec<ReconstructedFramingStream<'a>>,
    /// Input runs retained within the configured protocol budgets
    pub runs: Vec<ReconstructedFramingRun<'a>>,
    /// Reconstructed runs skipped by an explicit protocol input budget
    pub input_omissions: ReconstructedFramingInputOmissions,
}

impl ReconstructedFramingReport<'_> {
    /// Whether capture, candidate reporting, or input budgets left evidence incomplete
    #[must_use]
    pub fn is_partial(&self) -> bool {
        !self.reconstruction.complete
            || self.reconstruction.input_selection == Some(InputSelection::SelectedRecords)
            || self.input_omissions.omitted_runs != 0
            || self.bootstrap.is_none()
            || self.bootstrap.as_ref().is_some_and(|report| {
                !report.search_exhaustive_within_plan || !report.report_details_complete
            })
    }

    /// Find materialized boundaries by the deterministic run sample identifier
    #[must_use]
    pub fn framing_for_run(&self, sample: u64) -> Option<&FramingBootstrapRunReport> {
        self.bootstrap.as_ref().and_then(|report| {
            report
                .discovery
                .iter()
                .chain(&report.holdout)
                .find(|run| run.boundaries.sample == sample)
        })
    }
}

/// Reconstructed session direction with its original coverage and gap record
pub struct ReconstructedFramingStream<'a> {
    /// Capture, scope, session, and direction identity used during holdout splitting
    pub context: MessageContext,
    /// Capture record that identifies this reconstructed TCP session
    pub session_first_packet: u32,
    /// Whether the TCP tuple and sequence generation was ambiguous
    pub generation_ambiguous: bool,
    /// Exact reconstruction facts, including observed, conflicting, omitted, and missing spans
    pub stream: &'a Stream,
}

/// Exact contiguous run supplied to framing candidate generation
pub struct ReconstructedFramingRun<'a> {
    /// Stable identifier shared with boundary results
    pub sample: u64,
    /// Index of the containing session direction in `ReconstructedFramingReport::streams`
    pub stream_index: usize,
    /// First byte position in the reconstructed directional stream
    pub stream_offset: usize,
    /// Exact observed bytes borrowed from the reconstruction report
    pub bytes: &'a [u8],
    /// Original capture observations for the containing stream
    pub origins: &'a [Origin],
}

impl ReconstructedFramingRun<'_> {
    /// Map one local run interval to exact capture packet and frame intervals
    ///
    /// # Errors
    /// Returns an error when the requested interval is outside the run, its offsets overflow,
    /// or retained origins do not cover every requested byte
    pub fn map_range(&self, range: ByteRange) -> Result<ReconstructedSourceMapping, ProtocolError> {
        if range.start > range.end || range.end > self.bytes.len() {
            return Err(ProtocolError::InvalidBoundaryRange {
                start: range.start,
                end: range.end,
                run_length: self.bytes.len(),
            });
        }
        let run_end = self
            .stream_offset
            .checked_add(self.bytes.len())
            .ok_or(ProtocolError::StreamOffsetOverflow)?;
        let stream_range = ByteRange {
            start: self
                .stream_offset
                .checked_add(range.start)
                .ok_or(ProtocolError::StreamOffsetOverflow)?,
            end: self
                .stream_offset
                .checked_add(range.end)
                .ok_or(ProtocolError::StreamOffsetOverflow)?,
        };
        if stream_range.end > run_end {
            return Err(ProtocolError::StreamOffsetOverflow);
        }
        let mut origins = Vec::new();
        for origin in self.origins {
            let origin_end = origin
                .offset
                .checked_add(origin.length)
                .ok_or(ProtocolError::StreamOffsetOverflow)?;
            let start = origin.offset.max(stream_range.start);
            let end = origin_end.min(stream_range.end);
            if start >= end {
                continue;
            }
            origins
                .try_reserve(1)
                .map_err(|_| ProtocolError::AllocationFailed)?;
            origins.push(Origin {
                packet: origin.packet,
                frame_offset: origin
                    .frame_offset
                    .checked_add(start - origin.offset)
                    .ok_or(ProtocolError::StreamOffsetOverflow)?,
                offset: start,
                length: end - start,
            });
        }
        origins.sort_unstable_by_key(|origin| {
            (
                origin.offset,
                origin.packet,
                origin.frame_offset,
                origin.length,
            )
        });
        origins.dedup();
        let mut covered_to = stream_range.start;
        for origin in &origins {
            let origin_end = origin
                .offset
                .checked_add(origin.length)
                .ok_or(ProtocolError::StreamOffsetOverflow)?;
            if origin.offset > covered_to {
                return Err(ProtocolError::IncompleteSourceMap);
            }
            covered_to = covered_to.max(origin_end);
            if covered_to >= stream_range.end {
                break;
            }
        }
        if covered_to < stream_range.end {
            return Err(ProtocolError::IncompleteSourceMap);
        }
        Ok(ReconstructedSourceMapping {
            run_range: range,
            stream_range,
            origins,
        })
    }
}

/// Exact mapping from one candidate interval to capture observations
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ReconstructedSourceMapping {
    /// Half-open byte interval within its contiguous reconstructed run
    pub run_range: ByteRange,
    /// Half-open byte interval within the directional reconstructed stream
    pub stream_range: ByteRange,
    /// Packet and captured-frame intervals supplying every mapped byte
    pub origins: Vec<Origin>,
}

/// Reason one reconstructed run was left out of framing candidate generation
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconstructedFramingInputOmissionReason {
    /// The configured maximum number of input runs was already retained
    SampleLimit,
    /// The run exceeded the configured scan length
    RunByteLimit,
    /// The run did not fit the remaining aggregate byte budget
    TotalByteLimit,
}

/// Bounded example of an input run omitted under a protocol budget
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct ReconstructedFramingInputOmission {
    /// Stable run sample identifier
    pub sample: u64,
    /// Stream record in `ReconstructedFramingReport::streams`
    pub stream_index: usize,
    /// Number of reconstructed bytes in the omitted run
    pub length: usize,
    /// Budget that excluded the run
    pub reason: ReconstructedFramingInputOmissionReason,
}

/// Exact counts and bounded examples of reconstructed run input omissions
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ReconstructedFramingInputOmissions {
    /// Runs omitted after reaching the maximum input sample count
    pub sample_limit: usize,
    /// Runs omitted because their individual length exceeded the scan budget
    pub run_byte_limit: usize,
    /// Runs omitted because they exceeded remaining aggregate input bytes
    pub total_byte_limit: usize,
    /// Total omitted input runs across every budget reason
    pub omitted_runs: usize,
    /// First bounded examples in deterministic stream and run order
    pub examples: Vec<ReconstructedFramingInputOmission>,
    /// Omission examples not retained after the bounded example list filled
    pub omitted_examples: usize,
}

impl ReconstructedFramingInputOmissions {
    fn record(&mut self, omission: ReconstructedFramingInputOmission) -> Result<(), ProtocolError> {
        let reason_count = match omission.reason {
            ReconstructedFramingInputOmissionReason::SampleLimit => &mut self.sample_limit,
            ReconstructedFramingInputOmissionReason::RunByteLimit => &mut self.run_byte_limit,
            ReconstructedFramingInputOmissionReason::TotalByteLimit => &mut self.total_byte_limit,
        };
        *reason_count = reason_count
            .checked_add(1)
            .ok_or(ProtocolError::InvalidLimits)?;
        self.omitted_runs = self
            .omitted_runs
            .checked_add(1)
            .ok_or(ProtocolError::InvalidLimits)?;
        if self.examples.len() < MAX_INPUT_OMISSION_EXAMPLES {
            self.examples
                .try_reserve(1)
                .map_err(|_| ProtocolError::AllocationFailed)?;
            self.examples.push(omission);
        } else {
            self.omitted_examples = self
                .omitted_examples
                .checked_add(1)
                .ok_or(ProtocolError::InvalidLimits)?;
        }
        Ok(())
    }
}
