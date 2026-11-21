//! Bounded fragment candidates and TCP episodes without an endpoint overlap policy

mod fragments;
mod handshake;
mod model;
mod sessions;
mod stream;

pub use handshake::{HandshakeAssessment, HandshakeMatch, HandshakeStatus};
use l2_audit::ForensicScope;
use l2_capture::CapturedFrame;
use l2_core::FrameField;
use l2_discovery::{
    TransportHeader, fragment_packet_from_payload, ip_packet_from_payload,
    link::decode_network_frame, tcp_prefix_from_payload, truncated_tcp_tuple_from_payload,
};
pub use model::{
    ByteRun, Coverage, Datagram, Endpoint, InputSelection, Limits, Origin, ReconstructionReport,
    RecordRetentionLimit, RecordRetentionStatus, Stream, TcpSession, UdpMessage,
};
use std::{error::Error, fmt};

#[derive(Debug)]
pub struct ReconstructionError(&'static str);

impl fmt::Display for ReconstructionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}

impl Error for ReconstructionError {}

struct Transport {
    scope: ForensicScope,
    source: Endpoint,
    destination: Endpoint,
    packet: u32,
    header: TransportHeader,
    bytes: Vec<u8>,
    missing_bytes: usize,
    origins: Vec<Origin>,
    trailing_bytes: Vec<u8>,
    trailing_origins: Vec<Origin>,
    fragment_candidate: Option<usize>,
}

impl Transport {
    const fn declared_payload_len(&self) -> usize {
        self.bytes.len() + self.missing_bytes
    }
}

#[derive(Debug)]
pub(crate) struct IncompleteHeader {
    pub(crate) scope: ForensicScope,
    pub(crate) endpoints: [Endpoint; 2],
    pub(crate) packet: u32,
}

struct SequenceBudget {
    remaining: usize,
    omitted: usize,
    unmeasured_omitted_ranges: usize,
    omitted_tcp_bytes: u64,
    omitted_tcp_observations: u64,
    omitted_fragment_bytes: u64,
    omitted_fragment_observations: u64,
    range_observations: usize,
    range_retained_bytes: usize,
    memory: Option<crate::job::MemoryLease>,
    memory_before: u64,
}

#[derive(Clone, Copy)]
enum RangeKind {
    Tcp,
    Fragment,
}

impl SequenceBudget {
    fn retain_coverage(
        &mut self,
        coverage: Coverage,
        kind: RangeKind,
    ) -> Result<Coverage, ReconstructionError> {
        if let Some(memory) = &mut self.memory {
            let spans = coverage
                .spans
                .capacity()
                .checked_mul(std::mem::size_of::<crate::tcp_range::Span>())
                .and_then(|bytes| {
                    bytes.checked_add(
                        coverage
                            .spans
                            .len()
                            .checked_mul(std::mem::size_of::<ByteRun<'_>>())?,
                    )
                })
                .and_then(|bytes| {
                    coverage.spans.iter().try_fold(bytes, |total, span| {
                        total.checked_add(span.bytes.as_ref().map_or(0, Vec::capacity))
                    })
                })
                .and_then(|bytes| u64::try_from(bytes).ok())
                .and_then(|bytes| self.memory_before.checked_add(bytes))
                .ok_or(ReconstructionError("reconstruction range memory overflow"))?;
            memory.try_resize(spans).map_err(|_| {
                ReconstructionError("reconstruction range memory accounting failed")
            })?;
        }
        // Any unavailable observation or span also limits the whole investigation
        if coverage.omitted_observations != 0 || coverage.omitted_bytes != 0 {
            self.record_omitted_range()?;
        }
        let omitted_bytes = u64::try_from(coverage.omitted_bytes)
            .map_err(|_| ReconstructionError("omitted range bytes exceed the report counter"))?;
        match kind {
            RangeKind::Tcp => {
                self.omitted_tcp_bytes = add_report_count(self.omitted_tcp_bytes, omitted_bytes)?;
                self.omitted_tcp_observations =
                    add_report_count(self.omitted_tcp_observations, coverage.omitted_observations)?;
            }
            RangeKind::Fragment => {
                self.omitted_fragment_bytes =
                    add_report_count(self.omitted_fragment_bytes, omitted_bytes)?;
                self.omitted_fragment_observations = add_report_count(
                    self.omitted_fragment_observations,
                    coverage.omitted_observations,
                )?;
            }
        }
        Ok(coverage)
    }

    fn reserve(
        &mut self,
        length: usize,
        kind: RangeKind,
        input_bytes: usize,
        observations: usize,
    ) -> Result<bool, ReconstructionError> {
        let memory_fits = if length <= self.remaining {
            if let Some(memory) = &mut self.memory {
                self.memory_before = memory.bytes();
                let additional = crate::tcp_range::range_memory_bound(
                    length,
                    input_bytes.min(self.range_retained_bytes),
                    observations.min(self.range_observations),
                )
                .ok_or(ReconstructionError("reconstruction range memory overflow"))?;
                let requested = self
                    .memory_before
                    .checked_add(additional)
                    .ok_or(ReconstructionError("reconstruction range memory overflow"))?;
                match memory.try_resize(requested) {
                    Ok(()) => true,
                    Err(crate::job::MemoryError::Limit { .. }) => false,
                    Err(_) => {
                        return Err(ReconstructionError(
                            "reconstruction range memory admission failed",
                        ));
                    }
                }
            } else {
                true
            }
        } else {
            false
        };
        if memory_fits {
            self.remaining -= length;
            return Ok(true);
        }
        self.record_omitted_range()?;
        self.unmeasured_omitted_ranges = self
            .unmeasured_omitted_ranges
            .checked_add(1)
            .ok_or(ReconstructionError("unmeasured range count overflow"))?;
        let omitted_bytes = u64::try_from(length)
            .map_err(|_| ReconstructionError("omitted range extent exceeds the report counter"))?;
        match kind {
            RangeKind::Tcp => {
                self.omitted_tcp_bytes = add_report_count(self.omitted_tcp_bytes, omitted_bytes)?;
            }
            RangeKind::Fragment => {
                self.omitted_fragment_bytes =
                    add_report_count(self.omitted_fragment_bytes, omitted_bytes)?;
            }
        }
        Ok(false)
    }

    fn record_omitted_range(&mut self) -> Result<(), ReconstructionError> {
        self.omitted = self
            .omitted
            .checked_add(1)
            .ok_or(ReconstructionError("omitted range count overflow"))?;
        Ok(())
    }
}

fn add_report_count(total: u64, next: u64) -> Result<u64, ReconstructionError> {
    total.checked_add(next).ok_or(ReconstructionError(
        "reconstruction omission count overflow",
    ))
}

/// Retain bounded transport observations, freezing after any input quota omission
pub struct Reconstructor {
    limits: Limits,
    frames: u64,
    first_record: u32,
    input_selection: Option<InputSelection>,
    last_record: Option<u32>,
    omitted_frames: u64,
    unsupported_frames: u64,
    retained_bytes: usize,
    transports: Vec<Transport>,
    pieces: Vec<fragments::Piece>,
    incomplete_headers: Vec<IncompleteHeader>,
}

impl Default for Reconstructor {
    fn default() -> Self {
        Self::new()
    }
}

impl Reconstructor {
    #[must_use]
    pub fn new() -> Self {
        Self::empty(Limits::default(), 1)
    }

    /// Set checked resource budgets for a bounded investigation
    ///
    /// # Errors
    /// Rejects zero budgets
    pub const fn with_limits(limits: Limits) -> Result<Self, ReconstructionError> {
        Self::with_limits_at(limits, 1)
    }

    /// Retain consecutive globally numbered records from an explicitly selected window
    ///
    /// # Errors
    /// Rejects a zero first record or invalid reconstruction budgets
    pub const fn with_limits_at(
        limits: Limits,
        first_record: u32,
    ) -> Result<Self, ReconstructionError> {
        if first_record == 0
            || limits.frames == 0
            || limits.bytes == 0
            || limits.units == 0
            || limits.sessions == 0
            || limits.datagrams == 0
            || limits.range_bytes == 0
            || limits.range_observations == 0
            || limits.range_retained_bytes == 0
        {
            return Err(ReconstructionError(
                "reconstruction budgets must be positive",
            ));
        }
        Ok(Self::empty(limits, first_record))
    }

    const fn empty(limits: Limits, first_record: u32) -> Self {
        Self {
            limits,
            frames: 0,
            first_record,
            input_selection: None,
            last_record: None,
            omitted_frames: 0,
            unsupported_frames: 0,
            retained_bytes: 0,
            transports: Vec::new(),
            pieces: Vec::new(),
            incomplete_headers: Vec::new(),
        }
    }

    /// Observe the next consecutive record from the configured starting record
    ///
    /// Returns whether the record fits the retained capture prefix
    ///
    /// # Errors
    /// Rejects skipped, zero, repeated, or decreasing record numbers before state changes
    pub fn observe(
        &mut self,
        packet: u32,
        captured: &CapturedFrame,
    ) -> Result<bool, ReconstructionError> {
        self.accept_record_number(packet, InputSelection::ConsecutiveRecords)?;
        Ok(self.retain_record(packet, captured))
    }

    /// Observe an explicitly selected record while preserving its capture number
    ///
    /// Selected records may have gaps because unrelated records were not supplied.
    /// This mode identifies omitted input without claiming state from those records
    ///
    /// # Errors
    /// Rejects zero, repeated, decreasing, or mixed-mode record numbers before state changes
    pub fn observe_selected(
        &mut self,
        packet: u32,
        captured: &CapturedFrame,
    ) -> Result<bool, ReconstructionError> {
        self.accept_record_number(packet, InputSelection::SelectedRecords)?;
        Ok(self.retain_record(packet, captured))
    }

    fn accept_record_number(
        &mut self,
        packet: u32,
        selection: InputSelection,
    ) -> Result<(), ReconstructionError> {
        if self
            .input_selection
            .is_some_and(|current| current != selection)
        {
            return Err(ReconstructionError(
                "consecutive and selected record inputs cannot be mixed",
            ));
        }
        let valid = match selection {
            InputSelection::ConsecutiveRecords => {
                u64::from(packet) == self.frames + u64::from(self.first_record)
            }
            InputSelection::SelectedRecords => {
                packet != 0 && self.last_record.is_none_or(|last| packet > last)
            }
        };
        if !valid {
            let reason = match selection {
                InputSelection::ConsecutiveRecords => {
                    "capture record numbers must be consecutive from the configured first record"
                }
                InputSelection::SelectedRecords => {
                    "selected record numbers must be nonzero and strictly increasing"
                }
            };
            return Err(ReconstructionError(reason));
        }
        self.input_selection = Some(selection);
        self.last_record = Some(packet);
        self.frames += 1;
        Ok(())
    }

    fn retain_record(&mut self, packet: u32, captured: &CapturedFrame) -> bool {
        if self.omitted_frames != 0
            || self.frames > self.limits.frames
            || captured.bytes().len() > self.limits.bytes - self.retained_bytes
            || self.transports.len() + self.pieces.len() + self.incomplete_headers.len()
                == self.limits.units
        {
            self.omitted_frames += 1;
            return false;
        }
        // Reserving the full captured size also bounds control-only observations
        self.retained_bytes += captured.bytes().len();
        let Some(frame) = decode_network_frame(captured.metadata().link_type(), captured.bytes())
        else {
            self.unsupported_frames += 1;
            return true;
        };
        let Some(field) = frame.field() else {
            // Cooked protocol fields without EtherType semantics remain opaque
            self.unsupported_frames += 1;
            return true;
        };
        let FrameField::EtherType(protocol) = field else {
            return true;
        };
        let scope = ForensicScope::from_network_frame(captured.metadata(), &frame);
        // Offsets always refer to the original captured link header
        let header_length = frame.payload_offset();
        if let Some(fragment) = fragment_packet_from_payload(protocol, frame.payload()) {
            self.pieces.push(fragments::Piece::new(
                scope,
                packet,
                header_length,
                fragment,
            ));
            return true;
        }
        self.retain_transport(protocol, frame.payload(), scope, packet, header_length);
        true
    }

    fn retain_transport(
        &mut self,
        protocol: u16,
        payload: &[u8],
        scope: ForensicScope,
        packet: u32,
        header_length: usize,
    ) {
        let parsed = ip_packet_from_payload(protocol, payload).map_or_else(
            || {
                tcp_prefix_from_payload(protocol, payload)
                    .map(|(ip, transport, missing)| (ip.source, ip.destination, transport, missing))
            },
            |ip| {
                ip.transport
                    .map(|transport| (ip.source, ip.destination, transport, 0))
            },
        );
        if let Some((source, destination, transport, missing_bytes)) = parsed {
            self.transports.push(Transport {
                scope,
                source: Endpoint {
                    address: source,
                    port: transport.ports.0,
                },
                destination: Endpoint {
                    address: destination,
                    port: transport.ports.1,
                },
                packet,
                header: transport.header,
                bytes: transport.payload.to_vec(),
                missing_bytes,
                origins: vec![Origin {
                    packet,
                    frame_offset: header_length + transport.payload_offset,
                    offset: 0,
                    length: transport.payload.len(),
                }],
                trailing_bytes: transport.trailing_bytes.to_vec(),
                trailing_origins: vec![Origin {
                    packet,
                    frame_offset: header_length
                        + transport.payload_offset
                        + transport.payload.len(),
                    offset: 0,
                    length: transport.trailing_bytes.len(),
                }],
                fragment_candidate: None,
            });
        } else if let Some((ip, ports)) = truncated_tcp_tuple_from_payload(protocol, payload) {
            let source = Endpoint {
                address: ip.source,
                port: ports.0,
            };
            let destination = Endpoint {
                address: ip.destination,
                port: ports.1,
            };
            let endpoints = if source <= destination {
                [source, destination]
            } else {
                [destination, source]
            };
            self.incomplete_headers.push(IncompleteHeader {
                scope,
                endpoints,
                packet,
            });
        } else if matches!(protocol, 0x0800 | 0x86dd) {
            self.unsupported_frames += 1;
        }
    }

    /// Resolve only uniquely covered candidates and retain every interpretation limit
    ///
    /// # Errors
    /// Returns a checked range error if an internal interval exceeds its validated bound
    pub fn finish(self) -> Result<ReconstructionReport, ReconstructionError> {
        self.finish_with_memory(None)
    }

    pub(crate) fn finish_with_memory(
        mut self,
        memory: Option<crate::job::MemoryLease>,
    ) -> Result<ReconstructionReport, ReconstructionError> {
        let mut budget = SequenceBudget {
            remaining: self.limits.range_bytes,
            omitted: 0,
            unmeasured_omitted_ranges: 0,
            omitted_tcp_bytes: 0,
            omitted_tcp_observations: 0,
            omitted_fragment_bytes: 0,
            omitted_fragment_observations: 0,
            range_observations: self.limits.range_observations,
            range_retained_bytes: self.limits.range_retained_bytes,
            memory,
            memory_before: 0,
        };
        let (datagrams, recovered, omitted_fragments) =
            fragments::finish(self.pieces, self.limits.datagrams, &mut budget)?;
        self.transports.extend(recovered);
        self.transports.sort_by_key(|item| item.packet);
        let (mut sessions, udp, omitted_tcp_records) =
            sessions::finish(self.transports, self.limits.sessions, &mut budget)?;
        let incomplete_tcp_headers = self.incomplete_headers.len();
        let uncertain: std::collections::BTreeSet<_> = self
            .incomplete_headers
            .iter()
            .map(|header| (&header.scope, &header.endpoints))
            .collect();
        for session in &mut sessions {
            session.generation_ambiguous |=
                uncertain.contains(&(&session.scope, &session.endpoints));
        }
        let omitted_state_observations = sessions.iter().try_fold(0_usize, |total, session| {
            total
                .checked_add(session.handshake.omitted_observations)
                .ok_or(ReconstructionError(
                    "omitted state observation count overflow",
                ))
        })?;
        Ok(ReconstructionReport {
            _memory: budget.memory,
            incomplete_header_records: self.incomplete_headers,
            frames: self.frames,
            limits: self.limits,
            input_selection: self.input_selection,
            omitted_frames: self.omitted_frames,
            unsupported_frames: self.unsupported_frames,
            incomplete_tcp_headers,
            complete: self.omitted_frames == 0
                && incomplete_tcp_headers == 0
                && omitted_fragments == 0
                && omitted_tcp_records == 0
                && omitted_state_observations == 0
                && budget.omitted == 0,
            omitted_fragments,
            omitted_tcp_records,
            omitted_ranges: budget.omitted,
            unmeasured_omitted_ranges: budget.unmeasured_omitted_ranges,
            omitted_tcp_bytes: budget.omitted_tcp_bytes,
            omitted_tcp_observations: budget.omitted_tcp_observations,
            omitted_fragment_bytes: budget.omitted_fragment_bytes,
            omitted_fragment_observations: budget.omitted_fragment_observations,
            omitted_state_observations,
            datagrams,
            sessions,
            udp,
        })
    }
}
