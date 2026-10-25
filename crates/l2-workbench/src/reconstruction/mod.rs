//! Bounded fragment candidates and TCP episodes without an endpoint overlap policy

mod fragments;
mod handshake;
mod model;
mod sessions;
mod stream;

pub use handshake::{HandshakeAssessment, HandshakeMatch, HandshakeStatus};
use l2_audit::ForensicScope;
use l2_capture::{CapturedFrame, LinkType};
use l2_discovery::{TransportHeader, fragment_packet, ip_packet};
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
    origins: Vec<Origin>,
    trailing_bytes: Vec<u8>,
    trailing_origins: Vec<Origin>,
    fragment_candidate: Option<usize>,
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
        // Local observation quotas are also omissions from the whole investigation
        if coverage.omitted_observations != 0 {
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

    fn reserve(&mut self, length: usize, kind: RangeKind) -> Result<bool, ReconstructionError> {
        if length > self.remaining {
            self.record_omitted_range()?;
            self.unmeasured_omitted_ranges = self
                .unmeasured_omitted_ranges
                .checked_add(1)
                .ok_or(ReconstructionError("unmeasured range count overflow"))?;
            let omitted_bytes = u64::try_from(length).map_err(|_| {
                ReconstructionError("omitted range extent exceeds the report counter")
            })?;
            match kind {
                RangeKind::Tcp => {
                    self.omitted_tcp_bytes =
                        add_report_count(self.omitted_tcp_bytes, omitted_bytes)?;
                }
                RangeKind::Fragment => {
                    self.omitted_fragment_bytes =
                        add_report_count(self.omitted_fragment_bytes, omitted_bytes)?;
                }
            }
            Ok(false)
        } else {
            self.remaining -= length;
            Ok(true)
        }
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
            || self.transports.len() + self.pieces.len() == self.limits.units
        {
            self.omitted_frames += 1;
            return false;
        }
        // Reserving the full captured size also bounds control-only observations
        self.retained_bytes += captured.bytes().len();
        if captured.metadata().link_type() != LinkType::Ethernet {
            self.unsupported_frames += 1;
            return true;
        }
        let Ok(frame) = l2_core::decode(captured.bytes()) else {
            self.unsupported_frames += 1;
            return true;
        };
        let scope = ForensicScope::new(captured.metadata(), &frame);
        let header_length = 14 + frame.vlan_tags.len() * 4;
        if let Some(fragment) = fragment_packet(&frame) {
            self.pieces.push(fragments::Piece::new(
                scope,
                packet,
                header_length,
                fragment,
            ));
        } else if let Some(ip) = ip_packet(&frame) {
            if let Some(transport) = ip.transport {
                self.transports.push(Transport {
                    scope,
                    source: Endpoint {
                        address: ip.source,
                        port: transport.ports.0,
                    },
                    destination: Endpoint {
                        address: ip.destination,
                        port: transport.ports.1,
                    },
                    packet,
                    header: transport.header,
                    bytes: transport.payload.to_vec(),
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
            } else {
                self.unsupported_frames += 1;
            }
        } else if matches!(frame.field, l2_core::FrameField::EtherType(0x0800 | 0x86dd)) {
            self.unsupported_frames += 1;
        }
        true
    }

    /// Resolve only uniquely covered candidates and retain every interpretation limit
    ///
    /// # Errors
    /// Returns a checked range error if an internal interval exceeds its validated bound
    pub fn finish(mut self) -> Result<ReconstructionReport, ReconstructionError> {
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
        };
        let (datagrams, recovered, omitted_fragments) =
            fragments::finish(self.pieces, self.limits.datagrams, &mut budget)?;
        self.transports.extend(recovered);
        self.transports.sort_by_key(|item| item.packet);
        let (sessions, udp, omitted_tcp_records) =
            sessions::finish(self.transports, self.limits.sessions, &mut budget)?;
        let omitted_state_observations = sessions.iter().try_fold(0_usize, |total, session| {
            total
                .checked_add(session.handshake.omitted_observations)
                .ok_or(ReconstructionError(
                    "omitted state observation count overflow",
                ))
        })?;
        Ok(ReconstructionReport {
            frames: self.frames,
            limits: self.limits,
            input_selection: self.input_selection,
            omitted_frames: self.omitted_frames,
            unsupported_frames: self.unsupported_frames,
            complete: self.omitted_frames == 0
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
