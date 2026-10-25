//! Bounded little-endian PCAPNG evidence generation

use crate::{ABSOLUTE_MAX_INPUT_BYTES, ABSOLUTE_MAX_RECORD_COUNT, MAX_FRAME_LENGTH, WriterError};
use l2_capture::{
    CapturedFrame, Direction, FcsStatus, InterfaceId, LinkType, LinuxInterfaceIdentity,
    TimestampResolution,
};
use std::io::{Seek, SeekFrom, Write};

const SECTION_HEADER_BLOCK: u32 = 0x0a0d_0d0a;
const INTERFACE_DESCRIPTION_BLOCK: u32 = 1;
const ENHANCED_PACKET_BLOCK: u32 = 6;
const MAX_INTERFACES: usize = 64;
const OPTION_END: u16 = 0;
const OPTION_IF_DESCRIPTION: u16 = 3;
const OPTION_IF_TSRESOL: u16 = 9;
const OPTION_IF_FCSLEN: u16 = 13;
const OPTION_IF_TSOFFSET: u16 = 14;
const OPTION_EPB_FLAGS: u16 = 2;
const EPB_FCS_MAX_BYTES: u8 = 15;
const EPB_FIXED_BODY_LENGTH: usize = 20;

/// Largest output addressable by signed file offsets
pub const MAX_EVIDENCE_OUTPUT_BYTES: u64 = ABSOLUTE_MAX_INPUT_BYTES;

/// Interface-scoped values required to interpret enhanced packet blocks
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InterfaceConfig {
    link_type: LinkType,
    snaplen: u32,
    timestamp_resolution: TimestampResolution,
    timestamp_offset_seconds: i64,
    fcs: FcsStatus,
    linux_interface: Option<LinuxInterfaceIdentity>,
}

impl InterfaceConfig {
    /// Construct one checked Ethernet interface declaration
    ///
    /// A zero snapshot length means that the source did not declare a limit
    ///
    /// # Errors
    /// Returns an error when the snapshot length exceeds the frame ceiling
    pub const fn new(
        snaplen: u32,
        timestamp_resolution: TimestampResolution,
        timestamp_offset_seconds: i64,
        fcs: FcsStatus,
    ) -> Result<Self, WriterError> {
        Self::new_with_link_type(
            LinkType::Ethernet,
            snaplen,
            timestamp_resolution,
            timestamp_offset_seconds,
            fcs,
        )
    }

    /// Construct one checked interface declaration with its explicit data-link type
    ///
    /// # Errors
    /// Returns an error when the snapshot length exceeds the frame ceiling
    pub const fn new_with_link_type(
        link_type: LinkType,
        snaplen: u32,
        timestamp_resolution: TimestampResolution,
        timestamp_offset_seconds: i64,
        fcs: FcsStatus,
    ) -> Result<Self, WriterError> {
        if snaplen > MAX_FRAME_LENGTH {
            return Err(WriterError::InvalidSnaplen {
                snaplen,
                maximum: MAX_FRAME_LENGTH,
            });
        }
        Ok(Self {
            link_type,
            snaplen,
            timestamp_resolution,
            timestamp_offset_seconds,
            fcs,
            linux_interface: None,
        })
    }

    /// Return the checked data-link type declared by this interface
    #[must_use]
    pub const fn link_type(self) -> LinkType {
        self.link_type
    }

    /// Set the checked data-link type while retaining the other interface values
    #[must_use]
    pub const fn with_link_type(self, link_type: LinkType) -> Self {
        Self { link_type, ..self }
    }

    /// Return the declared snapshot length
    #[must_use]
    pub const fn snaplen(self) -> u32 {
        self.snaplen
    }

    /// Return the timestamp resolution used by this interface
    #[must_use]
    pub const fn timestamp_resolution(self) -> TimestampResolution {
        self.timestamp_resolution
    }

    /// Return the signed timestamp offset used by this interface
    #[must_use]
    pub const fn timestamp_offset_seconds(self) -> i64 {
        self.timestamp_offset_seconds
    }

    /// Return the interface FCS declaration
    #[must_use]
    pub const fn fcs(self) -> FcsStatus {
        self.fcs
    }

    /// Retain the checked identity reported by the acquisition backend
    #[must_use]
    pub const fn with_linux_interface(self, identity: LinuxInterfaceIdentity) -> Self {
        Self {
            linux_interface: Some(identity),
            ..self
        }
    }

    /// Return the identity that packets on this interface must retain
    #[must_use]
    pub const fn linux_interface(self) -> Option<LinuxInterfaceIdentity> {
        self.linux_interface
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WriterState {
    Active,
    Finished,
    Terminated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RegisteredInterface {
    source: InterfaceId,
    config: InterfaceConfig,
}

// Both blocks are assembled before either one is sent to the caller's sink
struct PreparedInterfaceFrame {
    interface: RegisteredInterface,
    index: u32,
    bytes: Vec<u8>,
}

/// Streaming PCAPNG writer with bounded per-block buffering and output accounting
pub struct PcapNgWriter<W> {
    output: W,
    output_limit: u64,
    bytes_written: u64,
    packet_count: u32,
    interfaces: Vec<RegisteredInterface>,
    collection_report_reserved: bool,
    state: WriterState,
}

impl<W: Write> PcapNgWriter<W> {
    /// Start one little-endian PCAPNG section
    ///
    /// # Errors
    /// Returns an error for an invalid quota or an underlying output failure
    pub fn new(output: W, output_limit: u64) -> Result<Self, WriterError> {
        Self::start(output, output_limit, None)
    }

    /// Start a section with source-reported acquisition conditions
    ///
    /// # Errors
    /// Returns a quota or output error before exposing a usable writer
    pub fn new_with_collection_report(
        output: W,
        output_limit: u64,
        report: crate::CollectionReport,
    ) -> Result<Self, WriterError> {
        Self::start(output, output_limit, Some(report))
    }

    fn start(
        output: W,
        output_limit: u64,
        report: Option<crate::CollectionReport>,
    ) -> Result<Self, WriterError> {
        let section = section_header(report)?;
        let minimum = u64::try_from(section.len()).map_err(|_| WriterError::LengthOverflow)?;
        if output_limit < minimum {
            return Err(WriterError::OutputLimitTooSmall {
                configured: output_limit,
                minimum,
            });
        }
        if output_limit > MAX_EVIDENCE_OUTPUT_BYTES {
            return Err(WriterError::OutputLimitTooLarge {
                configured: output_limit,
                maximum: MAX_EVIDENCE_OUTPUT_BYTES,
            });
        }
        let mut writer = Self {
            output,
            output_limit,
            bytes_written: 0,
            packet_count: 0,
            interfaces: Vec::new(),
            collection_report_reserved: report.is_some(),
            state: WriterState::Active,
        };
        writer.commit(&section)?;
        Ok(writer)
    }

    /// Register a capture source and emit its Interface Description Block
    ///
    /// # Errors
    /// Returns an error for duplicate or excessive interfaces, a full output
    /// quota, a finished writer, or an underlying output failure
    pub fn add_interface(
        &mut self,
        source: InterfaceId,
        config: InterfaceConfig,
    ) -> Result<u32, WriterError> {
        self.require_active()?;
        let index = self.next_interface_index(source)?;
        let block = interface_block(config)?;
        self.commit(&block)?;
        self.interfaces.push(RegisteredInterface { source, config });
        Ok(index)
    }

    /// Check a new interface and its first packet without changing writer state
    /// or writing to the output sink
    ///
    /// The returned value is the prospective total output size after the
    /// Interface Description Block and Enhanced Packet Block are committed.
    /// The transaction is checked again by [`Self::add_interface_and_write_frame`]
    /// because callers may change writer state between the two operations
    ///
    /// # Errors
    /// Returns the same deterministic validation or quota errors as the
    /// corresponding write operation
    pub fn preflight_interface_and_frame(
        &self,
        source: InterfaceId,
        config: InterfaceConfig,
        frame: &CapturedFrame,
    ) -> Result<u64, WriterError> {
        let prepared = self.prepare_interface_frame(source, config, frame)?;
        self.checked_attempted(prepared.bytes.len())
    }

    /// Add a new interface and write its first packet as one preflighted transaction
    ///
    /// All deterministic interface, packet, and output-budget checks happen
    /// before the first new-interface byte is sent to the sink. A generic
    /// [`Write`] implementation can still fail after a partial write; such a
    /// sink cannot provide rollback, so the writer becomes terminal and does
    /// not claim the logical interface or packet was committed
    ///
    /// # Errors
    /// Returns a deterministic validation or quota error before output, or an
    /// I/O error when the sink rejects the assembled transaction
    pub fn add_interface_and_write_frame(
        &mut self,
        source: InterfaceId,
        config: InterfaceConfig,
        frame: &CapturedFrame,
    ) -> Result<u32, WriterError> {
        let prepared = self.prepare_interface_frame(source, config, frame)?;
        self.commit(&prepared.bytes)?;
        self.interfaces.push(prepared.interface);
        // `prepare_interface_frame` rejects the maximum packet count first
        self.packet_count += 1;
        Ok(prepared.index)
    }

    /// Emit one Enhanced Packet Block after checking its interface metadata
    ///
    /// # Errors
    /// Returns an error when the packet references an unknown interface, its
    /// metadata cannot be represented losslessly, a bound is reached, or the
    /// output fails
    pub fn write_frame(&mut self, frame: &CapturedFrame) -> Result<(), WriterError> {
        self.require_active()?;
        if self.packet_count == ABSOLUTE_MAX_RECORD_COUNT {
            return Err(WriterError::PacketLimitExceeded {
                limit: ABSOLUTE_MAX_RECORD_COUNT,
            });
        }
        let source = frame.metadata().interface();
        let Some((output_index, registered)) = self
            .interfaces
            .iter()
            .enumerate()
            .find(|(_, interface)| interface.source == source)
        else {
            return Err(WriterError::UnknownInterface { source });
        };
        let output_index = u32::try_from(output_index).map_err(|_| WriterError::LengthOverflow)?;
        let block = Self::prepare_packet_block(frame, output_index, *registered)?;
        self.commit(&block)?;
        self.packet_count += 1;
        Ok(())
    }

    fn prepare_interface_frame(
        &self,
        source: InterfaceId,
        config: InterfaceConfig,
        frame: &CapturedFrame,
    ) -> Result<PreparedInterfaceFrame, WriterError> {
        self.require_active()?;
        if self.packet_count == ABSOLUTE_MAX_RECORD_COUNT {
            return Err(WriterError::PacketLimitExceeded {
                limit: ABSOLUTE_MAX_RECORD_COUNT,
            });
        }
        let index = self.next_interface_index(source)?;
        let interface = RegisteredInterface { source, config };
        let interface_block = interface_block(config)?;
        let packet_block = Self::prepare_packet_block(frame, index, interface)?;
        let bytes = transaction(&interface_block, &packet_block)?;
        Ok(PreparedInterfaceFrame {
            interface,
            index,
            bytes,
        })
    }

    fn prepare_packet_block(
        frame: &CapturedFrame,
        output_index: u32,
        registered: RegisteredInterface,
    ) -> Result<Vec<u8>, WriterError> {
        let source = frame.metadata().interface();
        if source != registered.source {
            return Err(WriterError::UnknownInterface { source });
        }
        if frame.metadata().link_type() != registered.config.link_type {
            return Err(WriterError::LinkTypeConfigurationMismatch);
        }
        let captured =
            u32::try_from(frame.captured_len()).map_err(|_| WriterError::LengthOverflow)?;
        if registered.config.snaplen != 0 && captured > registered.config.snaplen {
            return Err(WriterError::CapturedLengthExceedsSnaplen {
                captured,
                snaplen: registered.config.snaplen,
            });
        }
        if frame.metadata().vlan().is_some() {
            return Err(WriterError::UnsupportedVlanMetadata);
        }
        if frame.metadata().linux_interface() != registered.config.linux_interface {
            return Err(WriterError::LinuxInterfaceIdentityMismatch);
        }
        let timestamp = frame
            .metadata()
            .timestamp()
            .ok_or(WriterError::MissingTimestamp)?;
        if timestamp.resolution() != registered.config.timestamp_resolution
            || timestamp.offset_seconds() != registered.config.timestamp_offset_seconds
        {
            return Err(WriterError::TimestampConfigurationMismatch);
        }
        let flags = packet_flags(
            frame.metadata().direction(),
            frame.metadata().fcs(),
            registered.config.fcs,
        )?;
        let block = packet_block(
            output_index,
            timestamp.ticks(),
            frame.bytes(),
            frame.metadata().original_len(),
            flags,
        )?;
        Ok(block)
    }

    fn next_interface_index(&self, source: InterfaceId) -> Result<u32, WriterError> {
        if self
            .interfaces
            .iter()
            .any(|interface| interface.source == source)
        {
            return Err(WriterError::DuplicateInterface { source });
        }
        if self.interfaces.len() == MAX_INTERFACES {
            return Err(WriterError::InterfaceLimitExceeded {
                limit: MAX_INTERFACES,
            });
        }
        u32::try_from(self.interfaces.len()).map_err(|_| WriterError::LengthOverflow)
    }

    /// Flush the output and prevent further interfaces or packets
    ///
    /// Repeated calls after a successful finish are harmless
    ///
    /// # Errors
    /// Returns the first flush error or a prior terminal state
    pub fn finish(&mut self) -> Result<(), WriterError> {
        match self.state {
            WriterState::Finished => return Ok(()),
            WriterState::Terminated => return Err(WriterError::Terminated),
            WriterState::Active => {}
        }
        if let Err(error) = self.output.flush() {
            self.state = WriterState::Terminated;
            return Err(WriterError::Io(error));
        }
        self.state = WriterState::Finished;
        Ok(())
    }

    /// Replace a reserved acquisition declaration before flushing and publication
    ///
    /// The fixed-length comment leaves every packet offset and byte count intact
    /// A seekable sink must honor replacement writes at its requested position;
    /// append-only sinks are rejected after checking the resulting cursor
    ///
    /// # Errors
    /// Returns an error when no report was reserved, the writer is closed, or a
    /// seek or write fails; an I/O failure leaves the writer terminal. A generic
    /// sink may have side effects before a failed replacement is detected
    pub fn update_collection_report(
        &mut self,
        report: crate::CollectionReport,
    ) -> Result<(), WriterError>
    where
        W: Seek,
    {
        self.require_active()?;
        if !self.collection_report_reserved {
            return Err(WriterError::CollectionReportNotReserved);
        }
        let header = section_header(Some(report))?;
        let result = (|| -> std::io::Result<()> {
            let end = self.output.stream_position()?;
            let start = end.checked_sub(self.bytes_written).ok_or_else(|| {
                std::io::Error::other("PCAPNG output position moved outside its section")
            })?;
            let header_length = u64::try_from(header.len())
                .map_err(|_| std::io::Error::other("PCAPNG section header length overflow"))?;
            let replacement_end = start
                .checked_add(header_length)
                .ok_or_else(|| std::io::Error::other("PCAPNG section header position overflow"))?;
            let positioned = self.output.seek(SeekFrom::Start(start))?;
            if positioned != start {
                return Err(std::io::Error::other(
                    "PCAPNG output did not seek to the section header",
                ));
            }
            self.output.write_all(&header)?;
            self.output.flush()?;
            if self.output.stream_position()? != replacement_end {
                return Err(std::io::Error::other(
                    "PCAPNG output did not replace the section header in place",
                ));
            }
            let restored = self.output.seek(SeekFrom::Start(end))?;
            if restored != end || self.output.stream_position()? != end {
                return Err(std::io::Error::other(
                    "PCAPNG output did not restore its previous position",
                ));
            }
            Ok(())
        })();
        if let Err(error) = result {
            self.state = WriterState::Terminated;
            return Err(WriterError::Io(error));
        }
        Ok(())
    }

    /// Return the complete number of bytes committed to the sink
    #[must_use]
    pub const fn bytes_written(&self) -> u64 {
        self.bytes_written
    }

    /// Return the number of complete packet blocks committed to the sink
    #[must_use]
    pub const fn packet_count(&self) -> u32 {
        self.packet_count
    }

    /// Return the number of complete interface blocks committed to the sink
    #[must_use]
    pub const fn interface_count(&self) -> usize {
        self.interfaces.len()
    }

    /// Recover the caller-owned sink
    #[must_use]
    pub fn into_inner(self) -> W {
        self.output
    }

    const fn require_active(&self) -> Result<(), WriterError> {
        match self.state {
            WriterState::Active => Ok(()),
            WriterState::Finished => Err(WriterError::Finished),
            WriterState::Terminated => Err(WriterError::Terminated),
        }
    }

    fn commit(&mut self, block: &[u8]) -> Result<(), WriterError> {
        let attempted = self.checked_attempted(block.len())?;
        // A generic Write may fail after a partial side effect, so no later
        // block is accepted once write_all reports an error. There is no
        // general rollback contract for an arbitrary sink
        if let Err(error) = self.output.write_all(block) {
            self.state = WriterState::Terminated;
            return Err(WriterError::Io(error));
        }
        self.bytes_written = attempted;
        Ok(())
    }

    fn checked_attempted(&self, length: usize) -> Result<u64, WriterError> {
        let length = u64::try_from(length).map_err(|_| WriterError::LengthOverflow)?;
        let attempted = self
            .bytes_written
            .checked_add(length)
            .ok_or(WriterError::LengthOverflow)?;
        if attempted > self.output_limit {
            return Err(WriterError::OutputLimitExceeded {
                attempted,
                limit: self.output_limit,
            });
        }
        Ok(attempted)
    }
}

fn section_header(report: Option<crate::CollectionReport>) -> Result<Vec<u8>, WriterError> {
    let mut body = Vec::with_capacity(16);
    put_u32(&mut body, 0x1a2b_3c4d);
    put_u16(&mut body, 1);
    put_u16(&mut body, 0);
    body.extend_from_slice(&(-1_i64).to_le_bytes());
    if let Some(report) = report {
        let declaration = crate::pcapng_collection::encode(report);
        put_option(&mut body, 1, declaration.as_bytes())?;
        put_option(&mut body, OPTION_END, &[])?;
    }
    block(SECTION_HEADER_BLOCK, &body)
}

fn interface_block(config: InterfaceConfig) -> Result<Vec<u8>, WriterError> {
    let mut body = Vec::with_capacity(40);
    put_u16(&mut body, config.link_type.raw());
    put_u16(&mut body, 0);
    put_u32(&mut body, config.snaplen);

    if let Some(identity) = config.linux_interface {
        // The standard description option keeps this readable by other tools
        let description = crate::pcapng_linux_identity::encode(identity);
        put_option(&mut body, OPTION_IF_DESCRIPTION, description.as_bytes())?;
    }

    let resolution = if config.timestamp_resolution.radix() == 2 {
        0x80 | config.timestamp_resolution.exponent()
    } else {
        config.timestamp_resolution.exponent()
    };
    put_option(&mut body, OPTION_IF_TSRESOL, &[resolution])?;
    if config.timestamp_offset_seconds != 0 {
        put_option(
            &mut body,
            OPTION_IF_TSOFFSET,
            &config.timestamp_offset_seconds.to_le_bytes(),
        )?;
    }
    match config.fcs {
        FcsStatus::Unknown => {}
        FcsStatus::Absent => put_option(&mut body, OPTION_IF_FCSLEN, &[0])?,
        FcsStatus::Present { length } => {
            let bits = length
                .get()
                .checked_mul(8)
                .ok_or(WriterError::LengthOverflow)?;
            put_option(&mut body, OPTION_IF_FCSLEN, &[bits])?;
        }
    }
    put_option(&mut body, OPTION_END, &[])?;
    block(INTERFACE_DESCRIPTION_BLOCK, &body)
}

fn packet_block(
    interface: u32,
    timestamp: u64,
    bytes: &[u8],
    original_len: u32,
    flags: Option<u32>,
) -> Result<Vec<u8>, WriterError> {
    let padded = padded_length(bytes.len())?;
    let option_length = if flags.is_some() { 12 } else { 0 };
    let capacity = EPB_FIXED_BODY_LENGTH
        .checked_add(padded)
        .and_then(|length| length.checked_add(option_length))
        .ok_or(WriterError::LengthOverflow)?;
    let mut body = Vec::with_capacity(capacity);
    put_u32(&mut body, interface);
    put_u32(
        &mut body,
        u32::try_from(timestamp >> 32).map_err(|_| WriterError::LengthOverflow)?,
    );
    put_u32(
        &mut body,
        u32::try_from(timestamp & u64::from(u32::MAX)).map_err(|_| WriterError::LengthOverflow)?,
    );
    put_u32(
        &mut body,
        u32::try_from(bytes.len()).map_err(|_| WriterError::LengthOverflow)?,
    );
    put_u32(&mut body, original_len);
    body.extend_from_slice(bytes);
    body.resize(EPB_FIXED_BODY_LENGTH + padded, 0);
    if let Some(flags) = flags {
        put_option(&mut body, OPTION_EPB_FLAGS, &flags.to_le_bytes())?;
        put_option(&mut body, OPTION_END, &[])?;
    }
    block(ENHANCED_PACKET_BLOCK, &body)
}

fn transaction(first: &[u8], second: &[u8]) -> Result<Vec<u8>, WriterError> {
    let length = first
        .len()
        .checked_add(second.len())
        .ok_or(WriterError::LengthOverflow)?;
    let mut bytes = Vec::with_capacity(length);
    bytes.extend_from_slice(first);
    bytes.extend_from_slice(second);
    Ok(bytes)
}

fn packet_flags(
    direction: Direction,
    packet_fcs: FcsStatus,
    interface_fcs: FcsStatus,
) -> Result<Option<u32>, WriterError> {
    if direction == Direction::Unknown && packet_fcs == interface_fcs {
        return Ok(None);
    }
    let direction_bits = match direction {
        Direction::Unknown => 0,
        Direction::Inbound => 1,
        Direction::Outbound => 2,
    };
    let fcs_length = match packet_fcs {
        FcsStatus::Unknown => 0,
        FcsStatus::Present { length } if length.get() <= EPB_FCS_MAX_BYTES => length.get(),
        FcsStatus::Absent | FcsStatus::Present { .. } => {
            return Err(WriterError::UnrepresentablePacketFlags);
        }
    };
    Ok(Some(direction_bits | (u32::from(fcs_length) << 5)))
}

fn block(block_type: u32, body: &[u8]) -> Result<Vec<u8>, WriterError> {
    let total = body
        .len()
        .checked_add(12)
        .ok_or(WriterError::LengthOverflow)?;
    let total = u32::try_from(total).map_err(|_| WriterError::LengthOverflow)?;
    let mut output =
        Vec::with_capacity(usize::try_from(total).map_err(|_| WriterError::LengthOverflow)?);
    put_u32(&mut output, block_type);
    put_u32(&mut output, total);
    output.extend_from_slice(body);
    put_u32(&mut output, total);
    Ok(output)
}

fn put_option(output: &mut Vec<u8>, code: u16, value: &[u8]) -> Result<(), WriterError> {
    put_u16(output, code);
    put_u16(
        output,
        u16::try_from(value.len()).map_err(|_| WriterError::LengthOverflow)?,
    );
    output.extend_from_slice(value);
    let padded = padded_length(value.len())?;
    output.resize(
        output
            .len()
            .checked_add(padded.saturating_sub(value.len()))
            .ok_or(WriterError::LengthOverflow)?,
        0,
    );
    Ok(())
}

fn padded_length(length: usize) -> Result<usize, WriterError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(WriterError::LengthOverflow)
}

fn put_u16(output: &mut Vec<u8>, value: u16) {
    output.extend_from_slice(&value.to_le_bytes());
}

fn put_u32(output: &mut Vec<u8>, value: u32) {
    output.extend_from_slice(&value.to_le_bytes());
}
