//! Bounded streaming reader for packet-bearing PCAPNG blocks

use std::io::Read;

use l2_capture::{CapturedFrame, InterfaceId};

use crate::{
    CaptureLimits, Error,
    header::ByteOrder,
    pcapng_blocks::{
        Block, ENHANCED_PACKET_BLOCK, INTERFACE_DESCRIPTION_BLOCK, PACKET_BLOCK,
        SECTION_HEADER_BLOCK, SECTION_HEADER_MIN_LENGTH, SIMPLE_PACKET_BLOCK, parse_section_header,
        read_block,
    },
    pcapng_interfaces::parse_interface,
    pcapng_model::InterfaceDescription,
    pcapng_packets::{decode_enhanced_packet, decode_packet_block, decode_simple_packet},
};

const MAX_INTERFACES: u32 = 64;

/// A streaming, bounded PCAPNG reader for packet blocks with per-interface link types
pub struct PcapNgReader<R: Read> {
    reader: R,
    input_bytes: u64,
    records_read: u32,
    limits: CaptureLimits,
    section: u32,
    order: ByteOrder,
    current_interfaces: Vec<InterfaceDescription>,
    collection_summary: crate::CollectionSummary,
    terminated: bool,
}

impl<R: Read> PcapNgReader<R> {
    /// Read and validate the first Section Header Block
    ///
    /// # Errors
    ///
    /// Returns an error for malformed block framing, unsupported section versions,
    /// finite section lengths, malformed options, or input I/O
    pub fn new(reader: R) -> Result<Self, Error> {
        Self::with_limits(reader, CaptureLimits::default())
    }

    /// Read a PCAPNG capture using explicit byte and record ceilings
    ///
    /// # Errors
    /// Returns an error for malformed block framing, unsupported section versions,
    /// malformed limits, or input I/O
    pub fn with_limits(reader: R, limits: CaptureLimits) -> Result<Self, Error> {
        let mut capture = Self {
            reader,
            input_bytes: 0,
            records_read: 0,
            limits,
            section: 0,
            order: ByteOrder::Little,
            current_interfaces: Vec::new(),
            collection_summary: crate::CollectionSummary::default(),
            terminated: false,
        };
        let Some((block, bytes)) = read_block(
            &mut capture.reader,
            &mut capture.input_bytes,
            None,
            limits.max_input_bytes(),
            None,
        )?
        else {
            return Err(Error::UnexpectedEof {
                section: "PCAPNG section header",
                expected: SECTION_HEADER_MIN_LENGTH,
                received: 0,
            });
        };
        if block.block_type != SECTION_HEADER_BLOCK {
            return Err(Error::SectionHeaderRequired);
        }
        capture.order = block.order;
        capture.start_section(block, &bytes, false)?;
        Ok(capture)
    }

    /// Read the next packet-bearing block
    ///
    /// Unknown block types are validated and skipped. `None` means a clean end of
    /// the input at a block boundary. A reader becomes terminal after any malformed
    /// block or input error because its stream position can no longer be trusted
    ///
    /// # Errors
    ///
    /// Returns an error for malformed block framing, invalid packet metadata,
    /// invalid options, budget violations, or input I/O
    pub fn next_packet(&mut self) -> Result<Option<CapturedFrame>, Error> {
        if self.terminated {
            return Err(Error::ReaderTerminated);
        }

        let result = self.read_next_packet();
        if result.is_err() {
            self.terminated = true;
        }
        result
    }

    /// Borrow interface descriptions declared in the current section
    #[must_use]
    pub fn interface_descriptions(&self) -> &[InterfaceDescription] {
        &self.current_interfaces
    }

    /// Return source-declared collection conditions observed so far
    #[must_use]
    pub const fn collection_summary(&self) -> crate::CollectionSummary {
        self.collection_summary
    }

    fn read_next_packet(&mut self) -> Result<Option<CapturedFrame>, Error> {
        loop {
            let Some((block, bytes)) = read_block(
                &mut self.reader,
                &mut self.input_bytes,
                Some(self.order),
                self.limits.max_input_bytes(),
                Some((self.records_read, self.limits.max_records())),
            )?
            else {
                return Ok(None);
            };
            let block_offset = self
                .input_bytes
                .checked_sub(u64::try_from(bytes.len()).map_err(|_| Error::InvalidHeaderLayout)?)
                .ok_or(Error::InvalidHeaderLayout)?;

            match block.block_type {
                SECTION_HEADER_BLOCK => {
                    self.order = block.order;
                    self.start_section(block, &bytes, true)?;
                }
                INTERFACE_DESCRIPTION_BLOCK => self.add_interface(&bytes, block.order)?,
                PACKET_BLOCK => {
                    let decoded = decode_packet_block(
                        &bytes,
                        block.order,
                        self.section,
                        &self.current_interfaces,
                        block_offset,
                    )?;
                    self.collection_summary
                        .observe_packet_block_drops(decoded.drops_count);
                    self.records_read += 1;
                    return Ok(Some(decoded.frame));
                }
                ENHANCED_PACKET_BLOCK => {
                    let packet = decode_enhanced_packet(
                        &bytes,
                        block.order,
                        self.section,
                        &self.current_interfaces,
                        block_offset,
                    )?;
                    self.records_read += 1;
                    return Ok(Some(packet));
                }
                SIMPLE_PACKET_BLOCK => {
                    let packet = decode_simple_packet(
                        &bytes,
                        block.order,
                        &self.current_interfaces,
                        block_offset,
                    )?;
                    self.records_read += 1;
                    return Ok(Some(packet));
                }
                _ => {
                    // Unknown blocks are safely skippable after their framing was validated
                }
            }
        }
    }

    fn start_section(
        &mut self,
        block: Block,
        bytes: &[u8],
        increment_section: bool,
    ) -> Result<(), Error> {
        if increment_section {
            self.section =
                self.section
                    .checked_add(1)
                    .ok_or_else(|| Error::InputLimitExceeded {
                        attempted: u64::MAX,
                        limit: self.limits.max_input_bytes(),
                    })?;
        }
        self.collection_summary
            .observe(parse_section_header(bytes, block.order)?);
        self.current_interfaces.clear();
        Ok(())
    }

    fn add_interface(&mut self, bytes: &[u8], order: ByteOrder) -> Result<(), Error> {
        let current_index = u32::try_from(self.current_interfaces.len()).map_err(|_| {
            Error::InterfaceLimitExceeded {
                limit: MAX_INTERFACES,
            }
        })?;
        if current_index >= MAX_INTERFACES {
            return Err(Error::InterfaceLimitExceeded {
                limit: MAX_INTERFACES,
            });
        }
        let description = parse_interface(
            bytes,
            order,
            InterfaceId {
                section: self.section,
                index: current_index,
            },
        )?;
        self.current_interfaces.push(description);
        Ok(())
    }
}
