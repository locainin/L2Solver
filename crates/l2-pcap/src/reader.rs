//! Bounded, streaming classic PCAP reader

use l2_capture::FrameError;
use std::io::{self, Read};

use crate::{
    CaptureLimits, CaptureLocator, CaptureMetadata, CaptureTimestamp, CapturedFrame, Error,
    InterfaceId, LinkType, MAX_CONSECUTIVE_INTERRUPTS, MAX_FRAME_LENGTH, Packet,
    TimestampResolution, TimestampSource,
    header::{
        GLOBAL_HEADER_LENGTH, GlobalHeader, RECORD_HEADER_LENGTH, decode_u32, field,
        parse_global_header,
    },
};

/// A streaming reader for bounded classic PCAP 2.4 captures
pub struct CaptureReader<R: Read> {
    reader: R,
    header: GlobalHeader,
    records_read: u32,
    input_bytes: u64,
    limits: CaptureLimits,
    terminated: bool,
}

struct RecordFields {
    captured_length: u32,
    fraction: u32,
    original_length: u32,
    seconds: u32,
}

impl<R: Read> CaptureReader<R> {
    /// Read and validate the 24-byte global PCAP header
    ///
    /// # Errors
    /// Returns an error for an incomplete header, unsupported format, unsupported version,
    /// unsupported link metadata, or an input I/O failure
    pub fn new(reader: R) -> Result<Self, Error> {
        Self::with_limits(reader, CaptureLimits::default())
    }

    /// Read a classic PCAP file using explicit byte and record ceilings
    ///
    /// # Errors
    /// Returns an error for an incomplete header, unsupported format, malformed limits,
    /// unsupported metadata, or input I/O failure
    pub fn with_limits(reader: R, limits: CaptureLimits) -> Result<Self, Error> {
        let mut reader = reader;
        let mut bytes = [0; GLOBAL_HEADER_LENGTH];
        let mut input_bytes = 0;
        read_exact_counted(
            &mut reader,
            &mut bytes,
            &mut input_bytes,
            "global header",
            limits.max_input_bytes(),
        )?;
        let header = parse_global_header(&bytes)?;

        Ok(Self {
            reader,
            header,
            records_read: 0,
            input_bytes,
            limits,
            terminated: false,
        })
    }

    /// Return the checked data-link type declared by the global header
    #[must_use]
    pub const fn link_type(&self) -> LinkType {
        self.header.link_type
    }

    /// Read the next packet, returning `None` only at a clean record-boundary EOF
    ///
    /// A reader becomes terminal after any error because the underlying stream position may
    /// be unknown. Construct a new reader to retry from a known input position
    ///
    /// # Errors
    /// Returns an error for a partial record, malformed lengths or timestamps, an input or record
    /// budget violation, an I/O failure, or a reader that already reported an earlier error
    pub fn next_packet(&mut self) -> Result<Option<Packet>, Error> {
        if self.terminated {
            return Err(Error::ReaderTerminated);
        }

        match self.read_next_packet() {
            Ok(packet) => Ok(packet),
            Err(error) => {
                self.terminated = true;
                Err(error)
            }
        }
    }

    fn read_next_packet(&mut self) -> Result<Option<Packet>, Error> {
        let record_offset = self.input_bytes;
        let Some(header_bytes) = self.read_record_header()? else {
            return Ok(None);
        };
        let data_offset = self.input_bytes;

        if self.records_read >= self.limits.max_records() {
            return Err(Error::RecordLimitExceeded {
                limit: self.limits.max_records(),
            });
        }

        let fields = decode_record_fields(&header_bytes, self.header)?;
        // A valid microsecond fraction is below one million, so normalization fits in u32
        // Check the budget and integer conversion before allocating any packet bytes
        let payload_length =
            usize::try_from(fields.captured_length).map_err(|_| Error::LengthOverflow {
                length: fields.captured_length,
            })?;
        let attempted = self
            .input_bytes
            .checked_add(u64::from(fields.captured_length))
            .ok_or_else(|| Error::InputLimitExceeded {
                attempted: u64::MAX,
                limit: self.limits.max_input_bytes(),
            })?;
        if attempted > self.limits.max_input_bytes() {
            return Err(Error::InputLimitExceeded {
                attempted,
                limit: self.limits.max_input_bytes(),
            });
        }
        let mut bytes = vec![0; payload_length];
        read_exact_counted(
            &mut self.reader,
            &mut bytes,
            &mut self.input_bytes,
            "packet payload",
            self.limits.max_input_bytes(),
        )?;

        self.records_read += 1;
        let timestamp_ticks = u64::from(fields.seconds)
            .checked_mul(if self.header.nanosecond_timestamps {
                1_000_000_000
            } else {
                1_000_000
            })
            .and_then(|whole| whole.checked_add(u64::from(fields.fraction)))
            .ok_or(Error::LengthOverflow {
                length: fields.seconds,
            })?;
        let timestamp = CaptureTimestamp::new(
            timestamp_ticks,
            timestamp_resolution(self.header.nanosecond_timestamps),
            0,
            TimestampSource::CaptureFile,
        );
        let metadata = CaptureMetadata::new(
            InterfaceId {
                section: 0,
                index: 0,
            },
            fields.original_length,
            Some(CaptureLocator::ClassicPcap {
                record_offset,
                data_offset,
            }),
            Some(timestamp),
            l2_capture::Direction::Unknown,
            None,
            l2_capture::FcsStatus::Unknown,
        )
        .with_link_type(self.header.link_type);
        CapturedFrame::new(bytes, metadata)
            .map(Some)
            .map_err(Error::from)
    }

    fn read_record_header(&mut self) -> Result<Option<[u8; RECORD_HEADER_LENGTH]>, Error> {
        let mut bytes = [0; RECORD_HEADER_LENGTH];
        let mut received = 0;

        // A successful Read call must advance by at least one byte. A fixed
        // number of transitions therefore bounds even a broken reader whose
        // EOF result has been changed into a non-progressing success
        for _ in 0..RECORD_HEADER_LENGTH {
            if received == RECORD_HEADER_LENGTH {
                return Ok(Some(bytes));
            }

            // Limit each read to the bytes that remain in the total input budget
            let available = self.limits.max_input_bytes() - self.input_bytes;
            if available == 0 {
                let mut probe = [0; 1];
                let read = read_chunk(&mut self.reader, &mut probe)?;
                if read == 0 {
                    if received == 0 {
                        return Ok(None);
                    }
                    return Err(Error::UnexpectedEof {
                        section: "record header",
                        expected: RECORD_HEADER_LENGTH,
                        received,
                    });
                }
                return Err(Error::InputLimitExceeded {
                    attempted: self.input_bytes + 1,
                    limit: self.limits.max_input_bytes(),
                });
            }
            let available = usize::try_from(available).map_err(|_| Error::InputLimitExceeded {
                attempted: u64::MAX,
                limit: self.limits.max_input_bytes(),
            })?;
            let needed = RECORD_HEADER_LENGTH - received;
            let requested = needed.min(available);
            let Some(destination) = bytes.get_mut(received..received + requested) else {
                return Err(Error::InvalidHeaderLayout);
            };
            let read = read_chunk(&mut self.reader, destination)?;
            if read == 0 {
                if received == 0 {
                    return Ok(None);
                }
                return Err(Error::UnexpectedEof {
                    section: "record header",
                    expected: RECORD_HEADER_LENGTH,
                    received,
                });
            }
            self.input_bytes = self
                .input_bytes
                .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
                .ok_or_else(|| Error::InputLimitExceeded {
                    attempted: u64::MAX,
                    limit: self.limits.max_input_bytes(),
                })?;
            received += read;
        }

        // The loop can only finish with a complete header after a positive
        // read on its final transition
        if received == RECORD_HEADER_LENGTH {
            Ok(Some(bytes))
        } else {
            Err(Error::ReaderContractViolation {
                returned: 0,
                requested: RECORD_HEADER_LENGTH.saturating_sub(received),
            })
        }
    }
}

fn decode_record_fields(
    header: &[u8; RECORD_HEADER_LENGTH],
    global: GlobalHeader,
) -> Result<RecordFields, Error> {
    let fields = RecordFields {
        seconds: decode_u32(field::<4>(header, 0)?, global.byte_order),
        fraction: decode_u32(field::<4>(header, 4)?, global.byte_order),
        captured_length: decode_u32(field::<4>(header, 8)?, global.byte_order),
        original_length: decode_u32(field::<4>(header, 12)?, global.byte_order),
    };
    if fields.captured_length > global.snaplen {
        return Err(Error::InvalidCapturedLength {
            captured: fields.captured_length,
            snaplen: global.snaplen,
        });
    }
    if fields.original_length < fields.captured_length {
        return Err(Error::InvalidOriginalLength {
            captured: fields.captured_length,
            original: fields.original_length,
        });
    }
    if fields.captured_length > MAX_FRAME_LENGTH {
        return Err(Error::Frame(FrameError::FrameTooLong {
            length: usize::try_from(fields.captured_length).unwrap_or(usize::MAX),
            max: usize::try_from(MAX_FRAME_LENGTH).unwrap_or(usize::MAX),
        }));
    }
    let subsecond_limit = if global.nanosecond_timestamps {
        1_000_000_000
    } else {
        1_000_000
    };
    if fields.fraction >= subsecond_limit {
        return Err(Error::InvalidTimestampFraction {
            fraction: fields.fraction,
            nanoseconds: global.nanosecond_timestamps,
        });
    }
    Ok(fields)
}

const fn timestamp_resolution(nanoseconds: bool) -> TimestampResolution {
    if nanoseconds {
        TimestampResolution::NANOSECOND
    } else {
        TimestampResolution::MICROSECOND
    }
}

pub fn read_chunk<R: Read>(reader: &mut R, destination: &mut [u8]) -> Result<usize, Error> {
    let mut interrupted: u32 = 0;
    loop {
        match reader.read(destination) {
            Ok(read) if read <= destination.len() => return Ok(read),
            Ok(read) => {
                return Err(Error::ReaderContractViolation {
                    returned: read,
                    requested: destination.len(),
                });
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                interrupted = interrupted.saturating_add(1);
                if interrupted >= MAX_CONSECUTIVE_INTERRUPTS {
                    return Err(Error::InterruptedLimitExceeded {
                        limit: MAX_CONSECUTIVE_INTERRUPTS,
                    });
                }
                // Retry the same destination after a bounded interrupt
            }
            Err(error) => return Err(Error::Io(error)),
        }
    }
}

pub fn read_exact_counted<R: Read>(
    reader: &mut R,
    destination: &mut [u8],
    processed: &mut u64,
    section: &'static str,
    max_input_bytes: u64,
) -> Result<(), Error> {
    // The global header is fixed-size; packet callers check the budget before allocation
    let mut received = 0;
    while received < destination.len() {
        let Some(remaining) = destination.get_mut(received..) else {
            return Err(Error::InvalidHeaderLayout);
        };
        let needed = remaining.len();
        let available = max_input_bytes.saturating_sub(*processed);
        if u64::try_from(needed).unwrap_or(u64::MAX) > available {
            return Err(Error::InputLimitExceeded {
                attempted: (*processed).saturating_add(u64::try_from(needed).unwrap_or(u64::MAX)),
                limit: max_input_bytes,
            });
        }
        let read = read_chunk(reader, remaining)?;
        if read == 0 {
            return Err(Error::UnexpectedEof {
                section,
                expected: destination.len(),
                received,
            });
        }
        *processed = processed
            .checked_add(u64::try_from(read).unwrap_or(u64::MAX))
            .ok_or(Error::InputLimitExceeded {
                attempted: u64::MAX,
                limit: max_input_bytes,
            })?;
        received += read;
    }
    Ok(())
}
