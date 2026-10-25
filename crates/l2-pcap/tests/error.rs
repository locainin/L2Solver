use l2_capture::{FrameError, MetadataError};
use l2_pcap::Error;
use std::io;

fn assert_errors(errors: impl IntoIterator<Item = (Error, &'static str)>) {
    for (error, expected) in errors {
        assert_eq!(error.to_string(), expected);
    }
}

#[test]
fn classic_file_errors_preserve_context() {
    assert_errors([
        (
            Error::Io(io::Error::other("source detail")),
            "PCAP input/output error: source detail",
        ),
        (
            Error::UnexpectedEof {
                section: "record header",
                expected: 16,
                received: 1,
            },
            "unexpected end of input in record header: expected 16 bytes, received 1",
        ),
        (
            Error::UnsupportedFormat { name: "PCAPNG" },
            "unsupported capture format: PCAPNG",
        ),
        (
            Error::UnsupportedMagic {
                magic: [0, 1, 2, 3],
            },
            "unsupported PCAP magic 00010203",
        ),
        (
            Error::UnsupportedVersion { major: 1, minor: 0 },
            "unsupported PCAP version 1.0; only 2.4 is supported",
        ),
        (
            Error::InvalidSnaplen { snaplen: 0 },
            "invalid PCAP snapshot length 0; expected a nonzero u32",
        ),
        (
            Error::UnsupportedLinkMetadata { value: 0x0400_0001 },
            "unsupported link-layer metadata in network field 0x04000001",
        ),
    ]);
}

#[test]
fn classic_record_errors_preserve_context() {
    assert_errors([
        (
            Error::InvalidCapturedLength {
                captured: 2,
                snaplen: 1,
            },
            "captured packet length 2 exceeds snapshot length 1",
        ),
        (
            Error::InvalidOriginalLength {
                captured: 2,
                original: 1,
            },
            "captured packet length 2 exceeds original length 1",
        ),
        (
            Error::InvalidTimestampFraction {
                fraction: 1_000_000,
                nanoseconds: false,
            },
            "invalid timestamp 1000000 microseconds; expected a value below 1000000",
        ),
        (
            Error::LengthOverflow { length: u32::MAX },
            "packet length 4294967295 cannot be represented safely",
        ),
        (
            Error::InputLimitExceeded {
                attempted: 10,
                limit: 9,
            },
            "PCAP input budget exceeded: 10 bytes would be processed (limit 9)",
        ),
        (
            Error::RecordLimitExceeded { limit: 1 },
            "PCAP record limit exceeded: maximum 1 records",
        ),
        (
            Error::ReaderContractViolation {
                returned: 2,
                requested: 1,
            },
            "input reader returned 2 bytes for a 1-byte buffer",
        ),
        (
            Error::ReaderTerminated,
            "PCAP reader is terminated after a previous error",
        ),
        (
            Error::InvalidHeaderLayout,
            "invalid fixed PCAP header layout",
        ),
        (
            Error::InterruptedLimitExceeded { limit: 32 },
            "input reader returned Interrupted 32 consecutive times",
        ),
    ]);
}

#[test]
fn pcapng_section_errors_preserve_context() {
    assert_errors([
        (
            Error::InvalidBlockLength {
                block_type: 1,
                length: 12,
            },
            "PCAPNG block 0x00000001 has invalid length 12",
        ),
        (
            Error::BlockLengthExceeded {
                block_type: 6,
                length: 100,
                limit: 64,
            },
            "PCAPNG block 0x00000006 length 100 exceeds limit 64",
        ),
        (
            Error::BlockLengthNotAligned {
                block_type: 3,
                length: 13,
            },
            "PCAPNG block 0x00000003 length 13 is not 4-byte aligned",
        ),
        (
            Error::BlockLengthMismatch {
                block_type: 6,
                declared: 32,
                trailing: 36,
            },
            "PCAPNG block 0x00000006 length mismatch: header 32, trailer 36",
        ),
        (
            Error::InvalidByteOrderMagic { magic: 0xdead_beef },
            "invalid PCAPNG byte-order magic 0xdeadbeef",
        ),
        (
            Error::UnsupportedPcapNgVersion { major: 1, minor: 3 },
            "unsupported PCAPNG section version 1.3; supported versions are 1.0 and 1.2",
        ),
        (
            Error::UnsupportedSectionLength { length: 128 },
            "finite PCAPNG section length 128 is unsupported by the streaming reader",
        ),
        (
            Error::InvalidSectionLength { length: -2 },
            "invalid PCAPNG section length -2",
        ),
        (
            Error::SectionHeaderRequired,
            "PCAPNG input must begin with a section header block",
        ),
    ]);
}

#[test]
fn pcapng_packet_errors_preserve_context() {
    assert_errors([
        (
            Error::InterfaceLimitExceeded { limit: 64 },
            "PCAPNG section contains more than 64 interface descriptions",
        ),
        (
            Error::UnknownInterface {
                section: 2,
                index: 9,
            },
            "PCAPNG packet references unknown interface 9 in section 2",
        ),
        (
            Error::SimplePacketWithoutInterface,
            "PCAPNG simple packet has no interface description",
        ),
        (
            Error::DuplicateOption {
                block_type: 1,
                code: 9,
            },
            "PCAPNG block 0x00000001 repeats known option 9",
        ),
        (
            Error::OptionLimitExceeded { limit: 128 },
            "PCAPNG option list exceeds the 128-entry limit",
        ),
        (
            Error::OptionAfterTerminator { block_type: 6 },
            "PCAPNG block 0x00000006 contains an option after opt_endofopt",
        ),
    ]);
}

#[test]
fn preserves_option_error_context() {
    assert_errors([
        (
            Error::InvalidOptionLength {
                block_type: 1,
                code: 9,
                length: 2,
                expected: Some(1),
                minimum: None,
            },
            "PCAPNG block 0x00000001 option 9 has length 2; expected 1",
        ),
        (
            Error::InvalidOptionLength {
                block_type: 1,
                code: 11,
                length: 0,
                expected: None,
                minimum: Some(1),
            },
            "PCAPNG block 0x00000001 option 11 has length 0; expected at least 1",
        ),
        (
            Error::InvalidOptionLength {
                block_type: 1,
                code: 99,
                length: 2,
                expected: None,
                minimum: None,
            },
            "PCAPNG block 0x00000001 option 99 has invalid length 2",
        ),
        (
            Error::UnsupportedFcsLength { bits: 7 },
            "unsupported PCAPNG FCS length 7 bits; the reader requires whole octets",
        ),
        (
            Error::InvalidPacketFlags { flags: 0x1000 },
            "invalid PCAPNG enhanced-packet flags 0x00001000",
        ),
        (
            Error::Frame(FrameError::CapturedLengthExceedsOriginal {
                captured: 2,
                original: 1,
            }),
            "invalid captured frame: captured frame length 2 exceeds original length 1",
        ),
        (
            Error::Metadata(MetadataError::InvalidFcsLength { length: 0, max: 31 }),
            "invalid capture metadata: invalid FCS length 0 bytes; expected 1..=31",
        ),
    ]);
}

#[test]
fn nested_frame_errors_available_sources() {
    let error = Error::Frame(FrameError::FrameTooLong {
        length: 65_536,
        max: 65_535,
    });

    assert!(std::error::Error::source(&error).is_some());
    let metadata = Error::Metadata(MetadataError::InvalidFcsLength { length: 0, max: 31 });
    assert!(std::error::Error::source(&metadata).is_some());
    assert!(std::error::Error::source(&Error::ReaderTerminated).is_none());
}
