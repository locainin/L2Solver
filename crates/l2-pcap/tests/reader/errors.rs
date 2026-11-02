use l2_pcap::{CaptureReader, Error};
use std::io::{self, Read};

#[test]
fn io_errors_are_preserved() {
    struct FailingReader;

    impl Read for FailingReader {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::other("fixture failure"))
        }
    }

    let result = CaptureReader::new(FailingReader);
    assert!(matches!(result, Err(Error::Io(_))));
}

#[test]
fn reader_contract_violations_are_rejected() {
    struct OverreportingReader;

    impl Read for OverreportingReader {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            Ok(buffer.len().saturating_add(1))
        }
    }

    let result = CaptureReader::new(OverreportingReader);
    assert!(matches!(result, Err(Error::ReaderContractViolation { .. })));
}

#[test]
fn errors_render_context_io_sources() -> Result<(), Box<dyn std::error::Error>> {
    let errors = [
        Error::Io(io::Error::other("fixture failure")),
        Error::UnexpectedEof {
            section: "record header",
            expected: 16,
            received: 1,
        },
        Error::UnsupportedFormat { name: "PCAPNG" },
        Error::UnsupportedMagic {
            magic: [0, 1, 2, 3],
        },
        Error::UnsupportedVersion { major: 1, minor: 0 },
        Error::InvalidSnaplen { snaplen: 0 },
        Error::UnsupportedLinkMetadata { value: 0x0400_0001 },
        Error::InvalidCapturedLength {
            captured: 2,
            snaplen: 1,
        },
        Error::InvalidOriginalLength {
            captured: 2,
            original: 1,
        },
        Error::InvalidTimestampFraction {
            fraction: 1_000_000,
            nanoseconds: false,
        },
        Error::LengthOverflow { length: u32::MAX },
        Error::InputLimitExceeded {
            attempted: 10,
            limit: 9,
        },
        Error::RecordLimitExceeded { limit: 1 },
        Error::ReaderContractViolation {
            returned: 2,
            requested: 1,
        },
        Error::ReaderTerminated,
        Error::InvalidHeaderLayout,
    ];
    for error in errors {
        assert_ne!(error.to_string(), "");
    }

    let error = Error::Io(io::Error::other("source detail"));
    let source = std::error::Error::source(&error).ok_or("missing I/O source")?;
    assert_eq!(source.to_string(), "source detail");
    assert!(std::error::Error::source(&Error::ReaderTerminated).is_none());
    Ok(())
}
