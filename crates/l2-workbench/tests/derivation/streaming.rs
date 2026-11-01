use super::support::{gzip, zlib};
use l2_workbench::derivation::{
    Base64Alphabet, Base64Padding, Operation, StepFailure, StreamInput, StreamLimits,
    StreamTransformError, stream_transform,
};
use l2_workbench::job::MemoryBudget;
use std::{
    error::Error,
    io::{self, Cursor, Read},
};

const fn limits() -> StreamLimits {
    StreamLimits {
        max_input_bytes: 1_000_000,
        max_output_bytes: 1_000_000,
        max_work_bytes: 2_000_000,
        max_expansion_ratio: 1000,
    }
}

struct ShortReader<'a>(Cursor<&'a [u8]>);

impl Read for ShortReader<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count = buffer.len().min(3);
        self.0.read(
            buffer
                .get_mut(..count)
                .ok_or_else(|| io::Error::other("invalid short-read buffer"))?,
        )
    }
}

fn transform(
    input: &[u8],
    operation: &Operation,
    limits: StreamLimits,
) -> Result<Vec<u8>, StreamTransformError> {
    let mut output = Vec::new();
    let sha256 = l2_workbench::sha256(input);
    let receipt = stream_transform(
        &mut ShortReader(Cursor::new(input)),
        &mut output,
        operation,
        StreamInput {
            length: input.len(),
            sha256: &sha256,
        },
        limits,
        &MemoryBudget::new(u64::MAX),
    )?;
    assert_eq!(receipt.input_length, input.len());
    assert_eq!(receipt.input_sha256, sha256);
    assert_eq!(receipt.output_length, output.len());
    assert_eq!(receipt.output_sha256, l2_workbench::sha256(&output));
    assert_eq!(receipt.work_bytes, input.len() + output.len() + 4);
    Ok(output)
}

#[test]
fn streaming_decoders_handle_short_reads_and_exact_terminal_groups() -> Result<(), Box<dyn Error>> {
    let cases: &[(&[u8], Operation, &[u8])] = &[
        (b"41fF00", Operation::HexDecode {}, b"A\xff\x00"),
        (
            b"QUJDRA==",
            Operation::Base64Decode {
                alphabet: Base64Alphabet::Standard,
                padding: Base64Padding::Required,
            },
            b"ABCD",
        ),
        (
            b"-_8",
            Operation::Base64Decode {
                alphabet: Base64Alphabet::UrlSafe,
                padding: Base64Padding::Forbidden,
            },
            b"\xfb\xff",
        ),
        (
            b"prefix payload suffix",
            Operation::Slice {
                start: 7,
                length: Some(7),
            },
            b"payload",
        ),
    ];
    for (input, operation, expected) in cases {
        assert_eq!(transform(input, operation, limits())?, *expected);
    }
    for (compressed, operation) in [
        (gzip(b"compressed payload")?, Operation::GzipDecompress {}),
        (zlib(b"compressed payload")?, Operation::ZlibDecompress {}),
    ] {
        assert_eq!(
            transform(&compressed, &operation, limits())?,
            b"compressed payload"
        );
    }
    Ok(())
}

#[test]
fn streaming_decoders_reject_corrupt_tails_and_trailing_compressed_bytes()
-> Result<(), Box<dyn Error>> {
    let base64 = Operation::Base64Decode {
        alphabet: Base64Alphabet::Standard,
        padding: Base64Padding::Required,
    };
    for input in [b"QUJDRA=A".as_slice(), b"QUJDRA==AAAA", b"QUJ="] {
        assert!(matches!(
            transform(input, &base64, limits()),
            Err(StreamTransformError::Step(StepFailure::InvalidBase64))
        ));
    }
    assert!(matches!(
        transform(b"414", &Operation::HexDecode {}, limits()),
        Err(StreamTransformError::Step(
            StepFailure::InvalidHexLength { .. }
        ))
    ));
    assert!(matches!(
        transform(b"41fg", &Operation::HexDecode {}, limits()),
        Err(StreamTransformError::Step(StepFailure::InvalidHexDigit {
            offset: 3
        }))
    ));
    for (mut compressed, operation) in [
        (gzip(b"payload")?, Operation::GzipDecompress {}),
        (zlib(b"payload")?, Operation::ZlibDecompress {}),
    ] {
        compressed.extend_from_slice(b"trailing");
        assert!(matches!(
            transform(&compressed, &operation, limits()),
            Err(StreamTransformError::Step(
                StepFailure::TrailingCompressedData
            ))
        ));
        compressed.truncate(compressed.len() - 9);
        assert!(matches!(
            transform(&compressed, &operation, limits()),
            Err(StreamTransformError::Step(
                StepFailure::InvalidCompressedStream
            ))
        ));
    }
    Ok(())
}

#[test]
fn streaming_enforces_input_output_work_and_expansion_limits() -> Result<(), Box<dyn Error>> {
    let operation = Operation::HexDecode {};
    let input = b"41424344";
    assert!(matches!(
        transform(
            input,
            &operation,
            StreamLimits {
                max_input_bytes: 7,
                ..limits()
            }
        ),
        Err(StreamTransformError::InputLimit { .. })
    ));
    assert!(matches!(
        transform(
            input,
            &operation,
            StreamLimits {
                max_output_bytes: 3,
                ..limits()
            }
        ),
        Err(StreamTransformError::Step(
            StepFailure::OutputLimitExceeded { .. }
        ))
    ));
    assert!(matches!(
        transform(
            input,
            &operation,
            StreamLimits {
                max_work_bytes: 11,
                ..limits()
            }
        ),
        Err(StreamTransformError::Step(
            StepFailure::WorkBudgetExceeded { .. }
        ))
    ));
    let compressed = gzip(&[0; 4096])?;
    assert!(matches!(
        transform(
            &compressed,
            &Operation::GzipDecompress {},
            StreamLimits {
                max_expansion_ratio: 2,
                ..limits()
            }
        ),
        Err(StreamTransformError::ExpansionLimit { .. })
    ));
    Ok(())
}

#[test]
fn streaming_rejects_changed_identity_extra_bytes_and_unsupported_operations() {
    let input = b"4142";
    let wrong_digest = l2_workbench::sha256(b"4143");
    let result = stream_transform(
        &mut Cursor::new(input),
        &mut Vec::new(),
        &Operation::HexDecode {},
        StreamInput {
            length: input.len(),
            sha256: &wrong_digest,
        },
        limits(),
        &MemoryBudget::new(u64::MAX),
    );
    assert!(matches!(result, Err(StreamTransformError::InputChanged)));
    let digest = l2_workbench::sha256(b"41");
    let result = stream_transform(
        &mut Cursor::new(input),
        &mut Vec::new(),
        &Operation::HexDecode {},
        StreamInput {
            length: 2,
            sha256: &digest,
        },
        limits(),
        &MemoryBudget::new(u64::MAX),
    );
    assert!(matches!(result, Err(StreamTransformError::InputChanged)));
    assert!(matches!(
        transform(input, &Operation::Reverse {}, limits()),
        Err(StreamTransformError::UnsupportedOperation)
    ));
}

#[test]
fn declared_longer_input_is_a_source_change_for_every_stream_operation()
-> Result<(), Box<dyn Error>> {
    let encoded = b"QUJD".to_vec();
    let gzip = gzip(b"payload")?;
    let zlib = zlib(b"payload")?;
    for (bytes, operation, extra) in [
        (b"4142".to_vec(), Operation::HexDecode {}, 2),
        (
            encoded,
            Operation::Base64Decode {
                alphabet: Base64Alphabet::Standard,
                padding: Base64Padding::Required,
            },
            4,
        ),
        (gzip, Operation::GzipDecompress {}, 1),
        (zlib, Operation::ZlibDecompress {}, 1),
        (
            b"data".to_vec(),
            Operation::Slice {
                start: 0,
                length: None,
            },
            1,
        ),
    ] {
        let digest = l2_workbench::sha256(&bytes);
        let result = stream_transform(
            &mut Cursor::new(&bytes),
            &mut Vec::new(),
            &operation,
            StreamInput {
                length: bytes.len() + extra,
                sha256: &digest,
            },
            limits(),
            &MemoryBudget::new(u64::MAX),
        );
        assert!(
            matches!(result, Err(StreamTransformError::InputChanged)),
            "{operation:?}: {result:?}"
        );
    }
    Ok(())
}

struct FailingReader(io::ErrorKind);

impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::new(self.0, "injected source failure"))
    }
}

#[test]
fn source_read_errors_are_preserved_for_every_stream_operation() {
    let operations = [
        Operation::HexDecode {},
        Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        },
        Operation::GzipDecompress {},
        Operation::ZlibDecompress {},
        Operation::Slice {
            start: 0,
            length: None,
        },
    ];
    for operation in operations {
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::Other,
        ] {
            let result = stream_transform(
                &mut FailingReader(kind),
                &mut Vec::new(),
                &operation,
                StreamInput {
                    length: 4,
                    sha256: "unused",
                },
                limits(),
                &MemoryBudget::new(u64::MAX),
            );
            assert!(
                matches!(result, Err(StreamTransformError::Io(ref error)) if error.kind() == kind && error.to_string() == "injected source failure"),
                "{operation:?}, {kind:?}: {result:?}"
            );
        }
    }
}

#[test]
fn invalid_gzip_header_is_a_failed_transform_not_a_source_io_failure() {
    assert!(matches!(
        transform(b"not a gzip", &Operation::GzipDecompress {}, limits()),
        Err(StreamTransformError::Step(
            StepFailure::InvalidCompressedStream
        ))
    ));
}

#[test]
fn compressed_checksum_errors_are_failed_transforms() -> Result<(), Box<dyn Error>> {
    for (mut bytes, operation) in [
        (gzip(b"payload")?, Operation::GzipDecompress {}),
        (zlib(b"payload")?, Operation::ZlibDecompress {}),
    ] {
        let last = bytes.last_mut().ok_or("compressed fixture is empty")?;
        *last ^= 1;
        assert!(matches!(
            transform(&bytes, &operation, limits()),
            Err(StreamTransformError::Step(
                StepFailure::InvalidCompressedStream
            ))
        ));
    }
    Ok(())
}

#[test]
fn stream_workspace_requires_shared_memory_admission_before_reading() -> Result<(), Box<dyn Error>>
{
    use l2_workbench::derivation::STREAM_WORKSPACE_BYTES;
    use l2_workbench::job::{MemoryClass, MemoryError};
    let memory = MemoryBudget::new(STREAM_WORKSPACE_BYTES);
    let lease = memory.try_reserve(MemoryClass::Executor, 1)?;
    // A tiny header requests the largest possible gzip extra field
    let input = b"\x1f\x8b\x08\x04\x00\x00\x00\x00\x00\x00\xff\xff";
    let digest = l2_workbench::sha256(input);
    let mut reader = Cursor::new(input);
    let result = stream_transform(
        &mut reader,
        &mut Vec::new(),
        &Operation::GzipDecompress {},
        StreamInput {
            length: input.len(),
            sha256: &digest,
        },
        limits(),
        &memory,
    );
    assert!(matches!(
        result,
        Err(StreamTransformError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(reader.position(), 0);
    drop(lease);
    let input = b"4142";
    let digest = l2_workbench::sha256(input);
    let mut reader = Cursor::new(input);
    let mut result = Vec::new();
    stream_transform(
        &mut reader,
        &mut result,
        &Operation::HexDecode {},
        StreamInput {
            length: input.len(),
            sha256: &digest,
        },
        limits(),
        &memory,
    )?;
    assert_eq!(result, b"AB");
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn stream_work_reserves_bounded_probes_before_reading() {
    let mut reader = FailingReader(io::ErrorKind::Other);
    let result = stream_transform(
        &mut reader,
        &mut Vec::new(),
        &Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        },
        StreamInput {
            length: 4,
            sha256: "unused",
        },
        StreamLimits {
            max_work_bytes: 7,
            ..limits()
        },
        &MemoryBudget::new(u64::MAX),
    );
    assert!(matches!(
        result,
        Err(StreamTransformError::Step(
            StepFailure::WorkBudgetExceeded { limit: 7 }
        ))
    ));
}

fn malformed_sources() -> Vec<(Vec<u8>, Operation)> {
    vec![
        (b"z142".to_vec(), Operation::HexDecode {}),
        (
            b"!!!!".to_vec(),
            Operation::Base64Decode {
                alphabet: Base64Alphabet::Standard,
                padding: Base64Padding::Required,
            },
        ),
        (vec![0; 12], Operation::GzipDecompress {}),
        (vec![0; 4], Operation::ZlibDecompress {}),
    ]
}

struct PrefixThenError<'a> {
    prefix: Cursor<&'a [u8]>,
}

impl Read for PrefixThenError<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let read = self.prefix.read(buffer)?;
        if read == 0 {
            return Err(io::Error::other("late source failure"));
        }
        Ok(read)
    }
}

#[test]
fn malformed_streams_verify_the_complete_source_before_reporting_rejection() {
    for (bytes, operation) in malformed_sources() {
        let expected = l2_workbench::sha256(&vec![b'x'; bytes.len()]);
        let result = stream_transform(
            &mut Cursor::new(&bytes),
            &mut Vec::new(),
            &operation,
            StreamInput {
                length: bytes.len(),
                sha256: &expected,
            },
            limits(),
            &MemoryBudget::new(u64::MAX),
        );
        assert!(
            matches!(result, Err(StreamTransformError::InputChanged)),
            "changed {operation:?}: {result:?}"
        );
        let actual = l2_workbench::sha256(&bytes);
        let result = stream_transform(
            &mut Cursor::new(&bytes),
            &mut Vec::new(),
            &operation,
            StreamInput {
                length: bytes.len() + 4,
                sha256: &actual,
            },
            limits(),
            &MemoryBudget::new(u64::MAX),
        );
        assert!(
            matches!(result, Err(StreamTransformError::InputChanged)),
            "short {operation:?}: {result:?}"
        );
        let result = stream_transform(
            &mut PrefixThenError {
                prefix: Cursor::new(&bytes),
            },
            &mut Vec::new(),
            &operation,
            StreamInput {
                length: bytes.len() + 4,
                sha256: &actual,
            },
            limits(),
            &MemoryBudget::new(u64::MAX),
        );
        assert!(
            matches!(result, Err(StreamTransformError::Io(ref error)) if error.to_string() == "late source failure"),
            "I/O {operation:?}: {result:?}"
        );
    }
}

struct InterruptOnce<'a> {
    data: Cursor<&'a [u8]>,
    interrupted: bool,
}

impl Read for InterruptOnce<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if !self.interrupted {
            self.interrupted = true;
            return Err(io::ErrorKind::Interrupted.into());
        }
        self.data.read(buffer)
    }
}

#[test]
fn interrupted_source_reads_retry_without_losing_identity() -> Result<(), Box<dyn Error>> {
    for (bytes, operation) in [
        (b"4142".to_vec(), Operation::HexDecode {}),
        (
            b"QUI=".to_vec(),
            Operation::Base64Decode {
                alphabet: Base64Alphabet::Standard,
                padding: Base64Padding::Required,
            },
        ),
        (gzip(b"AB")?, Operation::GzipDecompress {}),
        (zlib(b"AB")?, Operation::ZlibDecompress {}),
        (
            b"AB".to_vec(),
            Operation::Slice {
                start: 0,
                length: None,
            },
        ),
    ] {
        let digest = l2_workbench::sha256(&bytes);
        let mut output = Vec::new();
        stream_transform(
            &mut InterruptOnce {
                data: Cursor::new(&bytes),
                interrupted: false,
            },
            &mut output,
            &operation,
            StreamInput {
                length: bytes.len(),
                sha256: &digest,
            },
            limits(),
            &MemoryBudget::new(u64::MAX),
        )?;
        assert_eq!(output, b"AB", "{operation:?}");
    }
    for operation in [
        Operation::HexDecode {},
        Operation::Base64Decode {
            alphabet: Base64Alphabet::Standard,
            padding: Base64Padding::Required,
        },
        Operation::GzipDecompress {},
        Operation::ZlibDecompress {},
        Operation::Slice {
            start: 0,
            length: None,
        },
    ] {
        let result = stream_transform(
            &mut FailingReader(io::ErrorKind::Interrupted),
            &mut Vec::new(),
            &operation,
            StreamInput {
                length: 4,
                sha256: "unused",
            },
            limits(),
            &MemoryBudget::new(u64::MAX),
        );
        assert!(
            matches!(result, Err(StreamTransformError::Io(ref error)) if error.kind() == io::ErrorKind::Interrupted),
            "{operation:?}: {result:?}"
        );
    }
    Ok(())
}
