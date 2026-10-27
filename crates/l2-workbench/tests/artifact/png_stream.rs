use std::{
    error::Error,
    fs::File,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};

use l2_workbench::artifact::{
    FileRange, PNG_SIGNATURE, PngError, PngLimits, PngReadError, parse_png, parse_png_from_reader,
    parse_png_from_reader_with_memory,
};

#[test]
fn png_chunk_metadata_uses_the_shared_live_memory_lease() -> Result<(), Box<dyn Error>> {
    use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryError};
    let mut bytes = PNG_SIGNATURE.to_vec();
    write_chunk(
        &mut bytes,
        *b"IHDR",
        &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
    )?;
    write_chunk(&mut bytes, *b"IEND", &[])?;
    let small = MemoryBudget::new(1);
    let mut lease = small.try_reserve(MemoryClass::Executor, 0)?;
    let result = parse_png_from_reader_with_memory(
        &mut Cursor::new(&bytes),
        bytes.len(),
        PngLimits::default(),
        &mut lease,
    );
    assert!(matches!(
        result,
        Err(PngReadError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(lease.bytes(), 0);
    let budget = MemoryBudget::new(4096);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = parse_png_from_reader_with_memory(
        &mut Cursor::new(&bytes),
        bytes.len(),
        PngLimits::default(),
        &mut lease,
    )?;
    assert_eq!(report.chunks.len(), 2);
    assert!(
        lease.bytes()
            >= u64::try_from(
                report.chunks.capacity()
                    * std::mem::size_of::<l2_workbench::artifact::PngRangeChunk>()
            )?
    );
    drop(report);
    drop(lease);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn streaming_png_validates_large_chunk_with_bounded_reads_and_exact_ranges()
-> Result<(), Box<dyn Error>> {
    const PAYLOAD_LENGTH: usize = 70 * 1024 * 1024;
    const BLOCK: usize = 16 * 1024;
    let mut file = tempfile::tempfile()?;
    file.write_all(&PNG_SIGNATURE)?;
    write_chunk(
        &mut file,
        *b"IHDR",
        &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
    )?;
    file.write_all(&u32::try_from(PAYLOAD_LENGTH)?.to_be_bytes())?;
    file.write_all(b"abCd")?;
    let zeroes = [0_u8; BLOCK];
    let mut crc = crc32fast::Hasher::new();
    crc.update(b"abCd");
    for _ in 0..(PAYLOAD_LENGTH / BLOCK) {
        file.write_all(&zeroes)?;
        crc.update(&zeroes);
    }
    file.write_all(&crc.finalize().to_be_bytes())?;
    write_chunk(&mut file, *b"IEND", &[])?;
    file.write_all(b"tail")?;
    let length = usize::try_from(file.stream_position()?)?;
    file.seek(SeekFrom::Start(0))?;
    let mut reader = BoundedRead { file, largest: 0 };
    let report = parse_png_from_reader(
        &mut reader,
        length,
        PngLimits {
            max_input_bytes: length,
            max_chunks: 3,
        },
    )?;
    assert_eq!(report.chunks.len(), 3);
    let chunk = report.chunks.get(1).ok_or("private chunk missing")?;
    assert_eq!(chunk.type_code, *b"abCd");
    assert_eq!(
        chunk.payload_range,
        FileRange {
            offset: 41,
            length: PAYLOAD_LENGTH
        }
    );
    assert_eq!(
        report.bytes_after_iend_range,
        FileRange {
            offset: length - 4,
            length: 4
        }
    );
    assert!(
        reader.largest <= BLOCK,
        "read buffer was {} bytes",
        reader.largest
    );
    Ok(())
}

#[test]
fn streaming_png_and_slice_parser_share_chunk_boundaries_and_errors() -> Result<(), Box<dyn Error>>
{
    let mut bytes = PNG_SIGNATURE.to_vec();
    write_chunk(
        &mut bytes,
        *b"IHDR",
        &[0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0],
    )?;
    write_chunk(&mut bytes, *b"abCd", b"payload")?;
    write_chunk(&mut bytes, *b"IEND", &[])?;
    bytes.extend_from_slice(b"tail");
    let slice = parse_png(&bytes, PngLimits::default())?;
    let stream =
        parse_png_from_reader(&mut Cursor::new(&bytes), bytes.len(), PngLimits::default())?;
    assert_eq!(stream.bytes_after_iend_range, slice.bytes_after_iend_range);
    for (stream_chunk, slice_chunk) in stream.chunks.iter().zip(&slice.chunks) {
        assert_eq!(stream_chunk.type_code, slice_chunk.type_code);
        assert_eq!(stream_chunk.chunk_range, slice_chunk.chunk_range);
        assert_eq!(stream_chunk.payload_range, slice_chunk.payload_range);
        assert_eq!(stream_chunk.stored_crc32, slice_chunk.stored_crc32);
    }
    for index in [0, 20, bytes.len() - 5] {
        let mut malformed = bytes.clone();
        *malformed.get_mut(index).ok_or("missing mutation byte")? ^= 1;
        let expected = parse_png(&malformed, PngLimits::default())
            .err()
            .ok_or("malformed PNG was accepted")?;
        let actual = parse_png_from_reader(
            &mut Cursor::new(&malformed),
            malformed.len(),
            PngLimits::default(),
        )
        .err()
        .ok_or("malformed PNG stream was accepted")?;
        assert!(
            matches!(actual, PngReadError::Format(ref error) if error == &expected),
            "unexpected error: {actual}"
        );
    }
    assert!(matches!(
        parse_png_from_reader(
            &mut Cursor::new(&bytes),
            bytes.len(),
            PngLimits {
                max_input_bytes: bytes.len() - 1,
                ..PngLimits::default()
            }
        ),
        Err(PngReadError::Format(PngError::InputTooLarge { .. }))
    ));
    Ok(())
}

#[test]
fn streaming_png_propagates_underlying_read_errors() {
    struct FailedRead;
    impl Read for FailedRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "read failed",
            ))
        }
    }
    assert!(
        matches!(parse_png_from_reader(&mut FailedRead, 64, PngLimits::default()), Err(PngReadError::Io(error)) if error.kind() == io::ErrorKind::PermissionDenied)
    );
}

fn write_chunk(
    output: &mut impl Write,
    kind: [u8; 4],
    payload: &[u8],
) -> Result<(), Box<dyn Error>> {
    output.write_all(&u32::try_from(payload.len())?.to_be_bytes())?;
    output.write_all(&kind)?;
    output.write_all(payload)?;
    let mut crc = crc32fast::Hasher::new();
    crc.update(&kind);
    crc.update(payload);
    output.write_all(&crc.finalize().to_be_bytes())?;
    Ok(())
}

struct BoundedRead {
    file: File,
    largest: usize,
}

impl Read for BoundedRead {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.largest = self.largest.max(bytes.len());
        self.file.read(bytes)
    }
}
