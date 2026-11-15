use super::super::{ProcessError, capture};
use std::{
    error::Error,
    io::{self, Cursor, Read},
};

#[test]
fn capture_capacity_limit() -> Result<(), Box<dyn Error>> {
    for maximum in [1, 17, 31, 33, 65, 513, 4097, 1_048_576] {
        for length in [maximum - 1, maximum] {
            let source: Vec<u8> = b"0123456789abcdef"
                .iter()
                .copied()
                .cycle()
                .take(length)
                .collect();
            let captured = capture(source.as_slice(), maximum)?;
            assert_eq!(captured, source, "maximum {maximum}, length {length}");
            assert!(
                captured.capacity() <= maximum,
                "maximum {maximum}, length {length}, capacity {}",
                captured.capacity()
            );
        }
    }
    Ok(())
}

#[test]
fn capture_output_limit() {
    assert!(matches!(
        capture(&b"abcd"[..], 3),
        Err(ProcessError::OutputLimit)
    ));
}

#[test]
fn capture_zero_limit() -> Result<(), Box<dyn Error>> {
    let captured = capture(&b""[..], 0)?;
    assert_eq!(captured, b"");
    assert_eq!(captured.capacity(), 0);
    assert!(matches!(
        capture(&b"x"[..], 0),
        Err(ProcessError::OutputLimit)
    ));
    Ok(())
}

#[test]
fn capture_maximum_usize() -> Result<(), Box<dyn Error>> {
    let captured = capture(&b"small"[..], usize::MAX)?;
    assert_eq!(captured, b"small");
    assert!(captured.capacity() < 1024);
    Ok(())
}

struct FailureReader(bool);

impl Read for FailureReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        if std::mem::replace(&mut self.0, true) {
            Ok(0)
        } else {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
    }
}

#[test]
fn capture_read_failure() {
    assert!(matches!(
        capture(FailureReader(false), 8),
        Err(ProcessError::Read(error)) if error.kind() == io::ErrorKind::BrokenPipe
    ));
}

struct InterruptedReader {
    remaining: Cursor<&'static [u8]>,
    reads: usize,
}

impl Read for InterruptedReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        if self.reads == 1 || self.reads == 3 {
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.remaining.read(buffer)
    }
}

#[test]
fn capture_interrupted_read() -> Result<(), Box<dyn Error>> {
    let reader = InterruptedReader {
        remaining: Cursor::new(b"captured"),
        reads: 0,
    };
    let captured = capture(reader, 8)?;
    assert_eq!(captured, b"captured");
    assert!(captured.capacity() <= 8);
    Ok(())
}
