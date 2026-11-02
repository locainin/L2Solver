#[path = "../src/output.rs"]
mod output;

use std::{
    cell::Cell,
    error::Error,
    io::{self, Write},
    rc::Rc,
};

struct OverReportingWriter;

impl Write for OverReportingWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len().saturating_add(1))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct FailedFlush;

impl Write for FailedFlush {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush failed"))
    }
}

struct BrokenPipeCounter {
    attempts: Rc<Cell<usize>>,
}

impl Write for BrokenPipeCounter {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        self.attempts.set(self.attempts.get() + 1);
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed pipe"))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.attempts.set(self.attempts.get() + 1);
        Err(io::Error::new(io::ErrorKind::BrokenPipe, "closed pipe"))
    }
}

struct OtherOutputError;

impl Write for OtherOutputError {
    fn write(&mut self, _bytes: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected output failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("injected output failure"))
    }
}

struct FailAfter {
    remaining: usize,
    accepted: usize,
}

impl FailAfter {
    const fn new(limit: usize) -> Self {
        Self {
            remaining: limit,
            accepted: 0,
        }
    }
}

impl Write for FailAfter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            return Err(io::Error::other("injected sink failure"));
        }
        let accepted = self.remaining.min(bytes.len());
        self.remaining -= accepted;
        self.accepted += accepted;
        Ok(accepted)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn rejects_bytes_after_output_limit() -> Result<(), Box<dyn Error>> {
    const { assert!(output::MAX_SURVEY_JSON_BYTES == 33_554_432) };
    let mut destination = Vec::new();
    let mut writer = output::BoundedWriter::new(&mut destination, 256);
    writer.write_all(&[0; 256])?;
    let error = match writer.write_all(&[1]) {
        Ok(()) => return Err("bytes over the limit were accepted".into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert!(error.to_string().contains("256 bytes"));
    assert_eq!(writer.written(), 256);
    assert_eq!(destination.len(), 256);

    let mut named_destination = Vec::new();
    let mut named = output::BoundedWriter::named(&mut named_destination, 1, "baseline JSON");
    let named_error = named
        .write_all(&[1, 2])
        .err()
        .ok_or("named writer accepted bytes over its limit")?;
    assert!(named_error.to_string().contains("baseline JSON"));
    assert_eq!(named.written(), 0);
    assert_eq!(named_destination.len(), 0);
    Ok(())
}

#[test]
fn bounded_writer_validates_counts_flushes() -> Result<(), Box<dyn Error>> {
    let mut invalid = output::BoundedWriter::new(OverReportingWriter, 8);
    assert!(invalid.write(&[1]).is_err());

    let mut failed = output::BoundedWriter::new(FailedFlush, 8);
    let Err(error) = failed.flush() else {
        return Err("flush failure was discarded".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::Other);
    Ok(())
}

#[test]
fn closed_pipe_discards_later_output() -> Result<(), Box<dyn Error>> {
    let attempts = Rc::new(Cell::new(0));
    let mut writer = output::BrokenPipeWriter::new(BrokenPipeCounter {
        attempts: Rc::clone(&attempts),
    });

    writer.write_all(b"first")?;
    writer.write_all(b"second")?;
    writer.flush()?;

    assert_eq!(attempts.get(), 1);
    Ok(())
}

#[test]
fn pipe_writer_preserves_other_errors() {
    let mut writer = output::BrokenPipeWriter::new(OtherOutputError);

    assert!(writer.write_all(b"data").is_err());
    assert!(writer.flush().is_err());
}

#[test]
fn json_publisher_each_short() -> Result<(), Box<dyn Error>> {
    let value = serde_json::json!({"status": "complete", "frames": 17});
    let mut complete = Vec::new();
    output::write_json(&value, &mut complete, 1_024)?;

    for boundary in 0..complete.len() {
        let mut sink = FailAfter::new(boundary);
        assert!(
            output::write_json(&value, &mut sink, 1_024).is_err(),
            "accepted a sink that fails after byte {boundary}"
        );
        assert!(sink.accepted <= boundary);
    }
    Ok(())
}
