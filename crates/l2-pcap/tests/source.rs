use std::io::{self, Cursor, Read};

use l2_pcap::{CaptureSource, TimestampResolution};

struct InterruptAfterDetection {
    input: Cursor<Vec<u8>>,
    reads: u8,
    interrupted: bool,
}

impl Read for InterruptAfterDetection {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.reads == 1 && !self.interrupted {
            self.interrupted = true;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        self.reads = self.reads.saturating_add(1);
        self.input.read(buffer)
    }
}

fn classic_capture() -> Vec<u8> {
    let mut capture = Vec::new();
    // Little-endian PCAP with microsecond timestamps and Ethernet link type
    capture.extend_from_slice(&[
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 64, 0, 0, 0, 1, 0, 0, 0,
    ]);
    capture.extend_from_slice(&[
        1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0, 3, 0, 0, 0, 0xaa, 0xbb, 0xcc,
    ]);
    capture
}

#[test]
fn replays_prefix_after_interrupted_read() -> Result<(), Box<dyn std::error::Error>> {
    let reader = InterruptAfterDetection {
        input: Cursor::new(classic_capture()),
        reads: 0,
        interrupted: false,
    };
    let mut source = CaptureSource::new(reader)?;
    let frame = source.next_packet()?.ok_or("missing replayed frame")?;
    assert_eq!(frame.bytes(), [0xaa, 0xbb, 0xcc]);
    assert_eq!(frame.metadata().original_len(), 3);
    assert_eq!(
        frame
            .metadata()
            .timestamp()
            .map(l2_pcap::CaptureTimestamp::resolution),
        Some(TimestampResolution::MICROSECOND)
    );
    assert!(source.next_packet()?.is_none());
    Ok(())
}
