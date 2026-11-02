use super::{
    captures,
    common::{ByteOrder, CaptureConfig, PacketConfig, one_packet},
};
use l2_pcap::{CaptureReader, Error};
use std::io::{self, Cursor, Read};

#[test]
fn interrupted_reads_are_retried() -> Result<(), Box<dyn std::error::Error>> {
    struct InterruptOnce<R> {
        inner: R,
        interrupted: bool,
    }

    impl<R: Read> Read for InterruptOnce<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if !self.interrupted {
                self.interrupted = true;
                return Err(io::Error::from(io::ErrorKind::Interrupted));
            }
            self.inner.read(buffer)
        }
    }

    let capture = one_packet(
        CaptureConfig {
            order: ByteOrder::Little,
            nanoseconds: false,
            snaplen: 64,
            network: 1,
        },
        PacketConfig {
            seconds: 1,
            fraction: 0,
            bytes: &[0xaa],
            original_len: 1,
        },
    );
    let source = InterruptOnce {
        inner: Cursor::new(capture),
        interrupted: false,
    };
    let mut reader = CaptureReader::new(source)?;
    assert_eq!(
        reader.next_packet()?.ok_or("missing packet")?.bytes(),
        [0xaa]
    );
    Ok(())
}

#[test]
fn repeated_interrupts_fail_bound() {
    struct AlwaysInterrupted;

    impl Read for AlwaysInterrupted {
        fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::Interrupted))
        }
    }

    assert!(matches!(
        CaptureReader::new(AlwaysInterrupted),
        Err(Error::InterruptedLimitExceeded { .. })
    ));
}

#[test]
fn reader_becomes_terminal_error() -> Result<(), Box<dyn std::error::Error>> {
    let mut capture = super::common::global_header(ByteOrder::Little, false, 64, 1);
    capture.extend_from_slice(&super::common::record_header(ByteOrder::Little, 1, 0, 2, 2));
    capture.push(0xaa);

    let mut reader = CaptureReader::new(Cursor::new(capture))?;
    assert!(matches!(
        reader.next_packet(),
        Err(Error::UnexpectedEof { .. })
    ));
    assert!(matches!(reader.next_packet(), Err(Error::ReaderTerminated)));
    Ok(())
}

#[test]
fn fragmented_reads_reassemble_records() -> Result<(), Box<dyn std::error::Error>> {
    struct Fragmented<R> {
        inner: R,
        limit: usize,
    }
    impl<R: Read> Read for Fragmented<R> {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            let length = buffer.len().min(self.limit);
            let destination = buffer
                .get_mut(..length)
                .ok_or_else(|| io::Error::other("invalid test read range"))?;
            self.inner.read(destination)
        }
    }
    let capture = captures::LLDP;
    for limit in 1..16 {
        let source = Fragmented {
            inner: capture,
            limit,
        };
        let mut reader = CaptureReader::new(source)?;
        let packet = reader.next_packet()?.ok_or("fragmented packet missing")?;
        assert_eq!(
            packet.bytes(),
            capture.get(40..).ok_or("fixture payload missing")?
        );
        assert_eq!(
            packet
                .metadata()
                .timestamp()
                .map(l2_pcap::CaptureTimestamp::ticks),
            Some(1_000_000)
        );
        assert_eq!(packet.metadata().original_len(), 41);
        assert!(reader.next_packet()?.is_none());
    }
    Ok(())
}
