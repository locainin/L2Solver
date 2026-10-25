use l2_io::{LinkIo, ReplayLink};
use std::{
    error::Error,
    io::{self, Cursor, Read},
};

#[test]
fn streaming_replay_default_without_retaining() -> Result<(), Box<dyn Error>> {
    let mut header = 0xa1b2_c3d4_u32.to_le_bytes().to_vec();
    header.extend_from_slice(&[2, 0, 4, 0]);
    header.extend_from_slice(&[0; 8]);
    header.extend_from_slice(&65_535_u32.to_le_bytes());
    header.extend_from_slice(&1_u32.to_le_bytes());
    let records = u64::from(l2_pcap::MAX_RECORD_COUNT) + 1;
    let reader = Cursor::new(header).chain(io::repeat(0).take(records * 16));
    let mut replay = ReplayLink::new(reader)?;
    let mut observed = 0;
    while let Some(frame) = replay.recv()? {
        assert!(frame.bytes().is_empty());
        observed += 1;
    }
    assert_eq!(observed, records);
    Ok(())
}
