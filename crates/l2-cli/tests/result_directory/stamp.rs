use super::OutputHasher;
use l2_workbench::job::{Counter, Job};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::{self, Seek, Write},
};

#[test]
fn output_hash_stops_at_the_captured_length_when_the_file_grows() -> Result<(), Box<dyn Error>> {
    let mut file = tempfile::tempfile()?;
    file.write_all(b"abc-extra")?;
    let job = Job::new("bounded output hash");
    let digest = OutputHasher::new(&job).hash_file(&mut file, 3)?;
    assert_eq!(digest, format!("{:x}", Sha256::digest(b"abc")));
    assert_eq!(file.stream_position()?, 3);
    assert_eq!(job.snapshot()?.counters.get(&Counter::Bytes), Some(&3));
    Ok(())
}

#[test]
fn output_hash_rejects_a_short_file_and_counts_only_bytes_read() -> Result<(), Box<dyn Error>> {
    let mut file = tempfile::tempfile()?;
    file.write_all(b"abc")?;
    let job = Job::new("short output hash");
    let error = OutputHasher::new(&job)
        .hash_file(&mut file, 4)
        .err()
        .ok_or("short output was accepted")?;
    assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    assert_eq!(job.snapshot()?.counters.get(&Counter::Bytes), Some(&3));
    Ok(())
}
