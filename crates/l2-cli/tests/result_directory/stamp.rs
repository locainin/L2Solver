use super::OutputHasher;
use l2_workbench::job::{Counter, Job};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::{self, Seek, Write},
};

#[cfg(target_os = "linux")]
#[test]
fn reuse_checks_output_permissions_in_both_modes() -> Result<(), Box<dyn Error>> {
    use std::{fs, os::unix::fs::PermissionsExt};

    for mode in [0o600, 0o644, 0o664, 0o646] {
        let root = tempfile::tempdir()?;
        let path = root.path().join("output.txt");
        fs::write(&path, b"content")?;
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
        let metadata = fs::File::open(&path)?.metadata()?;
        let digest = format!("{:x}", Sha256::digest(b"content"));
        let stamp = super::metadata_stamp("output.txt".into(), Some(digest), &metadata);
        let prepared = crate::publish::prepare_directory_replacement(root.path())?;

        for strict in [false, true] {
            let job = Job::new("reuse");
            let result = stamp.verify(&prepared, strict, &mut OutputHasher::new(&job));
            if mode & 0o022 == 0 {
                result?;
            } else {
                let error = result.err().ok_or("unsafe output was reused")?;
                assert_eq!(
                    error.kind(),
                    io::ErrorKind::PermissionDenied,
                    "mode={mode:o}, strict={strict}: {error}"
                );
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn reuse_rejects_metadata_change_during_hashing() -> Result<(), Box<dyn Error>> {
    use std::{fs, time::SystemTime};

    for strict in [false, true] {
        let root = tempfile::tempdir()?;
        let path = root.path().join("output.txt");
        fs::write(&path, b"content")?;
        let metadata = fs::File::open(&path)?.metadata()?;
        let digest = format!("{:x}", Sha256::digest(b"content"));
        let stamp = super::metadata_stamp("output.txt".into(), Some(digest), &metadata);
        let prepared = crate::publish::prepare_directory_replacement(root.path())?;
        let job = Job::new("reuse");
        let mut hasher = OutputHasher::new(&job);
        hasher.after_hash =
            Some(|file| file.set_times(fs::FileTimes::new().set_modified(SystemTime::UNIX_EPOCH)));

        let error = stamp
            .verify(&prepared, strict, &mut hasher)
            .err()
            .ok_or("reuse accepted changed file metadata")?;
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("changed after publication"));
        assert_ne!(fs::metadata(&path)?.modified()?, metadata.modified()?);
        assert_eq!(fs::read(path)?, b"content");
    }
    Ok(())
}

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
