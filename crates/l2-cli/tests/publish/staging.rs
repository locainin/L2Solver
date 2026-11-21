use super::StagedDirectory;
use std::{ffi::OsStr, fs, io};

#[test]
fn retained_stage_survives_drop() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let parent = fs::File::open(root.path())?.into();
    for retain in [false, true] {
        let mut staging = StagedDirectory::create(&parent, OsStr::new("output"))?;
        let path = root.path().join(&staging.name);
        fs::write(staging.writer_path().join("payload"), b"stage marker")?;
        if retain {
            staging.retain();
        }
        drop(staging);
        if retain {
            assert_eq!(fs::read(path.join("payload"))?, b"stage marker");
        } else {
            assert!(!path.try_exists()?);
        }
    }
    Ok(())
}
