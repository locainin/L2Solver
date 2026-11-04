//! Preserve the last cursor when its replacement changes or becomes corrupt

use super::*;
use serde::{Serialize, Serializer, ser::Error as _};
use std::{cell::Cell, path::Path};

#[derive(Clone, Copy)]
enum Change {
    Replace,
    Mutate,
    Truncate,
}

struct ChangingMetadata<'a> {
    directory: &'a Path,
    change: Change,
    changed: Cell<bool>,
}

impl Serialize for ChangingMetadata<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if !self.changed.replace(true) {
            let cursor = cursor_file(self.directory).map_err(S::Error::custom)?;
            match self.change {
                // A new inode with identical bytes must not be accepted as the synced file
                Change::Replace => {
                    fs::remove_file(&cursor).map_err(S::Error::custom)?;
                    fs::write(&cursor, b"new cursor").map_err(S::Error::custom)?;
                }
                // Equal-length content changes must also invalidate the pending file
                Change::Mutate => {
                    fs::write(&cursor, b"bad cursor").map_err(S::Error::custom)?;
                }
                // A short write must not publish a partial replacement
                Change::Truncate => {
                    fs::write(&cursor, b"short").map_err(S::Error::custom)?;
                }
            }
        }
        // Both encoding passes emit identical metadata
        serializer.serialize_u8(7)
    }
}

fn cursor_file(directory: &Path) -> Result<PathBuf, Box<dyn Error>> {
    for item in fs::read_dir(directory)? {
        let item = item?;
        if item.file_name().to_string_lossy().starts_with("cursor-") {
            return Ok(item.path().join("executor"));
        }
    }
    Err("cursor directory is missing".into())
}

#[test]
fn cursor_changed_during_metadata_serialization_cannot_replace_committed_state()
-> Result<(), Box<dyn Error>> {
    for change in [Change::Replace, Change::Mutate, Change::Truncate] {
        let mut fixture = Fixture::new(None)?;
        let directory = fixture.directory()?;
        let metadata = ChangingMetadata {
            directory: &directory,
            change,
            changed: Cell::new(false),
        };
        let result = fixture.lease.update_active_executor(
            &mut fixture.generation,
            &fixture.initial_snapshot,
            limits(),
            |writer| {
                writer.write_all(b"new cursor")?;
                Ok(&metadata)
            },
        );
        assert!(metadata.changed.get());
        assert!(result.is_err(), "a changed cursor was committed");
        fixture.assert_current(
            b"cursor-zero",
            &json!({"cursor":0}),
            &fixture.initial_snapshot,
        )?;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn same_length_current_corruption_keeps_the_displaced_cursor_and_its_charge()
-> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new(None)?;
    let directory = fixture.directory()?;
    let old = directory.join("executor");
    let link = fixture.temporary.path().join("held-cursor");
    // The extra link makes post-commit cleanup retain the old file and its reservation
    fs::hard_link(&old, &link)?;
    fixture.lease.update_active_executor(
        &mut fixture.generation,
        &fixture.initial_snapshot,
        limits(),
        |writer| {
            writer.write_all(b"new cursor")?;
            Ok(json!({"cursor":1}))
        },
    )?;
    assert!(old.exists());
    fs::remove_file(link)?;
    fs::write(cursor_file(&directory)?, b"bad cursor")?;
    let charged = fixture.cache.stats()?.entry_bytes;
    drop(fixture.lease);

    // Maintenance must validate the current bytes before deleting the prior cursor
    assert!(fixture.cache.lease(&stage_key("executor-update")?).is_err());
    assert_eq!(fs::read(old)?, b"cursor-zero");
    assert_eq!(fixture.cache.stats()?.entry_bytes, charged);
    Ok(())
}
