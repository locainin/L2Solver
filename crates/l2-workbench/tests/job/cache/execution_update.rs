use super::{cache_at, execution::limits, stage_key};
use l2_workbench::job::{
    Counter, Job, JobSnapshot,
    cache::{Cache, CacheError, ExecutionGeneration, Lease},
};
use serde_json::{Value, json};
use std::{error::Error, fs, io, path::PathBuf};

struct Fixture {
    temporary: tempfile::TempDir,
    cache: Cache,
    lease: Lease,
    generation: ExecutionGeneration,
    job: Job,
    initial_snapshot: JobSnapshot,
}

impl Fixture {
    fn new(memory: Option<&l2_workbench::job::MemoryBudget>) -> Result<Self, Box<dyn Error>> {
        let temporary = tempfile::tempdir()?;
        let cache = cache_at(temporary.path(), 64 * 1024)?;
        if let Some(memory) = memory {
            cache.attach_memory_budget(memory.clone())?;
        }
        let key = stage_key("executor-update")?;
        let job = Job::new("executor update");
        let initial_snapshot = job.snapshot()?;
        let mut lease = cache.lease(&key)?;
        let generation = lease.save_active_generation(&initial_snapshot, limits(), |writer| {
            let (graph, blobs, executor) = writer.streams();
            graph.write_all(b"original graph")?;
            blobs.write_all(b"original blobs")?;
            executor.write_all(b"cursor-zero")?;
            Ok(json!({"cursor":0}))
        })?;
        Ok(Self {
            temporary,
            cache,
            lease,
            generation,
            job,
            initial_snapshot,
        })
    }

    fn directory(&self) -> Result<PathBuf, Box<dyn Error>> {
        let database =
            rusqlite::Connection::open(self.temporary.path().join("state/cache.sqlite3"))?;
        let relative: String =
            database.query_row("SELECT relative_path FROM executions", [], |row| row.get(0))?;
        Ok(self.temporary.path().join("cache/entries").join(relative))
    }

    fn assert_current(
        &self,
        cursor: &[u8],
        metadata: &Value,
        snapshot: &JobSnapshot,
    ) -> Result<(), Box<dyn Error>> {
        let mut active = self
            .lease
            .load_active(limits())?
            .ok_or("checkpoint was lost")?;
        assert_eq!(active.generation(), &self.generation);
        assert_eq!(active.snapshot(), snapshot);
        assert_eq!(active.metadata(), metadata);
        let (graph, blobs, executor) = active.streams();
        for (reader, expected) in [
            (graph, b"original graph".as_slice()),
            (blobs, b"original blobs".as_slice()),
            (executor, cursor),
        ] {
            let mut bytes = Vec::new();
            reader.read_to_end(&mut bytes)?;
            assert_eq!(bytes, expected);
        }
        Ok(())
    }
}

#[test]
fn executor_updates_preserve_case_files_and_commit_matching_progress() -> Result<(), Box<dyn Error>>
{
    let mut fixture = Fixture::new(None)?;
    let directory = fixture.directory()?;
    let originals = [
        fs::metadata(directory.join("graph"))?,
        fs::metadata(directory.join("blobs"))?,
    ];
    for count in [7, 23] {
        fixture.job.increment(Counter::CandidatesExamined, count)?;
        let snapshot = fixture.job.snapshot()?;
        let cursor = format!("cursor-{count}");
        let metadata = json!({"cursor":count});
        fixture.lease.update_active_executor(
            &mut fixture.generation,
            &snapshot,
            limits(),
            |writer| {
                writer.write_all(cursor.as_bytes())?;
                Ok(&metadata)
            },
        )?;
        fixture.assert_current(cursor.as_bytes(), &metadata, &snapshot)?;
        for (name, before) in ["graph", "blobs"].into_iter().zip(&originals) {
            let after = fs::metadata(directory.join(name))?;
            assert_eq!(after.modified()?, before.modified()?);
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                assert_eq!(after.dev(), before.dev());
                assert_eq!(after.ino(), before.ino());
                assert_eq!(after.ctime_nsec(), before.ctime_nsec());
            }
        }
        let mut physical = 0_u64;
        for item in fs::read_dir(&directory)? {
            let item = item?;
            let metadata = item.metadata()?;
            physical += if metadata.is_file() {
                metadata.len()
            } else {
                assert_eq!(fs::read_dir(item.path())?.count(), 1);
                fs::metadata(item.path().join("executor"))?.len()
            };
        }
        let database =
            rusqlite::Connection::open(fixture.temporary.path().join("state/cache.sqlite3"))?;
        let envelope: u64 = database.query_row(
            "SELECT length(CAST(envelope_json AS BLOB)) FROM executions",
            [],
            |row| row.get(0),
        )?;
        assert_eq!(fixture.cache.stats()?.entry_bytes, physical + envelope);
        assert_eq!(
            fs::read_dir(&directory)?.count(),
            3,
            "displaced cursor files were retained"
        );
    }
    Ok(())
}

#[test]
fn interrupted_or_oversized_executor_update_keeps_the_prior_checkpoint()
-> Result<(), Box<dyn Error>> {
    for oversized in [false, true] {
        let mut fixture = Fixture::new(None)?;
        let snapshot = fixture.initial_snapshot.clone();
        let usage = fixture.cache.stats()?.entry_bytes;
        let result = fixture.lease.update_active_executor(
            &mut fixture.generation,
            &snapshot,
            limits(),
            |writer| {
                if oversized {
                    // Ignoring a failed write must never turn an incomplete cursor into success
                    let _ = writer.write_all(&[0; 1025]);
                    Ok(json!({"cursor":1}))
                } else {
                    writer.write_all(b"interrupted cursor")?;
                    Err(io::Error::other("injected interrupted writer").into())
                }
            },
        );
        assert!(result.is_err());
        if oversized {
            assert!(matches!(result, Err(CacheError::QuotaExceeded { .. })));
        }
        fixture.assert_current(b"cursor-zero", &json!({"cursor":0}), &snapshot)?;
        assert_eq!(fixture.cache.stats()?.entry_bytes, usage);
    }
    Ok(())
}

#[test]
fn failed_executor_database_commit_preserves_case_cursor_and_snapshot() -> Result<(), Box<dyn Error>>
{
    let mut fixture = Fixture::new(None)?;
    let snapshot = fixture.initial_snapshot.clone();
    let database =
        rusqlite::Connection::open(fixture.temporary.path().join("state/cache.sqlite3"))?;
    database.execute_batch("CREATE TRIGGER reject_cursor BEFORE UPDATE ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")?;
    fixture.job.increment(Counter::CandidatesExamined, 11)?;
    assert!(
        fixture
            .lease
            .update_active_executor(
                &mut fixture.generation,
                &fixture.job.snapshot()?,
                limits(),
                |writer| {
                    writer.write_all(b"uncommitted cursor")?;
                    Ok(json!({"cursor":11}))
                }
            )
            .is_err()
    );
    fixture.assert_current(b"cursor-zero", &json!({"cursor":0}), &snapshot)?;
    database.execute_batch("DROP TRIGGER reject_cursor;")?;
    // Reopening the lease reclaims an ambiguous failed commit without removing the live files
    let key = stage_key("executor-update")?;
    drop(fixture.lease);
    fixture.lease = fixture.cache.lease(&key)?;
    fixture.assert_current(b"cursor-zero", &json!({"cursor":0}), &snapshot)?;
    Ok(())
}

#[test]
fn stale_executor_generation_is_rejected_before_starting_the_writer() -> Result<(), Box<dyn Error>>
{
    let mut fixture = Fixture::new(None)?;
    let mut stale = fixture.generation.clone();
    let snapshot = fixture.job.snapshot()?;
    fixture.lease.update_active_metadata(
        &mut fixture.generation,
        &snapshot,
        limits(),
        &json!({"cursor":0,"revision":1}),
    )?;
    let called = std::cell::Cell::new(false);
    assert!(
        fixture
            .lease
            .update_active_executor(&mut stale, &snapshot, limits(), |_| {
                called.set(true);
                Ok(json!({"cursor":1}))
            })
            .is_err()
    );
    assert!(!called.get());
    fixture.assert_current(b"cursor-zero", &json!({"cursor":0,"revision":1}), &snapshot)?;
    Ok(())
}

#[test]
fn executor_update_requires_memory_admission_before_calling_the_writer()
-> Result<(), Box<dyn Error>> {
    let memory = l2_workbench::job::MemoryBudget::new(64 * 1024 * 1024);
    let mut fixture = Fixture::new(Some(&memory))?;
    let before = memory.snapshot()?;
    let blocker = memory.try_reserve(
        l2_workbench::job::MemoryClass::Executor,
        before.limit_bytes - before.used_bytes - 1,
    )?;
    let called = std::cell::Cell::new(false);
    let result = fixture.lease.update_active_executor(
        &mut fixture.generation,
        &fixture.initial_snapshot,
        limits(),
        |_| {
            called.set(true);
            Ok(json!({"cursor":1}))
        },
    );
    assert!(matches!(result, Err(CacheError::Memory(_))));
    assert!(!called.get());
    drop(blocker);
    assert_eq!(memory.snapshot()?.used_bytes, before.used_bytes);
    drop(fixture.lease);
    fixture.cache = cache_at(fixture.temporary.path(), 64 * 1024)?;
    fixture.lease = fixture.cache.lease(&stage_key("executor-update")?)?;
    fixture.assert_current(
        b"cursor-zero",
        &json!({"cursor":0}),
        &fixture.initial_snapshot.clone(),
    )?;
    Ok(())
}

#[test]
fn aggregate_cache_quota_failure_keeps_the_committed_executor() -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new(None)?;
    let usage = fixture.cache.stats()?.entry_bytes;
    drop(fixture.lease);
    fixture.cache = cache_at(fixture.temporary.path(), usage + 1)?;
    fixture.lease = fixture.cache.lease(&stage_key("executor-update")?)?;
    let result = fixture.lease.update_active_executor(
        &mut fixture.generation,
        &fixture.initial_snapshot,
        limits(),
        |writer| {
            writer.write_all(b"new cursor cannot fit")?;
            Ok(json!({"cursor":1}))
        },
    );
    assert!(matches!(result, Err(CacheError::QuotaExceeded { .. })));
    fixture.assert_current(
        b"cursor-zero",
        &json!({"cursor":0}),
        &fixture.initial_snapshot.clone(),
    )?;
    assert_eq!(fixture.cache.stats()?.entry_bytes, usage);
    Ok(())
}

#[test]
fn legacy_execution_envelopes_can_update_without_replacing_the_case() -> Result<(), Box<dyn Error>>
{
    for version in [1, 2] {
        let mut fixture = Fixture::new(None)?;
        let database =
            rusqlite::Connection::open(fixture.temporary.path().join("state/cache.sqlite3"))?;
        let encoded: String =
            database.query_row("SELECT envelope_json FROM executions", [], |row| row.get(0))?;
        let mut envelope: Value = serde_json::from_str(&encoded)?;
        *envelope
            .get_mut("version")
            .ok_or("missing envelope version")? = json!(version);
        if version == 1 {
            envelope
                .as_object_mut()
                .ok_or("missing envelope object")?
                .remove("revision");
        }
        let migrated = serde_json::to_string(&envelope)?;
        let delta = i64::try_from(migrated.len())? - i64::try_from(encoded.len())?;
        database.execute(
            "UPDATE executions SET envelope_json = ?1, bytes = bytes + ?2",
            rusqlite::params![migrated, delta],
        )?;
        // The verified reader supplies an identity for the actual older representation
        let active = fixture
            .lease
            .load_active(limits())?
            .ok_or("legacy checkpoint was lost")?;
        fixture.generation = active.generation().clone();
        drop(active);
        fixture.lease.update_active_executor(
            &mut fixture.generation,
            &fixture.initial_snapshot,
            limits(),
            |writer| {
                writer.write_all(b"new cursor")?;
                Ok(json!({"cursor":1}))
            },
        )?;
        fixture.assert_current(
            b"new cursor",
            &json!({"cursor":1}),
            &fixture.initial_snapshot.clone(),
        )?;
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn symlinked_cursor_debris_cannot_escape_the_owned_cache() -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new(None)?;
    let unrelated = tempfile::tempdir()?;
    fs::write(unrelated.path().join("executor"), b"unrelated bytes")?;
    std::os::unix::fs::symlink(unrelated.path(), fixture.directory()?.join("cursor-rogue"))?;
    let called = std::cell::Cell::new(false);
    assert!(
        fixture
            .lease
            .update_active_executor(
                &mut fixture.generation,
                &fixture.initial_snapshot,
                limits(),
                |_| {
                    called.set(true);
                    Ok(json!({"cursor":1}))
                }
            )
            .is_err()
    );
    assert!(!called.get());
    assert_eq!(
        fs::read(unrelated.path().join("executor"))?,
        b"unrelated bytes"
    );
    fixture.assert_current(
        b"cursor-zero",
        &json!({"cursor":0}),
        &fixture.initial_snapshot.clone(),
    )?;
    Ok(())
}

#[cfg(target_os = "linux")]
#[path = "execution_update/crash.rs"]
mod crash;

#[path = "execution_update/corruption.rs"]
mod corruption;

#[cfg(target_os = "linux")]
#[path = "execution_update/cleanup_limits.rs"]
mod cleanup_limits;

#[cfg(unix)]
#[path = "execution_update/accounting.rs"]
mod accounting;
