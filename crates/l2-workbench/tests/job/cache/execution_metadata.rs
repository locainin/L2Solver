use super::{cache_at, execution::limits, stage_key};
use l2_workbench::job::{Counter, Job, MemoryBudget, MemoryError, cache::CacheError};
use serde_json::json;
use std::error::Error;

#[test]
fn typed_borrowed_metadata_is_written_and_updated_without_a_json_value()
-> Result<(), Box<dyn Error>> {
    #[derive(serde::Serialize)]
    struct Cursor<'a> {
        candidates: usize,
        cohort: &'a str,
    }

    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("typed-metadata")?;
    let snapshot = Job::new("typed metadata").snapshot()?;
    let mut lease = cache.lease(&key)?;
    let first = Cursor {
        candidates: 3,
        cohort: "frozen cohort",
    };
    let mut generation = lease.save_active_generation(&snapshot, limits(), |_| Ok(&first))?;
    lease.update_active_metadata(
        &mut generation,
        &snapshot,
        limits(),
        &Cursor {
            candidates: 7,
            cohort: "frozen cohort",
        },
    )?;
    let active = lease.load_active(limits())?.ok_or("missing generation")?;
    assert_eq!(active.generation(), &generation);
    assert_eq!(
        active.metadata(),
        &json!({"candidates": 7, "cohort": "frozen cohort"})
    );
    Ok(())
}

#[test]
fn changing_serialized_metadata_cannot_break_the_admitted_size() -> Result<(), Box<dyn Error>> {
    struct Changing<'a> {
        calls: std::cell::Cell<usize>,
        larger: &'a str,
        large_first: bool,
    }

    impl serde::Serialize for Changing<'_> {
        fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
            let calls = self.calls.get();
            self.calls.set(calls + 1);
            serializer.serialize_str(if (calls == 0) == self.large_first {
                self.larger
            } else {
                "small"
            })
        }
    }

    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    cache.attach_memory_budget(MemoryBudget::new(64 * 1024 * 1024))?;
    let key = stage_key("changing-typed-metadata")?;
    let snapshot = Job::new("changing typed metadata").snapshot()?;
    let mut lease = cache.lease(&key)?;
    let mut generation =
        lease.save_active_generation(&snapshot, limits(), |_| Ok(json!({"cursor": 1})))?;
    let larger = "x".repeat(4_096);
    for large_first in [false, true] {
        let changing = Changing {
            calls: std::cell::Cell::new(0),
            larger: &larger,
            large_first,
        };
        assert!(
            lease
                .update_active_metadata(&mut generation, &snapshot, limits(), &changing)
                .is_err()
        );
        let active = lease
            .load_active(limits())?
            .ok_or("prior generation was lost")?;
        assert_eq!(active.metadata(), &json!({"cursor": 1}));
        drop(active);

        let changing = Changing {
            calls: std::cell::Cell::new(0),
            larger: &larger,
            large_first,
        };
        assert!(
            lease
                .save_active_generation(&snapshot, limits(), |_| Ok(changing))
                .is_err()
        );
        let active = lease
            .load_active(limits())?
            .ok_or("prior generation was lost")?;
        assert_eq!(active.metadata(), &json!({"cursor": 1}));
    }
    Ok(())
}

#[test]
fn saving_a_generation_returns_the_same_identity_as_a_verified_load() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("metadata-saved-identity")?;
    let snapshot = Job::new("metadata saved identity").snapshot()?;
    let mut lease = cache.lease(&key)?;
    let generation = lease.save_active_generation(&snapshot, limits(), |writer| {
        let (graph, blobs, executor) = writer.streams();
        graph.write_all(b"graph")?;
        blobs.write_all(b"blob bytes")?;
        executor.write_all(b"queued executor")?;
        Ok(json!({"cursor": 0}))
    })?;
    let active = lease.load_active(limits())?.ok_or("missing generation")?;
    assert_eq!(active.generation(), &generation);
    Ok(())
}

#[test]
fn metadata_update_reuses_case_streams_and_restores_the_matching_snapshot()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("metadata-update")?;
    let job = Job::new("metadata update");
    let mut lease = cache.lease(&key)?;
    lease.save_active(&job.snapshot()?, limits(), |writer| {
        let (graph, blobs, executor) = writer.streams();
        graph.write_all(b"original graph")?;
        blobs.write_all(b"original blobs")?;
        executor.write_all(b"original executor")?;
        Ok(json!({"cursor": 0}))
    })?;
    let active = lease.load_active(limits())?.ok_or("missing generation")?;
    let mut generation = active.generation().clone();
    drop(active);
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let path: String = database.query_row(
        "SELECT relative_path FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    let graph = temporary
        .path()
        .join("cache/entries")
        .join(&path)
        .join("graph");
    let graph_before = std::fs::metadata(&graph)?;
    let old_usage = cache.stats()?.entry_bytes;
    let old_envelope: i64 = database.query_row(
        "SELECT length(CAST(envelope_json AS BLOB)) FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    job.increment(Counter::CandidatesExamined, 23)?;
    let snapshot = job.snapshot()?;
    lease.update_active_metadata(&mut generation, &snapshot, limits(), &json!({"cursor": 23}))?;
    let graph_after = std::fs::metadata(&graph)?;
    assert_eq!(graph_after.modified()?, graph_before.modified()?);
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        assert_eq!(graph_after.ino(), graph_before.ino());
        assert_eq!(graph_after.dev(), graph_before.dev());
    }
    let mut restored = lease.load_active(limits())?.ok_or("missing generation")?;
    assert_eq!(restored.generation(), &generation);
    assert_eq!(restored.snapshot(), &snapshot);
    assert_eq!(restored.metadata(), &json!({"cursor": 23}));
    let mut graph_bytes = Vec::new();
    restored.streams().0.read_to_end(&mut graph_bytes)?;
    assert_eq!(graph_bytes, b"original graph");
    let new_envelope: i64 = database.query_row(
        "SELECT length(CAST(envelope_json AS BLOB)) FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    assert_eq!(
        i128::from(cache.stats()?.entry_bytes) - i128::from(old_usage),
        i128::from(new_envelope - old_envelope)
    );
    Ok(())
}

#[test]
fn memory_admission_failure_preserves_the_existing_metadata() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let key = stage_key("metadata-memory")?;
    let snapshot = Job::new("metadata memory").snapshot()?;
    let producer = cache_at(temporary.path(), 64 * 1024)?;
    let mut writer = producer.lease(&key)?;
    writer.save_active(&snapshot, limits(), |_| Ok(json!({"cursor": 1})))?;
    let active = writer.load_active(limits())?.ok_or("missing generation")?;
    let mut generation = active.generation().clone();
    drop(active);
    drop(writer);
    drop(producer);

    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let mut lease = cache.lease(&key)?;
    let budget = MemoryBudget::new(1);
    cache.attach_memory_budget(budget.clone())?;
    assert!(matches!(
        lease.update_active_metadata(&mut generation, &snapshot, limits(), &json!({"cursor": 2})),
        Err(CacheError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    drop(lease);
    drop(cache);
    let unbudgeted = cache_at(temporary.path(), 64 * 1024)?;
    assert_eq!(
        unbudgeted
            .lease(&key)?
            .load_active(limits())?
            .ok_or("prior generation was lost")?
            .metadata(),
        &json!({"cursor": 1})
    );
    Ok(())
}

#[test]
fn failed_metadata_update_and_stale_generation_preserve_the_committed_state()
-> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("metadata-failure")?;
    let job = Job::new("metadata failure");
    let snapshot = job.snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({"cursor": 1})))?;
    let active = lease.load_active(limits())?.ok_or("missing generation")?;
    let mut generation = active.generation().clone();
    drop(active);
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    // Reject the second row update after the execution row has already changed in the transaction
    database.execute_batch("CREATE TRIGGER reject_metadata BEFORE UPDATE ON checkpoints BEGIN SELECT RAISE(ABORT, 'injected failure'); END;")?;
    job.increment(Counter::CandidatesExamined, 2)?;
    let later = job.snapshot()?;
    assert!(
        lease
            .update_active_metadata(&mut generation, &later, limits(), &json!({"cursor": 2}))
            .is_err()
    );
    let restored = lease.load_active(limits())?.ok_or("missing generation")?;
    assert_eq!(restored.metadata(), &json!({"cursor": 1}));
    assert_eq!(restored.snapshot(), &snapshot);
    drop(restored);
    database.execute_batch("DROP TRIGGER reject_metadata;")?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({"cursor": 3})))?;
    assert!(
        lease
            .update_active_metadata(&mut generation, &snapshot, limits(), &json!({"cursor": 4}))
            .is_err()
    );
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("missing generation")?
            .metadata(),
        &json!({"cursor": 3})
    );
    Ok(())
}

#[test]
fn quota_rejection_keeps_the_previous_metadata_and_usage() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 4_096)?;
    let key = stage_key("metadata-quota")?;
    let snapshot = Job::new("metadata quota").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({"cursor": 1})))?;
    let active = lease.load_active(limits())?.ok_or("missing generation")?;
    let mut generation = active.generation().clone();
    drop(active);
    let old_usage = cache.stats()?.entry_bytes;
    let error = lease
        .update_active_metadata(
            &mut generation,
            &snapshot,
            limits(),
            &json!({"cursor": "x".repeat(5_000)}),
        )
        .expect_err("metadata must fit the cache quota");
    assert!(matches!(error, CacheError::QuotaExceeded { .. }));
    assert_eq!(cache.stats()?.entry_bytes, old_usage);
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("missing generation")?
            .metadata(),
        &json!({"cursor": 1})
    );
    Ok(())
}

#[test]
fn oversized_metadata_does_not_replace_the_previous_generation() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("metadata-bound")?;
    let snapshot = Job::new("metadata bound").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({"cursor": 1})))?;
    let active = lease.load_active(limits())?.ok_or("missing generation")?;
    let mut generation = active.generation().clone();
    drop(active);
    let old_usage = cache.stats()?.entry_bytes;
    let oversized = json!({"cursor": "x".repeat(10_000)});
    assert!(
        lease
            .update_active_metadata(&mut generation, &snapshot, limits(), &oversized)
            .is_err()
    );
    assert_eq!(cache.stats()?.entry_bytes, old_usage);
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("missing generation")?
            .metadata(),
        &json!({"cursor": 1})
    );
    Ok(())
}

#[test]
fn stale_metadata_revision_cannot_overwrite_a_newer_cursor() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("metadata-revision")?;
    let snapshot = Job::new("metadata revision").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({"cursor": 1})))?;
    let active = lease.load_active(limits())?.ok_or("missing generation")?;
    let mut current = active.generation().clone();
    let mut stale = current.clone();
    drop(active);

    lease.update_active_metadata(&mut current, &snapshot, limits(), &json!({"cursor": 2}))?;
    assert!(
        lease
            .update_active_metadata(&mut stale, &snapshot, limits(), &json!({"cursor": 3}))
            .is_err(),
        "a prior metadata revision must not replace a newer cursor"
    );
    lease.update_active_metadata(&mut current, &snapshot, limits(), &json!({"cursor": 4}))?;
    assert_eq!(
        lease
            .load_active(limits())?
            .ok_or("missing generation")?
            .metadata(),
        &json!({"cursor": 4})
    );
    Ok(())
}

#[test]
fn returning_to_the_same_metadata_does_not_revalidate_an_old_revision() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("metadata-revision-repeated-value")?;
    let snapshot = Job::new("metadata revision repeated value").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({"cursor": 1})))?;
    let active = lease.load_active(limits())?.ok_or("missing generation")?;
    let mut current = active.generation().clone();
    let mut stale = current.clone();
    drop(active);

    lease.update_active_metadata(&mut current, &snapshot, limits(), &json!({"cursor": 2}))?;
    lease.update_active_metadata(&mut current, &snapshot, limits(), &json!({"cursor": 1}))?;
    assert!(
        lease
            .update_active_metadata(&mut stale, &snapshot, limits(), &json!({"cursor": 3}))
            .is_err(),
        "an earlier revision must stay invalid even if its contents recur"
    );
    Ok(())
}

#[test]
fn legacy_envelope_is_upgraded_and_rejects_an_inconsistent_revision() -> Result<(), Box<dyn Error>>
{
    let temporary = tempfile::tempdir()?;
    let cache = cache_at(temporary.path(), 64 * 1024)?;
    let key = stage_key("metadata-legacy-envelope")?;
    let snapshot = Job::new("legacy envelope").snapshot()?;
    let mut lease = cache.lease(&key)?;
    lease.save_active(&snapshot, limits(), |_| Ok(json!({"cursor": 1})))?;
    let database = rusqlite::Connection::open(temporary.path().join("state/cache.sqlite3"))?;
    let encoded: String = database.query_row(
        "SELECT envelope_json FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    let mut legacy: serde_json::Value = serde_json::from_str(&encoded)?;
    legacy["version"] = json!(1);
    legacy
        .as_object_mut()
        .ok_or("envelope must be an object")?
        .remove("revision");
    replace_envelope(&database, key.as_str(), &legacy)?;

    let active = lease
        .load_active(limits())?
        .ok_or("missing legacy generation")?;
    let mut generation = active.generation().clone();
    drop(active);
    lease.update_active_metadata(&mut generation, &snapshot, limits(), &json!({"cursor": 2}))?;
    let encoded: String = database.query_row(
        "SELECT envelope_json FROM executions WHERE key = ?1",
        [key.as_str()],
        |row| row.get(0),
    )?;
    let mut upgraded: serde_json::Value = serde_json::from_str(&encoded)?;
    assert_eq!(upgraded["version"], 2);
    assert_eq!(upgraded["revision"], 1);
    upgraded["version"] = json!(1);
    replace_envelope(&database, key.as_str(), &upgraded)?;
    assert!(lease.load_active(limits()).is_err());
    Ok(())
}

fn replace_envelope(
    database: &rusqlite::Connection,
    key: &str,
    envelope: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let encoded = serde_json::to_string(envelope)?;
    database.execute(
        "UPDATE executions SET bytes = bytes - length(CAST(envelope_json AS BLOB)) + length(CAST(?1 AS BLOB)), envelope_json = ?1 WHERE key = ?2",
        (&encoded, key),
    )?;
    Ok(())
}
