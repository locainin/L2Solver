use l2_workbench::job::{
    MemoryBudget,
    cache::{Cache, Checkpoint, SourceIdentity, StageKey},
};
use rusqlite::{Connection, params};
use std::error::Error;

pub struct Fixture {
    cache: Cache,
    connection: Connection,
    key: StageKey,
    // Keep private cache and state roots alive until their database handles close
    _directory: tempfile::TempDir,
}

impl Fixture {
    pub fn new() -> Result<Self, Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let state = directory.path().join("state");
        let cache = Cache::open_at_with_memory_budget(
            directory.path().join("cache"),
            &state,
            1024 * 1024,
            MemoryBudget::new(16 * 1024 * 1024),
        )?;
        let key = StageKey::new(
            "fuzz_checkpoint",
            1,
            "fuzz_v1",
            &serde_json::json!({}),
            &SourceIdentity::from_sha256(l2_workbench::sha256(b"fuzz"))?,
            &[],
        )?;
        let connection = Connection::open(state.join("cache.sqlite3"))?;
        Ok(Self {
            cache,
            connection,
            key,
            _directory: directory,
        })
    }

    pub fn read(
        &self,
        input: &[u8],
        status: i64,
        version: i64,
    ) -> Result<Option<Checkpoint>, Box<dyn Error>> {
        // SQLite stores a text value, including invalid UTF-8, without interpreting SQL from input
        self.connection.execute(
            "INSERT INTO checkpoints (key,status,snapshot_version,snapshot_json,updated_ns)
             VALUES (?1,?2,?3,CAST(?4 AS TEXT),0)
             ON CONFLICT(key) DO UPDATE SET status=excluded.status,
             snapshot_version=excluded.snapshot_version,snapshot_json=excluded.snapshot_json",
            params![self.key.as_str(), status, version, input],
        )?;
        Ok(self.cache.read_checkpoint(&self.key)?)
    }
}
