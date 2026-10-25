//! Durable model checks and source-scoped event queries without copying a case per result

mod chain_deadline;
mod chains;
mod checks;
mod derivations;
mod event_reader;
mod events;
mod evidence;
mod external;
mod ledger;
mod migration;
mod model;
mod objects;
mod receipts;
mod tool_receipts;
mod verify;

pub(crate) use events::validate_event;

use crate::{evidence::Case, store::paths};
pub use chain_deadline::ChainDeadline;
pub use model::{
    Chain, ChainPlan, Check, CheckBindingOrigin, CheckKind, CheckOutcome,
    DEFAULT_MAX_TOOL_REPORT_BYTES, DerivationInput, DerivationSummary, Entry, Event, EventJoin,
    EventSelector, Hypothesis, JournalOptions, Overview, RecordedCheck, ToolReceiptSummary,
};
use rusqlite::{Connection, OpenFlags};
use std::{
    cell::Cell,
    error::Error,
    fs::File,
    io::{self, Read, Write},
    path::Path,
};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;
const APPLICATION_ID: u32 = 0x4c32_4a52;
const VERSION: u32 = 3;
pub(super) const CHECK_IDENTITY_INDEX_SQL: &str =
    "CREATE INDEX IF NOT EXISTS checks_identity_order ON checks(identity,id)";
/// One immutable base case and a transactional, append-only investigation database
pub struct Journal {
    connection: Connection,
    directory: paths::Directory,
    options: JournalOptions,
    chain_query_active: Cell<bool>,
}
impl Journal {
    /// Save the base case once inside a caller-managed staging directory
    ///
    /// # Errors
    /// Rejects existing files, invalid budgets and unavailable storage
    /// The CLI publishes the staging directory atomically after success
    pub fn create(path: &Path, case: &Case, options: JournalOptions) -> Result<Self> {
        validate_options(options)?;
        let directory = paths::Directory::open(path)?;
        let bytes = case.to_json()?;
        let base = directory.path().join("base-case.json");
        let mut file = File::create_new(base)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        File::create_new(directory.path().join("journal.sqlite"))?;
        let connection = Connection::open_with_flags(
            std::fs::canonicalize(directory.path().join("journal.sqlite"))?,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure(&connection, options)?;
        connection.pragma_update(None, "application_id", APPLICATION_ID)?;
        connection.pragma_update(None, "user_version", VERSION)?;
        connection.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
          CREATE TABLE metadata(key TEXT PRIMARY KEY,value TEXT NOT NULL) STRICT;
          CREATE TABLE objects(sha256 TEXT PRIMARY KEY,bytes BLOB NOT NULL) STRICT;
          CREATE TABLE hypotheses(id TEXT PRIMARY KEY,model TEXT NOT NULL,output TEXT REFERENCES objects(sha256),receipt TEXT REFERENCES objects(sha256)) STRICT;
          CREATE TABLE checks(id INTEGER PRIMARY KEY CHECK(id>0),hypothesis TEXT NOT NULL REFERENCES hypotheses(id),identity TEXT NOT NULL,value TEXT NOT NULL,evidence TEXT NOT NULL REFERENCES objects(sha256),binding_origin TEXT NOT NULL CHECK(binding_origin IN ('recorded','legacy_unverified'))) STRICT;
          CREATE INDEX checks_hypothesis_order ON checks(hypothesis,id);
          CREATE TABLE events(id INTEGER PRIMARY KEY,identity TEXT UNIQUE NOT NULL,source TEXT NOT NULL,scope TEXT NOT NULL,packet INTEGER NOT NULL,kind TEXT NOT NULL,actor TEXT,peer TEXT,value TEXT NOT NULL) STRICT;
          CREATE INDEX events_scope_order ON events(source,scope,packet);
          CREATE INDEX events_kind_actor_order ON events(kind,actor,source,scope,packet);
          CREATE TABLE tool_receipts(id INTEGER PRIMARY KEY,sha256 TEXT UNIQUE NOT NULL REFERENCES objects(sha256),tool TEXT NOT NULL,version TEXT NOT NULL,source_sha256 TEXT NOT NULL,schema_version INTEGER NOT NULL) STRICT;
          CREATE TABLE event_receipts(event_identity TEXT NOT NULL REFERENCES events(identity),receipt_sha256 TEXT NOT NULL REFERENCES tool_receipts(sha256),frame INTEGER NOT NULL CHECK(frame>0),PRIMARY KEY(event_identity,receipt_sha256)) STRICT;")?;
        ensure_check_identity_index(&connection)?;
        connection.execute(
            "INSERT INTO metadata VALUES('base_case_sha256',?1)",
            [crate::sha256(&bytes)],
        )?;
        directory.sync()?;
        Ok(Self {
            connection,
            directory,
            options,
            chain_query_active: Cell::new(false),
        })
    }
    /// Open an existing investigation without replacing its base evidence
    ///
    /// # Errors
    /// Rejects unsupported databases, invalid budgets and storage errors
    pub fn open(path: &Path, options: JournalOptions) -> Result<Self> {
        validate_options(options)?;
        let directory = paths::Directory::open(path)?;
        let path = directory.path().join("journal.sqlite");
        paths::regular(&path)?;
        let connection = Connection::open_with_flags(
            std::fs::canonicalize(path)?,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure(&connection, options)?;
        let app: u32 = connection.pragma_query_value(None, "application_id", |r| r.get(0))?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |r| r.get(0))?;
        if app != APPLICATION_ID || version != VERSION {
            return Err(invalid("unsupported investigation journal"));
        }
        // Version 3 predates this performance-only index, so writable opens repair it in place
        ensure_check_identity_index(&connection)?;
        Ok(Self {
            connection,
            directory,
            options,
            chain_query_active: Cell::new(false),
        })
    }
    /// Open an existing investigation using a read-only `SQLite` connection
    ///
    /// # Errors
    /// Rejects unsupported databases, invalid budgets and storage errors
    pub fn open_readonly(path: &Path, options: JournalOptions) -> Result<Self> {
        validate_options(options)?;
        let directory = paths::Directory::open(path)?;
        let path = directory.path().join("journal.sqlite");
        paths::regular(&path)?;
        let connection = Connection::open_with_flags(
            std::fs::canonicalize(path)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        configure_readonly(&connection, options)?;
        let app: u32 = connection.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: u32 = connection.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if app != APPLICATION_ID || version != VERSION {
            return Err(invalid("unsupported investigation journal"));
        }
        Ok(Self {
            connection,
            directory,
            options,
            chain_query_active: Cell::new(false),
        })
    }
    /// Recheck the retained case hash before using its node identifiers
    ///
    /// # Errors
    /// Rejects changed, malformed or missing base evidence
    pub fn base_case(&self) -> Result<Case> {
        let expected = self.base_case_sha256()?;
        let mut bytes = Vec::new();
        paths::regular(&self.directory.path().join("base-case.json"))?
            .take(u64::try_from(crate::evidence::MAX_CASE_JSON_BYTES)? + 1)
            .read_to_end(&mut bytes)?;
        if crate::sha256(&bytes) != expected {
            return Err(invalid("base case changed after journal creation"));
        }
        Ok(Case::from_json(&bytes)?)
    }
    /// Summarize durable work without materializing its evidence objects
    ///
    /// # Errors
    /// Rejects malformed or oversized base-case metadata and returns database errors
    pub fn overview(&self) -> Result<Overview> {
        let base_case_sha256 = self.base_case_sha256()?;
        Ok(Overview {
            hypotheses: self
                .connection
                .query_row("SELECT COUNT(*) FROM hypotheses", [], |r| r.get(0))?,
            checks: self
                .connection
                .query_row("SELECT COUNT(*) FROM checks", [], |r| r.get(0))?,
            events: self
                .connection
                .query_row("SELECT COUNT(*) FROM events", [], |r| r.get(0))?,
            tool_receipts: self.connection.query_row(
                "SELECT COUNT(*) FROM tool_receipts",
                [],
                |r| r.get(0),
            )?,
            base_case_sha256,
            limitations: vec![
                "Check kinds and imported event meanings are caller assertions with retained evidence",
                "Passing structural checks does not establish a credential or cryptographic authenticity",
                "Legacy-unverified checks remain in history but do not determine conclusions or review ordering",
                "Check binding origins are stored metadata, not a signature or hostile-tamper guarantee",
                "Event chains establish source-scoped capture ordering, not maliciousness or causation",
            ],
        })
    }
    /// Read several journal views from one `SQLite` snapshot
    ///
    /// Nested calls reuse an active snapshot on the same connection
    ///
    /// # Errors
    /// Returns visitor, verification, or storage errors
    pub fn read_snapshot<T>(&self, visitor: impl FnOnce(&Self) -> Result<T>) -> Result<T> {
        let snapshot = self
            .connection
            .is_autocommit()
            .then(|| self.connection.unchecked_transaction())
            .transpose()?;
        let result = visitor(self);
        match (snapshot, result) {
            (Some(snapshot), Ok(value)) => {
                snapshot.commit()?;
                Ok(value)
            }
            (Some(_) | None, Err(error)) => Err(error),
            (None, Ok(value)) => Ok(value),
        }
    }
    fn encoded(&self, value: &impl serde::Serialize) -> Result<Vec<u8>> {
        encode_metadata(value, self.options.max_entry_bytes)
    }

    fn base_case_sha256(&self) -> Result<String> {
        base_case_sha256(&self.connection)
    }
}
fn ensure_check_identity_index(connection: &Connection) -> Result<()> {
    connection.execute(CHECK_IDENTITY_INDEX_SQL, [])?;
    Ok(())
}
fn require_sqlite_json(connection: &Connection) -> Result<()> {
    const EXPECTED: &str = "18446744073709551615";
    let observed = connection.query_row(
        "SELECT '{\"value\":18446744073709551615}' -> '$.value'",
        [],
        |row| row.get::<_, String>(0),
    );
    match observed {
        Ok(value) if value == EXPECTED => Ok(()),
        Ok(value) => Err(invalid(format!(
            "SQLite returned an incompatible JSON value {value:?}; SQLite 3.38.0 or newer with JSON support is required"
        ))),
        Err(error) => Err(invalid(format!(
            "SQLite 3.38.0 or newer with JSON support is required: {error}"
        ))),
    }
}
fn configure(connection: &Connection, options: JournalOptions) -> Result<()> {
    require_sqlite_json(connection)?;
    connection.pragma_update(None, "cache_size", -i64::from(options.cache_mib) * 1024)?;
    let effective: i64 = connection.pragma_query_value(None, "cache_size", |row| row.get(0))?;
    if effective != -i64::from(options.cache_mib) * 1024 {
        return Err(invalid(
            "requested cache budget exceeds SQLite's representable cache setting",
        ));
    }
    connection.execute_batch("PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=FILE; PRAGMA mmap_size=0;")?;
    Ok(())
}
fn configure_readonly(connection: &Connection, options: JournalOptions) -> Result<()> {
    require_sqlite_json(connection)?;
    connection.pragma_update(None, "cache_size", -i64::from(options.cache_mib) * 1024)?;
    connection.execute_batch(
        "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF; PRAGMA temp_store=FILE; PRAGMA mmap_size=0; PRAGMA query_only=ON;",
    )?;
    Ok(())
}
fn validate_options(options: JournalOptions) -> Result<()> {
    if options.cache_mib == 0 || options.max_entry_bytes == 0 || options.max_tool_report_bytes == 0
    {
        return Err(invalid("journal budgets must be nonzero"));
    }
    Ok(())
}
fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}

pub(super) fn bounded_text(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    maximum: usize,
    description: &str,
) -> Result<String> {
    // Check SQLite's byte count before row.get allocates the stored text
    let length: u64 = row.get(length_column)?;
    if length > u64::try_from(maximum)? {
        return Err(invalid(format!(
            "{description} exceeds configured metadata reader budget"
        )));
    }
    Ok(row.get(value_column)?)
}

pub(super) fn required_sha256(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    description: &str,
) -> Result<String> {
    // A length mismatch is rejected before SQLite materializes attacker-controlled text
    let length: u64 = row.get(length_column)?;
    if length != 64 {
        return Err(invalid(format!(
            "{description} must be a 64-character SHA-256 hash"
        )));
    }
    let digest: String = row.get(value_column)?;
    if !crate::hashing::is_sha256_digest(&digest) {
        return Err(invalid(format!(
            "{description} must be a 64-character SHA-256 hash"
        )));
    }
    Ok(digest)
}

pub(super) fn optional_sha256(
    row: &rusqlite::Row<'_>,
    length_column: usize,
    value_column: usize,
    description: &str,
) -> Result<Option<String>> {
    let length: Option<u64> = row.get(length_column)?;
    match length {
        None => Ok(None),
        Some(64) => required_sha256(row, length_column, value_column, description).map(Some),
        Some(_) => Err(invalid(format!(
            "{description} must be a 64-character SHA-256 hash"
        ))),
    }
}

pub(super) fn base_case_sha256(connection: &Connection) -> Result<String> {
    let mut statement = connection.prepare(
        "SELECT length(CAST(value AS BLOB)),value FROM metadata WHERE key='base_case_sha256'",
    )?;
    let mut rows = statement.query([])?;
    let row = rows.next()?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
    // Fixed-size identities use their format invariant, independent of variable metadata budgets
    required_sha256(row, 0, 1, "base-case metadata")
}

fn encode_metadata(value: &impl serde::Serialize, maximum: usize) -> Result<Vec<u8>> {
    let mut counter = crate::serialization::CountWriter::new(maximum);
    serde_json::to_writer(&mut counter, value).map_err(|e| {
        invalid(format!(
            "metadata exceeds configured entry budget or cannot serialize: {e}"
        ))
    })?;
    Ok(serde_json::to_vec(value)?)
}
