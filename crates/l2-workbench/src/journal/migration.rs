use super::{Journal, JournalOptions, Result, checks, invalid, paths};
use rusqlite::{Connection, MAIN_DB, OpenFlags};
use sha2::Digest;
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::Path,
};

const IO_BUFFER_BYTES: usize = 64 * 1024;

impl Journal {
    /// Copy a version 1 or 2 journal into a caller-managed empty staging directory
    ///
    /// The source remains read-only. The staged database is upgraded and fully
    /// verified before this method succeeds.
    ///
    /// # Errors
    /// Rejects nonempty staging directories, unsupported sources, invalid records or storage failures
    pub fn migrate_copy(
        source_path: &Path,
        staging_path: &Path,
        options: JournalOptions,
    ) -> Result<()> {
        super::validate_options(options)?;
        let source_directory = paths::Directory::open(source_path)?;
        let staging_directory = paths::Directory::open(staging_path)?;
        if fs::read_dir(staging_path)?.next().is_some() {
            return Err(invalid("journal migration staging directory must be empty"));
        }
        let source_database_path = source_directory.path().join("journal.sqlite");
        paths::regular(&source_database_path)?;
        let source_database = Connection::open_with_flags(
            fs::canonicalize(source_database_path)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        let app: u32 =
            source_database.pragma_query_value(None, "application_id", |row| row.get(0))?;
        let version: u32 =
            source_database.pragma_query_value(None, "user_version", |row| row.get(0))?;
        if app != super::APPLICATION_ID || !matches!(version, 1 | 2) {
            return Err(invalid("migration requires a version 1 or 2 journal"));
        }
        let base_hash = super::base_case_sha256(&source_database)?;

        copy_base_case(&source_directory, &staging_directory, &base_hash)?;
        let staged_database_path = staging_directory.path().join("journal.sqlite");
        source_database.backup(MAIN_DB, &staged_database_path, None)?;
        drop(source_database);

        let staged_database = Connection::open_with_flags(
            fs::canonicalize(staged_database_path)?,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        super::configure(&staged_database, options)?;
        migrate_schema(&staged_database, version, options.max_entry_bytes)?;
        staged_database.pragma_update(None, "user_version", super::VERSION)?;
        drop(staged_database);

        let migrated = Self::open_readonly(staging_path, options)?;
        migrated.verify()?;
        staging_directory.sync()?;
        Ok(())
    }
}

fn copy_base_case(
    source: &paths::Directory,
    staging: &paths::Directory,
    expected_hash: &str,
) -> Result<()> {
    let mut input = paths::regular(&source.path().join("base-case.json"))?;
    let mut output = File::create_new(staging.path().join("base-case.json"))?;
    let mut digest = sha2::Sha256::new();
    let mut buffer = vec![0_u8; IO_BUFFER_BYTES].into_boxed_slice();
    let mut length = 0_u64;
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        let bytes = buffer
            .get(..count)
            .ok_or_else(|| invalid("base case reader returned an invalid byte count"))?;
        length = length
            .checked_add(u64::try_from(count)?)
            .ok_or_else(|| invalid("base case length exceeds the supported range"))?;
        if length > u64::try_from(crate::evidence::MAX_CASE_JSON_BYTES)? {
            return Err(invalid("retained base case exceeds its byte limit"));
        }
        digest.update(bytes);
        output.write_all(bytes)?;
    }
    output.sync_all()?;
    if format!("{:x}", digest.finalize()) != expected_hash {
        return Err(invalid("base case changed before journal migration"));
    }
    Ok(())
}

fn migrate_schema(connection: &Connection, version: u32, budget: usize) -> Result<()> {
    let transaction = connection.unchecked_transaction()?;
    transaction.execute_batch(
        "ALTER TABLE checks RENAME TO checks_before_migration;
         CREATE TABLE checks(
             id INTEGER PRIMARY KEY CHECK(id>0),
             hypothesis TEXT NOT NULL REFERENCES hypotheses(id),
             identity TEXT NOT NULL,
             value TEXT NOT NULL,
             evidence TEXT NOT NULL REFERENCES objects(sha256),
             binding_origin TEXT NOT NULL CHECK(binding_origin IN ('recorded','legacy_unverified'))
         ) STRICT;",
    )?;
    if version == 1 {
        migrate_v1_checks(&transaction, budget)?;
    } else {
        migrate_v2_checks(&transaction, budget)?;
    }
    transaction.execute_batch(
        "DROP TABLE checks_before_migration;
         CREATE INDEX checks_hypothesis_order ON checks(hypothesis,id);
         CREATE TABLE tool_receipts(
             id INTEGER PRIMARY KEY,
             sha256 TEXT UNIQUE NOT NULL REFERENCES objects(sha256),
             tool TEXT NOT NULL,
             version TEXT NOT NULL,
             source_sha256 TEXT NOT NULL,
             schema_version INTEGER NOT NULL
         ) STRICT;
         CREATE TABLE event_receipts(
             event_identity TEXT NOT NULL REFERENCES events(identity),
             receipt_sha256 TEXT NOT NULL REFERENCES tool_receipts(sha256),
             frame INTEGER NOT NULL CHECK(frame>0),
             PRIMARY KEY(event_identity,receipt_sha256)
         ) STRICT;",
    )?;
    transaction.execute(super::CHECK_IDENTITY_INDEX_SQL, [])?;
    transaction.pragma_update(None, "user_version", super::VERSION)?;
    transaction.commit()?;
    Ok(())
}

fn migrate_v1_checks(transaction: &rusqlite::Transaction<'_>, budget: usize) -> Result<()> {
    {
        let mut statement = transaction.prepare(
            "SELECT id,length(CAST(hypothesis AS BLOB)),hypothesis,length(CAST(value AS BLOB)),value,length(CAST(evidence AS BLOB)),evidence FROM checks_before_migration ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: u64 = row.get(0)?;
            let hypothesis = super::required_sha256(row, 1, 2, "legacy check hypothesis")?;
            let value_length: u64 = row.get(3)?;
            if value_length > u64::try_from(budget)? {
                return Err(invalid(
                    "legacy check exceeds the migration metadata budget",
                ));
            }
            let value: String = row.get(4)?;
            let evidence = super::required_sha256(row, 5, 6, "legacy check evidence")?;
            let identity = checks::identity(&hypothesis, value.as_bytes(), &evidence)?;
            checks::decode(
                id,
                &hypothesis,
                identity.clone(),
                value.clone(),
                evidence.clone(),
                "legacy_unverified",
            )?;
            transaction.execute(
                "INSERT INTO checks(id,hypothesis,identity,value,evidence,binding_origin) VALUES(?1,?2,?3,?4,?5,'legacy_unverified')",
                rusqlite::params![id, hypothesis, identity, value, evidence],
            )?;
        }
    }
    Ok(())
}

fn migrate_v2_checks(transaction: &rusqlite::Transaction<'_>, budget: usize) -> Result<()> {
    {
        let mut statement = transaction.prepare(
            "SELECT id,length(CAST(hypothesis AS BLOB)),hypothesis,length(CAST(identity AS BLOB)),identity,length(CAST(value AS BLOB)),value,length(CAST(evidence AS BLOB)),evidence FROM checks_before_migration ORDER BY id",
        )?;
        let mut rows = statement.query([])?;
        while let Some(row) = rows.next()? {
            let id: u64 = row.get(0)?;
            let hypothesis = super::required_sha256(row, 1, 2, "legacy check hypothesis")?;
            let identity = super::required_sha256(row, 3, 4, "legacy check identity")?;
            let value_length: u64 = row.get(5)?;
            if value_length > u64::try_from(budget)? {
                return Err(invalid(
                    "legacy check exceeds the migration metadata budget",
                ));
            }
            let value: String = row.get(6)?;
            let evidence = super::required_sha256(row, 7, 8, "legacy check evidence")?;
            checks::decode(
                id,
                &hypothesis,
                identity.clone(),
                value.clone(),
                evidence.clone(),
                "recorded",
            )?;
            transaction.execute(
                "INSERT INTO checks(id,hypothesis,identity,value,evidence,binding_origin) VALUES(?1,?2,?3,?4,?5,'recorded')",
                rusqlite::params![id, hypothesis, identity, value, evidence],
            )?;
        }
    }
    Ok(())
}
