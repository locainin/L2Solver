//! Disk-backed capture facts with exact source bytes and capture-order relationships

mod context;
mod dns;
mod flows;
mod ingest;
mod integrity;
mod investigate;
mod ip_pair_cohort;
mod model;
mod packets;
pub(crate) mod paths;
mod schema;
mod scopes;
mod shared;
mod verify;

use crate::job::MemoryBudget;
pub use model::{
    Flow, FlowCohortAnalysis, FlowCohortCoverage, FlowPageAnalysis, FlowPageCoverage,
    FlowPageError, IngestReceipt, Inventory, Options, Packet, Relationship, SharedFactKind,
    SharedGroup, SharedGroupCursor, SharedOccurrence, SharedOccurrenceCursor, SharedWarning,
    Source,
};
use rusqlite::{Connection, OpenFlags};
use std::{
    error::Error,
    fs::{self, File},
    io,
    path::Path,
};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

/// Disk index schema, including cooked capture interpretation and normalized scopes
pub const SCHEMA_VERSION: u32 = 6;

/// One `SQLite` index and content-addressed copies of its original capture sources
pub struct Store {
    connection: Connection,
    directory: paths::Directory,
    sources: paths::Directory,
    memory_budget: Option<MemoryBudget>,
}

impl Store {
    /// Create a fresh index inside an existing output staging directory
    ///
    /// # Errors
    /// Rejects existing index files, invalid options, and storage failures
    pub fn create(directory: &Path, options: Options) -> Result<Self> {
        options.validate()?;
        let directory = paths::Directory::open(directory)?;
        let path = directory.path().join("index.sqlite");
        // Reserve the destination before SQLite opens it, so creation never replaces evidence
        File::create_new(&path)?;
        fs::create_dir(directory.path().join("sources"))?;
        let sources = paths::Directory::open(&directory.path().join("sources"))?;
        // SQLite resolves its pathname for journal files; it needs the checked physical path
        let database_path = fs::canonicalize(&path)?;
        let connection = Connection::open_with_flags(
            &database_path,
            OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        schema::configure(&connection, options)?;
        schema::create(&connection)?;
        Ok(Self {
            connection,
            directory,
            sources,
            memory_budget: None,
        })
    }

    /// Open a published index without write authority
    ///
    /// # Errors
    /// Rejects non-regular indexes, unsupported schemas, older cooked indexes
    /// requiring a rebuild, and storage failures
    pub fn open(directory: &Path, options: Options) -> Result<Self> {
        options.validate()?;
        let directory = paths::Directory::open(directory)?;
        let sources = paths::Directory::open(&directory.path().join("sources"))?;
        let path = directory.path().join("index.sqlite");
        if !fs::symlink_metadata(&path)?.is_file() {
            return Err(invalid("index must be a regular file"));
        }
        let connection = Connection::open_with_flags(
            fs::canonicalize(&path)?,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )?;
        schema::configure(&connection, options)?;
        schema::validate(&connection)?;
        Ok(Self {
            connection,
            directory,
            sources,
            memory_budget: None,
        })
    }

    /// Attach the shared budget used by subsequently constructed evidence Cases
    ///
    /// # Errors
    /// Returns an error if a budget has already been attached to this Store
    pub fn set_memory_budget(&mut self, budget: MemoryBudget) -> Result<()> {
        if self.memory_budget.is_some() {
            return Err(invalid("store memory budget is already set"));
        }
        self.memory_budget = Some(budget);
        Ok(())
    }

    /// Return the budget used for evidence Cases, if one was attached
    #[must_use]
    pub const fn memory_budget(&self) -> Option<&MemoryBudget> {
        self.memory_budget.as_ref()
    }
}

fn invalid(message: impl Into<String>) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidData, message.into()).into()
}
