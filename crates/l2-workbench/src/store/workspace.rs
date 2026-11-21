use super::{Result, invalid};
use crate::{job::workspace_capacity, storage::SparseWriter};
use rusqlite::Connection;
#[cfg(target_os = "linux")]
use rusqlite::OptionalExtension;
use std::{
    fs::File,
    io::{self, Write},
};

// SQLite limits rollback-journal sectors to 64 KiB, including header padding
const MAX_SECTOR_BYTES: u64 = 65_536;
const MAX_DATABASE_PAGES: u64 = 4_294_967_294;

pub(super) struct Workspace {
    total: u64,
    page_size: u64,
    journal: u64,
    existing_sources: u64,
}

impl Workspace {
    pub fn new(
        connection: &Connection,
        available: u64,
        existing_sources: u64,
        ceiling: Option<u64>,
    ) -> Result<Self> {
        let mode: String = connection.pragma_query_value(None, "journal_mode", |row| row.get(0))?;
        if mode != "delete" {
            return Err(invalid(
                "capture workspace requires a DELETE rollback journal",
            ));
        }
        let page_size: u64 = connection.pragma_query_value(None, "page_size", |row| row.get(0))?;
        let pages: u64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
        let database = pages
            .checked_mul(page_size)
            .ok_or_else(|| invalid("workspace size overflow"))?;
        let sector = journal_sector(connection)?;
        // A page is journalled at most once; each spill may add a padded header
        let journal = pages
            .checked_mul(page_size + 8 + 2 * sector)
            .and_then(|size| size.checked_add(2 * sector))
            .ok_or_else(|| invalid("workspace journal size overflow"))?;
        let total = database
            .saturating_add(existing_sources)
            .saturating_add(workspace_capacity(available));
        let workspace = Self {
            total: ceiling.map_or(total, |limit| total.min(limit)),
            page_size,
            journal,
            existing_sources,
        };
        workspace.admit(connection, 0)?;
        Ok(workspace)
    }

    fn admit(&self, connection: &Connection, source: u64) -> Result<()> {
        let pages = self
            .total
            .checked_sub(self.journal)
            .and_then(|remaining| remaining.checked_sub(self.existing_sources))
            .and_then(|remaining| remaining.checked_sub(source))
            // One statement journal can retain a copy of each database page
            .map(|remaining| (remaining / (2 * self.page_size + 4)).min(MAX_DATABASE_PAGES))
            .ok_or_else(|| invalid("capture workspace byte limit exceeded"))?;
        let current: u64 = connection.pragma_query_value(None, "page_count", |row| row.get(0))?;
        if pages < current {
            return Err(invalid("capture workspace byte limit exceeded"));
        }
        let effective: u64 =
            connection.pragma_update_and_check(None, "max_page_count", pages, |row| row.get(0))?;
        if effective > pages {
            return Err(invalid("unable to set capture workspace page limit"));
        }
        Ok(())
    }

    pub fn writer<'a>(
        &'a self,
        connection: &'a Connection,
        file: &'a mut File,
        maximum: u64,
    ) -> io::Result<Writer<'a>> {
        Ok(Writer {
            workspace: self,
            connection,
            file: SparseWriter::new(file, maximum)?,
        })
    }
}

fn journal_sector(connection: &Connection) -> Result<u64> {
    #[cfg(target_os = "linux")]
    {
        // The bundled Linux SQLite VFS uses its compiled default for every file
        let option: Option<String> = connection.query_row(
            "SELECT compile_options FROM pragma_compile_options WHERE compile_options GLOB 'DEFAULT_SECTOR_SIZE=*'",
            [], |row| row.get(0),
        ).optional()?;
        Ok(option
            .as_deref()
            .and_then(|value| value.strip_prefix("DEFAULT_SECTOR_SIZE="))
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|value| value.is_power_of_two() && (32..=MAX_SECTOR_BYTES).contains(value))
            .unwrap_or(MAX_SECTOR_BYTES))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = connection;
        Ok(MAX_SECTOR_BYTES)
    }
}

pub(super) struct Writer<'a> {
    workspace: &'a Workspace,
    connection: &'a Connection,
    file: SparseWriter<'a>,
}

impl Writer<'_> {
    pub fn finish(self) -> io::Result<u64> {
        self.file.finish()
    }
}

impl Write for Writer<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let source = self
            .file
            .position()
            .checked_add(u64::try_from(bytes.len()).map_err(io::Error::other)?)
            .ok_or_else(|| io::Error::other("capture byte count overflow"))?;
        self.workspace
            .admit(self.connection, source)
            .map_err(|error| io::Error::other(error.to_string()))?;
        self.file.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}
