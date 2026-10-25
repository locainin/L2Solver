use super::Result;
use l2_audit::ForensicScope;
use rusqlite::{Connection, OptionalExtension};
use std::collections::HashMap;

const CACHE_ENTRIES: usize = 8192;

/// The database owns all scopes; this bounded cache only avoids repeated SQL lookups
#[derive(Default)]
pub(super) struct Cache {
    values: HashMap<Vec<u8>, i64>,
}

impl Cache {
    pub(super) fn retain(&mut self, connection: &Connection, scope: &ForensicScope) -> Result<i64> {
        let value = serde_json::to_vec(scope)?;
        if let Some(id) = self.values.get(&value) {
            return Ok(*id);
        }
        let inserted = connection
            .prepare_cached(
                "INSERT INTO scopes(value) VALUES(?1) ON CONFLICT(value) DO NOTHING RETURNING id",
            )?
            .query_row([&value], |row| row.get(0))
            .optional()?;
        let id = match inserted {
            Some(id) => id,
            None => connection
                .prepare_cached("SELECT id FROM scopes WHERE value=?1")?
                .query_row([&value], |row| row.get(0))?,
        };
        // Eviction changes lookup cost and never discards disk-resident evidence
        if self.values.len() == CACHE_ENTRIES {
            self.values.clear();
        }
        self.values.insert(value, id);
        Ok(id)
    }
}
