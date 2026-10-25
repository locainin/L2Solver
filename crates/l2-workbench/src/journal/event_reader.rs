use super::{Event, Journal, Result, invalid};
use rusqlite::{params, types::ValueRef};

impl Journal {
    /// Stream validated events in stable journal insertion order
    ///
    /// # Errors
    /// Rejects malformed or oversized event records and returns storage or visitor errors
    pub fn visit_events(
        &self,
        after: u64,
        limit: Option<u64>,
        mut visitor: impl FnMut(Event) -> Result<()>,
    ) -> Result<u64> {
        if limit == Some(0) {
            return Ok(0);
        }
        self.read_snapshot(|journal| {
            let mut check = || Ok(());
            visit(
                &journal.connection,
                journal.options.max_entry_bytes,
                Some(after),
                limit,
                &mut check,
                &mut visitor,
            )
        })
    }
}

pub(super) fn validate_all_events(
    connection: &rusqlite::Connection,
    budget: usize,
    check: &mut impl FnMut() -> Result<()>,
) -> Result<()> {
    // Reuse the canonical event reader so every chain observes verified evidence
    let mut discard = |_: Event| Ok(());
    visit(connection, budget, None, None, check, &mut discard).map(|_| ())
}

fn visit(
    connection: &rusqlite::Connection,
    budget: usize,
    after: Option<u64>,
    limit: Option<u64>,
    check: &mut impl FnMut() -> Result<()>,
    visitor: &mut impl FnMut(Event) -> Result<()>,
) -> Result<u64> {
    check()?;
    let minimum_id = match after {
        Some(after) => match i64::try_from(after)?.checked_add(1) {
            Some(minimum) => minimum,
            None => return Ok(0),
        },
        None => i64::MIN,
    };
    let mut statement = connection.prepare(
        "SELECT id,identity,length(CAST(identity AS BLOB)),length(CAST(value AS BLOB)),value,length(CAST(source AS BLOB)),source,length(CAST(scope AS BLOB)),scope,packet,length(CAST(kind AS BLOB)),kind,length(CAST(actor AS BLOB)),actor,length(CAST(peer AS BLOB)),peer FROM events WHERE id>=?1 ORDER BY id LIMIT ?2",
    )?;
    check()?;
    let mut rows = statement.query(params![
        minimum_id,
        limit.map(i64::try_from).transpose()?.unwrap_or(-1)
    ])?;
    check()?;
    let budget_u64 = u64::try_from(budget)?;
    let mut count = 0_u64;
    loop {
        check()?;
        let Some(row) = rows.next()? else {
            break;
        };
        check()?;
        let event = validated_event(row, budget_u64)?;
        check()?;
        visitor(event)?;
        check()?;
        count = count
            .checked_add(1)
            .ok_or_else(|| invalid("event count exceeds the supported range"))?;
    }
    check()?;
    Ok(count)
}

fn validated_event(row: &rusqlite::Row<'_>, budget: u64) -> Result<Event> {
    let id: i64 = row.get(0)?;
    if id <= 0 {
        return Err(invalid("journal event row ID must be positive"));
    }
    if row.get::<_, u64>(2)? != 64 {
        return Err(invalid(
            "journal event identity must be a 64-character SHA-256 hash",
        ));
    }
    if row.get::<_, u64>(3)? > budget {
        return Err(invalid("event exceeds configured metadata reader budget"));
    }
    validate_index_column_lengths(row, budget)?;

    // Parse the canonical evidence before comparing each duplicated query index
    let identity = row.get_ref(1)?.as_str()?;
    let value: String = row.get(4)?;
    let event: Event = serde_json::from_str(&value)?;
    if event.source != row.get_ref(6)?.as_str()?
        || event.scope != row.get_ref(8)?.as_str()?
        || event.packet != row.get::<_, u64>(9)?
        || event.kind != row.get_ref(11)?.as_str()?
        || !optional_text_matches(event.actor.as_deref(), row.get_ref(13)?)?
        || !optional_text_matches(event.peer.as_deref(), row.get_ref(15)?)?
    {
        return Err(invalid(
            "journal event index columns disagree with its evidence",
        ));
    }
    super::events::validate_event(&event)?;
    if crate::sha256(value.as_bytes()) != identity {
        return Err(invalid("journal event identity mismatch"));
    }
    Ok(event)
}

fn validate_index_column_lengths(row: &rusqlite::Row<'_>, budget: u64) -> Result<()> {
    for (index, name) in [(5, "source"), (7, "scope"), (10, "kind")] {
        if row.get::<_, u64>(index)? > budget {
            return Err(invalid(format!(
                "event index column {name} exceeds configured metadata reader budget"
            )));
        }
    }
    for (index, name) in [(12, "actor"), (14, "peer")] {
        if row
            .get::<_, Option<u64>>(index)?
            .is_some_and(|length| length > budget)
        {
            return Err(invalid(format!(
                "event index column {name} exceeds configured metadata reader budget"
            )));
        }
    }
    Ok(())
}

fn optional_text_matches(expected: Option<&str>, actual: ValueRef<'_>) -> rusqlite::Result<bool> {
    match actual {
        ValueRef::Null => Ok(expected.is_none()),
        value => Ok(expected == Some(value.as_str()?)),
    }
}
