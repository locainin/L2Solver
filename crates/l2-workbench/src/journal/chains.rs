use super::{Chain, ChainPlan, Event, EventSelector, Journal, Result, event_reader, invalid};
use rusqlite::{Connection, params_from_iter, types::Value};
use std::fmt::Write as _;

impl Journal {
    /// Stream ordered event chains using disk-backed joins over the whole investigation
    ///
    /// The work budget is checked between query and row-processing phases and around visitor
    /// calls. A visitor already in progress cannot be interrupted; an expired budget is
    /// reported when that visitor returns
    ///
    /// # Errors
    /// Rejects empty plans, invalid field paths, expired deadlines, database engine limits
    /// and visitor errors
    pub fn visit_chains(
        &self,
        plan: &ChainPlan,
        mut visitor: impl FnMut(Chain) -> Result<()>,
    ) -> Result<u64> {
        let _activity = ChainActivity::enter(&self.chain_query_active)?;
        let deadline = Deadline::install(&self.connection, plan.max_elapsed_ms.milliseconds())?;
        let (sql, args) = query(plan, &deadline)?;
        deadline.check()?;
        if plan.limit == Some(0) {
            return Ok(0);
        }
        deadline.check()?;
        let emitted = self.read_snapshot(|journal| {
            visit_chains_in_snapshot(
                &journal.connection,
                plan,
                journal.options.max_entry_bytes,
                &sql,
                args,
                &deadline,
                &mut visitor,
            )
        })?;
        deadline.check()?;
        Ok(emitted)
    }
}

struct ChainActivity<'a> {
    active: &'a std::cell::Cell<bool>,
}

impl<'a> ChainActivity<'a> {
    fn enter(active: &'a std::cell::Cell<bool>) -> Result<Self> {
        if active.get() {
            return Err(invalid("nested chain queries are not supported"));
        }
        active.set(true);
        Ok(Self { active })
    }
}

impl Drop for ChainActivity<'_> {
    fn drop(&mut self) {
        self.active.set(false);
    }
}

fn visit_chains_in_snapshot(
    connection: &Connection,
    plan: &ChainPlan,
    metadata_budget: usize,
    sql: &str,
    args: Vec<Value>,
    deadline: &Deadline<'_>,
    visitor: &mut impl FnMut(Chain) -> Result<()>,
) -> Result<u64> {
    // Validate every event before filters can hide altered index columns or evidence
    deadline.normalize(event_reader::validate_all_events(
        connection,
        metadata_budget,
        &mut || deadline.check(),
    ))?;
    deadline.check()?;
    let mut statement = deadline.sqlite(connection.prepare(sql))?;
    deadline.check()?;
    let mut rows = deadline.sqlite(statement.query(params_from_iter(args)))?;
    deadline.check()?;
    let mut emitted = 0_u64;
    loop {
        deadline.check()?;
        let Some(row) = deadline.sqlite(rows.next())? else {
            break;
        };
        let mut events = Vec::with_capacity(plan.steps.len());
        for i in 0..plan.steps.len() {
            deadline.check()?;
            // The canonical reader verified this value in the same database snapshot
            let value = row.get::<_, String>(i)?;
            deadline.check()?;
            events.push(serde_json::from_str::<Event>(&value)?);
            deadline.check()?;
        }
        deadline.check()?;
        let matches_gap = plan
            .max_gap_ticks
            .is_none_or(|maximum| comparable_intervals(&events, maximum));
        deadline.check()?;
        if !matches_gap {
            continue;
        }
        let visitor_result = visitor(Chain {
            relation: "capture_order_cooccurrence",
            events,
            interpretation: "Selected observations occurred in this source order; this does not establish dependency, malicious intent or causation",
        });
        // The visitor is synchronous and cannot be interrupted while it is running
        visitor_result?;
        deadline.check()?;
        emitted = emitted
            .checked_add(1)
            .ok_or_else(|| invalid("chain result count exceeds the supported range"))?;
        if plan.limit.is_some_and(|limit| emitted >= limit) {
            break;
        }
    }
    deadline.check()?;
    Ok(emitted)
}
fn query(plan: &ChainPlan, deadline: &Deadline<'_>) -> Result<(String, Vec<Value>)> {
    deadline.check()?;
    if plan.steps.is_empty() {
        return Err(invalid("a chain needs at least one event selector"));
    }
    let mut sql = String::from("SELECT ");
    for i in 0..plan.steps.len() {
        deadline.check()?;
        if i != 0 {
            sql.push(',');
        }
        write!(sql, "e{i}.value")?;
    }
    sql.push_str(" FROM events e0");
    for i in 1..plan.steps.len() {
        deadline.check()?;
        let previous = i - 1;
        // Source order is comparable within one capture scope, never across unrelated captures
        write!(
            sql,
            " JOIN events e{i} ON e{i}.source=e0.source AND e{i}.scope=e0.scope AND e{i}.packet>e{previous}.packet"
        )?;
        if plan.same_actor {
            write!(sql, " AND e{i}.actor=e0.actor")?;
        }
    }
    sql.push_str(" WHERE 1=1");
    let mut args = Vec::new();
    for (i, selector) in plan.steps.iter().enumerate() {
        deadline.check()?;
        add_selector(&mut sql, &mut args, i, selector, deadline)?;
    }
    for join in &plan.joins {
        deadline.check()?;
        if join.left_step >= plan.steps.len() || join.right_step >= plan.steps.len() {
            return Err(invalid("chain join refers to an absent step"));
        }
        let (left, left_type) = field_expression(join.left_step, &join.left_field, &mut args)?;
        let (right, right_type) = field_expression(join.right_step, &join.right_field, &mut args)?;
        deadline.check()?;
        write!(
            sql,
            " AND {left} IS NOT NULL AND {left_type}={right_type} AND {left}={right}"
        )?;
    }
    sql.push_str(" ORDER BY ");
    let mut first_order_column = true;
    for i in 0..plan.steps.len() {
        for column in ["source", "packet", "id"] {
            deadline.check()?;
            if !first_order_column {
                sql.push(',');
            }
            write!(sql, "e{i}.{column}")?;
            first_order_column = false;
        }
    }
    if plan.max_gap_ticks.is_none()
        && let Some(limit) = plan.limit
    {
        args.push(Value::Integer(i64::try_from(limit)?));
        write!(sql, " LIMIT ?{}", args.len())?;
    }
    Ok((sql, args))
}
fn add_selector(
    sql: &mut String,
    args: &mut Vec<Value>,
    step: usize,
    selector: &EventSelector,
    deadline: &Deadline<'_>,
) -> Result<()> {
    deadline.check()?;
    add_index_selector(sql, args, &format!("e{step}"), selector, deadline)?;
    for (field, value) in &selector.fields {
        deadline.check()?;
        args.push(Value::Text(field_path(field)?));
        let path_parameter = args.len();
        args.push(Value::Text(serde_json::to_string(value)?));
        let value_parameter = args.len();
        deadline.check()?;
        // JSON types distinguish true from 1, and IS allows explicit null values to match
        write!(
            sql,
            " AND json_type(e{step}.value,?{path_parameter})=json_type(?{value_parameter},'$') AND (e{step}.value -> ?{path_parameter}) IS (?{value_parameter} -> '$')"
        )?;
    }
    deadline.check()
}

fn add_index_selector(
    sql: &mut String,
    args: &mut Vec<Value>,
    table: &str,
    selector: &EventSelector,
    deadline: &Deadline<'_>,
) -> Result<()> {
    for (column, value) in [
        ("kind", &selector.kind),
        ("actor", &selector.actor),
        ("peer", &selector.peer),
    ] {
        deadline.check()?;
        if let Some(value) = value {
            args.push(Value::Text(value.clone()));
            write!(sql, " AND {table}.{column}=?{}", args.len())?;
        }
    }
    deadline.check()
}
fn comparable_intervals(events: &[Event], maximum: u64) -> bool {
    events.windows(2).all(|pair| {
        let [from, to] = pair else { return false };
        from.clock.is_some()
            && from.clock == to.clock
            && from
                .ticks
                .zip(to.ticks)
                .and_then(|(a, b)| b.checked_sub(a))
                .is_some_and(|delta| delta <= maximum)
    })
}
fn field_path(field: &str) -> Result<String> {
    if field.split('.').any(|part| {
        part.is_empty()
            || !part
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
    }) {
        return Err(invalid(
            "event field paths must contain dot-separated names",
        ));
    }
    Ok(format!(
        "$.fields.{}",
        field
            .split('.')
            .map(|p| format!("\"{p}\""))
            .collect::<Vec<_>>()
            .join(".")
    ))
}
fn field_expression(step: usize, field: &str, args: &mut Vec<Value>) -> Result<(String, String)> {
    match field {
        "actor" | "peer" | "kind" | "source" | "scope" => Ok((
            format!(
                "CASE WHEN e{step}.{field} IS NULL THEN NULL ELSE json_quote(e{step}.{field}) END"
            ),
            "'text'".to_owned(),
        )),
        "packet" => Ok((
            format!("json_quote(e{step}.packet)"),
            "'integer'".to_owned(),
        )),
        value => {
            let field = value.strip_prefix("fields.").ok_or_else(|| {
                invalid("join fields must name an event column or start with fields.")
            })?;
            args.push(Value::Text(field_path(field)?));
            let number = args.len();
            Ok((
                format!("e{step}.value -> ?{number}"),
                format!("json_type(e{step}.value,?{number})"),
            ))
        }
    }
}

struct Deadline<'a> {
    connection: &'a rusqlite::Connection,
    deadline: Option<std::time::Instant>,
}
impl<'a> Deadline<'a> {
    fn install(connection: &'a rusqlite::Connection, milliseconds: Option<u64>) -> Result<Self> {
        let deadline = match milliseconds {
            Some(0) => return Err(invalid("chain query time budget is already exhausted")),
            Some(milliseconds) => Some(
                std::time::Instant::now()
                    .checked_add(std::time::Duration::from_millis(milliseconds))
                    .ok_or_else(|| invalid("chain deadline exceeds the monotonic clock range"))?,
            ),
            None => None,
        };
        if let Some(deadline) = deadline {
            // Polling frequency controls deadline overhead, not how much evidence may be searched
            connection
                .progress_handler(1_000, Some(move || std::time::Instant::now() >= deadline))?;
        }
        Ok(Self {
            connection,
            deadline,
        })
    }

    fn check(&self) -> Result<()> {
        let Some(deadline) = self.deadline else {
            return Ok(());
        };
        if std::time::Instant::now() >= deadline {
            return Err(invalid("chain query time budget is exhausted"));
        }
        Ok(())
    }

    fn sqlite<T>(&self, result: rusqlite::Result<T>) -> Result<T> {
        self.normalize(result.map_err(Into::into))
    }

    fn normalize<T>(&self, result: Result<T>) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(error)
                if error
                    .downcast_ref::<rusqlite::Error>()
                    .and_then(rusqlite::Error::sqlite_error_code)
                    == Some(rusqlite::ErrorCode::OperationInterrupted) =>
            {
                // The installed progress handler interrupts only after this deadline expires
                self.check()?;
                Err(error)
            }
            Err(error) => Err(error),
        }
    }
}
impl Drop for Deadline<'_> {
    fn drop(&mut self) {
        let _ = self.connection.progress_handler(0, None::<fn() -> bool>);
    }
}
