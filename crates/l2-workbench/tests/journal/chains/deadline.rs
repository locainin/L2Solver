use super::super::support::event;
use l2_workbench::{
    evidence::Case,
    journal::{ChainDeadline, ChainPlan, EventSelector, Journal, JournalOptions},
};
use std::{
    error::Error,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
    thread,
    time::Duration,
};

fn plan(deadline: ChainDeadline) -> ChainPlan {
    ChainPlan {
        steps: vec![EventSelector::default()],
        same_actor: false,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: deadline,
    }
}

#[test]
fn nested_snapshot_during_chain() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(1, "observation", "lan", "host"))?;

    let count = journal.read_snapshot(|snapshot| {
        snapshot.visit_chains(&plan(ChainDeadline::limited(1_000)), |_| {
            snapshot.read_snapshot(|nested| {
                assert_eq!(nested.overview()?.events, 1);
                Ok(())
            })
        })
    })?;

    assert_eq!(count, 1);
    Ok(())
}

#[test]
fn visitor_unwind_deadline_cleanup() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut journal = Journal::create(directory.path(), &Case::new(), JournalOptions::default())?;
    for packet in 1..=128 {
        journal.record_event(&event(packet, "observation", "lan", "host"))?;
    }
    let limited = plan(ChainDeadline::limited(500));
    let mut visited = false;

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let _ = journal.visit_chains(&limited, |_| {
            visited = true;
            thread::sleep(Duration::from_millis(550));
            resume_unwind(Box::new("visitor unwind"))
        });
    }));

    assert!(visited, "the visitor must run before unwinding");
    assert!(outcome.is_err(), "the visitor unwind must reach the caller");
    let count = journal.visit_chains(&plan(ChainDeadline::unlimited()), |_| Ok(()))?;
    assert_eq!(
        count, 128,
        "the expired deadline must not affect later work"
    );
    Ok(())
}
