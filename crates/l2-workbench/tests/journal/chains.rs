use super::support::event;
use l2_workbench::{
    evidence::Case,
    journal::{ChainDeadline, ChainPlan, EventSelector, Journal, JournalOptions},
};
use serde_json::json;
use std::error::Error;

#[test]
fn event_chains_not_scopes_actors() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    for e in [
        event(1, "lookup", "lan", "host-A"),
        event(10000, "connect", "other-lan", "host-A"),
        event(20000, "connect", "lan", "host-B"),
        event(30000, "connect", "lan", "host-A"),
    ] {
        journal.record_event(&e)?;
    }
    let mut other_source = event(25000, "connect", "lan", "host-A");
    other_source.source = "source-B".into();
    journal.record_event(&other_source)?;
    let plan = ChainPlan {
        steps: vec![
            EventSelector {
                kind: Some("lookup".into()),
                ..Default::default()
            },
            EventSelector {
                kind: Some("connect".into()),
                ..Default::default()
            },
        ],
        same_actor: true,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };
    let mut chains = Vec::new();
    journal.visit_chains(&plan, |c| {
        chains.push(c);
        Ok(())
    })?;
    assert_eq!(chains.len(), 1);
    assert_eq!(
        chains
            .first()
            .ok_or("missing chain")?
            .events
            .get(1)
            .ok_or("missing second event")?
            .packet,
        30000
    );
    assert_eq!(
        chains.first().ok_or("missing chain")?.relation,
        "capture_order_cooccurrence"
    );
    Ok(())
}

#[test]
fn exact_time_selectors_noncomparable_chains() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(1, "start", "lan", "host"))?;
    let mut other = event(2, "finish", "lan", "host");
    other.clock = Some("different-clock".into());
    journal.record_event(&other)?;
    let mut selector = EventSelector {
        kind: Some("finish".into()),
        ..Default::default()
    };
    selector.fields.insert("result".into(), json!("observed"));
    let plan = ChainPlan {
        steps: vec![
            EventSelector {
                kind: Some("start".into()),
                ..Default::default()
            },
            selector,
        ],
        same_actor: true,
        max_gap_ticks: Some(100),
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };
    let mut count = 0;
    journal.visit_chains(&plan, |_| {
        count += 1;
        Ok(())
    })?;
    assert_eq!(count, 0);
    Ok(())
}

#[test]
fn field_selector_large_unsigned_integers() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    let mut observed = event(1, "observation", "lan", "host");
    observed.fields = json!({"token": u64::MAX});
    journal.record_event(&observed)?;

    let mut selector = EventSelector {
        kind: Some("observation".into()),
        ..Default::default()
    };
    selector.fields.insert("token".into(), json!(u64::MAX - 1));
    let plan = ChainPlan {
        steps: vec![selector],
        same_actor: true,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };
    let mut emitted = 0;
    journal.visit_chains(&plan, |_| {
        emitted += 1;
        Ok(())
    })?;

    assert_eq!(
        emitted, 0,
        "distinct JSON integers must not collapse through SQLite REAL conversion"
    );
    Ok(())
}

#[test]
fn field_join_large_unsigned_integers() -> Result<(), Box<dyn Error>> {
    use l2_workbench::journal::EventJoin;

    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    let mut request = event(1, "request", "lan", "host");
    request.fields = json!({"token": u64::MAX - 1});
    journal.record_event(&request)?;
    let mut different = event(2, "response", "lan", "host");
    different.fields = json!({"token": u64::MAX});
    journal.record_event(&different)?;
    let mut matching = event(3, "response", "lan", "host");
    matching.fields = json!({"token": u64::MAX - 1});
    journal.record_event(&matching)?;

    let plan = ChainPlan {
        steps: vec![
            EventSelector {
                kind: Some("request".into()),
                ..Default::default()
            },
            EventSelector {
                kind: Some("response".into()),
                ..Default::default()
            },
        ],
        same_actor: true,
        max_gap_ticks: None,
        limit: None,
        max_elapsed_ms: ChainDeadline::unlimited(),
        joins: vec![EventJoin {
            left_step: 0,
            left_field: "fields.token".into(),
            right_step: 1,
            right_field: "fields.token".into(),
        }],
    };
    let mut response_packets = Vec::new();
    journal.visit_chains(&plan, |chain| {
        response_packets.push(chain.events.get(1).ok_or("missing response event")?.packet);
        Ok(())
    })?;

    assert_eq!(response_packets, [3]);
    Ok(())
}

#[test]
fn returned_chain_successful_visitor_calls() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(1, "observation", "lan", "host"))?;
    journal.record_event(&event(2, "observation", "lan", "host"))?;
    let plan = ChainPlan {
        steps: vec![EventSelector::default()],
        same_actor: false,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };
    let mut visitor_calls = 0_u64;

    let returned = journal.visit_chains(&plan, |_| {
        visitor_calls += 1;
        Ok(())
    })?;

    assert_eq!(returned, 2);
    assert_eq!(visitor_calls, returned);
    Ok(())
}

#[test]
fn chain_limit_requested_number_results() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    for packet in 1..=3 {
        journal.record_event(&event(packet, "observation", "lan", "host"))?;
    }
    let plan = ChainPlan {
        steps: vec![EventSelector::default()],
        same_actor: false,
        max_gap_ticks: None,
        limit: Some(2),
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };
    let mut packets = Vec::new();

    let returned = journal.visit_chains(&plan, |chain| {
        packets.push(chain.events.first().ok_or("missing chain event")?.packet);
        Ok(())
    })?;

    assert_eq!(returned, 2);
    assert_eq!(packets, [1, 2]);
    Ok(())
}

#[test]
fn chain_field_without_unrelated_events() -> Result<(), Box<dyn Error>> {
    use l2_workbench::journal::EventJoin;
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    let mut request = event(1, "request", "lan", "client");
    request.peer = Some("server".into());
    journal.record_event(&request)?;
    let mut response = event(2, "response", "lan", "server");
    response.peer = Some("client".into());
    journal.record_event(&response)?;
    let mut other = event(3, "response", "lan", "other-server");
    other.peer = Some("client".into());
    journal.record_event(&other)?;
    let plan = ChainPlan {
        steps: vec![
            EventSelector {
                kind: Some("request".into()),
                ..Default::default()
            },
            EventSelector {
                kind: Some("response".into()),
                ..Default::default()
            },
        ],
        same_actor: false,
        max_gap_ticks: None,
        limit: None,
        max_elapsed_ms: ChainDeadline::unlimited(),
        joins: vec![EventJoin {
            left_step: 0,
            left_field: "peer".into(),
            right_step: 1,
            right_field: "actor".into(),
        }],
    };
    let mut found = Vec::new();
    journal.visit_chains(&plan, |c| {
        found.push(c);
        Ok(())
    })?;
    assert_eq!(found.len(), 1);
    assert_eq!(
        found
            .first()
            .ok_or("missing chain")?
            .events
            .get(1)
            .ok_or("missing second event")?
            .actor
            .as_deref(),
        Some("server")
    );
    Ok(())
}

#[test]
fn expired_chain_without_emitting_results() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(1, "start", "lan", "host"))?;
    let plan = ChainPlan {
        steps: vec![EventSelector::default()],
        same_actor: true,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::limited(0),
    };
    let mut emitted = 0;
    assert!(
        journal
            .visit_chains(&plan, |_| {
                emitted += 1;
                Ok(())
            })
            .is_err()
    );
    assert_eq!(emitted, 0);
    let mut unlimited = plan;
    unlimited.max_elapsed_ms = ChainDeadline::unlimited();
    journal.visit_chains(&unlimited, |_| {
        emitted += 1;
        Ok(())
    })?;
    assert_eq!(emitted, 1);
    Ok(())
}

#[test]
fn chain_deadline_blocking_visitor() -> Result<(), Box<dyn Error>> {
    use std::time::Duration;

    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    // Enough rows exercise SQLite's progress callback and its cleanup on every supported build
    for packet in 1..=256 {
        journal.record_event(&event(packet, "start", "lan", "host"))?;
    }
    let plan = ChainPlan {
        steps: vec![EventSelector::default()],
        same_actor: true,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::limited(100),
    };
    let mut visitor_called = false;

    let result = journal.visit_chains(&plan, |_| {
        visitor_called = true;
        std::thread::sleep(Duration::from_millis(150));
        Ok(())
    });

    assert!(visitor_called, "the test must reach the visitor");
    assert!(
        result.is_err(),
        "an expired visitor call must fail on return"
    );

    let Err(visitor_error) = journal.visit_chains(&plan, |_| {
        std::thread::sleep(Duration::from_millis(150));
        Err(std::io::Error::other("visitor rejected the chain").into())
    }) else {
        return Err("the visitor error must be returned".into());
    };
    assert!(
        visitor_error
            .to_string()
            .contains("visitor rejected the chain"),
        "the deadline must not mask a visitor error: {visitor_error}"
    );

    let mut unlimited = plan;
    unlimited.max_elapsed_ms = ChainDeadline::unlimited();
    let mut emitted = 0;
    journal.visit_chains(&unlimited, |_| {
        emitted += 1;
        Ok(())
    })?;
    assert_eq!(emitted, 256, "the expired deadline handler must be cleared");
    Ok(())
}

#[test]
fn sqlite_deadline_chain_budget_error() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    for packet in 1..=128 {
        journal.record_event(&event(packet, "observation", "lan", "host"))?;
    }
    let plan = ChainPlan {
        steps: vec![EventSelector::default(); 4],
        same_actor: false,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::limited(20),
    };

    let error = journal
        .visit_chains(&plan, |_| Ok(()))
        .err()
        .ok_or("the combinatorial join must exhaust its deadline")?;

    assert!(
        error
            .to_string()
            .contains("chain query time budget is exhausted"),
        "SQLite interruption must retain the public deadline diagnostic: {error}"
    );
    Ok(())
}

#[test]
fn nested_chain_without_outer_query() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(1, "observation", "lan", "host"))?;
    let inner = ChainPlan {
        steps: vec![EventSelector::default()],
        same_actor: false,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };
    let mut outer = inner.clone();
    outer.limit = Some(1);
    outer.max_elapsed_ms = ChainDeadline::limited(1_000);
    let mut nested_error = None;

    let emitted = journal.visit_chains(&outer, |_| {
        let Err(error) = journal.visit_chains(&inner, |_| Ok(())) else {
            return Err(std::io::Error::other(
                "nested chain queries must not replace the outer deadline handler",
            )
            .into());
        };
        nested_error = Some(error.to_string());
        Ok(())
    })?;

    assert_eq!(emitted, 1);
    assert!(
        nested_error
            .as_deref()
            .is_some_and(|error| error.contains("nested chain queries are not supported")),
        "the nested query must fail with a stable diagnostic: {nested_error:?}"
    );
    Ok(())
}

#[test]
fn journal_verification_disagree_event_evidence() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(1, "start", "lan", "host"))?;
    journal.verify()?;
    let db = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    db.execute("UPDATE events SET actor='different-host'", [])?;
    assert!(journal.verify().is_err());
    Ok(())
}

#[test]
fn chain_query_filter_hides_event() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(1, "start", "lan", "host"))?;
    let plan = ChainPlan {
        steps: vec![EventSelector {
            kind: Some("start".into()),
            ..Default::default()
        }],
        same_actor: true,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };

    let db = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    db.execute("UPDATE events SET kind='hidden-by-filter'", [])?;
    drop(db);

    let mut visitor_called = false;
    let error = journal
        .visit_chains(&plan, |_| {
            visitor_called = true;
            Ok(())
        })
        .err()
        .ok_or("a chain query must validate events before applying its filters")?;

    assert!(
        !visitor_called,
        "invalid evidence must never reach the visitor"
    );
    assert!(
        error.to_string().contains("index columns disagree"),
        "unexpected integrity error: {error}"
    );
    Ok(())
}

#[test]
fn chain_query_no_longer_identity() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    let mut first = event(1, "start", "lan", "host");
    first.fields = json!({"result": "observed"});
    journal.record_event(&first)?;
    let original = event(2, "start", "lan", "host");
    let mut original = original;
    original.fields = json!({"result": "observed"});
    journal.record_event(&original)?;
    let mut selector = EventSelector {
        kind: Some("start".into()),
        ..Default::default()
    };
    selector.fields.insert("result".into(), json!("observed"));
    let plan = ChainPlan {
        steps: vec![selector],
        same_actor: true,
        max_gap_ticks: None,
        limit: Some(1),
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };

    // Alter only an unindexed field so the identity check is the decisive guard
    let mut changed = original;
    changed.fields = json!({"result": "hidden-by-filter"});
    let db = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    db.execute(
        "UPDATE events SET value=?1 WHERE packet=2",
        [serde_json::to_string(&changed)?],
    )?;
    drop(db);

    let mut visitor_called = false;
    let error = journal
        .visit_chains(&plan, |_| {
            visitor_called = true;
            Ok(())
        })
        .err()
        .ok_or("a chain query must verify each event identity")?;

    assert!(
        !visitor_called,
        "invalid evidence must never reach the visitor"
    );
    assert!(
        error.to_string().contains("event identity mismatch"),
        "unexpected integrity error: {error}"
    );
    Ok(())
}

#[test]
fn chain_query_outside_public_cursor() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let mut journal = Journal::create(dir.path(), &Case::new(), JournalOptions::default())?;
    journal.record_event(&event(1, "altered", "lan", "host"))?;
    journal.record_event(&event(2, "selected", "lan", "host"))?;
    let db = rusqlite::Connection::open(dir.path().join("journal.sqlite"))?;
    db.execute("UPDATE events SET id=-1 WHERE packet=1", [])?;
    drop(db);

    let plan = ChainPlan {
        steps: vec![EventSelector {
            kind: Some("selected".into()),
            ..Default::default()
        }],
        same_actor: true,
        max_gap_ticks: None,
        limit: None,
        joins: Vec::new(),
        max_elapsed_ms: ChainDeadline::unlimited(),
    };
    let mut visitor_called = false;
    let error = journal
        .visit_chains(&plan, |_| {
            visitor_called = true;
            Ok(())
        })
        .err()
        .ok_or("the integrity scan must include rows before the public cursor")?;

    assert!(
        !visitor_called,
        "a chain must not be emitted from a journal with hidden invalid rows"
    );
    assert!(
        error.to_string().contains("row ID must be positive"),
        "unexpected integrity error: {error}"
    );
    assert!(
        journal.verify().is_err(),
        "whole-journal verification must use the same complete event scan"
    );
    Ok(())
}
