use super::{frames, support::capture};
use l2_workbench::{
    job::{MemoryBudget, MemoryClass},
    reconstruction::Limits,
    store::{Options, Store},
};
use std::{error::Error, io::Cursor};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn indexed_flow_cases_use_the_supplied_shared_budget() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let source = store.ingest(
        "flow.pcap",
        Cursor::new(capture(&[frames::tcp(false, 100, 2, b"hello")?])?),
    )?;
    let flow = store
        .packet(&source.source_id, 1)?
        .flow
        .ok_or("expected indexed flow")?;
    let expected = store.investigate_flow(flow)?;
    let budget = MemoryBudget::new(1_000_000);
    store.set_memory_budget(budget.clone())?;
    assert!(store.set_memory_budget(MemoryBudget::new(1)).is_err());
    let actual = store.investigate_flow(flow)?;
    assert_eq!(actual.case, expected.case);
    assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
    drop(actual);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn supplementary_flow_pages_use_the_same_case_budget() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let records = [
        frames::tcp(false, 100, 2, b"first")?,
        frames::tcp(false, 105, 0x10, b"second")?,
        frames::tcp(false, 111, 0x10, b"third")?,
    ];
    let source = store.ingest("flow.pcap", Cursor::new(capture(&records)?))?;
    let flow = store
        .packet(&source.source_id, 1)?
        .flow
        .ok_or("expected indexed flow")?;
    let budget = MemoryBudget::new(1_000_000);
    store.set_memory_budget(budget.clone())?;
    let limits = Limits {
        frames: 1,
        ..Limits::default()
    };
    let mut pages = 0;
    store.visit_flow_pages_after_prefix(flow, 1, limits, |page| {
        assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
        pages += 1;
        drop(page);
        Ok(())
    })?;
    assert_eq!(pages, 2);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn ip_pair_cohort_cases_use_the_same_case_budget() -> TestResult {
    let temporary = tempfile::tempdir()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let records = [
        frames::tcp_ports(false, (40_000, 8_000), 100, 2, b"first")?,
        frames::tcp_ports(false, (41_000, 8_000), 200, 2, b"second")?,
    ];
    store.ingest("cohort.pcap", Cursor::new(capture(&records)?))?;
    let budget = MemoryBudget::new(1_000_000);
    store.set_memory_budget(budget.clone())?;
    let mut cohorts = 0;
    store.visit_ip_pair_cohort_analyses(Limits::default(), |cohort| {
        assert!(budget.snapshot()?.used(MemoryClass::Case) > 0);
        cohorts += 1;
        drop(cohort);
        Ok(())
    })?;
    assert_eq!(cohorts, 1);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
