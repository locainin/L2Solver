use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits, Edge, EvidenceError, EvidenceStatus},
    job::{MemoryBudget, MemoryClass, MemoryError},
    sha256,
};
use serde_json::json;
use std::error::Error;
use std::io::{self, Read};
use std::sync::Barrier;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::thread;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn case_growth_rejects_pressure_before_retaining_new_blob() -> TestResult {
    let budget = MemoryBudget::new(1_000_000);
    let mut case = Case::with_memory_budget(&budget)?;
    case.add_bytes_node("original", b"old", Vec::new(), json!({}))?;
    let before = case.to_json()?;
    let before_used = budget.snapshot()?.used_bytes;
    let other = budget.try_reserve(MemoryClass::Executor, 1_000_000 - before_used - 1)?;

    let error = case
        .add_bytes_node("new", b"four", Vec::new(), json!({}))
        .err();
    assert!(matches!(
        error,
        Some(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(case.to_json()?, before);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Case), before_used);

    drop(other);
    case.add_bytes_node("new", b"four", Vec::new(), json!({}))?;
    assert!(budget.snapshot()?.used(MemoryClass::Case) >= before_used + 4);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn source_metadata_and_limitations_participate_in_shared_pressure() -> TestResult {
    let budget = MemoryBudget::new(1_000_000);
    let mut case = Case::with_memory_budget(&budget)?;
    case.add_source("first.bin", "file", 0, &sha256(b""), None)?;
    let used = budget.snapshot()?.used(MemoryClass::Case);
    assert!(
        used > 0,
        "source records and their index need a live charge"
    );
    let other = budget.try_reserve(MemoryClass::Executor, 1_000_000 - used - 1)?;
    let before = case.to_json()?;
    let failure = case.add_limitation("bounded explanation");
    assert!(matches!(
        failure,
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(case.to_json()?, before);
    drop(other);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn rebinding_source_label_does_not_mutate_the_case_when_memory_is_unavailable() -> TestResult {
    let budget = MemoryBudget::new(1_000_000);
    let mut case = Case::with_memory_budget(&budget)?;
    let source = case.add_source("a", "file", 0, &sha256(b""), None)?;
    let used = budget.snapshot()?.used(MemoryClass::Case);
    let other = budget.try_reserve(MemoryClass::Executor, 1_000_000 - used)?;
    let before = case.to_json()?;
    let result = case.rebind_source_label(&source, "longer-name.bin");
    assert!(matches!(
        result,
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(case.to_json()?, before);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Case), used);
    drop(other);
    case.rebind_source_label(&source, "longer-name.bin")?;
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn graph_nodes_and_edges_are_admitted_before_they_are_retained() -> TestResult {
    let budget = MemoryBudget::new(1_000_000);
    let mut case = Case::with_memory_budget(&budget)?;
    let first = case.add_node("first", None, Vec::new(), json!({"kind": "value"}))?;
    let second = case.add_node("second", None, Vec::new(), json!({}))?;
    let used = budget.snapshot()?.used(MemoryClass::Case);
    assert!(
        used > 0,
        "graph records need a live charge even without blobs"
    );
    let other = budget.try_reserve(MemoryClass::Executor, 1_000_000 - used - 1)?;
    let before = case.to_json()?;
    let failure = case.add_edge(Edge {
        from: first,
        to: second,
        relation: "related".to_owned(),
        status: EvidenceStatus::Observed,
        reason: "The nodes are related".to_owned(),
    });
    assert!(matches!(
        failure,
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(case.to_json()?, before);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Case), used);
    drop(other);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn failed_transaction_releases_the_rolled_back_blob_charge() -> TestResult {
    let budget = MemoryBudget::new(1_000_000);
    let mut case = Case::with_memory_budget(&budget)?;
    case.add_bytes_node("original", b"old", Vec::new(), json!({}))?;
    let before = budget.snapshot()?.used(MemoryClass::Case);
    let result = case.transaction(|case| {
        case.add_bytes_node("temporary", b"discarded", Vec::new(), json!({}))?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });
    assert_eq!(result, Err(EvidenceError::InvalidSourceRange));
    assert_eq!(case.resource_usage().blob_bytes, 3);
    let after = budget.snapshot()?.used(MemoryClass::Case);
    assert!(after >= before);
    let repeated = case.transaction(|case| {
        case.add_bytes_node("temporary", b"discarded", Vec::new(), json!({}))?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });
    assert_eq!(repeated, Err(EvidenceError::InvalidSourceRange));
    assert_eq!(budget.snapshot()?.used(MemoryClass::Case), after);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn transaction_checkpoint_is_admitted_before_its_storage_is_allocated() -> TestResult {
    let budget = MemoryBudget::new(0);
    let mut case = Case::with_memory_budget(&budget)?;
    let mut ran = false;
    let result = case.transaction(|_| {
        ran = true;
        Ok::<(), EvidenceError>(())
    });
    assert!(matches!(
        result,
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert!(!ran);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn snapshot_restore_charges_the_new_case_and_fails_cleanly_under_pressure() -> TestResult {
    let mut original = Case::new();
    original.add_bytes_node(
        "content",
        b"snapshot contents",
        Vec::new(),
        json!({"sample":1}),
    )?;
    let mut graph = Vec::new();
    let mut pack = Vec::new();
    let limits = CaseSnapshotLimits::new(1_000_000, 1_000_000);
    original.write_snapshot(&mut graph, &mut pack, limits)?;

    let budget = MemoryBudget::new(1_000_000);
    let (restored, _) =
        Case::from_snapshot_with_memory(graph.as_slice(), pack.as_slice(), limits, &budget)?;
    assert_eq!(restored, original);
    assert!(
        budget.snapshot()?.used(MemoryClass::Case) >= u64::try_from(b"snapshot contents".len())?
    );
    drop(restored);
    assert_eq!(budget.snapshot()?.used_bytes, 0);

    let restricted = MemoryBudget::new(1);
    let result =
        Case::from_snapshot_with_memory(graph.as_slice(), pack.as_slice(), limits, &restricted);
    assert!(matches!(
        result,
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(restricted.snapshot()?.used_bytes, 0);
    Ok(())
}

struct CountingInput<R> {
    input: R,
    reads: Arc<AtomicUsize>,
}

impl<R: Read> Read for CountingInput<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.reads.fetch_add(1, Ordering::SeqCst);
        self.input.read(output)
    }
}

#[test]
fn snapshot_reader_buffers_are_admitted_before_input_is_read() -> TestResult {
    let budget = MemoryBudget::new(1);
    let reads = Arc::new(AtomicUsize::new(0));
    let graph = CountingInput {
        input: &b""[..],
        reads: Arc::clone(&reads),
    };
    let result = Case::from_snapshot_with_memory(
        graph,
        &b""[..],
        CaseSnapshotLimits::new(1_000_000, 1_000_000),
        &budget,
    );
    assert!(matches!(
        result,
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(reads.load(Ordering::SeqCst), 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn snapshot_record_buffer_respects_pressure_in_addition_to_reader_buffers() -> TestResult {
    let mut graph = Vec::new();
    let mut pack = Vec::new();
    let limits = CaseSnapshotLimits::new(1_000_000, 1_000_000);
    Case::new().write_snapshot(&mut graph, &mut pack, limits)?;
    let budget = MemoryBudget::new(2 * 16 * 1024);
    let result =
        Case::from_snapshot_with_memory(graph.as_slice(), pack.as_slice(), limits, &budget);
    assert!(matches!(
        result,
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn malformed_budgeted_snapshot_releases_reader_and_partial_case_charges() -> TestResult {
    let limits = CaseSnapshotLimits::new(1_000_000, 1_000_000);
    let mut original = Case::new();
    original.add_bytes_node("content", b"payload", Vec::new(), json!({}))?;
    let mut graph = Vec::new();
    let mut pack = Vec::new();
    original.write_snapshot(&mut graph, &mut pack, limits)?;
    let budget = MemoryBudget::new(1_000_000);
    let shortened = pack
        .get(..pack.len() - 1)
        .ok_or("expected a nonempty blob pack")?;
    let result = Case::from_snapshot_with_memory(graph.as_slice(), shortened, limits, &budget);
    assert!(result.is_err());
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn concurrent_cases_share_one_bound_and_keep_successful_growth_charged() -> TestResult {
    let probe_budget = MemoryBudget::new(1_000_000);
    let mut probe = Case::with_memory_budget(&probe_budget)?;
    probe.add_node("initial", None, Vec::new(), json!({}))?;
    let baseline = probe_budget.snapshot()?.used(MemoryClass::Case);
    probe.add_node(
        "extra",
        None,
        Vec::new(),
        json!({"payload": "x".repeat(64)}),
    )?;
    let growth = probe_budget.snapshot()?.used(MemoryClass::Case) - baseline;
    let budget = MemoryBudget::new(2 * baseline + growth);
    let mut first = Case::with_memory_budget(&budget)?;
    let mut second = Case::with_memory_budget(&budget)?;
    first.add_node("initial", None, Vec::new(), json!({}))?;
    second.add_node("initial", None, Vec::new(), json!({}))?;
    let barrier = Arc::new(Barrier::new(2));
    let handles = [first, second]
        .into_iter()
        .map(|mut case| {
            let barrier = Arc::clone(&barrier);
            thread::spawn(move || {
                barrier.wait();
                let admitted = case
                    .add_node(
                        "extra",
                        None,
                        Vec::new(),
                        json!({"payload": "x".repeat(64)}),
                    )
                    .is_ok();
                barrier.wait();
                admitted
            })
        })
        .collect::<Vec<_>>();
    let mut admitted = 0;
    for handle in handles {
        admitted += usize::from(handle.join().map_err(|_| "worker panicked")?);
    }
    assert_eq!(admitted, 1);
    assert!(budget.snapshot()?.peak_bytes <= 2 * baseline + growth);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn case_validation_admits_reference_tracking_before_allocating_it() -> TestResult {
    let budget = MemoryBudget::new(1_000_000);
    let mut case = Case::with_memory_budget(&budget)?;
    case.add_bytes_node("content", b"payload", Vec::new(), json!({}))?;
    let used = budget.snapshot()?.used(MemoryClass::Case);
    let other = budget.try_reserve(MemoryClass::Executor, 1_000_000 - used)?;
    let result = case.validate();
    assert!(matches!(
        result,
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(budget.snapshot()?.used(MemoryClass::Case), used);
    drop(other);
    case.validate()?;
    assert_eq!(budget.snapshot()?.used(MemoryClass::Case), used);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn validation_rejects_duplicate_aliases_in_unsorted_imported_sources() -> TestResult {
    let mut case = Case::new();
    case.add_source("source.bin", "file", 0, &sha256(b""), None)?;
    let mut document = serde_json::to_value(&case)?;
    let source = document
        .get_mut("sources")
        .and_then(serde_json::Value::as_array_mut)
        .and_then(|sources| sources.first_mut())
        .ok_or("expected a source")?;
    let fields = source.as_object_mut().ok_or("expected source fields")?;
    fields.insert(
        "aliases".to_owned(),
        json!(["second.bin", "first.bin", "second.bin"]),
    );
    let result = Case::from_json(&serde_json::to_vec(&document)?);
    assert!(matches!(
        result,
        Err(EvidenceError::InvalidText {
            field: "duplicate source alias"
        })
    ));
    Ok(())
}

#[test]
fn checked_case_copy_reserves_a_second_charge_and_has_a_distinct_identity() -> TestResult {
    let budget = MemoryBudget::new(1_000_000);
    let mut case = Case::with_memory_budget(&budget)?;
    case.add_bytes_node("original", b"old", Vec::new(), json!({}))?;
    let used = budget.snapshot()?.used(MemoryClass::Case);
    let cloned = case.try_clone()?;
    assert_eq!(cloned, case);
    assert!(!case.identity().identifies(&cloned));
    assert!(budget.snapshot()?.used(MemoryClass::Case) > used);
    drop(cloned);
    assert_eq!(budget.snapshot()?.used(MemoryClass::Case), used);

    let other = budget.try_reserve(MemoryClass::Executor, 1_000_000 - used)?;
    assert!(matches!(
        case.try_clone(),
        Err(EvidenceError::Memory(MemoryError::Limit { .. }))
    ));
    drop(other);
    drop(case);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
