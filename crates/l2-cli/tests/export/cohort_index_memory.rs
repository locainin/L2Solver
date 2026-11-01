use std::{error::Error, mem::size_of};

use l2_workbench::{
    evidence::Case,
    job::{MemoryBudget, MemoryError},
};
use serde_json::json;

const ENTRIES: usize = 1_024;
type TestResult = Result<(), Box<dyn Error>>;

fn collect_cohort(
    cohort: &super::CohortAnalysis,
    budget: &MemoryBudget,
) -> Result<super::super::ArtifactCoverage, Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    super::collect_cohort_artifacts(
        &mut artifacts,
        cohort,
        Some("cohort-case"),
        &json!({"kind": "cohort"}),
        Some(budget),
    )?;
    Ok(artifacts.coverage())
}

fn case_with_artifact() -> Result<Case, Box<dyn Error>> {
    let mut case = Case::new();
    case.add_bytes_node("ftp_data_candidate", b"payload", Vec::new(), json!({}))?;
    Ok(case)
}

fn cohort_with_many_packets() -> Result<super::CohortAnalysis, Box<dyn Error>> {
    let packets = (0..ENTRIES)
        .rev()
        .map(|packet| Ok((u32::try_from(packet)?, 10)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok(super::cohort_analysis(
        case_with_artifact()?,
        vec![super::flow(10)],
        packets,
    ))
}

fn cohort_with_many_flows() -> Result<super::CohortAnalysis, Box<dyn Error>> {
    let flows = (0..ENTRIES)
        .map(|flow| Ok(super::flow(i64::try_from(flow)?)))
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    Ok(super::cohort_analysis(
        case_with_artifact()?,
        flows,
        Vec::new(),
    ))
}

#[test]
fn packet_lookup_rejects_insufficient_publication_memory() -> TestResult {
    let cohort = cohort_with_many_packets()?;
    let budget = MemoryBudget::new(4 * 1024);
    let error = collect_cohort(&cohort, &budget)
        .err()
        .ok_or("packet lookup ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn packet_lookup_releases_its_charge_after_publication() -> TestResult {
    let cohort = cohort_with_many_packets()?;
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    let coverage = collect_cohort(&cohort, &budget)?;
    assert_eq!(coverage.references_selected, 1);
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(ENTRIES * size_of::<(u32, usize)>())?);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn flow_lookup_rejects_insufficient_publication_memory() -> TestResult {
    let cohort = cohort_with_many_flows()?;
    let budget = MemoryBudget::new(4 * 1024);
    let error = collect_cohort(&cohort, &budget)
        .err()
        .ok_or("flow lookup ignored shared publication memory")?;
    assert!(matches!(
        crate::memory_error::find(error.as_ref()),
        Some(MemoryError::Limit { .. })
    ));
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn flow_lookup_releases_its_charge_after_publication() -> TestResult {
    let cohort = cohort_with_many_flows()?;
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let coverage = collect_cohort(&cohort, &budget)?;
    assert_eq!(coverage.references_selected, 1);
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(ENTRIES * size_of::<(i64, usize)>())?);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn unsorted_duplicate_lookups_keep_the_last_witness_and_exact_flow_context() -> TestResult {
    let mut case = Case::new();
    super::add_source(&mut case)?;
    let packet_seven = case.add_bytes_node(
        "ftp_data_candidate",
        b"packet seven",
        vec![super::source_range(7, 0, 12)],
        json!({}),
    )?;
    let packet_one = case.add_bytes_node(
        "ftp_data_candidate",
        b"packet one",
        vec![super::source_range(1, 0, 10)],
        json!({}),
    )?;
    let missing_packet = case.add_bytes_node(
        "ftp_data_candidate",
        b"missing packet",
        vec![super::source_range(u64::from(u32::MAX) + 1, 0, 14)],
        json!({}),
    )?;
    let mut old_ten = super::flow(10);
    old_ten.source_id = "earlier-source".to_owned();
    let mut last_ten = super::flow(10);
    last_ten.source_id = "later-source".to_owned();
    last_ten.scope = json!({"interface": 5});
    let twenty = super::flow(20);
    let expected_ten = serde_json::to_value(&last_ten)?;
    let expected_twenty = serde_json::to_value(&twenty)?;
    let cohort = super::cohort_analysis(
        case,
        vec![twenty, old_ten, last_ten],
        vec![(7, 10), (1, 20), (7, 20), (1, 10)],
    );
    let temporary = tempfile::tempdir()?;
    let mut artifacts = super::super::ArtifactCollection::new(
        temporary.path(),
        super::super::ArtifactLimits::default(),
    )?;
    let budget = MemoryBudget::new(2 * 1024 * 1024);
    super::collect_cohort_artifacts(
        &mut artifacts,
        &cohort,
        Some("cohort-case"),
        &json!({"kind": "cohort"}),
        Some(&budget),
    )?;
    let mut found = 0;
    artifacts.visit_artifact_origins(|_, _, origin| {
        found += 1;
        assert_eq!(origin.case_id.as_deref(), Some("cohort-case"));
        match origin.selected_node_id {
            Some(id) if id == packet_seven => {
                assert_eq!(origin.flow.as_ref(), Some(&expected_twenty));
                assert_eq!(origin.supporting_flows, [expected_twenty.clone()]);
                assert!(origin.cohort_scope.is_none());
            }
            Some(id) if id == packet_one => {
                assert_eq!(origin.flow.as_ref(), Some(&expected_ten));
                assert_eq!(origin.supporting_flows, [expected_ten.clone()]);
                assert!(origin.cohort_scope.is_none());
            }
            Some(id) if id == missing_packet => {
                assert!(origin.flow.is_none());
                assert_eq!(
                    origin.supporting_flows,
                    [expected_ten.clone(), expected_twenty.clone()]
                );
                assert_eq!(
                    origin.cohort_scope,
                    Some(json!({
                        "source_id": "source-20",
                        "scope": null,
                        "unordered_ip_pair": ["192.0.2.1", "198.51.100.2"],
                        "split": false,
                    }))
                );
            }
            _ => return Err("unexpected source node".into()),
        }
        Ok(())
    })?;
    assert_eq!(found, 3);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}
