use super::*;
use crate::workbench::recovery_executor::lookup_fixture as fixture;
use serde_json::json;
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;

struct TcpGraph {
    case: Case,
    episode: u64,
    direction: u64,
    run: u64,
}

fn tcp_graph() -> TestResult<TcpGraph> {
    let mut case = Case::new();
    let episode = case.add_node("tcp_episode", None, Vec::new(), json!({}))?;
    let direction = case.add_node("tcp_direction", None, Vec::new(), json!({}))?;
    let run = case.add_node("tcp_byte_run", None, Vec::new(), json!({}))?;
    fixture::link(
        &mut case,
        episode,
        direction,
        "contains",
        EvidenceStatus::Hypothesis,
    )?;
    fixture::link(
        &mut case,
        direction,
        run,
        "contains",
        EvidenceStatus::Observed,
    )?;
    Ok(TcpGraph {
        case,
        episode,
        direction,
        run,
    })
}

fn index(case: &Case) -> TestResult<TcpAncestryIndex> {
    let nodes = case.nodes().iter().map(|node| (node.id, node)).collect();
    Ok(TcpAncestryIndex::index_case(case, &nodes)?)
}

#[test]
fn unrelated_edges_do_not_increase_tcp_parent_table_capacity() -> TestResult<()> {
    let mut graph = tcp_graph()?;
    let baseline = index(&graph.case)?;
    fixture::unrelated_edges(&mut graph.case, "supports", 4_096)?;
    let extended = index(&graph.case)?;
    assert_eq!(
        extended.direction_parents.capacity(),
        baseline.direction_parents.capacity()
    );
    assert_eq!(
        extended.episode_parents.capacity(),
        baseline.episode_parents.capacity()
    );
    let resolved = extended
        .resolve_run(graph.run)
        .map_err(|_| "ancestry was lost")?;
    assert_eq!(resolved.direction_node_id, graph.direction);
    assert_eq!(resolved.episode_node_id, graph.episode);
    assert_eq!(resolved.direction_contains_status, EvidenceStatus::Observed);
    assert_eq!(resolved.episode_contains_status, EvidenceStatus::Hypothesis);
    Ok(())
}

#[test]
fn non_tcp_contains_edges_do_not_allocate_tcp_parent_tables() -> TestResult<()> {
    let mut case = Case::new();
    fixture::unrelated_edges(&mut case, "contains", 4_096)?;
    let indexed = index(&case)?;
    assert_eq!(indexed.direction_parents.capacity(), 0);
    assert_eq!(indexed.episode_parents.capacity(), 0);
    Ok(())
}

#[test]
fn repeated_parent_observations_remain_ambiguous_without_extra_map_slots() -> TestResult<()> {
    let mut graph = tcp_graph()?;
    let baseline = index(&graph.case)?;
    for _ in 0..4_096 {
        fixture::link(
            &mut graph.case,
            graph.direction,
            graph.run,
            "contains",
            EvidenceStatus::Observed,
        )?;
    }
    let extended = index(&graph.case)?;
    assert_eq!(extended.direction_parents.len(), 1);
    assert_eq!(
        extended.direction_parents.capacity(),
        baseline.direction_parents.capacity()
    );
    assert_eq!(
        extended.direction_parents.get(&graph.run).map(Vec::len),
        Some(4_097)
    );
    assert_eq!(
        extended.resolve_run(graph.run),
        Err(TcpAncestryError::Ambiguous)
    );
    Ok(())
}
