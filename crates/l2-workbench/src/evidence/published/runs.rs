//! Consecutive edge runs shared by the published writer and reader

use super::super::Edge;

pub(super) const MIN_EDGE_RUN: usize = 3;

pub(super) struct Run {
    pub(super) from_step: i8,
    pub(super) to_step: i8,
    pub(super) length: usize,
}

/// Find the longest run beginning at the current insertion-order position
pub(super) fn next_run(edges: &[Edge]) -> Option<Run> {
    let first = edges.first()?;
    let second = edges.get(1)?;
    if !same_description(first, second) {
        return None;
    }
    let from_step = unit_step(first.from, second.from)?;
    let to_step = unit_step(first.to, second.to)?;
    let mut previous = second;
    let mut length = 2;
    for edge in edges.iter().skip(2) {
        if !same_description(first, edge)
            || advance(previous.from, from_step, 1) != Some(edge.from)
            || advance(previous.to, to_step, 1) != Some(edge.to)
        {
            break;
        }
        length += 1;
        previous = edge;
    }
    (length >= MIN_EDGE_RUN).then_some(Run {
        from_step,
        to_step,
        length,
    })
}

fn same_description(first: &Edge, next: &Edge) -> bool {
    first.relation == next.relation && first.status == next.status && first.reason == next.reason
}

fn unit_step(first: u64, next: u64) -> Option<i8> {
    if first == next {
        Some(0)
    } else if first.checked_add(1) == Some(next) {
        Some(1)
    } else if first.checked_sub(1) == Some(next) {
        Some(-1)
    } else {
        None
    }
}

/// Reject an unknown step or an endpoint that would overflow
pub(super) const fn advance(value: u64, step: i8, count: u64) -> Option<u64> {
    match step {
        -1 => value.checked_sub(count),
        0 => Some(value),
        1 => value.checked_add(count),
        _ => None,
    }
}
