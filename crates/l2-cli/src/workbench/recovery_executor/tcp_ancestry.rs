//! Resolve TCP ancestry only when its recorded parent links are unique

use l2_workbench::evidence::{Case, Edge, EvidenceStatus, Node};
use std::collections::HashMap;

#[cfg(test)]
#[path = "../../../tests/workbench/recovery_executor/tcp_ancestry.rs"]
mod tests;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct TcpAncestry {
    pub(super) direction_node_id: u64,
    pub(super) direction_contains_status: EvidenceStatus,
    pub(super) episode_node_id: u64,
    pub(super) episode_contains_status: EvidenceStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TcpAncestryError {
    Missing,
    Ambiguous,
    Invalid,
}

#[derive(Clone, Copy)]
struct ParentLink {
    node_id: u64,
    status: EvidenceStatus,
}

#[derive(Default)]
pub(super) struct TcpAncestryIndex {
    direction_parents: HashMap<u64, Vec<ParentLink>>,
    episode_parents: HashMap<u64, Vec<ParentLink>>,
}

impl TcpAncestryIndex {
    pub(super) fn index_edge(
        &mut self,
        edge: &Edge,
        nodes: &HashMap<u64, &Node>,
    ) -> Result<(), std::collections::TryReserveError> {
        if edge.relation != "contains" {
            return Ok(());
        }
        let (Some(parent), Some(child)) = (nodes.get(&edge.from), nodes.get(&edge.to)) else {
            return Ok(());
        };
        let parents = match (parent.kind.as_str(), child.kind.as_str()) {
            ("tcp_direction", "tcp_byte_run") => &mut self.direction_parents,
            ("tcp_episode", "tcp_direction") => &mut self.episode_parents,
            _ => return Ok(()),
        };
        // Reserve only for a new child; repeated observations share the same map slot
        if !parents.contains_key(&child.id) {
            parents.try_reserve(1)?;
        }
        let links = parents.entry(child.id).or_default();
        links.try_reserve(1)?;
        links.push(ParentLink {
            node_id: parent.id,
            status: edge.status,
        });
        Ok(())
    }

    pub(super) fn index_case(
        case: &Case,
        nodes: &HashMap<u64, &Node>,
    ) -> Result<Self, std::collections::TryReserveError> {
        let mut index = Self::default();
        for edge in case.edges() {
            index.index_edge(edge, nodes)?;
        }
        Ok(index)
    }

    pub(super) fn resolve_run(&self, run_id: u64) -> Result<TcpAncestry, TcpAncestryError> {
        let direction = unique_parent(&self.direction_parents, run_id)?;
        if direction.status != EvidenceStatus::Observed {
            return Err(TcpAncestryError::Invalid);
        }
        let episode = unique_parent(&self.episode_parents, direction.node_id)?;
        if !episode_context_status(episode.status) {
            return Err(TcpAncestryError::Invalid);
        }
        Ok(TcpAncestry {
            direction_node_id: direction.node_id,
            direction_contains_status: direction.status,
            episode_node_id: episode.node_id,
            episode_contains_status: episode.status,
        })
    }
}

fn unique_parent(
    parents: &HashMap<u64, Vec<ParentLink>>,
    child_id: u64,
) -> Result<ParentLink, TcpAncestryError> {
    match parents.get(&child_id).map(Vec::as_slice) {
        None | Some([]) => Err(TcpAncestryError::Missing),
        Some([parent]) => Ok(*parent),
        Some(_) => Err(TcpAncestryError::Ambiguous),
    }
}

const fn episode_context_status(status: EvidenceStatus) -> bool {
    matches!(
        status,
        EvidenceStatus::Observed | EvidenceStatus::Hypothesis
    )
}
