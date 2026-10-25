use super::visit;
use l2_workbench::{
    evidence::{Edge, Source},
    query::QueryMatch,
};
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Serialize)]
pub(super) struct PacketFilter {
    pub source_id: String,
    pub expression: String,
}

#[derive(Serialize)]
pub(super) struct ScopedMatch {
    pub page: Option<String>,
    #[serde(flatten)]
    pub evidence: QueryMatch,
    pub blob: Option<String>,
    pub details: Value,
    pub relations: Vec<Edge>,
    pub packet_filters: Vec<PacketFilter>,
}

#[derive(Serialize)]
pub(super) struct QueryReport<'a> {
    pub inventory: visit::VisitSummary,
    pub sources: Vec<Source>,
    pub filters: &'a [String],
    pub matched_nodes: usize,
    pub omitted_matches: usize,
    pub complete: bool,
    pub matches: Vec<ScopedMatch>,
    pub case_limitations: BTreeSet<String>,
    pub omitted_limitation_occurrences: usize,
    pub limitations: Vec<&'static str>,
}
