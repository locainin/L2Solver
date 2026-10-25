//! Query views share one selector and retain the saved explanation beside each match

mod model;
mod packets;
mod presentation;

use super::visit;
use crate::{arguments::OutputFormat, output::BoundedWriter};
use l2_workbench::{
    evidence::{Case, Edge, MAX_LIMITATIONS, Source},
    query::{Selector, select},
};
use model::{QueryReport, ScopedMatch};
use std::{
    collections::{BTreeSet, HashMap},
    error::Error,
    io::Write,
    path::Path,
};

#[derive(Default)]
struct Collection {
    sources: Vec<Source>,
    matched_nodes: usize,
    matches: Vec<ScopedMatch>,
    bytes: usize,
    case_limitations: BTreeSet<String>,
    omitted_limitation_occurrences: usize,
}

pub(super) fn run(
    path: &Path,
    filters: &[String],
    maximum: usize,
    max_report_bytes: usize,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let values: Vec<_> = filters.iter().map(String::as_str).collect();
    let selector = Selector::parse(&values)?;
    let mut collection = Collection::default();
    let inventory = visit::cases(path, |case, page| {
        collection.observe(case, &page, &selector, maximum, max_report_bytes)
    })?;
    let omitted_matches = collection.matched_nodes - collection.matches.len();
    let complete = inventory.collection_complete
        && omitted_matches == 0
        && collection.omitted_limitation_occurrences == 0;
    let report = QueryReport {
        inventory,
        sources: collection.sources,
        filters,
        matched_nodes: collection.matched_nodes,
        omitted_matches,
        complete,
        matches: collection.matches,
        case_limitations: collection.case_limitations,
        omitted_limitation_occurrences: collection.omitted_limitation_occurrences,
        limitations: vec![
            "Selectors describe retained evidence; omissions and unsupported protocols prevent claims of absence",
            "Bundle node IDs and relation endpoints are local to their page; context-only packet matches are excluded",
            "Graph integrity and page hashes are checked here; exact capture bytes require independent source validation",
            "Packet filters identify supporting records in the named source, including context; open the original matching capture, not a renumbered subset",
            "Relation statuses describe individual saved edges, not a verified interpretation of the whole node",
            "Auxiliary VLAN, interface, section, and clock values are capture parser metadata and require source validation",
        ],
    };
    match format {
        OutputFormat::Json => serde_json::to_writer(output, &report)?,
        OutputFormat::Text => presentation::text(&report, output)?,
        OutputFormat::Html => presentation::html(&report, output)?,
    }
    Ok(complete)
}

impl Collection {
    fn observe(
        &mut self,
        case: &Case,
        page: &visit::PageContext<'_>,
        selector: &Selector,
        maximum: usize,
        max_report_bytes: usize,
    ) -> Result<(), Box<dyn Error>> {
        for source in case.sources() {
            if !self.sources.iter().any(|saved| saved.id == source.id) {
                self.sources.push(source.clone());
            }
        }
        for limitation in case.limitations() {
            if self.case_limitations.len() < MAX_LIMITATIONS
                || self.case_limitations.contains(limitation)
            {
                self.case_limitations.insert(limitation.clone());
            } else {
                self.omitted_limitation_occurrences += 1;
            }
        }
        // Look up saved explanations once per page rather than rescanning its graph per match
        let nodes: HashMap<_, _> = case.nodes().iter().map(|node| (node.id, node)).collect();
        let mut edges: HashMap<_, Vec<&Edge>> = HashMap::new();
        for edge in case.edges() {
            edges.entry(edge.from).or_default().push(edge);
            if edge.from != edge.to {
                edges.entry(edge.to).or_default().push(edge);
            }
        }
        for evidence in select(case, selector) {
            if page.primary.is_some_and(|(first, last)| {
                !evidence.packet_numbers.is_empty()
                    && !evidence
                        .packet_numbers
                        .iter()
                        .any(|number| (u64::from(first)..=u64::from(last)).contains(number))
            }) {
                continue;
            }
            self.matched_nodes += 1;
            if self.matches.len() == maximum {
                continue;
            }
            let node = nodes
                .get(&evidence.node_id)
                .ok_or("query selected a missing saved node")?;
            let result = ScopedMatch {
                page: page.path.map(str::to_owned),
                blob: node.blob.clone(),
                details: node.details.clone(),
                relations: edges
                    .get(&node.id)
                    .into_iter()
                    .flatten()
                    .map(|edge| (*edge).clone())
                    .collect(),
                packet_filters: packets::filters(&evidence.source_ranges),
                evidence,
            };
            // Count JSON through the shared writer without allocating a second match document
            let mut counter = BoundedWriter::named(
                std::io::sink(),
                max_report_bytes - self.bytes,
                "query match",
            );
            match serde_json::to_writer(&mut counter, &result) {
                Ok(()) => {
                    self.bytes += counter.written();
                    self.matches.push(result);
                }
                // The sink cannot fail; an I/O error means this match exceeded the byte budget
                Err(error) if error.is_io() => {}
                Err(error) => return Err(error.into()),
            }
        }
        Ok(())
    }
}
