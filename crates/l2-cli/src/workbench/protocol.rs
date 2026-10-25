use super::{load, selected};
use crate::arguments::ProtocolAnalysisArgs;
use l2_workbench::{
    evidence::{Case, Node},
    protocol::{
        self, ByteRunSample, Direction, MessageContext, MessageRole, MessageSample, ProtocolError,
    },
};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    error::Error,
    io::Write,
    path::Path,
};

const RUN_ROLE_LIMITATION: &str = "An unclassified tcp_byte_run is a stream; assign a request or response role to analyze the whole run as one caller-selected message, or enable --infer-run-boundaries to inspect boundary hypotheses";
const MESSAGE_LIMITATION: &str = "Caller-selected message samples use the explicit sample label as their boundary assumption; reconstructed TCP run boundaries alone do not establish application message boundaries";
const RUN_MESSAGE_ASSUMPTION: &str = "caller_selected_message";
const RUN_STREAM_ASSUMPTION: &str = "candidate_boundaries";

pub(super) fn run(
    path: &Path,
    samples: &[String],
    field: Option<&str>,
    analysis: &ProtocolAnalysisArgs,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let limits = analysis.limits();
    check_sample_count(samples.len(), limits.max_samples)?;
    let case = load(path)?;
    let lineage = ContextLineage::new(&case);
    let collected = collect_samples(
        &case,
        &lineage,
        samples,
        limits,
        analysis.infer_run_boundaries,
    )?;
    let boundary_extractions = infer_run_boundaries(&collected.runs, limits)?;
    let framing = infer_framing(&collected.messages, &collected.runs, limits)?;
    let correlation =
        infer_selected_correlation(&collected.messages, &collected.runs, field, limits)?;
    let correlation_candidates = infer_correlation_candidates(&collected.messages, limits)?;

    serde_json::to_writer(
        output,
        &json!({
            "case_collection_complete": case.collection_complete(),
            "protocol_limits": limits,
            "samples": collected.provenance,
            "framing": framing,
            "correlation": correlation,
            "correlation_candidates": correlation_candidates,
            "boundary_extractions": boundary_extractions,
            "boundary_assumptions": if collected.runs.is_empty() { vec![MESSAGE_LIMITATION] } else { vec![RUN_ROLE_LIMITATION] },
        }),
    )?;
    Ok(case.collection_complete())
}

const fn check_sample_count(count: usize, maximum: usize) -> Result<(), ProtocolError> {
    if count > maximum {
        return Err(ProtocolError::TooManySamples { count, maximum });
    }
    Ok(())
}

struct CollectedSamples<'a> {
    messages: Vec<MessageSample<'a>>,
    runs: Vec<ByteRunSample<'a>>,
    provenance: Vec<serde_json::Value>,
    selected_bytes: usize,
}

fn collect_samples<'a>(
    case: &'a Case,
    lineage: &ContextLineage<'a>,
    samples: &[String],
    limits: protocol::ProtocolLimits,
    infer_runs: bool,
) -> Result<CollectedSamples<'a>, Box<dyn Error>> {
    let mut collected = CollectedSamples {
        messages: Vec::with_capacity(samples.len()),
        runs: Vec::new(),
        provenance: Vec::with_capacity(samples.len()),
        selected_bytes: 0,
    };
    for sample in samples {
        collect_sample(case, lineage, sample, limits, infer_runs, &mut collected)?;
    }
    Ok(collected)
}

fn collect_sample<'a>(
    case: &'a Case,
    lineage: &ContextLineage<'a>,
    sample: &str,
    limits: protocol::ProtocolLimits,
    infer_runs: bool,
    collected: &mut CollectedSamples<'a>,
) -> Result<(), Box<dyn Error>> {
    let (id, role) = sample
        .split_once(':')
        .ok_or("sample must use NODE:ROLE syntax")?;
    let id = id.parse::<u64>()?;
    let role = parse_role(role)?;
    let (node, bytes) = selected::bytes(case, id)?;
    account_selected_bytes(collected, bytes.len(), limits.max_total_bytes)?;
    let context = message_context(lineage, node)?;
    let context_provenance = context.clone();
    let boundary_assumption =
        if node.kind == "tcp_byte_run" && role == MessageRole::Unclassified && infer_runs {
            collected.runs.push(ByteRunSample {
                sample: id,
                context,
                bytes,
            });
            RUN_STREAM_ASSUMPTION
        } else {
            if node.kind == "tcp_byte_run" && role == MessageRole::Unclassified {
                return Err(RUN_ROLE_LIMITATION.into());
            }
            collected.messages.push(MessageSample {
                sample: id,
                role,
                bytes,
                context,
            });
            RUN_MESSAGE_ASSUMPTION
        };
    collected.provenance.push(
        json!({"node_id":id,"kind":node.kind,"blob":node.blob,"source_ranges":node.ranges,"context":context_provenance,"boundary_assumption":boundary_assumption}),
    );
    Ok(())
}

fn parse_role(role: &str) -> Result<MessageRole, Box<dyn Error>> {
    match role {
        "request" => Ok(MessageRole::Request),
        "response" => Ok(MessageRole::Response),
        "unclassified" => Ok(MessageRole::Unclassified),
        _ => Err("sample role must be request, response, or unclassified".into()),
    }
}

fn account_selected_bytes(
    collected: &mut CollectedSamples<'_>,
    sample_bytes: usize,
    maximum: usize,
) -> Result<(), ProtocolError> {
    collected.selected_bytes = collected.selected_bytes.checked_add(sample_bytes).ok_or(
        ProtocolError::TotalBytesTooLarge {
            total: usize::MAX,
            maximum,
        },
    )?;
    if collected.selected_bytes > maximum {
        return Err(ProtocolError::TotalBytesTooLarge {
            total: collected.selected_bytes,
            maximum,
        });
    }
    Ok(())
}

fn infer_run_boundaries(
    runs: &[ByteRunSample<'_>],
    limits: protocol::ProtocolLimits,
) -> Result<Vec<protocol::BoundaryExtractionReport>, ProtocolError> {
    runs.iter()
        .map(|run| protocol::infer_run_boundaries_with_limits(run, limits))
        .collect()
}

fn infer_framing(
    messages: &[MessageSample<'_>],
    runs: &[ByteRunSample<'_>],
    limits: protocol::ProtocolLimits,
) -> Result<Option<protocol::FramingReport>, ProtocolError> {
    if messages.len() >= 4 || (runs.is_empty() && !messages.is_empty()) {
        Ok(Some(protocol::infer_framing_with_limits(messages, limits)?))
    } else {
        Ok(None)
    }
}

fn infer_selected_correlation(
    messages: &[MessageSample<'_>],
    runs: &[ByteRunSample<'_>],
    field: Option<&str>,
    limits: protocol::ProtocolLimits,
) -> Result<Option<protocol::CorrelationReport>, Box<dyn Error>> {
    if !runs.is_empty() && !messages.is_empty() && messages.len() < 4 && field.is_some() {
        return Err(
            "explicit field correlation needs at least four complete message samples".into(),
        );
    }
    field
        .map(|field| {
            let (request, remaining) = field
                .split_once(':')
                .ok_or("field must use REQUEST_OFFSET:RESPONSE_OFFSET:WIDTH")?;
            let (response, width) = remaining
                .split_once(':')
                .ok_or("field must use REQUEST_OFFSET:RESPONSE_OFFSET:WIDTH")?;
            Ok(protocol::correlate_fields_with_limits(
                messages,
                request.parse()?,
                response.parse()?,
                width.parse()?,
                limits,
            )?)
        })
        .transpose()
}

fn infer_correlation_candidates(
    messages: &[MessageSample<'_>],
    limits: protocol::ProtocolLimits,
) -> Result<Option<protocol::CorrelationCandidateReport>, ProtocolError> {
    if messages.len() >= 4 {
        Ok(Some(protocol::infer_correlation_candidates(
            messages, limits,
        )?))
    } else {
        Ok(None)
    }
}

fn message_context(
    lineage: &ContextLineage<'_>,
    node: &Node,
) -> Result<Option<MessageContext>, Box<dyn Error>> {
    let Some(direction_node) = lineage.tcp_direction_ancestor(node.id) else {
        return Ok(None);
    };
    let sessions = lineage
        .parents
        .get(&direction_node.id)
        .into_iter()
        .flatten()
        .filter(|parent| parent.contains)
        .filter_map(|parent| lineage.nodes.get(&parent.node).copied())
        .filter(|candidate| candidate.kind == "tcp_episode")
        .collect::<Vec<_>>();
    let [session_node] = sessions.as_slice() else {
        return Ok(None);
    };
    let sources = node
        .ranges
        .iter()
        .map(|range| range.source.as_str())
        .collect::<BTreeSet<_>>();
    let Some(source) = sources.first().copied() else {
        return Ok(None);
    };
    if sources.len() != 1 {
        return Ok(None);
    }
    let Some(scope) = session_node.details.get("scope") else {
        return Ok(None);
    };
    let Some(endpoints) = session_node
        .details
        .get("endpoints")
        .and_then(serde_json::Value::as_array)
    else {
        return Ok(None);
    };
    let [first, second] = endpoints.as_slice() else {
        return Ok(None);
    };
    let Some(direction_source) = direction_node.details.get("source") else {
        return Ok(None);
    };
    let Some(direction_destination) = direction_node.details.get("destination") else {
        return Ok(None);
    };
    let direction = if direction_source == first && direction_destination == second {
        Direction::FirstToSecond
    } else if direction_source == second && direction_destination == first {
        Direction::SecondToFirst
    } else {
        return Ok(None);
    };
    let scope = serde_json::to_string(scope)?;
    Ok(Some(MessageContext {
        source: source.to_owned(),
        scope,
        session: session_node.id,
        direction,
    }))
}

struct ContextLineage<'a> {
    nodes: HashMap<u64, &'a Node>,
    parents: HashMap<u64, Vec<ParentLink>>,
}

struct ParentLink {
    node: u64,
    contains: bool,
}

impl<'a> ContextLineage<'a> {
    fn new(case: &'a Case) -> Self {
        let nodes = case.nodes().iter().map(|node| (node.id, node)).collect();
        let mut parents = HashMap::<u64, Vec<ParentLink>>::new();
        for edge in case
            .edges()
            .iter()
            .filter(|edge| matches!(edge.relation.as_str(), "contains" | "parsed_as"))
        {
            parents.entry(edge.to).or_default().push(ParentLink {
                node: edge.from,
                contains: edge.relation == "contains",
            });
        }
        Self { nodes, parents }
    }

    fn tcp_direction_ancestor(&self, start: u64) -> Option<&'a Node> {
        // Resolve every owner at the nearest graph depth before choosing one
        let mut frontier = BTreeSet::from([start]);
        let mut visited = BTreeSet::from([start]);
        while !frontier.is_empty() {
            let mut next_frontier = BTreeSet::new();
            let mut directions = BTreeMap::new();
            for child in frontier {
                for parent_link in self.parents.get(&child).into_iter().flatten() {
                    if !visited.insert(parent_link.node) {
                        continue;
                    }
                    let Some(parent) = self.nodes.get(&parent_link.node).copied() else {
                        continue;
                    };
                    if parent.kind == "tcp_direction" {
                        directions.insert(parent.id, parent);
                    } else {
                        next_frontier.insert(parent.id);
                    }
                }
            }
            match directions.len() {
                0 => frontier = next_frontier,
                1 => return directions.into_values().next(),
                _ => return None,
            }
        }
        None
    }
}
