//! Build a reusable, source-verified carrier plan from evidence nodes

use super::{
    carriers::{self, CarrierPlan, MappingPlan, SamplePlan, SourcePlan},
    input, load,
};
use l2_workbench::{
    carrier::discovery::{DiscoveryView, MappedNode, mapped_node_with_view},
    carrier::{
        self, Ambiguity, MAX_INPUT_BYTES, MAX_SAMPLE_BYTES, MAX_SAMPLES, MAX_SOURCES, Rule, Sample,
        SourceReader,
    },
    evidence::{ByteMapping, Case, Node},
};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    error::Error,
    io::Write,
    path::{Path, PathBuf},
};

/// Generate a native carrier plan with exact mapped ranges and verified source files
pub(super) fn run(
    case_path: &Path,
    node_ids: &[u64],
    view_name: &str,
    source_paths: &[PathBuf],
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let view = parse_view(view_name)?;
    let case = load(case_path)?;
    let plan = build_plan(&case, node_ids, view, source_paths)?;
    carriers::validate_generated_plan_size(&plan)?;
    serde_json::to_writer(output, &plan)?;
    Ok(case.collection_complete())
}

fn build_plan(
    case: &Case,
    node_ids: &[u64],
    view: DiscoveryView,
    source_paths: &[PathBuf],
) -> Result<CarrierPlan, Box<dyn Error>> {
    if node_ids.is_empty()
        || node_ids.len() > MAX_SAMPLES
        || source_paths.is_empty()
        || source_paths.len() > MAX_SOURCES
    {
        return Err("carrier plan needs bounded selected nodes and source files".into());
    }
    let mut seen = HashSet::with_capacity(node_ids.len());
    let mut samples = Vec::with_capacity(node_ids.len());
    let mut required_sources = BTreeSet::new();
    let mut expected_bytes = Vec::with_capacity(node_ids.len());
    let context_index = CaseContextIndex::build(case);
    let mut total_input = 0_usize;
    let mut total_ranges = 0_usize;
    for node_id in node_ids {
        if !seen.insert(*node_id) {
            return Err("selected node IDs must be unique".into());
        }
        let mapped = mapped_node_with_view(case, *node_id, view)?;
        ensure_supported_kind(mapped.node)?;
        if mapped.bytes.is_empty() || mapped.bytes.len() > MAX_SAMPLE_BYTES {
            return Err("selected sample exceeds the existing carrier sample bound".into());
        }
        total_input = total_input
            .checked_add(mapped.bytes.len())
            .filter(|length| *length <= MAX_INPUT_BYTES)
            .ok_or("selected bytes exceed the existing carrier input bound")?;
        total_ranges = total_ranges
            .checked_add(mapped.mappings.len())
            .filter(|count| *count <= l2_workbench::carrier::MAX_TOTAL_RANGES)
            .ok_or("selected mappings exceed the existing carrier range bound")?;
        for mapping in &mapped.mappings {
            required_sources.insert(mapping.range.source.clone());
        }
        let (event_id, sequence, ambiguity) = sample_context(&context_index, &mapped);
        expected_bytes.push(mapped.bytes);
        samples.push(SamplePlan {
            id: mapped.node.id,
            event_id: Some(event_id),
            sequence,
            length: mapped.bytes.len(),
            mappings: mapped
                .mappings
                .into_iter()
                .map(|mapping| MappingPlan {
                    offset: mapping.offset,
                    range: mapping.range,
                })
                .collect(),
            time: None,
            ambiguity,
        });
    }
    let mut sources = verify_sources(case, &required_sources, source_paths)?;
    verify_retained_bytes(&mut sources.readers, &samples, &expected_bytes)?;
    Ok(CarrierPlan {
        sources: sources.plans,
        samples,
        rules: vec![Rule::Bytes],
        composition: None,
        action: None,
    })
}

struct VerifiedSources {
    plans: Vec<SourcePlan>,
    readers: Vec<SourceReader>,
}

fn verify_retained_bytes(
    sources: &mut [SourceReader],
    samples: &[SamplePlan],
    expected_bytes: &[&[u8]],
) -> Result<(), Box<dyn Error>> {
    if samples.len() != expected_bytes.len() {
        return Err("carrier sample verification inputs disagree".into());
    }
    let mut mappings = Vec::new();
    mappings
        .try_reserve_exact(samples.len())
        .map_err(|_| "carrier mapping verification allocation failed")?;
    for sample in samples {
        let mut sample_mappings = Vec::new();
        sample_mappings
            .try_reserve_exact(sample.mappings.len())
            .map_err(|_| "carrier mapping verification allocation failed")?;
        sample_mappings.extend(sample.mappings.iter().map(|mapping| ByteMapping {
            offset: mapping.offset,
            range: mapping.range.clone(),
        }));
        mappings.push(sample_mappings);
    }

    let mut native = Vec::new();
    native
        .try_reserve_exact(samples.len())
        .map_err(|_| "carrier sample verification allocation failed")?;
    for (sample, sample_mappings) in samples.iter().zip(&mappings) {
        native.push(Sample {
            id: sample.id,
            event_id: sample.event_id.as_deref(),
            sequence: sample.sequence,
            length: sample.length,
            mappings: sample_mappings,
            time: None,
            ambiguity: sample.ambiguity,
        });
    }
    // One canonical pass preserves cross-sample validation and reuses each source index
    carrier::verify_sample_bytes(sources, &native, expected_bytes)?;
    Ok(())
}

fn ensure_supported_kind(node: &Node) -> Result<(), Box<dyn Error>> {
    if matches!(
        node.kind.as_str(),
        "packet"
            | "udp_payload"
            | "tcp_byte_run"
            | "http_body"
            | "ftp_data_candidate"
            | "imported_source"
            | "decoding_output"
    ) {
        Ok(())
    } else {
        Err(format!(
            "node {} ({}) is not a retained byte sample",
            node.id, node.kind
        )
        .into())
    }
}

fn verify_sources(
    case: &Case,
    required: &BTreeSet<String>,
    paths: &[PathBuf],
) -> Result<VerifiedSources, Box<dyn Error>> {
    if required.is_empty() || required.len() != paths.len() {
        return Err(
            "provide exactly one source file for every source range in the selection".into(),
        );
    }
    let expected: BTreeMap<_, _> = case
        .sources()
        .iter()
        .filter(|source| required.contains(&source.id))
        .map(|source| (source.id.clone(), source.length))
        .collect();
    if expected.len() != required.len() {
        return Err("a selected byte mapping references a source missing from the case".into());
    }
    let mut plans = BTreeMap::new();
    for path in paths {
        let reader = SourceReader::identify(input::regular_no_follow(path)?)?;
        let source_id = reader.id().to_owned();
        let expected_length = expected
            .get(&source_id)
            .copied()
            .ok_or("a provided source file does not match a selected source identity")?;
        if reader.length() != expected_length {
            return Err(
                "a provided source file has a different length from the selected source".into(),
            );
        }
        let stored_path = path.canonicalize()?;
        if stored_path.to_str().is_none() {
            return Err("source paths in reusable JSON plans must be valid Unicode".into());
        }
        if plans
            .insert(
                source_id.clone(),
                (
                    SourcePlan {
                        id: source_id,
                        length: expected_length,
                        path: stored_path,
                    },
                    reader,
                ),
            )
            .is_some()
        {
            return Err("each selected source identity must have one supplied path".into());
        }
    }
    let provided: BTreeSet<_> = plans.keys().cloned().collect();
    if provided != required.clone() {
        return Err("one or more selected source files are missing".into());
    }
    let mut source_plans = Vec::new();
    let mut readers = Vec::new();
    source_plans
        .try_reserve_exact(plans.len())
        .map_err(|_| "carrier source plan allocation failed")?;
    readers
        .try_reserve_exact(plans.len())
        .map_err(|_| "carrier source reader allocation failed")?;
    for (plan, reader) in plans.into_values() {
        source_plans.push(plan);
        readers.push(reader);
    }
    Ok(VerifiedSources {
        plans: source_plans,
        readers,
    })
}

fn sample_context(
    context_index: &CaseContextIndex,
    mapped: &MappedNode<'_>,
) -> (String, Option<u64>, Ambiguity) {
    let memberships = context_index
        .episode_memberships
        .get(&mapped.node.id)
        .map_or(&[][..], Vec::as_slice);
    let event_id = match memberships {
        [episode] => format!("tcp_episode:{episode}"),
        [] => format!("sample:{}", mapped.node.id),
        _ => format!("ambiguous_episode_membership:{}", mapped.node.id),
    };
    let sequence = ["record", "available_at_record", "sequence", "offset"]
        .iter()
        .find_map(|key| {
            mapped
                .node
                .details
                .get(*key)
                .and_then(serde_json::Value::as_u64)
        });
    let ambiguous = memberships.len() > 1
        || match mapped.node.kind.as_str() {
            "packet" => {
                mapped
                    .node
                    .details
                    .get("truncated")
                    .and_then(serde_json::Value::as_bool)
                    == Some(true)
                    || mapped
                        .node
                        .details
                        .get("fragmented")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
            }
            "udp_payload" => {
                mapped
                    .node
                    .details
                    .get("identity_ambiguous")
                    .and_then(serde_json::Value::as_bool)
                    != Some(false)
                    || mapped
                        .node
                        .details
                        .get("from_fragments")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
            }
            "tcp_byte_run" => {
                mapped
                    .node
                    .details
                    .get("start_known")
                    .and_then(serde_json::Value::as_bool)
                    != Some(true)
                    || mapped
                        .node
                        .details
                        .get("generation_ambiguous")
                        .and_then(serde_json::Value::as_bool)
                        == Some(true)
                    || context_index
                        .direction_ambiguity
                        .get(&mapped.node.id)
                        .copied()
                        .unwrap_or(true)
            }
            _ => false,
        };
    (
        event_id,
        sequence,
        if ambiguous {
            Ambiguity::MultipleCandidates
        } else {
            Ambiguity::None
        },
    )
}

struct CaseContextIndex {
    episode_memberships: HashMap<u64, Vec<u64>>,
    direction_ambiguity: HashMap<u64, bool>,
}

impl CaseContextIndex {
    fn build(case: &Case) -> Self {
        let episodes: HashSet<_> = case
            .nodes()
            .iter()
            .filter(|node| node.kind == "tcp_episode")
            .map(|node| node.id)
            .collect();
        let directions: HashMap<_, _> = case
            .nodes()
            .iter()
            .filter(|node| node.kind == "tcp_direction")
            .map(|node| {
                (
                    node.id,
                    node.details
                        .get("sequence_ambiguous")
                        .and_then(serde_json::Value::as_bool)
                        != Some(false),
                )
            })
            .collect();
        let mut episode_memberships: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        let mut direction_episodes: HashMap<u64, BTreeSet<u64>> = HashMap::new();
        let mut direction_ambiguity = HashMap::new();
        for edge in case.edges() {
            match edge.relation.as_str() {
                "supports" if episodes.contains(&edge.to) => {
                    episode_memberships
                        .entry(edge.from)
                        .or_default()
                        .insert(edge.to);
                }
                "contains"
                    if episodes.contains(&edge.from) && directions.contains_key(&edge.to) =>
                {
                    direction_episodes
                        .entry(edge.to)
                        .or_default()
                        .insert(edge.from);
                }
                _ => {}
            }
        }
        for edge in case
            .edges()
            .iter()
            .filter(|edge| edge.relation == "contains" && directions.contains_key(&edge.from))
        {
            if let Some(episode_ids) = direction_episodes.get(&edge.from) {
                episode_memberships
                    .entry(edge.to)
                    .or_default()
                    .extend(episode_ids);
            }
            if let Some(ambiguous) = directions.get(&edge.from) {
                direction_ambiguity
                    .entry(edge.to)
                    .and_modify(|current| *current |= *ambiguous)
                    .or_insert(*ambiguous);
            }
        }
        Self {
            episode_memberships: episode_memberships
                .into_iter()
                .map(|(node_id, ids)| (node_id, ids.into_iter().collect()))
                .collect(),
            direction_ambiguity,
        }
    }
}

pub(super) fn parse_view(name: &str) -> Result<DiscoveryView, Box<dyn Error>> {
    match name {
        "bytes" => Ok(DiscoveryView::Bytes),
        "payload" => Ok(DiscoveryView::Payload),
        _ => Err("view must be bytes or payload".into()),
    }
}
