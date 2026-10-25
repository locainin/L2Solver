use super::{graph::Context, network::value_node};
use crate::{
    evidence::EvidenceStatus,
    measurement::{
        Clock, MessageSample, TimedSample, evaluate_constant_prefix, evaluate_length_fields,
        measure_bytes, measure_timing,
    },
};
use l2_audit::ForensicScope;
use l2_discovery::{TransportHeader, ip_packet};
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::error::Error;

#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct Key {
    scope: ForensicScope,
    source: l2_discovery::NetworkAddress,
    destination: l2_discovery::NetworkAddress,
    ports: (u16, u16),
    protocol: u8,
}
#[derive(Eq, Ord, PartialEq, PartialOrd)]
struct CohortKey {
    scope: ForensicScope,
    endpoint: l2_discovery::NetworkAddress,
    port: u16,
    protocol: u8,
    direction: CohortDirection,
    local_identity: l2_discovery::NetworkAddress,
}
#[derive(Clone, Copy, Eq, Ord, PartialEq, PartialOrd)]
enum CohortDirection {
    ToEndpoint,
    FromEndpoint,
}
struct ConnectionMember {
    series: u64,
    packets: Vec<u32>,
}
struct CohortMember<'a> {
    connection: &'a ConnectionMember,
    peer_endpoint: (l2_discovery::NetworkAddress, u16),
}
struct Sample<'a> {
    packet: u32,
    bytes: &'a [u8],
    time: TimedSample,
}

pub(super) fn add(context: &mut Context<'_>) -> Result<(), Box<dyn Error>> {
    let mut groups: BTreeMap<Key, Vec<Sample<'_>>> = BTreeMap::new();
    let mut omitted = 0;
    for (&packet, captured) in context.records {
        let Some((key, sample)) = sample(captured, packet)? else {
            continue;
        };
        if !groups.contains_key(&key) && groups.len() == 2048 {
            omitted += 1;
            continue;
        }
        let samples = groups.entry(key).or_default();
        if samples.len() == crate::measurement::MAX_SAMPLES {
            omitted += 1;
            continue;
        }
        samples.push(sample);
    }
    let episodes = packet_episodes(context);
    let mut members = Vec::with_capacity(groups.len());
    for (key, samples) in groups {
        let series_id = series(context, &key, &samples)?;
        members.push((
            key,
            ConnectionMember {
                series: series_id,
                packets: samples.iter().map(|sample| sample.packet).collect(),
            },
        ));
    }
    endpoint_cohorts(context, &members, &episodes)?;
    if omitted != 0 {
        context.incomplete = true;
        context.case.add_limitation(&format!(
            "{omitted} carrier samples were omitted after series or sample budgets"
        ))?;
    }
    Ok(())
}

fn sample(
    captured: &l2_capture::CapturedFrame,
    packet: u32,
) -> Result<Option<(Key, Sample<'_>)>, Box<dyn Error>> {
    // The source link type defines the byte layout, even when another parser could accept it
    if !captured.metadata().link_type().is_ethernet() {
        return Ok(None);
    }
    let Ok(frame) = l2_core::decode(captured.bytes()) else {
        return Ok(None);
    };
    let Some(ip) = ip_packet(&frame) else {
        return Ok(None);
    };
    let Some(transport) = ip.transport else {
        return Ok(None);
    };
    let scope = ForensicScope::new(captured.metadata(), &frame);
    let scope_id = serde_json::to_string(&scope)?;
    let timestamp = captured.metadata().timestamp();
    let (radix, exponent, offset) = timestamp.map_or((10, 0, 0), |time| {
        (
            time.resolution().radix(),
            time.resolution().exponent(),
            time.offset_seconds(),
        )
    });
    let clock_id = if timestamp.is_some() {
        format!("capture:{}:{}", scope.section, scope.interface)
    } else {
        "timestamp_not_supplied".to_owned()
    };
    let clock = Clock::new(clock_id, scope_id, radix, exponent, offset)?;
    let key = Key {
        scope,
        source: ip.source,
        destination: ip.destination,
        ports: transport.ports,
        protocol: if matches!(transport.header, TransportHeader::Udp) {
            17
        } else {
            6
        },
    };
    Ok(Some((
        key,
        Sample {
            packet,
            bytes: transport.payload,
            time: TimedSample {
                packet: u64::from(packet),
                clock,
                ticks: timestamp.map(l2_capture::CaptureTimestamp::ticks),
            },
        },
    )))
}

fn series(
    context: &mut Context<'_>,
    key: &Key,
    samples: &[Sample<'_>],
) -> Result<u64, Box<dyn Error>> {
    let id=context.case.add_node("carrier_series",None,Vec::new(),json!({
        "scope":key.scope,"source":key.source,"destination":key.destination,"ports":key.ports,"protocol":key.protocol,
        "samples":samples.len(),"boundary_kind":boundary_kind(key),
        "interpretation":"TCP segment boundaries are not inferred application message boundaries",
    }))?;
    context.packet_edges(
        samples.iter().map(|sample| sample.packet),
        id,
        EvidenceStatus::Observed,
    )?;
    let bytes: Vec<_> = samples.iter().map(|sample| sample.bytes).collect();
    let profile = measure_bytes(&bytes)?;
    let profile_id = value_node(
        context,
        "byte_measurements",
        serde_json::to_value(profile)?,
        &[],
    )?;
    context.edge(
        id,
        profile_id,
        "measured_by",
        EvidenceStatus::Observed,
        "Exact lengths, byte counts, bit planes, case counts, and adjacent repeats were counted",
    )?;
    let times: Vec<_> = samples.iter().map(|sample| sample.time.clone()).collect();
    let timing = measure_timing(&times)?;
    let timing_id = value_node(
        context,
        "timing_measurements",
        json!({"measurements":timing,
        "timebase_lookup":"Referenced packet timestamp metadata defines exact tick units and offsets; absent timestamps have no measured unit"}),
        &[],
    )?;
    context.edge(
        id,
        timing_id,
        "measured_by",
        EvidenceStatus::Observed,
        "Adjacent capture ticks were compared only within the same scope and timebase",
    )?;
    layouts(context, id, key, samples)?;
    Ok(id)
}

fn packet_episodes(context: &Context<'_>) -> HashMap<u32, BTreeSet<u64>> {
    let episode_ids: HashSet<_> = context
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == "tcp_episode")
        .map(|node| node.id)
        .collect();
    let packets_by_node: HashMap<_, _> = context
        .packet_nodes
        .iter()
        .map(|(packet, node)| (*node, *packet))
        .collect();
    let mut memberships: HashMap<u32, BTreeSet<u64>> = HashMap::new();
    for edge in context.case.edges() {
        if edge.relation != "supports" || !episode_ids.contains(&edge.to) {
            continue;
        }
        if let Some(packet) = packets_by_node.get(&edge.from) {
            memberships.entry(*packet).or_default().insert(edge.to);
        }
    }
    memberships
}

fn endpoint_cohorts(
    context: &mut Context<'_>,
    members: &[(Key, ConnectionMember)],
    episodes: &HashMap<u32, BTreeSet<u64>>,
) -> Result<(), Box<dyn Error>> {
    let cohorts = group_cohorts(members);
    for (key, connections) in cohorts {
        let peer_tuples: BTreeSet<_> = connections
            .iter()
            .map(|member| member.peer_endpoint)
            .collect();
        if peer_tuples.len() < 2 {
            continue;
        }
        let packet_count: usize = connections
            .iter()
            .map(|member| member.connection.packets.len())
            .try_fold(0_usize, usize::checked_add)
            .ok_or("carrier cohort packet count overflowed")?;
        let series_ids: BTreeSet<_> = connections
            .iter()
            .map(|member| member.connection.series)
            .collect();
        let episode_ids: BTreeSet<_> = connections
            .iter()
            .flat_map(|member| member.connection.packets.iter())
            .filter_map(|packet| episodes.get(packet))
            .flat_map(|ids| ids.iter().copied())
            .collect();
        let id = context.case.add_node("carrier_endpoint_cohort", None, Vec::new(), json!({
            "scope": key.scope,
            "endpoint": key.endpoint.to_string(),
            "port": key.port,
            "protocol": key.protocol,
            "direction": key.direction.as_str(),
            "local_address": key.local_identity.to_string(),
            "peer_tuple_count": peer_tuples.len(),
            "carrier_series_count": series_ids.len(),
            "packet_count": packet_count,
            "tcp_episode_count": episode_ids.len(),
            "interpretation": "Repeated directional endpoints across distinct peer tuples form a candidate service cohort; this does not establish service identity, endpoint ownership, or intent",
        }))?;
        for series in series_ids {
            context.edge(
                id,
                series,
                "includes_connection",
                EvidenceStatus::Hypothesis,
                "This directional carrier series shares the exact capture scope, endpoint, direction, and local address candidate",
            )?;
        }
        for episode in episode_ids {
            context.edge(
                id,
                episode,
                "contains_candidate_episode",
                EvidenceStatus::Hypothesis,
                "This TCP episode has packet membership in one included directional series",
            )?;
        }
    }
    Ok(())
}

fn group_cohorts(
    members: &[(Key, ConnectionMember)],
) -> BTreeMap<CohortKey, Vec<CohortMember<'_>>> {
    let mut cohorts: BTreeMap<CohortKey, Vec<CohortMember<'_>>> = BTreeMap::new();
    for (key, member) in members {
        // Each direction keeps the opposite address as a cohort identity component
        add_cohort_member(
            &mut cohorts,
            CohortKey {
                scope: key.scope.clone(),
                endpoint: key.destination,
                port: key.ports.1,
                protocol: key.protocol,
                direction: CohortDirection::ToEndpoint,
                local_identity: key.source,
            },
            member,
            (key.source, key.ports.0),
        );
        add_cohort_member(
            &mut cohorts,
            CohortKey {
                scope: key.scope.clone(),
                endpoint: key.source,
                port: key.ports.0,
                protocol: key.protocol,
                direction: CohortDirection::FromEndpoint,
                local_identity: key.destination,
            },
            member,
            (key.destination, key.ports.1),
        );
    }
    cohorts
}

fn add_cohort_member<'a>(
    cohorts: &mut BTreeMap<CohortKey, Vec<CohortMember<'a>>>,
    key: CohortKey,
    member: &'a ConnectionMember,
    peer_endpoint: (l2_discovery::NetworkAddress, u16),
) {
    cohorts.entry(key).or_default().push(CohortMember {
        connection: member,
        peer_endpoint,
    });
}

impl CohortDirection {
    const fn as_str(self) -> &'static str {
        match self {
            Self::ToEndpoint => "to_endpoint",
            Self::FromEndpoint => "from_endpoint",
        }
    }
}

fn layouts(
    context: &mut Context<'_>,
    series: u64,
    key: &Key,
    samples: &[Sample<'_>],
) -> Result<(), Box<dyn Error>> {
    let layout_samples: Vec<_> = samples
        .iter()
        .filter(|sample| !sample.bytes.is_empty())
        .map(|sample| MessageSample::new(u64::from(sample.packet), sample.bytes))
        .collect();
    let details = match evaluate_length_fields(&layout_samples) {
        Ok(mut layout) => {
            let tested = layout.candidates.len();
            // Selection uses only discovery samples; selected holdout counterexamples survive
            layout.candidates.retain(|candidate| {
                candidate.discovery.status == EvidenceStatus::ConstraintSatisfied
            });
            let selected = layout.candidates.len();
            json!({"tested_candidates":tested,"selected_by_discovery":selected,"rejected_or_untestable":tested-selected,
                "results":layout,"boundary_kind":boundary_kind(key)})
        }
        Err(error) => {
            json!({"status":"not_tested","reason":error.to_string(),"boundary_kind":boundary_kind(key)})
        }
    };
    let id = value_node(context, "length_field_hypotheses", details, &[])?;
    context.edge(
        series,
        id,
        "tested_by",
        EvidenceStatus::Hypothesis,
        "Explicit field equations use discovery samples and separate holdout samples",
    )?;
    let prefixes: Vec<_> = [1, 2, 4, 8, 16]
        .into_iter()
        .map(
            |width| match evaluate_constant_prefix(&layout_samples, width) {
                Ok(result) => serde_json::to_value(result),
                Err(error) => {
                    Ok(json!({"width":width,"status":"not_tested","reason":error.to_string()}))
                }
            },
        )
        .collect::<Result<_, _>>()?;
    let id = value_node(
        context,
        "prefix_hypotheses",
        json!({"results":prefixes,"boundary_kind":boundary_kind(key)}),
        &[],
    )?;
    context.edge(series,id,"tested_by",EvidenceStatus::Hypothesis,"Literal discovery prefixes were challenged by held-out samples; mismatches and short samples remain explicit")?;
    Ok(())
}

const fn boundary_kind(key: &Key) -> &'static str {
    if key.protocol == 17 {
        "udp_datagram"
    } else {
        "tcp_segment_payload"
    }
}
