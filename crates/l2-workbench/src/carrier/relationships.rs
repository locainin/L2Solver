use super::{
    fingerprint::{equivalent_values, exact_value_hash},
    model::{
        Ambiguity, CarrierError, MAX_REPORT_RANGES, Observation, Omission, OmissionReason,
        Relationship, RelationshipMember, Report, Rule, TimingStatus, Value,
    },
};
use std::collections::{BTreeMap, BTreeSet};

const MAX_RELATIONSHIPS: usize = 16_384;
const MAX_RELATIONSHIP_MEMBERS: usize = 1024;
const MAX_OMISSION_DETAILS: usize = super::model::MAX_OMISSION_DETAILS;
type ObservationBuckets = BTreeMap<(Rule, [u8; 32]), Vec<usize>>;

#[derive(Clone, Copy)]
struct RelationshipFacts {
    cross_sources: bool,
    cross_events: bool,
    ambiguity: Ambiguity,
}

pub(super) fn add_relationships(
    report: &mut Report,
    retained_ranges: &mut usize,
) -> Result<(), CarrierError> {
    let buckets = observation_buckets(&report.observations)?;
    for ((rule, digest), indexes) in buckets {
        for group in exact_groups(&report.observations, &indexes)? {
            if group.len() < 2 {
                continue;
            }
            let Some(facts) = relationship_facts(&report.observations, &group)? else {
                continue;
            };
            if !facts.cross_sources && !facts.cross_events {
                continue;
            }
            add_relationship(report, retained_ranges, &rule, digest, group, facts);
        }
    }
    Ok(())
}

fn observation_buckets(observations: &[Observation]) -> Result<ObservationBuckets, CarrierError> {
    let mut buckets = ObservationBuckets::new();
    for (index, observation) in observations.iter().enumerate() {
        let Some(value) = observation.value.as_ref() else {
            continue;
        };
        if !relation_value_supported(value) {
            continue;
        }
        let digest = exact_value_hash(&observation.rule, value)?;
        // Hashes narrow the lookup; exact comparison below also guards against collisions
        buckets
            .entry((observation.rule.clone(), digest))
            .or_default()
            .push(index);
    }
    Ok(buckets)
}

const fn relation_value_supported(value: &Value) -> bool {
    match value {
        Value::Timing {
            delta_ticks: Some(_),
            status: TimingStatus::Measured,
            left_clock: Some(_),
            right_clock: Some(_),
            ..
        } => true,
        Value::Timing { .. } => false,
        _ => true,
    }
}

fn exact_groups(
    observations: &[Observation],
    indexes: &[usize],
) -> Result<Vec<Vec<usize>>, CarrierError> {
    let mut groups: Vec<Vec<usize>> = Vec::new();
    for index in indexes {
        let observation = observations
            .get(*index)
            .ok_or(CarrierError::InvalidSampleId)?;
        let value = observation
            .value
            .as_ref()
            .ok_or(CarrierError::InvalidSampleId)?;
        let mut matched = false;
        for group in &mut groups {
            let representative_index = group.first().ok_or(CarrierError::InvalidSampleId)?;
            let representative = observations
                .get(*representative_index)
                .and_then(|candidate| candidate.value.as_ref())
                .ok_or(CarrierError::InvalidSampleId)?;
            if equivalent_values(value, representative) {
                group.push(*index);
                matched = true;
                break;
            }
        }
        if !matched {
            groups.push(vec![*index]);
        }
    }
    Ok(groups)
}

fn relationship_facts(
    observations: &[Observation],
    indexes: &[usize],
) -> Result<Option<RelationshipFacts>, CarrierError> {
    let mut sources = BTreeSet::new();
    let mut events = BTreeSet::new();
    let mut ambiguity = Ambiguity::None;
    for index in indexes {
        let observation = observations
            .get(*index)
            .ok_or(CarrierError::InvalidSampleId)?;
        for range in &observation.ranges {
            sources.insert(range.source.clone());
        }
        if let Some(event_id) = &observation.event_id {
            events.insert(event_id.clone());
        }
        if observation.ambiguity == Ambiguity::MultipleCandidates {
            ambiguity = Ambiguity::MultipleCandidates;
        }
    }
    if sources.is_empty() {
        return Ok(None);
    }
    Ok(Some(RelationshipFacts {
        cross_sources: sources.len() > 1,
        cross_events: events.len() > 1,
        ambiguity,
    }))
}

fn add_relationship(
    report: &mut Report,
    retained_ranges: &mut usize,
    rule: &Rule,
    digest: [u8; 32],
    indexes: Vec<usize>,
    facts: RelationshipFacts,
) {
    if report.relationships.len() == MAX_RELATIONSHIPS {
        omit_relationship(report, rule, indexes.len());
        return;
    }
    let member_count = indexes.len();
    let mut members = Vec::with_capacity(member_count.min(MAX_RELATIONSHIP_MEMBERS));
    for index in indexes {
        if members.len() == MAX_RELATIONSHIP_MEMBERS {
            continue;
        }
        let Some(observation) = report.observations.get(index) else {
            continue;
        };
        let Some(sample_id) = observation.sample_ids.first().copied() else {
            continue;
        };
        let Some(next_ranges) = retained_ranges.checked_add(observation.ranges.len()) else {
            report.complete = false;
            continue;
        };
        if next_ranges > MAX_REPORT_RANGES {
            report.complete = false;
            continue;
        }
        *retained_ranges = next_ranges;
        members.push(RelationshipMember {
            observation_id: observation.id,
            sample_id,
            event_id: observation.event_id.clone(),
            ranges: observation.ranges.clone(),
            ambiguity: observation.ambiguity,
        });
    }
    let omitted_members = member_count.saturating_sub(members.len());
    if omitted_members > 0 {
        omit_relationship(report, rule, omitted_members);
    }
    report.relationships.push(Relationship {
        rule: rule.clone(),
        value_sha256: digest_hex(&digest),
        members,
        member_count,
        omitted_members,
        cross_sources: facts.cross_sources,
        cross_events: facts.cross_events,
        ambiguity: facts.ambiguity,
    });
}

fn omit_relationship(report: &mut Report, rule: &Rule, count: usize) {
    report.complete = false;
    report.omitted_count = report.omitted_count.saturating_add(count);
    if report.omissions.len() < MAX_OMISSION_DETAILS {
        report.omissions.push(Omission {
            sample_id: None,
            rule: rule.clone(),
            reason: OmissionReason::ReportBudget,
        });
    }
}

fn digest_hex(digest: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(64);
    for byte in digest {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        if let Some(digit) = HEX.get(high) {
            output.push(char::from(*digit));
        }
        if let Some(digit) = HEX.get(low) {
            output.push(char::from(*digit));
        }
    }
    output
}
