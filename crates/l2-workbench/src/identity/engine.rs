use super::{
    CorrelationOptions, CorrelationPlan, CorrelationReport, IdentityBinding, IdentityCandidate,
    IdentityGroup, ParticipantResolution, ResolutionStatus, ResolvedEvent, Result, Work, clocks,
    invalid, validation,
};
use crate::journal::Event;
use std::collections::{BTreeMap, BTreeSet};

/// Use the journal's exact event representation as the cross-report identity
///
/// # Errors
/// Rejects event values that cannot be serialized
pub fn event_identity(event: &Event) -> Result<String> {
    Ok(crate::sha256(
        &serde_json::to_vec(event).map_err(|e| invalid(e.to_string()))?,
    ))
}

/// Resolve supplied identity and time evidence without inferring device ownership
///
/// # Errors
/// Rejects malformed claims, duplicate event identities, exhausted work or unsupported arithmetic
pub fn correlate(
    events: &[Event],
    plan: &CorrelationPlan,
    options: CorrelationOptions,
) -> Result<CorrelationReport> {
    let mut work = Work {
        maximum: options.max_work_items,
        used: 0,
    };
    validation::validate(plan, options, &mut work)?;
    let bindings = binding_index(&plan.bindings);
    let mut resolved = Vec::new();
    let mut by_identity = BTreeMap::new();
    let mut groups: BTreeMap<String, BTreeSet<usize>> = BTreeMap::new();
    for event in events.iter().take(options.max_events) {
        work.charge()?;
        crate::journal::validate_event(event).map_err(|error| invalid(error.to_string()))?;
        let identity = event_identity(event)?;
        if by_identity
            .insert(identity.clone(), resolved.len())
            .is_some()
        {
            return Err(invalid(
                "duplicate event identities cannot be treated as separate observations",
            ));
        }
        let actor = participant(event, event.actor.as_deref(), &bindings, &mut work)?;
        let peer = participant(event, event.peer.as_deref(), &bindings, &mut work)?;
        for participant in [&actor, &peer]
            .into_iter()
            .flatten()
            .filter(|p| p.status == ResolutionStatus::Unique)
        {
            if let Some(candidate) = participant.candidates.first() {
                groups
                    .entry(candidate.identity.clone())
                    .or_default()
                    .insert(resolved.len());
            }
        }
        resolved.push(ResolvedEvent {
            identity,
            event: event.clone(),
            actor,
            peer,
            times: clocks::intervals(event, &plan.calibrations, &mut work)?,
        });
    }
    let comparisons = comparisons(&plan.comparisons, &by_identity, &resolved, &mut work)?;
    let omitted_events = events.len() - resolved.len();
    let header_associations = super::observations::header_associations(&resolved);
    Ok(CorrelationReport {
        plan_sha256: crate::sha256(&serde_json::to_vec(plan).map_err(|e| invalid(e.to_string()))?),
        bindings: plan.bindings.clone(),
        calibrations: plan.calibrations.clone(),
        events: resolved,
        groups: groups
            .into_iter()
            .map(|(identity, events)| IdentityGroup {
                identity,
                event_indices: events.into_iter().collect(),
            })
            .collect(),
        header_associations,
        comparisons,
        omitted_events,
        work_items: work.used,
        complete: omitted_events == 0,
        limitations: vec![
            "Identity bindings and clock calibrations are supplied evidence claims; source authentication and physical ownership are not established",
            "Equal identity labels group eligible observations; they do not establish dependency or malicious intent",
            "Clock ordering is conditional on the recorded mapping, validity interval and uncertainty; no cross-clock ordering is inferred without a mapping",
            "Missing or omitted observations cannot establish absence; competing identity and clock mappings are retained",
            "MAC/IP header associations describe co-occurring claims; routing, proxies and spoofing prevent an ownership inference",
        ],
    })
}

fn comparisons(
    requests: &[super::ComparisonRequest],
    identities: &BTreeMap<String, usize>,
    events: &[ResolvedEvent],
    work: &mut Work,
) -> Result<Vec<super::TimeComparison>> {
    let mut results = Vec::new();
    for request in requests {
        work.charge()?;
        let left = identities
            .get(&request.left_event)
            .and_then(|index| events.get(*index));
        let right = identities
            .get(&request.right_event)
            .and_then(|index| events.get(*index));
        results.push(clocks::compare(request, left, right, work)?);
    }
    Ok(results)
}
type BindingIndex<'a> = BTreeMap<(&'a str, &'a str, &'a str), Vec<&'a IdentityBinding>>;
fn binding_index(bindings: &[IdentityBinding]) -> BindingIndex<'_> {
    let mut index: BindingIndex<'_> = BTreeMap::new();
    for binding in bindings {
        index
            .entry((
                binding.source.as_str(),
                binding.scope.as_str(),
                binding.subject.as_str(),
            ))
            .or_default()
            .push(binding);
    }
    index
}
fn participant(
    event: &Event,
    subject: Option<&str>,
    bindings: &BindingIndex<'_>,
    work: &mut Work,
) -> Result<Option<ParticipantResolution>> {
    let Some(subject) = subject else {
        return Ok(None);
    };
    let mut candidates: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for binding in bindings
        .get(&(event.source.as_str(), event.scope.as_str(), subject))
        .into_iter()
        .flatten()
    {
        work.charge()?;
        if event.packet >= binding.first_packet
            && binding.last_packet.is_none_or(|last| event.packet <= last)
        {
            candidates
                .entry(binding.identity.clone())
                .or_default()
                .push(binding.id.clone());
        }
    }
    let status = match candidates.len() {
        0 => ResolutionStatus::Unmapped,
        1 => ResolutionStatus::Unique,
        _ => ResolutionStatus::Ambiguous,
    };
    Ok(Some(ParticipantResolution {
        observed: subject.into(),
        status,
        candidates: candidates
            .into_iter()
            .map(|(identity, binding_ids)| IdentityCandidate {
                identity,
                binding_ids,
            })
            .collect(),
    }))
}
