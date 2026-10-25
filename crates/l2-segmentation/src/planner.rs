//! Deterministic bounded plan construction

use l2_canary::{NONCE_LEN, RunId};

use crate::{Agent, DirectedRule, Plan, PlanError, PlanInput, Probe, SegmentId};

/// Maximum number of controlled agents in one plan
pub const MAX_AGENTS: usize = 64;

/// Maximum number of logical segments in one plan
pub const MAX_SEGMENTS: usize = 64;

/// Maximum number of explicit directed policy rules in one plan
pub const MAX_DIRECTED_RULES: usize = 4_096;

/// Maximum number of generated probes in one plan
pub const MAX_PROBES: usize = 4_096;

/// Minimum attempts permitted for one directed rule
pub const MIN_ATTEMPTS_PER_RULE: u8 = 1;

/// Maximum attempts permitted for one directed rule
pub const MAX_ATTEMPTS_PER_RULE: u8 = 8;

const NONCE_MARKER: [u8; 8] = *b"l2seg-v1";

/// Validate input and generate a stable plan with no transmission side effects
///
/// Rules are sorted by source and destination, agents by segment and identity,
/// and probes by rule, source agent, destination agent, and attempt number
/// Reverse direction is generated only when its own rule is present
///
/// # Errors
///
/// Returns [`PlanError`] when a collection, relationship, or generated probe
/// count falls outside the fixed planner bounds
pub fn plan(input: &PlanInput) -> Result<Plan, PlanError> {
    // Reject oversized input before any collection is cloned
    validate_collection_bounds(input)?;

    // Sorting makes equivalent input produce byte-for-byte equal plan data
    let segments = sorted_segments(input)?;
    let agents = sorted_agents(input, &segments)?;
    let rules = sorted_rules(input, &segments)?;

    // Probe capacity is checked before allocation and material generation
    let probes = build_probes(input.run_id_value(), &agents, &rules)?;

    Ok(Plan {
        run_id: input.run_id_value(),
        segments,
        agents,
        rules,
        probes,
    })
}

impl TryFrom<&PlanInput> for Plan {
    type Error = PlanError;

    fn try_from(input: &PlanInput) -> Result<Self, Self::Error> {
        plan(input)
    }
}

const fn validate_collection_bounds(input: &PlanInput) -> Result<(), PlanError> {
    if input.agents.len() > MAX_AGENTS {
        return Err(PlanError::AgentLimitExceeded {
            count: input.agents.len(),
            maximum: MAX_AGENTS,
        });
    }
    if input.segments.len() > MAX_SEGMENTS {
        return Err(PlanError::SegmentLimitExceeded {
            count: input.segments.len(),
            maximum: MAX_SEGMENTS,
        });
    }
    if input.rules.len() > MAX_DIRECTED_RULES {
        return Err(PlanError::RuleLimitExceeded {
            count: input.rules.len(),
            maximum: MAX_DIRECTED_RULES,
        });
    }
    Ok(())
}

fn sorted_segments(input: &PlanInput) -> Result<Vec<SegmentId>, PlanError> {
    let mut segments = input.segments.clone();
    segments.sort_unstable();

    let mut previous = None;
    for segment in &segments {
        if previous == Some(*segment) {
            return Err(PlanError::DuplicateSegment { segment: *segment });
        }
        previous = Some(*segment);
    }
    Ok(segments)
}

fn sorted_agents(input: &PlanInput, segments: &[SegmentId]) -> Result<Vec<Agent>, PlanError> {
    // Segment order is the primary key so rule scans stay stable
    let mut agents = input.agents.clone();
    agents.sort_unstable_by_key(|agent| (agent.segment(), agent.id()));

    let mut identities = std::collections::BTreeSet::new();
    for agent in &agents {
        // Every agent must belong to the declared inventory
        if !segments.contains(&agent.segment()) {
            return Err(PlanError::UnknownAgentSegment {
                agent: agent.id(),
                segment: agent.segment(),
            });
        }
        if !identities.insert(agent.id()) {
            return Err(PlanError::DuplicateAgent { agent: agent.id() });
        }
    }
    Ok(agents)
}

fn sorted_rules(input: &PlanInput, segments: &[SegmentId]) -> Result<Vec<DirectedRule>, PlanError> {
    // A direction is unique by its two segment endpoints
    let mut rules = input.rules.clone();
    rules.sort_unstable_by_key(|rule| (rule.source, rule.destination));

    let mut previous = None;
    for rule in &rules {
        // Validate references before building any canary material
        if !segments.contains(&rule.source) {
            return Err(PlanError::UnknownSourceSegment {
                segment: rule.source,
            });
        }
        if !segments.contains(&rule.destination) {
            return Err(PlanError::UnknownDestinationSegment {
                segment: rule.destination,
            });
        }
        if !(MIN_ATTEMPTS_PER_RULE..=MAX_ATTEMPTS_PER_RULE).contains(&rule.attempts) {
            return Err(PlanError::AttemptsOutOfRange {
                source: rule.source,
                destination: rule.destination,
                attempts: rule.attempts,
                minimum: MIN_ATTEMPTS_PER_RULE,
                maximum: MAX_ATTEMPTS_PER_RULE,
            });
        }
        let direction = (rule.source, rule.destination);
        if previous == Some(direction) {
            return Err(PlanError::DuplicateRule {
                source: rule.source,
                destination: rule.destination,
            });
        }
        previous = Some(direction);
    }
    Ok(rules)
}

fn build_probes(
    run_id: RunId,
    agents: &[Agent],
    rules: &[DirectedRule],
) -> Result<Vec<Probe>, PlanError> {
    let expected_count = count_probes(agents, rules)?;
    if expected_count > MAX_PROBES {
        return Err(PlanError::ProbeLimitExceeded {
            count: expected_count,
            maximum: MAX_PROBES,
        });
    }

    let mut probes = Vec::with_capacity(expected_count);
    let mut sequence = 1_u64;
    for rule in rules {
        // Each explicit rule expands only across its own agent pairs
        for source in agents.iter().filter(|agent| agent.segment() == rule.source) {
            for destination in agents
                .iter()
                .filter(|agent| agent.segment() == rule.destination)
            {
                // A same-segment rule tests traffic between agents, never an agent against itself
                if source.id() == destination.id() {
                    continue;
                }
                for attempt in MIN_ATTEMPTS_PER_RULE..=rule.attempts {
                    // Sequence and nonce together identify one planned attempt
                    let nonce = nonce_for(sequence)?;
                    probes.push(Probe {
                        run_id,
                        source: *source,
                        destination: *destination,
                        expectation: rule.expectation,
                        attempt,
                        sequence,
                        nonce,
                    });
                    sequence = sequence.checked_add(1).ok_or(PlanError::SequenceOverflow)?;
                }
            }
        }
    }
    Ok(probes)
}

fn count_probes(agents: &[Agent], rules: &[DirectedRule]) -> Result<usize, PlanError> {
    let mut total = 0_usize;
    for rule in rules {
        // Count before allocation so the fixed probe ceiling remains effective
        let source_count = agents
            .iter()
            .filter(|agent| agent.segment() == rule.source)
            .count();
        let pairs = if rule.source == rule.destination {
            // A same-segment path needs two endpoints for a meaningful direction
            if source_count < 2 {
                return Err(PlanError::NoDistinctAgentPairs {
                    segment: rule.source,
                });
            }
            source_count
                .checked_mul(source_count - 1)
                .ok_or(PlanError::ProbeCountOverflow)?
        } else {
            if source_count == 0 {
                return Err(PlanError::NoSourceAgents {
                    source: rule.source,
                    destination: rule.destination,
                });
            }
            let destination_count = agents
                .iter()
                .filter(|agent| agent.segment() == rule.destination)
                .count();
            if destination_count == 0 {
                return Err(PlanError::NoDestinationAgents {
                    source: rule.source,
                    destination: rule.destination,
                });
            }
            source_count
                .checked_mul(destination_count)
                .ok_or(PlanError::ProbeCountOverflow)?
        };
        let rule_count = pairs
            .checked_mul(usize::from(rule.attempts))
            .ok_or(PlanError::ProbeCountOverflow)?;
        total = total
            .checked_add(rule_count)
            .ok_or(PlanError::ProbeCountOverflow)?;
    }
    Ok(total)
}

fn nonce_for(sequence: u64) -> Result<[u8; NONCE_LEN], PlanError> {
    let mut nonce = [0_u8; NONCE_LEN];
    let sequence_bytes = sequence.to_be_bytes();
    let Some(prefix) = nonce.get_mut(..sequence_bytes.len()) else {
        return Err(PlanError::SequenceOverflow);
    };
    prefix.copy_from_slice(&sequence_bytes);
    let Some(suffix) = nonce.get_mut(sequence_bytes.len()..) else {
        return Err(PlanError::SequenceOverflow);
    };
    suffix.copy_from_slice(&NONCE_MARKER);
    Ok(nonce)
}
