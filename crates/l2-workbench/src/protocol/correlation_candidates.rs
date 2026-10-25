use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Write as _,
};

use super::{
    CorrelationAlias, CorrelationCandidate, CorrelationCandidateFit, CorrelationCandidateReport,
    CorrelationCounterexample, Direction, MessageContext, MessageRole, MessageSample,
    ProtocolError, ProtocolLimits,
    sampling::{field, groups_for_indices, split_indices, validate_samples},
};

const MIN_SAMPLES: usize = 4;
const MAX_FIELD_OFFSET: usize = 32;
const CANDIDATE_WIDTHS: [usize; 4] = [1, 2, 4, 8];
const MAX_CANDIDATE_COUNTEREXAMPLES: usize = 16;
const MAX_CANDIDATE_ALIASES: usize = 16;
const LIMITATIONS: [&str; 4] = [
    "Candidates describe equality across caller-labeled request and response cohorts, not transaction identity",
    "Candidates use only earlier requests in the same source, scope, session, and opposite direction when context is present",
    "Several field positions may produce the same observed support pattern and remain aliases",
    "Field-position search covers offsets below 32 and widths 1, 2, 4, and 8 bytes; other layouts remain untested",
];
const NEXT_OBSERVATION: &str = "Collect a session where the remaining field-position candidates predict different equality outcomes";

/// Search bounded request and response prefixes for session-compatible field equality
///
/// Candidate positions are learned from discovery cohorts and scored on independent
/// holdout cohorts. Equality alone does not identify a transaction field
///
/// # Errors
/// Returns an error when samples, context, holdout groups, or limits are invalid
pub fn infer_correlation_candidates(
    samples: &[MessageSample<'_>],
    limits: ProtocolLimits,
) -> Result<CorrelationCandidateReport, ProtocolError> {
    let contextual = validate_samples(samples, MIN_SAMPLES, limits)?;
    let split = split_indices(samples, contextual)?;
    let hypotheses = discover_hypotheses(samples, &split.discovery, contextual)?;
    let omitted_candidates = hypotheses.len().saturating_sub(limits.max_candidates);
    let retained = hypotheses
        .into_iter()
        .take(limits.max_candidates)
        .collect::<Vec<_>>();

    let discovery_groups = groups_for_indices(samples, &split.discovery, contextual)?;
    let holdout_groups = groups_for_indices(samples, &split.holdout, contextual)?;
    let mut evaluated = BTreeMap::new();
    for hypothesis in retained {
        let (discovery, discovery_signature) =
            evaluate_hypothesis(samples, &discovery_groups, hypothesis, contextual)?;
        let (holdout, holdout_signature) =
            evaluate_hypothesis(samples, &holdout_groups, hypothesis, contextual)?;
        let candidate = CorrelationCandidate {
            request_offset: hypothesis.request_offset,
            response_offset: hypothesis.response_offset,
            width: hypothesis.width,
            discovery,
            holdout,
            aliases: Vec::new(),
            omitted_aliases: 0,
        };
        evaluated.insert(
            hypothesis,
            EvaluatedCandidate {
                candidate,
                signature: CandidateSignature {
                    discovery: discovery_signature,
                    holdout: holdout_signature,
                },
            },
        );
    }

    let candidates = candidates_with_aliases(&evaluated);
    Ok(CorrelationCandidateReport {
        candidates,
        discovery_samples: sample_ids(samples, &split.discovery)?,
        holdout_samples: sample_ids(samples, &split.holdout)?,
        split_basis: split.basis,
        omitted_candidates,
        next_observation: NEXT_OBSERVATION,
        limitations: LIMITATIONS.to_vec(),
    })
}

fn candidates_with_aliases(
    evaluated: &BTreeMap<FieldHypothesis, EvaluatedCandidate>,
) -> Vec<CorrelationCandidate> {
    let mut aliases = BTreeMap::<CandidateSignature, Vec<FieldHypothesis>>::new();
    for (hypothesis, candidate) in evaluated {
        aliases
            .entry(candidate.signature.clone())
            .or_default()
            .push(*hypothesis);
    }
    evaluated
        .iter()
        .map(|(hypothesis, evaluated_candidate)| {
            let mut candidate = evaluated_candidate.candidate.clone();
            if let Some(aliases) = aliases.get(&evaluated_candidate.signature) {
                let alternatives = aliases
                    .iter()
                    .filter(|alias| *alias != hypothesis)
                    .collect::<Vec<_>>();
                candidate.omitted_aliases =
                    alternatives.len().saturating_sub(MAX_CANDIDATE_ALIASES);
                candidate.aliases = alternatives
                    .iter()
                    .take(MAX_CANDIDATE_ALIASES)
                    .filter_map(|alias| {
                        evaluated
                            .get(alias)
                            .map(|alias_candidate| CorrelationAlias {
                                request_offset: alias.request_offset,
                                response_offset: alias.response_offset,
                                width: alias.width,
                                discovery_supported_sessions: alias_candidate
                                    .candidate
                                    .discovery
                                    .supported_sessions,
                                holdout_supported_sessions: alias_candidate
                                    .candidate
                                    .holdout
                                    .supported_sessions,
                            })
                    })
                    .collect();
            }
            candidate
        })
        .collect()
}

fn discover_hypotheses(
    samples: &[MessageSample<'_>],
    indices: &[usize],
    contextual: bool,
) -> Result<Vec<FieldHypothesis>, ProtocolError> {
    let groups = groups_for_indices(samples, indices, contextual)?;
    let mut hypotheses = BTreeSet::new();
    for group in groups {
        let mut prior_requests =
            BTreeMap::<(Option<Direction>, usize, Vec<u8>), BTreeSet<usize>>::new();
        for index in group {
            let sample = samples
                .get(index)
                .ok_or(ProtocolError::InsufficientSamples {
                    count: samples.len(),
                })?;
            let direction = sample.context.as_ref().map(|context| context.direction);
            match sample.role {
                MessageRole::Request => {
                    for width in CANDIDATE_WIDTHS {
                        for offset in 0..MAX_FIELD_OFFSET {
                            if let Some(value) = field(sample.bytes, offset, width) {
                                prior_requests
                                    .entry((direction, width, value.to_vec()))
                                    .or_default()
                                    .insert(offset);
                            }
                        }
                    }
                }
                MessageRole::Response => {
                    let request_direction = direction.map(Direction::opposite);
                    for width in CANDIDATE_WIDTHS {
                        for response_offset in 0..MAX_FIELD_OFFSET {
                            let Some(value) = field(sample.bytes, response_offset, width) else {
                                continue;
                            };
                            let Some(request_offsets) =
                                prior_requests.get(&(request_direction, width, value.to_vec()))
                            else {
                                continue;
                            };
                            for request_offset in request_offsets {
                                hypotheses.insert(FieldHypothesis {
                                    request_offset: *request_offset,
                                    response_offset,
                                    width,
                                });
                            }
                        }
                    }
                }
                MessageRole::Unclassified => {}
            }
        }
    }
    Ok(hypotheses.into_iter().collect())
}

fn evaluate_hypothesis(
    samples: &[MessageSample<'_>],
    groups: &[Vec<usize>],
    hypothesis: FieldHypothesis,
    contextual: bool,
) -> Result<(CorrelationCandidateFit, Vec<CohortOutcome>), ProtocolError> {
    let mut fit = CorrelationCandidateFit {
        session_count: groups.len(),
        compared_sessions: 0,
        supported_sessions: 0,
        counterexample_count: 0,
        untestable_sessions: 0,
        counterexamples: Vec::new(),
        omitted_counterexamples: 0,
    };
    let mut signature = Vec::with_capacity(groups.len());
    for group in groups {
        match evaluate_group(samples, group, hypothesis, contextual)? {
            GroupOutcome::Supported(key) => {
                fit.compared_sessions += 1;
                fit.supported_sessions += 1;
                signature.push(CohortOutcome {
                    key,
                    supported: Some(true),
                });
            }
            GroupOutcome::Counterexample(key, example) => {
                fit.compared_sessions += 1;
                fit.counterexample_count += 1;
                if fit.counterexamples.len() < MAX_CANDIDATE_COUNTEREXAMPLES {
                    fit.counterexamples.push(example);
                } else {
                    fit.omitted_counterexamples += 1;
                }
                signature.push(CohortOutcome {
                    key,
                    supported: Some(false),
                });
            }
            GroupOutcome::Untestable(key) => {
                fit.untestable_sessions += 1;
                signature.push(CohortOutcome {
                    key,
                    supported: None,
                });
            }
        }
    }
    Ok((fit, signature))
}

fn evaluate_group(
    samples: &[MessageSample<'_>],
    group: &[usize],
    hypothesis: FieldHypothesis,
    contextual: bool,
) -> Result<GroupOutcome, ProtocolError> {
    let group_context = group
        .first()
        .and_then(|index| samples.get(*index))
        .and_then(|sample| sample.context.as_ref());
    let key = CohortKey::from_context(group_context);
    let mut prior_requests = BTreeMap::<Option<Direction>, Vec<(u64, Vec<u8>)>>::new();
    let mut first_mismatch = None;
    let mut compared = false;
    for index in group {
        let sample = samples
            .get(*index)
            .ok_or(ProtocolError::InsufficientSamples {
                count: samples.len(),
            })?;
        let direction = if contextual {
            sample.context.as_ref().map(|context| context.direction)
        } else {
            None
        };
        match sample.role {
            MessageRole::Request => {
                if let Some(value) =
                    field(sample.bytes, hypothesis.request_offset, hypothesis.width)
                {
                    prior_requests
                        .entry(direction)
                        .or_default()
                        .push((sample.sample, value.to_vec()));
                }
            }
            MessageRole::Response => {
                let Some(value) = field(sample.bytes, hypothesis.response_offset, hypothesis.width)
                else {
                    continue;
                };
                let request_direction = direction.map(Direction::opposite);
                let Some(requests) = prior_requests.get(&request_direction) else {
                    continue;
                };
                let Some((request_sample, request_value)) = requests.first() else {
                    continue;
                };
                compared = true;
                if requests
                    .iter()
                    .any(|(_, candidate)| candidate.as_slice() == value)
                {
                    return Ok(GroupOutcome::Supported(key));
                }
                if first_mismatch.is_none() {
                    first_mismatch = Some(CorrelationCounterexample {
                        session: group_context.map(|context| context.session),
                        request_sample: *request_sample,
                        response_sample: sample.sample,
                        request_value_hex: hex(request_value),
                        response_value_hex: hex(value),
                    });
                }
            }
            MessageRole::Unclassified => {}
        }
    }
    match (compared, first_mismatch) {
        (true, Some(example)) => Ok(GroupOutcome::Counterexample(key, example)),
        _ => Ok(GroupOutcome::Untestable(key)),
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(result, "{byte:02x}");
    }
    result
}

fn sample_ids(samples: &[MessageSample<'_>], indices: &[usize]) -> Result<Vec<u64>, ProtocolError> {
    indices
        .iter()
        .map(|index| {
            samples.get(*index).map(|sample| sample.sample).ok_or(
                ProtocolError::InsufficientSamples {
                    count: samples.len(),
                },
            )
        })
        .collect()
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct FieldHypothesis {
    request_offset: usize,
    response_offset: usize,
    width: usize,
}

#[derive(Clone)]
struct EvaluatedCandidate {
    candidate: CorrelationCandidate,
    signature: CandidateSignature,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CandidateSignature {
    discovery: Vec<CohortOutcome>,
    holdout: Vec<CohortOutcome>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CohortOutcome {
    key: CohortKey,
    supported: Option<bool>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct CohortKey {
    source: Option<String>,
    scope: Option<String>,
    session: Option<u64>,
}

impl CohortKey {
    fn from_context(context: Option<&MessageContext>) -> Self {
        Self {
            source: context.map(|context| context.source.clone()),
            scope: context.map(|context| context.scope.clone()),
            session: context.map(|context| context.session),
        }
    }
}

enum GroupOutcome {
    Supported(CohortKey),
    Counterexample(CohortKey, CorrelationCounterexample),
    Untestable(CohortKey),
}
