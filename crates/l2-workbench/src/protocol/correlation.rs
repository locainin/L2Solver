use std::collections::BTreeMap;

use super::model::{
    CorrelationReport, CorrelationSplit, CorrelationStatus, FieldTransition, MessageContext,
    MessageRole, MessageSample, ProtocolError, ProtocolLimits,
};
use super::sampling::{field, sample_refs, split_indices, validate_limits, validate_samples};

const MIN_SAMPLES: usize = 4;
const LIMITATIONS: [&str; 2] = [
    "Field equality is an explicit candidate relationship and does not establish protocol meaning",
    "Context limits equality matches to one source, scope, session, and opposite direction",
];

/// Correlate caller-selected request and response fields in capture order
///
/// Requests with unavailable fields are counted as untestable. A unique match
/// consumes its pending request; ambiguous requests remain pending for later
/// responses. Discovery and holdout state never share requests
///
/// # Errors
/// Returns an error when samples, fields, identifiers, or byte budgets are invalid
pub fn correlate_fields(
    samples: &[MessageSample<'_>],
    request_offset: usize,
    response_offset: usize,
    width: usize,
) -> Result<CorrelationReport, ProtocolError> {
    correlate_fields_with_limits(
        samples,
        request_offset,
        response_offset,
        width,
        ProtocolLimits::default(),
    )
}

/// Correlate request and response fields under caller-selected checked resource budgets
///
/// # Errors
/// Returns an error when samples, context, fields, holdout groups, or limits are invalid
pub fn correlate_fields_with_limits(
    samples: &[MessageSample<'_>],
    request_offset: usize,
    response_offset: usize,
    width: usize,
    limits: ProtocolLimits,
) -> Result<CorrelationReport, ProtocolError> {
    validate_limits(limits)?;
    validate_hypothesis(
        request_offset,
        response_offset,
        width,
        limits.max_message_bytes,
    )?;
    let contextual = validate_samples(samples, MIN_SAMPLES, limits)?;
    let split = split_indices(samples, contextual)?;
    let discovery_samples = sample_refs(samples, &split.discovery)?;
    let holdout_samples = sample_refs(samples, &split.holdout)?;
    Ok(CorrelationReport {
        request_offset,
        response_offset,
        width,
        split_basis: split.basis,
        discovery: correlate_split(&discovery_samples, request_offset, response_offset, width),
        holdout: correlate_split(&holdout_samples, request_offset, response_offset, width),
        limitations: LIMITATIONS.to_vec(),
    })
}

fn validate_hypothesis(
    request_offset: usize,
    response_offset: usize,
    width: usize,
    maximum_message_bytes: usize,
) -> Result<(), ProtocolError> {
    if width == 0 {
        return Err(ProtocolError::InvalidFieldWidth {
            width,
            maximum: maximum_message_bytes,
        });
    }
    for offset in [request_offset, response_offset] {
        if offset
            .checked_add(width)
            .is_none_or(|end| end > maximum_message_bytes)
        {
            return Err(ProtocolError::InvalidFieldRange {
                offset,
                width,
                maximum: maximum_message_bytes,
            });
        }
    }
    Ok(())
}

fn correlate_split(
    samples: &[&MessageSample<'_>],
    request_offset: usize,
    response_offset: usize,
    width: usize,
) -> CorrelationSplit {
    let mut pending = BTreeMap::<Vec<u8>, Vec<PendingRequest>>::new();
    let mut transitions = Vec::new();
    let mut untestable_requests = 0;
    for sample in samples {
        match sample.role {
            MessageRole::Request => {
                if let Some(value) = field(sample.bytes, request_offset, width) {
                    pending
                        .entry(value.to_vec())
                        .or_default()
                        .push(PendingRequest {
                            sample: sample.sample,
                            context: sample.context.clone(),
                        });
                } else {
                    untestable_requests += 1;
                }
            }
            MessageRole::Response => transitions.push(response_transition(
                sample,
                &mut pending,
                response_offset,
                width,
            )),
            MessageRole::Unclassified => {}
        }
    }
    CorrelationSplit {
        samples: samples.iter().map(|sample| sample.sample).collect(),
        transitions,
        pending_requests: pending.values().map(Vec::len).sum(),
        untestable_requests,
    }
}

fn response_transition(
    sample: &MessageSample<'_>,
    pending: &mut BTreeMap<Vec<u8>, Vec<PendingRequest>>,
    offset: usize,
    width: usize,
) -> FieldTransition {
    let Some(value) = field(sample.bytes, offset, width) else {
        return empty_transition(sample.sample, CorrelationStatus::Untestable);
    };
    let Some(requests) = pending.get(value) else {
        return empty_transition(sample.sample, CorrelationStatus::Unmatched);
    };
    let context = classify_matches(requests, sample.context.as_ref());
    match context.compatible_ids.as_slice() {
        [] => FieldTransition {
            response_sample: sample.sample,
            status: if context.cross_session_equal_count > 0 {
                CorrelationStatus::CrossSessionEqual
            } else if context.equal_outside_context_count > 0 {
                CorrelationStatus::ContextMismatch
            } else {
                CorrelationStatus::Unmatched
            },
            candidate_count: 0,
            candidate_requests: Vec::new(),
            request_sample: None,
            equal_outside_context_count: context.equal_outside_context_count,
            cross_session_equal_count: context.cross_session_equal_count,
            equal_outside_context_requests: context.equal_outside_context_requests,
            omitted_equal_outside_context_requests: context.omitted_equal_outside_context_requests,
            omitted_candidate_requests: 0,
        },
        [request] => {
            if let Some(requests) = pending.get_mut(value) {
                requests.retain(|candidate| candidate.sample != *request);
                if requests.is_empty() {
                    pending.remove(value);
                }
            }
            FieldTransition {
                response_sample: sample.sample,
                status: CorrelationStatus::Unique,
                candidate_count: 1,
                candidate_requests: vec![*request],
                request_sample: Some(*request),
                equal_outside_context_count: context.equal_outside_context_count,
                cross_session_equal_count: context.cross_session_equal_count,
                equal_outside_context_requests: context.equal_outside_context_requests,
                omitted_equal_outside_context_requests: context
                    .omitted_equal_outside_context_requests,
                omitted_candidate_requests: 0,
            }
        }
        candidates => {
            let candidate_requests = candidates
                .iter()
                .take(super::MAX_MATCH_CANDIDATES)
                .copied()
                .collect::<Vec<_>>();
            FieldTransition {
                response_sample: sample.sample,
                status: CorrelationStatus::Ambiguous,
                candidate_count: candidates.len(),
                omitted_candidate_requests: candidates
                    .len()
                    .saturating_sub(candidate_requests.len()),
                candidate_requests,
                request_sample: None,
                equal_outside_context_count: context.equal_outside_context_count,
                cross_session_equal_count: context.cross_session_equal_count,
                equal_outside_context_requests: context.equal_outside_context_requests,
                omitted_equal_outside_context_requests: context
                    .omitted_equal_outside_context_requests,
            }
        }
    }
}

const fn empty_transition(response_sample: u64, status: CorrelationStatus) -> FieldTransition {
    FieldTransition {
        response_sample,
        status,
        candidate_count: 0,
        candidate_requests: Vec::new(),
        request_sample: None,
        equal_outside_context_count: 0,
        cross_session_equal_count: 0,
        equal_outside_context_requests: Vec::new(),
        omitted_equal_outside_context_requests: 0,
        omitted_candidate_requests: 0,
    }
}

struct ClassifiedMatches {
    compatible_ids: Vec<u64>,
    equal_outside_context_count: usize,
    cross_session_equal_count: usize,
    equal_outside_context_requests: Vec<u64>,
    omitted_equal_outside_context_requests: usize,
}

fn classify_matches(
    requests: &[PendingRequest],
    response: Option<&MessageContext>,
) -> ClassifiedMatches {
    let compatible_ids = requests
        .iter()
        .filter(|request| compatible(request.context.as_ref(), response))
        .map(|request| request.sample)
        .collect::<Vec<_>>();
    let outside = requests
        .iter()
        .filter(|request| !compatible(request.context.as_ref(), response))
        .collect::<Vec<_>>();
    let cross_session_equal_count = outside
        .iter()
        .filter(|request| different_session_in_scope(request.context.as_ref(), response))
        .count();
    let equal_outside_context_requests = outside
        .iter()
        .take(super::MAX_MATCH_CANDIDATES)
        .map(|request| request.sample)
        .collect::<Vec<_>>();
    let equal_outside_context_count = outside.len();
    ClassifiedMatches {
        compatible_ids,
        equal_outside_context_count,
        cross_session_equal_count,
        omitted_equal_outside_context_requests: equal_outside_context_count
            .saturating_sub(equal_outside_context_requests.len()),
        equal_outside_context_requests,
    }
}

#[derive(Clone)]
struct PendingRequest {
    sample: u64,
    context: Option<MessageContext>,
}

fn compatible(request: Option<&MessageContext>, response: Option<&MessageContext>) -> bool {
    match (request, response) {
        (None, None) => true,
        (Some(request), Some(response)) => {
            same_session(Some(request), Some(response))
                && request.direction.opposite() == response.direction
        }
        _ => false,
    }
}

fn same_session(left: Option<&MessageContext>, right: Option<&MessageContext>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => {
            left.source == right.source
                && left.scope == right.scope
                && left.session == right.session
        }
        _ => false,
    }
}

fn different_session_in_scope(
    request: Option<&MessageContext>,
    response: Option<&MessageContext>,
) -> bool {
    match (request, response) {
        (Some(request), Some(response)) => {
            request.source == response.source
                && request.scope == response.scope
                && request.session != response.session
        }
        _ => false,
    }
}
