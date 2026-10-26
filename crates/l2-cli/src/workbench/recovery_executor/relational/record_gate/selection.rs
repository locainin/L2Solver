use super::super::super::RecoveryExecutionError;
use super::super::DecodedFrameOutput;
use super::super::{invalid_policy, operational};
use std::collections::{BTreeMap, BTreeSet};

pub(super) struct LearningSelection {
    pub(super) indices: Vec<usize>,
    pub(super) omitted_messages: usize,
    pub(super) session_count: usize,
}

pub(super) fn select_learning_frames(
    frames: &[DecodedFrameOutput],
    maximum_messages: usize,
    discovery: &BTreeSet<u64>,
    heldout: &BTreeSet<u64>,
) -> Result<LearningSelection, RecoveryExecutionError> {
    let mut by_session = BTreeMap::<(u64, u64), Vec<usize>>::new();
    for (index, frame) in frames.iter().enumerate() {
        if !discovery.contains(&frame.context.session) && !heldout.contains(&frame.context.session)
        {
            continue;
        }
        by_session
            .entry((frame.session_order, frame.context.session))
            .or_default()
            .push(index);
    }
    let required_sessions = discovery.union(heldout).copied().collect::<BTreeSet<_>>();
    if required_sessions.len() != by_session.len()
        || required_sessions.is_empty()
        || maximum_messages < required_sessions.len()
    {
        return Ok(LearningSelection {
            indices: Vec::new(),
            omitted_messages: frames.len(),
            session_count: by_session.len(),
        });
    }
    let total_messages = by_session
        .values()
        .try_fold(0_usize, |total, items| total.checked_add(items.len()))
        .ok_or_else(|| invalid_policy("record gate message count overflowed"))?;
    let selection_limit = total_messages.min(maximum_messages);
    let mut indices = Vec::new();
    indices
        .try_reserve_exact(selection_limit)
        .map_err(|source| operational("record gate selection allocation failed", source))?;
    let sessions = by_session.into_values().collect::<Vec<_>>();
    let mut next_per_session = vec![0_usize; sessions.len()];
    // Take one frame per session at a time so large sessions cannot fill the budget first
    while indices.len() < selection_limit {
        let mut added = false;
        for (session_index, session_frames) in sessions.iter().enumerate() {
            let position = next_per_session
                .get_mut(session_index)
                .ok_or_else(|| invalid_policy("record gate session cursor is missing"))?;
            if let Some(frame_index) = session_frames.get(*position) {
                indices.push(*frame_index);
                *position = position.saturating_add(1);
                added = true;
                if indices.len() == selection_limit {
                    break;
                }
            }
        }
        if !added {
            break;
        }
    }
    Ok(LearningSelection {
        indices,
        omitted_messages: total_messages.saturating_sub(selection_limit),
        session_count: sessions.len(),
    })
}
