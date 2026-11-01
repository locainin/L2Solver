//! Bound and account for switching candidates using the common listener

use std::{sync::atomic::AtomicBool, time::Instant};

use l2_capture::CapturedFrame;

use crate::{ActiveLink, Limits, RunError, RunSummary, session::run_listen_until};

// Keep retained evidence bounded independently of packet and byte budgets
const MAX_OBSERVATIONS: usize = 64;

pub(super) struct Collection<T> {
    pub observations: Vec<T>,
    pub unmatched_packets: u32,
    pub summary: RunSummary,
}

pub(super) fn collect<E, T>(
    link: &mut impl ActiveLink,
    limits: Limits,
    cancelled: &AtomicBool,
    deadline: Instant,
    classify: impl Fn(&[u8]) -> Option<E>,
    observation: impl Fn(CapturedFrame, E) -> T,
) -> Result<Collection<T>, RunError> {
    let mut observations = Vec::new();
    observations
        .try_reserve_exact(MAX_OBSERVATIONS)
        .map_err(|_| RunError::Allocation)?;
    let mut unmatched_packets = 0;
    let summary = run_listen_until(link, limits, cancelled, deadline, |frame| {
        classify(frame.bytes()).map_or_else(
            || {
                unmatched_packets += 1;
                false
            },
            |evidence| {
                observations.push(observation(frame, evidence));
                observations.len() == MAX_OBSERVATIONS
            },
        )
    })?;
    Ok(Collection {
        observations,
        unmatched_packets,
        summary,
    })
}
