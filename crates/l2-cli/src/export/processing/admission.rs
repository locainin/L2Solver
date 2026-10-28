//! Reserve Case startup growth before dispatching work to the recovery pool

#[cfg(test)]
#[path = "../../../tests/export/admission.rs"]
mod tests;

use super::{PendingCase, case_mut};
use crate::export::recovery_cache::RecoveryContext;
use l2_workbench::{
    evidence::Case,
    job::{MemoryBudget, MemoryError, MemorySnapshot, MemoryWorkingSet, Phase},
    protocol::ProtocolLimits,
};
use std::error::Error;

// Four missed monitor intervals make an old observation unsuitable for a new admission
const MAX_SAMPLE_AGE_MS: u64 = 1_000;
// This margin covers uncharged runtime allocations; it is not an RSS guarantee
const SAFETY_MARGIN_DIVISOR: u64 = 8;

/// Hold a worker's reservation until its recovery and snapshot writes finish
#[derive(Debug)]
pub(super) struct Admission {
    working_set: Option<MemoryWorkingSet>,
}

impl Admission {
    pub(super) fn memory(&self) -> Option<&MemoryBudget> {
        self.working_set.as_ref().map(MemoryWorkingSet::budget)
    }
}

pub(super) fn admit(
    pending: &mut PendingCase,
    active: usize,
    context: &RecoveryContext<'_>,
) -> Result<Option<Admission>, Box<dyn Error>> {
    if let Some(job) = context.job {
        job.check_cancelled()?;
    }
    let Some(memory) = context.memory else {
        return Ok(Some(Admission { working_set: None }));
    };
    let growth = startup_growth(case_mut(&mut pending.item))?;
    let mut snapshot = memory.snapshot()?;
    if snapshot.system.is_some() || snapshot.system_observation_failures != 0 {
        // Reuse the job's OS monitor; component-only budgets do not enable process accounting
        crate::recovery_job::refresh_memory_observation(memory)?;
        snapshot = memory.snapshot()?;
    }
    let admission = check_pressure(&snapshot, growth).and_then(|()| memory.try_working_set(growth));
    match admission {
        Ok(work) => {
            case_mut(&mut pending.item).use_working_set(&work)?;
            Ok(Some(Admission {
                working_set: Some(work),
            }))
        }
        Err(MemoryError::Limit { .. } | MemoryError::Pressure { .. }) if active > 0 => {
            if let Some(job) = context.job {
                job.set_current(
                    Phase::FramingRecordDiscovery,
                    "Waiting for active recovery and buffered Case memory",
                )?;
            }
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

fn startup_growth(case: &Case) -> Result<u64, Box<dyn Error>> {
    let usage = case.resource_usage();
    let retained = match case.charged_memory_bytes() {
        Some(bytes) => bytes,
        None => u64::try_from(usage.blob_bytes)? + u64::try_from(usage.details_bytes)?,
    };
    // Cache restoration and graph growth reuse a retained-Case allowance at separate stages
    // Evidence transactions keep incremental checkpoints instead of cloning the whole Case
    // Later graph growth uses live leases and can exceed this initial forecast only if it fits
    let reports = u64::try_from(ProtocolLimits::default().max_report_bytes)?;
    reports
        .checked_mul(2)
        .and_then(|reports| retained.checked_add(reports))
        .ok_or_else(|| "recovery working-set size overflowed".into())
}

fn check_pressure(snapshot: &MemorySnapshot, growth: u64) -> Result<(), MemoryError> {
    let Some(system) = snapshot.system.filter(|_| {
        snapshot
            .system_sample_age_ms
            .is_some_and(|age| age <= MAX_SAMPLE_AGE_MS)
    }) else {
        // Logical admission remains available; missing OS data stays visible in telemetry
        return Ok(());
    };
    let mut headroom = snapshot
        .limit_bytes
        .saturating_sub(system.process_rss_bytes);
    let mut limit = snapshot.limit_bytes;
    if let Some(cgroup) = system.cgroup {
        for available in [cgroup.max_headroom_bytes, cgroup.high_headroom_bytes]
            .into_iter()
            .flatten()
        {
            headroom = headroom.min(available);
        }
        for inherited in [cgroup.effective_max_bytes, cgroup.effective_high_bytes]
            .into_iter()
            .flatten()
        {
            limit = limit.min(inherited);
        }
    }
    // Clean-looking file pages remain charged until the kernel actually reclaims them
    let available = headroom
        .saturating_sub(snapshot.working_sets.reserved_bytes)
        .saturating_sub(limit / SAFETY_MARGIN_DIVISOR);
    if growth > available {
        return Err(MemoryError::Pressure {
            available,
            requested: growth,
        });
    }
    Ok(())
}
