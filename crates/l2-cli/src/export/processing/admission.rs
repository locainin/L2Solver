//! Reserve Case startup growth before dispatching work to the recovery pool

#[cfg(test)]
#[path = "../../../tests/export/admission.rs"]
mod tests;

use super::{PendingCase, case_mut};
use crate::export::recovery_cache::RecoveryContext;
use crate::recovery_job::{
    MAX_MEMORY_SAMPLE_AGE, MEMORY_OBSERVATION_INTERVAL, MEMORY_SAFETY_MARGIN_DIVISOR,
};
use l2_workbench::{
    evidence::Case,
    job::{Job, MemoryBudget, MemoryError, MemorySnapshot, MemoryWorkingSet, Phase},
    protocol::ProtocolLimits,
};
use std::{error::Error, thread, time::Duration};

// Two further samples distinguish a transient cleanup peak from sustained pressure
const QUIESCENT_PRESSURE_RECHECKS: u8 = 2;

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
    let admission = check_admission_pressure(active, growth, context.job, || observe(memory))
        .and_then(|()| memory.try_working_set(growth).map_err(Into::into));
    match admission {
        Ok(work) => {
            case_mut(&mut pending.item).use_working_set(&work)?;
            Ok(Some(Admission {
                working_set: Some(work),
            }))
        }
        Err(error)
            if active > 0
                && matches!(
                    crate::memory_error::find(error.as_ref()),
                    Some(MemoryError::Limit { .. } | MemoryError::Pressure { .. })
                ) =>
        {
            if let Some(job) = context.job {
                job.set_current(
                    Phase::FramingRecordDiscovery,
                    "Waiting for active recovery and buffered Case memory",
                )?;
            }
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn observe(memory: &MemoryBudget) -> Result<MemorySnapshot, MemoryError> {
    let mut snapshot = memory.snapshot()?;
    if snapshot.system.is_some() || snapshot.system_observation_failures != 0 {
        // Reuse the job's OS monitor; component-only budgets do not enable process accounting
        crate::recovery_job::refresh_memory_observation(memory)?;
        snapshot = memory.snapshot()?;
    }
    Ok(snapshot)
}

fn check_admission_pressure(
    active: usize,
    growth: u64,
    job: Option<&Job>,
    mut observe: impl FnMut() -> Result<MemorySnapshot, MemoryError>,
) -> Result<(), Box<dyn Error>> {
    let mut rechecks = if active == 0 {
        QUIESCENT_PRESSURE_RECHECKS
    } else {
        0
    };
    loop {
        if let Some(job) = job {
            job.check_cancelled()?;
        }
        let snapshot = observe()?;
        if let Some(job) = job {
            // Cancellation can arrive while the kernel observation is being read
            job.check_cancelled()?;
        }
        match check_pressure(&snapshot, growth) {
            Err(MemoryError::Pressure { .. }) if rechecks > 0 => {
                rechecks -= 1;
                if let Some(job) = job {
                    job.set_current(
                        Phase::FramingRecordDiscovery,
                        "Waiting for released recovery storage to settle",
                    )?;
                }
                // Active workers return immediately so the collector can release their results
                thread::sleep(MEMORY_OBSERVATION_INTERVAL);
            }
            result => return result.map_err(Into::into),
        }
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
            .is_some_and(|age| Duration::from_millis(age) <= MAX_MEMORY_SAMPLE_AGE)
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
        .saturating_sub(limit / MEMORY_SAFETY_MARGIN_DIVISOR);
    if growth > available {
        return Err(MemoryError::Pressure {
            available,
            requested: growth,
        });
    }
    Ok(())
}
