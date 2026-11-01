//! Aggregate work and spool-output reservations for streaming refinement

use super::super::{
    input::{LoadedSource, SourceData},
    policy::{RefinePolicy, STREAM_EXPANSION_RATIO},
};
use super::observation::PROPOSAL_PREFIX_BYTES;
use crate::arguments::RecoveryProfile;
use l2_workbench::{
    derivation::{Operation, StreamReceipt},
    recovery::proposals::transform_proposal_scan_work_bound,
};
use std::error::Error;

const RANGE_SCAN_RESERVE_BYTES: usize = 64 * 1024 * 1024;

pub(super) fn observation_work(length: usize) -> Option<usize> {
    length
        .checked_mul(2)?
        .checked_add(transform_proposal_scan_work_bound(
            length.min(PROPOSAL_PREFIX_BYTES),
        )?)
}

#[cfg(test)]
#[path = "../../../tests/refine/stream_budget.rs"]
mod tests;

pub(in crate::refine) struct StreamingBudget {
    pub(super) work: usize,
    pub(super) output: usize,
    pub(super) zip: usize,
    pub(super) attempts: usize,
}

impl StreamingBudget {
    pub(in crate::refine) fn new(
        policy: &RefinePolicy,
        sources: &[LoadedSource],
    ) -> Result<Self, Box<dyn Error>> {
        let source_work = sources
            .iter()
            .try_fold(0_usize, |total, source| match &source.data {
                SourceData::Memory { .. } => total.checked_add(source.length()),
                SourceData::File(_) => total.checked_add(source.length())?.checked_add(1),
                SourceData::Skipped(_) => Some(total),
            })
            .ok_or("source identity work overflows")?;
        Ok(Self {
            // Each file keeps one work unit for its required identity-only scan
            work: policy
                .stream_work_limit
                .checked_sub(source_work)
                .ok_or("source identity exceeds the stream work limit")?,
            output: policy.stream_output_limit,
            zip: policy.analyzer.limits.max_zip_expanded_bytes,
            attempts: policy.analyzer.limits.max_artifacts,
        })
    }

    pub(in crate::refine) fn reserve_observation(
        &mut self,
        length: usize,
    ) -> Result<Option<usize>, Box<dyn Error>> {
        let required = observation_work(length).ok_or("stream observation work overflows")?;
        let Some(remaining) = self.work.checked_sub(required) else {
            return Ok(None);
        };
        self.work = remaining;
        Ok(Some(required))
    }

    pub(in crate::refine) fn begin_source(&mut self) -> Result<(), Box<dyn Error>> {
        self.work = self.work.checked_add(1).ok_or("stream work overflows")?;
        Ok(())
    }

    pub(in crate::refine) fn range_work_limit(
        &self,
        length: usize,
        existing: usize,
        profile: RecoveryProfile,
    ) -> usize {
        let requested = if profile == RecoveryProfile::Fast {
            existing
        } else {
            existing.max(
                length
                    .saturating_mul(3)
                    .saturating_add(RANGE_SCAN_RESERVE_BYTES),
            )
        };
        requested.min(self.work)
    }

    pub(in crate::refine) fn charge_range_work(
        &mut self,
        work: usize,
    ) -> Result<(), Box<dyn Error>> {
        self.work = self
            .work
            .checked_sub(work)
            .ok_or("refinement work exceeded the shared budget")?;
        Ok(())
    }

    pub(in crate::refine) fn charge_zip_work(&mut self, work: usize) -> Result<(), Box<dyn Error>> {
        self.zip = self
            .zip
            .checked_sub(work)
            .ok_or("ZIP expansion exceeded the shared budget")?;
        Ok(())
    }

    pub(in crate::refine) const fn zip_remaining(&self) -> usize {
        self.zip
    }

    pub(in crate::refine) const fn work_remaining(&self) -> usize {
        self.work
    }

    pub(super) fn reserve(&mut self, length: usize, operation: &Operation) -> Option<Reservation> {
        if self.attempts == 0 {
            return None;
        }
        let base = length.checked_add(4)?;
        let maximum_output = self.output.min(output_bound(length, operation)?);
        let available = self.work.checked_sub(base)?;
        let mut low = 0;
        let mut high = maximum_output;
        // Find the largest output whose actual bounded observation cost fits
        while low < high {
            let candidate = low + (high - low).div_ceil(2);
            if output_work(candidate).is_some_and(|work| work <= available) {
                low = candidate;
            } else {
                high = candidate - 1;
            }
        }
        let output = low;
        if output == 0 {
            return None;
        }
        let work = base.checked_add(output_work(output)?)?;
        self.work -= work;
        self.output -= output;
        self.attempts -= 1;
        Some(Reservation { work, output, base })
    }

    pub(super) fn refund(
        &mut self,
        reservation: Reservation,
        receipt: Option<&StreamReceipt>,
    ) -> Result<(), Box<dyn Error>> {
        let (used_work, used_output) = if let Some(receipt) = receipt {
            let observed = observation_work(receipt.output_length)
                .ok_or("stream observation work overflows")?;
            (
                receipt
                    .work_bytes
                    .checked_add(observed)
                    .and_then(|work| work.checked_add(receipt.output_length))
                    .ok_or("stream work overflows")?,
                receipt.output_length,
            )
        } else {
            (0, 0)
        };
        self.work = self
            .work
            .checked_add(
                reservation
                    .work
                    .checked_sub(used_work)
                    .ok_or("stream work exceeds reservation")?,
            )
            .ok_or("stream work refund overflows")?;
        self.output = self
            .output
            .checked_add(
                reservation
                    .output
                    .checked_sub(used_output)
                    .ok_or("stream output exceeds reservation")?,
            )
            .ok_or("stream output refund overflows")?;
        Ok(())
    }
}

fn output_work(output: usize) -> Option<usize> {
    // Cover output, two syntax observations, and a possible publication read
    output
        .checked_mul(4)?
        .checked_add(transform_proposal_scan_work_bound(
            output.min(PROPOSAL_PREFIX_BYTES),
        )?)
}

const fn output_bound(length: usize, operation: &Operation) -> Option<usize> {
    match operation {
        Operation::HexDecode {} => Some(length / 2),
        Operation::Base64Decode { .. } => length.div_ceil(4).checked_mul(3),
        Operation::GzipDecompress {} | Operation::ZlibDecompress {} => {
            Some(length.saturating_mul(STREAM_EXPANSION_RATIO))
        }
        _ => None,
    }
}

#[derive(Clone, Copy)]
pub(super) struct Reservation {
    pub(super) work: usize,
    pub(super) output: usize,
    pub(super) base: usize,
}
