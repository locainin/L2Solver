//! Separate limits for work needed to check a restored checkpoint

/// A bounded meter for checkpoint validation performed during this invocation
///
/// The two limits count output-verification work bytes and absolute-pair scheduler steps
/// Charges remain visible after rejection or cancellation and do not change frozen search work
#[derive(Debug)]
pub struct RelationalRestoreBudget {
    max_verification_work_bytes: usize,
    max_schedule_steps: usize,
    verification_work_bytes: usize,
    schedule_steps: usize,
}

impl RelationalRestoreBudget {
    /// Set the maximum extra work allowed while validating checkpoints
    #[must_use]
    pub const fn new(max_verification_work_bytes: usize, max_schedule_steps: usize) -> Self {
        Self {
            max_verification_work_bytes,
            max_schedule_steps,
            verification_work_bytes: 0,
            schedule_steps: 0,
        }
    }

    /// Return verification work charged while checking checkpoints and caller-owned evidence
    #[must_use]
    pub const fn verification_work_bytes(&self) -> usize {
        self.verification_work_bytes
    }

    /// Return the remaining allowance for caller-owned evidence validation
    #[must_use]
    pub const fn remaining_verification_work_bytes(&self) -> usize {
        self.max_verification_work_bytes - self.verification_work_bytes
    }

    /// Return scheduler transitions charged while checking saved positions
    #[must_use]
    pub const fn schedule_steps(&self) -> usize {
        self.schedule_steps
    }

    /// Charge output or caller evidence work before it is performed
    ///
    /// Return false without charging when the requested work exceeds the remaining allowance
    /// An exclusively borrowed nested work meter may instead receive the remaining allowance
    /// first, then charge its consumed amount here before the decoder returns
    #[must_use]
    pub const fn try_charge_verification(&mut self, bytes: usize) -> bool {
        let Some(next) = self.verification_work_bytes.checked_add(bytes) else {
            return false;
        };
        if next > self.max_verification_work_bytes {
            return false;
        }
        self.verification_work_bytes = next;
        true
    }

    pub(super) const fn charge_schedule(&mut self) -> bool {
        let Some(next) = self.schedule_steps.checked_add(1) else {
            return false;
        };
        if next > self.max_schedule_steps {
            return false;
        }
        self.schedule_steps = next;
        true
    }

    pub(super) const fn can_schedule(&self, steps: usize) -> bool {
        steps <= self.max_schedule_steps - self.schedule_steps
    }
}
