//! Preserve context sharing and ordered schema application inputs

use super::super::input::{RecordCohortKey, RecordDiscoveryInputOmissions, RecordFrameInput};
use super::{LearningSample, RecordDiscoveryContext};
use crate::workbench::recovery_executor::{RecoveryCandidateId, RecoveryError};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, sync::Arc};

#[derive(Serialize)]
pub(in crate::workbench::recovery_executor) struct ContextsRef<'a> {
    applications: Vec<&'a [RecordFrameInput]>,
    candidates: Vec<(RecoveryCandidateId, Vec<ContextRef<'a>>)>,
    reports: Vec<(u64, ContextRef<'a>)>,
}

#[derive(Serialize)]
struct ContextRef<'a> {
    key: &'a RecordCohortKey,
    inputs: &'a [RecordFrameInput],
    application: usize,
    sampling: LearningSample,
    omitted_frames: usize,
    eligibility_omissions: &'a RecordDiscoveryInputOmissions,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(in crate::workbench::recovery_executor) struct Contexts {
    applications: Vec<Vec<RecordFrameInput>>,
    candidates: Vec<(RecoveryCandidateId, Vec<Context>)>,
    reports: Vec<(u64, Context)>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Context {
    key: RecordCohortKey,
    inputs: Vec<RecordFrameInput>,
    application: usize,
    sampling: LearningSample,
    omitted_frames: usize,
    eligibility_omissions: RecordDiscoveryInputOmissions,
}

impl<'a> ContextsRef<'a> {
    pub(in crate::workbench::recovery_executor) fn capture(
        candidates: &'a HashMap<RecoveryCandidateId, Vec<RecordDiscoveryContext>>,
        reports: &'a HashMap<u64, RecordDiscoveryContext>,
    ) -> Result<Self, RecoveryError> {
        let mut value = Self {
            applications: Vec::new(),
            candidates: Vec::new(),
            reports: Vec::new(),
        };
        let mut indexes = HashMap::new();
        let entries = crate::workbench::recovery_executor::checkpoint::collections::sorted_entries(
            candidates,
        )
        .map_err(|_| RecoveryError::AllocationFailed)?;
        for (id, contexts) in entries {
            let mut saved = Vec::new();
            saved
                .try_reserve_exact(contexts.len())
                .map_err(|_| RecoveryError::AllocationFailed)?;
            for context in contexts {
                saved.push(value.context(context, &mut indexes)?);
            }
            value
                .candidates
                .try_reserve(1)
                .map_err(|_| RecoveryError::AllocationFailed)?;
            value.candidates.push((*id, saved));
        }
        let entries =
            crate::workbench::recovery_executor::checkpoint::collections::sorted_entries(reports)
                .map_err(|_| RecoveryError::AllocationFailed)?;
        for (id, context) in entries {
            let saved = value.context(context, &mut indexes)?;
            value
                .reports
                .try_reserve(1)
                .map_err(|_| RecoveryError::AllocationFailed)?;
            value.reports.push((*id, saved));
        }
        Ok(value)
    }

    fn context(
        &mut self,
        context: &'a RecordDiscoveryContext,
        indexes: &mut HashMap<(usize, usize), usize>,
    ) -> Result<ContextRef<'a>, RecoveryError> {
        let key = (
            Arc::as_ptr(&context.application_inputs).addr(),
            context.application_inputs.len(),
        );
        let application = if let Some(index) = indexes.get(&key) {
            *index
        } else {
            let index = self.applications.len();
            self.applications
                .try_reserve(1)
                .map_err(|_| RecoveryError::AllocationFailed)?;
            indexes
                .try_reserve(1)
                .map_err(|_| RecoveryError::AllocationFailed)?;
            self.applications.push(context.application_inputs.as_ref());
            indexes.insert(key, index);
            index
        };
        Ok(ContextRef {
            key: &context.key,
            inputs: &context.inputs,
            application,
            sampling: context.sampling,
            omitted_frames: context.omitted_frames,
            eligibility_omissions: &context.eligibility_omissions,
        })
    }
}

type RestoredContexts = (
    HashMap<RecoveryCandidateId, Vec<RecordDiscoveryContext>>,
    HashMap<u64, RecordDiscoveryContext>,
);

impl Contexts {
    pub(in crate::workbench::recovery_executor) fn restore(
        self,
    ) -> Result<RestoredContexts, RecoveryError> {
        let mut applications = Vec::new();
        applications
            .try_reserve_exact(self.applications.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for inputs in self.applications {
            applications.push(Arc::<[RecordFrameInput]>::from(inputs));
        }
        let mut candidates = HashMap::new();
        candidates
            .try_reserve(self.candidates.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for (id, contexts) in self.candidates {
            let mut saved = Vec::new();
            saved
                .try_reserve_exact(contexts.len())
                .map_err(|_| RecoveryError::AllocationFailed)?;
            for context in contexts {
                saved.push(context.restore(&applications)?);
            }
            if candidates.insert(id, saved).is_some() {
                return Err(RecoveryError::InvalidCheckpoint);
            }
        }
        let mut reports = HashMap::new();
        reports
            .try_reserve(self.reports.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for (id, context) in self.reports {
            if reports
                .insert(id, context.restore(&applications)?)
                .is_some()
            {
                return Err(RecoveryError::InvalidCheckpoint);
            }
        }
        Ok((candidates, reports))
    }
}

impl Context {
    fn restore(
        self,
        applications: &[Arc<[RecordFrameInput]>],
    ) -> Result<RecordDiscoveryContext, RecoveryError> {
        let application_inputs = Arc::clone(
            applications
                .get(self.application)
                .ok_or(RecoveryError::InvalidCheckpoint)?,
        );
        Ok(RecordDiscoveryContext {
            key: self.key,
            inputs: self.inputs,
            application_inputs,
            sampling: self.sampling,
            omitted_frames: self.omitted_frames,
            eligibility_omissions: self.eligibility_omissions,
        })
    }
}
