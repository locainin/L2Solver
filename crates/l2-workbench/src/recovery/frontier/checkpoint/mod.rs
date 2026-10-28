//! Capture and restore bounded coordinator state at a transaction boundary

mod format;
mod secrets;
mod validate;
mod writer;

use super::super::{RecoveryCandidateState, RecoveryResourcePolicy};
use super::{RecoveryCoordinator, RecoveryError};
use crate::evidence::Case;
use format::{AssociationRef, CandidateRef, CheckpointRef, InputRef};
use serde_json::value::RawValue;
use sha2::{Digest, Sha256};
use std::io::{self, Write};

impl RecoveryCoordinator {
    /// Check a recipe before storing it in executor-owned checkpoint metadata
    ///
    /// # Errors
    /// Returns an error for literal secret material or an invalid recipe identity
    pub fn validate_checkpoint_recipe(
        recipe: &crate::derivation::Recipe,
    ) -> Result<(), RecoveryError> {
        secrets::validate_recipe(recipe)?;
        crate::derivation::validate_recipe_identity(recipe)
            .map_err(RecoveryError::InvalidTaskIdentity)
    }

    /// Stream a versioned checkpoint paired with the exact supplied evidence Case
    ///
    /// The byte limit applies to the encoded checkpoint, not the Case. A failed write
    /// can leave a partial document in the destination. Secret-bearing recipes and
    /// running candidates are rejected before writing any bytes
    ///
    /// # Errors
    /// Returns an error for a different Case, a running candidate, a secret-bearing
    /// recipe, an invalid association, an exceeded byte limit, or a failed write
    pub fn write_checkpoint<W: Write>(
        &self,
        case: &Case,
        output: &mut W,
        max_checkpoint_bytes: usize,
    ) -> Result<usize, RecoveryError> {
        if self.case_identity.is_some() {
            self.ensure_case(case)?;
        }
        // Check every task and association before forwarding any output bytes
        for candidate in &self.candidates {
            if matches!(candidate.state, RecoveryCandidateState::Running(_)) {
                return Err(RecoveryError::CheckpointRunningCandidate);
            }
            secrets::validate_task(&candidate.task)?;
        }
        let associations = self.checkpoint_associations(case)?;
        let candidates = self.checkpoint_candidates()?;
        writer::write(
            output,
            max_checkpoint_bytes,
            &CheckpointRef {
                version: format::VERSION,
                case_sha256: case_digest(case)?,
                resources: self.resources,
                candidates,
                frontier: &self.frontier,
                work_bytes: self.work_bytes,
                lineage_work: self.lineage_work,
                associations,
            },
        )
    }

    fn checkpoint_associations(
        &self,
        case: &Case,
    ) -> Result<Vec<AssociationRef<'_>>, RecoveryError> {
        let mut associations = Vec::new();
        associations
            .try_reserve_exact(self.transform_proposal_associations.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for (report_node_id, identity) in &self.transform_proposal_associations {
            secrets::validate_association(identity)?;
            if case.node(*report_node_id).is_none() {
                return Err(RecoveryError::InvalidCheckpoint);
            }
            let identity = serde_json::from_slice::<&RawValue>(identity)
                .map_err(|_| RecoveryError::InvalidCheckpoint)?;
            associations.push(AssociationRef {
                report_node_id: *report_node_id,
                identity,
            });
        }
        // Hash-set iteration is arbitrary, so choose a stable checkpoint order
        associations.sort_unstable_by(|left, right| {
            (left.report_node_id, left.identity.get())
                .cmp(&(right.report_node_id, right.identity.get()))
        });
        Ok(associations)
    }

    fn checkpoint_candidates(&self) -> Result<Vec<CandidateRef<'_>>, RecoveryError> {
        let mut candidates = Vec::new();
        candidates
            .try_reserve_exact(self.candidates.len())
            .map_err(|_| RecoveryError::AllocationFailed)?;
        for candidate in &self.candidates {
            let mut inputs = Vec::new();
            inputs
                .try_reserve_exact(candidate.inputs.len())
                .map_err(|_| RecoveryError::AllocationFailed)?;
            for input in &candidate.inputs {
                inputs.push(InputRef {
                    blob_id: &input.blob_id,
                    origin_node_ids: &input.origin_node_ids,
                });
            }
            candidates.push(CandidateRef {
                inputs,
                task: &candidate.task,
                depth: candidate.depth,
                parent_ids: &candidate.parent_ids,
                pending_origin_node_ids: &candidate.pending_origin_node_ids,
                completion_priority: candidate.completion_priority,
                state: &candidate.state,
            });
        }
        Ok(candidates)
    }

    /// Restore a bounded checkpoint and bind it to the supplied exact evidence Case
    ///
    /// The expected resource policy must match the policy saved with the checkpoint
    /// The encoded byte limit is checked before parsing; retained collections are checked
    /// against the expected policy before allocating their owned records
    ///
    /// # Errors
    /// Returns an error when the checkpoint exceeds its limit, is malformed, contains a
    /// running or secret-bearing task, or disagrees with the Case or expected policy
    pub fn restore(
        case: &Case,
        expected_resources: RecoveryResourcePolicy,
        bytes: &[u8],
        max_checkpoint_bytes: usize,
    ) -> Result<Self, RecoveryError> {
        if bytes.len() > max_checkpoint_bytes {
            return Err(RecoveryError::InvalidCheckpoint);
        }
        format::preflight(bytes, expected_resources)?;
        let checkpoint: format::Checkpoint =
            serde_json::from_slice(bytes).map_err(|_| RecoveryError::InvalidCheckpoint)?;
        if checkpoint.version != format::VERSION
            || checkpoint.resources != expected_resources
            || checkpoint.case_sha256 != case_digest(case)?
        {
            return Err(RecoveryError::InvalidCheckpoint);
        }
        validate::restore(case, checkpoint)
    }
}

fn case_digest(case: &Case) -> Result<String, RecoveryError> {
    struct HashWriter(Sha256);
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    // Stream the graph into the digest instead of retaining another Case encoding
    let mut writer = HashWriter(Sha256::new());
    serde_json::to_writer(&mut writer, case).map_err(|_| RecoveryError::InvalidCheckpoint)?;
    Ok(format!("{:x}", writer.0.finalize()))
}
