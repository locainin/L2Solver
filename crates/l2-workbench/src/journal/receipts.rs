use super::{DerivationSummary, Hypothesis, Journal, Result, invalid};
use crate::derivation::{ConstraintReport, ConstraintStatus, DerivationStatus};
use serde::Deserialize;

#[derive(Deserialize)]
struct Receipt {
    status: DerivationStatus,
    input_sha256: String,
    output_sha256: String,
    output_length: u64,
    constraints: Vec<ConstraintReport>,
}

impl Journal {
    pub(super) fn derivation_summary(
        &self,
        output: Option<&str>,
        receipt: Option<&str>,
        hypothesis: &Hypothesis,
    ) -> Result<Option<DerivationSummary>> {
        let (output, receipt) = match (output, receipt) {
            (None, None) => return Ok(None),
            (Some(output), Some(receipt)) => (output, receipt),
            _ => {
                return Err(invalid(
                    "journal derivation has an incomplete output/receipt pair",
                ));
            }
        };
        let receipt: Receipt =
            serde_json::from_slice(&self.object(receipt, self.options.max_entry_bytes)?)?;
        let length: u64 = self.connection.query_row(
            "SELECT length(bytes) FROM objects WHERE sha256=?1",
            [output],
            |row| row.get(0),
        )?;
        // Both references must describe the same retained bytes and original input
        if receipt.output_sha256 != output
            || receipt.output_length != length
            || hypothesis
                .input
                .get("sha256")
                .and_then(serde_json::Value::as_str)
                != Some(receipt.input_sha256.as_str())
        {
            return Err(invalid(
                "journal receipt disagrees with its linked input or output",
            ));
        }
        let failed_step = match receipt.status {
            DerivationStatus::Completed => None,
            DerivationStatus::Failed { step_index } => Some(step_index),
        };
        Ok(Some(DerivationSummary {
            operation_completed: failed_step.is_none(),
            constraints_satisfied: receipt
                .constraints
                .iter()
                .all(|check| check.status == ConstraintStatus::Satisfied),
            failed_step,
        }))
    }
}
