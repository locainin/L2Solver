use super::{DerivationInput, Hypothesis, Journal, Result, invalid};
use crate::derivation::{self, Recipe};
use rusqlite::params;
use serde_json::{Value, json};

impl Journal {
    /// Store a derivation as delta evidence without serializing another complete case
    ///
    /// # Errors
    /// Rejects changed evidence, missing byte nodes, invalid recipes and storage errors
    pub fn derive(&mut self, input: DerivationInput<'_>, recipe: &Recipe) -> Result<String> {
        let (bytes, input) = self.derivation_input(input)?;
        let report = derivation::run(&bytes, recipe)?;
        let id = self.record(&Hypothesis {
            title: "Recorded derivation".into(),
            input,
            operation: serde_json::to_value(recipe)?,
            assumptions: Vec::new(),
        })?;
        let output = crate::sha256(&report.output);
        let receipt = self.encoded(
            &json!({"status":report.status,"input_length":report.input_length,"input_sha256":report.input_sha256,"output_length":report.output.len(),"output_sha256":report.output_sha256,"steps":report.steps,"constraints":report.constraints,"intermediate_bytes":report.intermediate_bytes,"external_acceptance":"not_tested"}),
        )?;
        let receipt_id = crate::sha256(&receipt);
        let previous = {
            let mut statement = self.connection.prepare(
                "SELECT length(CAST(output AS BLOB)),output FROM hypotheses WHERE id=?1",
            )?;
            let mut rows = statement.query([&id])?;
            let row = rows.next()?.ok_or(rusqlite::Error::QueryReturnedNoRows)?;
            super::optional_sha256(row, 0, 1, "journal derivation output")?
        };
        if previous.as_ref().is_some_and(|p| p != &output) {
            return Err(invalid("an exact derivation changed output"));
        }
        let tx = self.connection.transaction()?;
        tx.execute(
            "INSERT OR IGNORE INTO objects VALUES(?1,?2)",
            params![output, report.output],
        )?;
        tx.execute(
            "INSERT OR IGNORE INTO objects VALUES(?1,?2)",
            params![receipt_id, receipt],
        )?;
        tx.execute(
            "UPDATE hypotheses SET output=?2,receipt=?3 WHERE id=?1",
            params![id, output, receipt_id],
        )?;
        tx.commit()?;
        Ok(id)
    }
    /// Export exact derived bytes with their stored content hash checked again
    ///
    /// # Errors
    /// Rejects missing output and changed objects
    pub fn output(&self, id: &str) -> Result<Vec<u8>> {
        let entry = self.entry(id)?;
        let hash = entry
            .output_sha256
            .ok_or_else(|| invalid("hypothesis has no output"))?;
        self.object(&hash, crate::derivation::MAX_OUTPUT_BYTES)
    }
    fn derivation_input(&self, input: DerivationInput<'_>) -> Result<(Vec<u8>, Value)> {
        match input {
            DerivationInput::BaseNode(node) => {
                let case = self.base_case()?;
                let selected = case
                    .nodes()
                    .iter()
                    .find(|n| n.id == node)
                    .ok_or_else(|| invalid("missing input node"))?;
                let blob = selected
                    .blob
                    .as_ref()
                    .ok_or_else(|| invalid("selected node has no bytes"))?;
                let bytes = case
                    .blobs()
                    .iter()
                    .find(|b| &b.id == blob)
                    .ok_or_else(|| invalid("selected blob is missing"))?
                    .bytes
                    .clone();
                let identity = json!({"base_case":self.overview()?.base_case_sha256,"node":node,"sha256":crate::sha256(&bytes)});
                Ok((bytes, identity))
            }
            DerivationInput::DerivedOutput(parent) => {
                let entry = self.entry(parent)?;
                if !entry.derivation.as_ref().is_some_and(|result| {
                    result.operation_completed && result.constraints_satisfied
                }) {
                    return Err(invalid(
                        "derived input requires a completed parent with satisfied constraints",
                    ));
                }
                let hash = entry
                    .output_sha256
                    .as_deref()
                    .ok_or_else(|| invalid("completed parent has no output"))?;
                let bytes = self.object(hash, derivation::MAX_OUTPUT_BYTES)?;
                let identity = json!({"parent":parent,"sha256":crate::sha256(&bytes)});
                Ok((bytes, identity))
            }
        }
    }
}
