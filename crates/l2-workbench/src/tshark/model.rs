use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Complete `TShark` receipt bound to the exact offline input bytes
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TsharkReport {
    #[serde(deserialize_with = "deserialize_schema_version")]
    pub schema_version: u8,
    pub source: SourceIdentity,
    pub source_packet_count: PacketCountReceipt,
    pub provenance: Provenance,
    pub tool: ToolReceipt,
    pub output_sha256: String,
    pub packets: Vec<EnrichedPacket>,
}

impl TsharkReport {
    /// Validate the receipt's schema, digests, and original frame sequence
    ///
    /// # Errors
    /// Rejects unsupported reports, incomplete tool metadata, invalid hashes, or changed frame order
    pub fn validate(&self) -> Result<(), String> {
        validate_schema_version(self.schema_version)?;
        validate_sha256(&self.source.sha256, "TShark source")?;
        validate_sha256(
            &self.source_packet_count.output_sha256,
            "TShark source packet count output",
        )?;
        validate_sha256(&self.output_sha256, "TShark decoded output")?;
        if self.source.label.trim().is_empty() {
            return Err("TShark report source label is empty".into());
        }
        if !self.provenance.source_change_verified
            || !self.provenance.tool_derived
            || self.provenance.physical_byte_ranges != "not_reported"
            || !matches!(
                self.provenance.tls_decryption.as_str(),
                "disabled" | "explicit_keylog"
            )
        {
            return Err("TShark report provenance is invalid".into());
        }
        self.tool.validate(self.source.length)?;
        if (self.provenance.tls_decryption == "explicit_keylog")
            != self.tool.profile.tls_keylog.is_some()
        {
            return Err("TShark TLS provenance disagrees with its supplied key log".into());
        }
        // Source traversal covers frames that a truncated decoded prefix could omit
        if u64::try_from(self.packets.len()).ok() != Some(self.source_packet_count.count) {
            return Err("TShark decoded packet count differs from the source packet count".into());
        }
        for (index, packet) in self.packets.iter().enumerate() {
            let expected = u64::try_from(index)
                .ok()
                .and_then(|value| value.checked_add(1))
                .ok_or_else(|| "TShark packet count exceeds the supported range".to_owned())?;
            if packet.packet_number != expected
                || tshark_frame_number(&packet.fields) != Some(expected)
                || !packet.tool_derived
            {
                return Err(
                    "TShark report frame identities are missing, duplicated, or out of order"
                        .into(),
                );
            }
            if !packet.fields.is_object() {
                return Err("TShark packet fields must be an object".into());
            }
            if packet.reassembled_fields.iter().any(String::is_empty) {
                return Err("TShark reassembled field names must be nonempty".into());
            }
        }
        Ok(())
    }
}

fn validate_schema_version(version: u8) -> Result<(), String> {
    match version {
        2 => Ok(()),
        1 => Err("legacy TShark report schema version 1 lacks source packet-count evidence; regenerate the report".into()),
        _ => Err("unsupported TShark report schema version".into()),
    }
}

fn deserialize_schema_version<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let version = u8::deserialize(deserializer)?;
    // Reject legacy receipts before their missing completeness field obscures the reason
    validate_schema_version(version).map_err(serde::de::Error::custom)?;
    Ok(version)
}

/// Separate `TShark` traversal of the source capture with protocol dissection disabled
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PacketCountReceipt {
    pub count: u64,
    pub output_sha256: String,
}

/// Content-derived identity for one file supplied to `TShark`
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceIdentity {
    pub label: String,
    pub length: u64,
    pub sha256: String,
}

/// Statements about how returned protocol fields were obtained
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provenance {
    pub source_change_verified: bool,
    pub tool_derived: bool,
    pub tls_decryption: String,
    pub physical_byte_ranges: String,
}

/// `TShark` build, configuration, plugin inventory, invocation, and diagnostics
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ToolReceipt {
    pub executable_requested: String,
    pub executable: String,
    pub executable_bytes: u64,
    pub executable_sha256: String,
    pub version: String,
    pub budgets: BudgetReceipt,
    pub profile: ProfileReceipt,
    pub plugins: Vec<PluginRecord>,
    pub plugin_inventory_sha256: String,
    pub version_output_sha256: String,
    pub effective_preferences_sha256: String,
    pub effective_preferences_count: usize,
    pub verified_profile_preferences: BTreeMap<String, String>,
    pub invocations: Vec<InvocationReceipt>,
    pub diagnostics: Vec<Diagnostic>,
}

impl ToolReceipt {
    fn validate(&self, source_length: u64) -> Result<(), String> {
        for (value, name) in [
            (&self.executable_sha256, "TShark executable"),
            (&self.plugin_inventory_sha256, "TShark plugin inventory"),
            (&self.version_output_sha256, "TShark version output"),
            (
                &self.effective_preferences_sha256,
                "TShark effective preferences",
            ),
            (
                &self.profile.preferences_sha256,
                "TShark profile preferences",
            ),
        ] {
            validate_sha256(value, name)?;
        }
        if self.executable_requested.trim().is_empty()
            || self.executable.trim().is_empty()
            || self.executable_bytes == 0
            || self.version.trim().is_empty()
            || self.profile.name.trim().is_empty()
            || self.profile.name_resolution != "disabled_by_-n"
            || self.profile.process_environment.trim().is_empty()
            || self.budgets.combined_input_bytes < source_length
            || self.budgets.timeout_seconds == 0
            || self.budgets.metadata_stdout_bytes_per_phase == 0
            || self.budgets.json_output_bytes == 0
            || self.budgets.diagnostic_bytes_per_phase == 0
            || self.effective_preferences_count == 0
            || self.invocations.is_empty()
        {
            return Err("TShark tool receipt is incomplete".into());
        }
        if self.plugins.iter().any(|plugin| {
            plugin.name.trim().is_empty()
                || plugin.version.trim().is_empty()
                || plugin.kind.trim().is_empty()
                || plugin.path.trim().is_empty()
        }) {
            return Err("TShark plugin inventory contains an incomplete entry".into());
        }
        if let Some(keylog) = &self.profile.tls_keylog {
            validate_sha256(&keylog.sha256, "TShark TLS key log")?;
            if keylog.label.trim().is_empty()
                || keylog.length == 0
                || keylog.length > self.budgets.combined_input_bytes - source_length
            {
                return Err("TShark TLS key log identity is incomplete".into());
            }
        }
        for diagnostic in &self.diagnostics {
            validate_sha256(&diagnostic.sha256, "TShark diagnostic")?;
            if diagnostic.phase.trim().is_empty() {
                return Err("TShark diagnostic phase is empty".into());
            }
        }
        if self
            .invocations
            .iter()
            .any(|invocation| invocation.phase.trim().is_empty())
        {
            return Err("TShark invocation phase is empty".into());
        }
        self.validate_capture_invocations()?;
        Ok(())
    }

    fn validate_capture_invocations(&self) -> Result<(), String> {
        let mut counts = self
            .invocations
            .iter()
            .filter(|invocation| invocation.phase == "packet_count");
        let count = counts
            .next()
            .ok_or("TShark source packet count invocation is missing")?;
        // Keep the count bound to the same snapshot and profile without a packet filter
        if counts.next().is_some()
            || !count.argv.iter().map(String::as_str).eq([
                "-n",
                "-C",
                self.profile.name.as_str(),
                "--disable-all-protocols",
                "-r",
                "<source-snapshot>",
                "-T",
                "fields",
                "-e",
                "frame.number",
            ])
        {
            return Err("TShark source packet count invocation is not source-bound".into());
        }
        let mut decodes = self
            .invocations
            .iter()
            .filter(|invocation| invocation.phase == "decode");
        let decode = decodes
            .next()
            .ok_or("TShark decode invocation is missing")?;
        let mut expected = vec!["-n", "-2", "-q", "-C", self.profile.name.as_str()];
        // An explicit keylog is the only permitted override and must name the supplied snapshot
        if self.profile.tls_keylog.is_some() {
            expected.extend(["-o", "tls.keylog_file:<keylog-snapshot>"]);
        }
        expected.extend([
            "-r",
            "<source-snapshot>",
            "-T",
            "json",
            "--no-duplicate-keys",
        ]);
        // Exact arguments also reject extra filters, source operands, or preference overrides
        if decodes.next().is_some() || !decode.argv.iter().map(String::as_str).eq(expected) {
            return Err(
                "TShark decode invocation does not match its source, profile, format, or key log"
                    .into(),
            );
        }
        Ok(())
    }
}

/// Operator-selected process, source, and decoded-output limits
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetReceipt {
    pub timeout_seconds: u32,
    pub combined_input_bytes: u64,
    pub metadata_stdout_bytes_per_phase: usize,
    pub json_output_bytes: usize,
    pub diagnostic_bytes_per_phase: usize,
}

/// Sanitized argument vector supplied to one recorded `TShark` phase
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InvocationReceipt {
    pub phase: String,
    pub argv: Vec<String>,
}

/// Fixed profile identity and the explicit dissector settings applied
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileReceipt {
    pub name: String,
    pub preferences_sha256: String,
    pub name_resolution: String,
    pub reassembly_preferences: Vec<String>,
    pub process_environment: String,
    pub tls_keylog: Option<SourceIdentity>,
}

/// One plugin reported by `TShark`'s own registry dump
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PluginRecord {
    pub name: String,
    pub version: String,
    pub kind: String,
    pub path: String,
}

/// Bounded stderr captured from one `TShark` phase
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Diagnostic {
    pub phase: String,
    pub message: String,
    pub sha256: String,
}

/// Protocol fields decoded by `TShark` for one original capture frame
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EnrichedPacket {
    pub packet_number: u64,
    pub tool_derived: bool,
    pub fields: Value,
    pub reassembled_fields: BTreeSet<String>,
}

/// Tool fields reported for one original capture frame
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TsharkFrameObservation {
    pub receipt_sha256: String,
    pub tool_version: String,
    pub packet_number: u64,
    pub fields: Value,
    pub reassembled_fields: BTreeSet<String>,
}

fn validate_sha256(value: &str, name: &str) -> Result<(), String> {
    if !crate::hashing::is_sha256_digest(value) {
        return Err(format!("{name} identity is not a lowercase SHA-256 digest"));
    }
    Ok(())
}

fn tshark_frame_number(fields: &Value) -> Option<u64> {
    let number = fields.get("frame")?.get("frame.number")?;
    number
        .as_u64()
        .or_else(|| number.as_str()?.parse::<u64>().ok())
}
