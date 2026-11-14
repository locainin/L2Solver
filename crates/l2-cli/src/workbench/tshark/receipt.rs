use super::{
    count::CaptureCount,
    decode::CaptureDecode,
    inspection::ToolInspection,
    model::{
        BudgetReceipt, Diagnostic, InvocationReceipt, ProfileReceipt, Provenance, SourceIdentity,
        ToolReceipt, TsharkReport,
    },
    preparation::PreparedCapture,
    profile::{PROFILE, REASSEMBLY_PREFERENCES},
};
use l2_workbench::sha256;
use std::{ffi::OsString, path::Path};

pub(super) fn build_report(
    prepared: PreparedCapture,
    inspection: ToolInspection,
    counted: CaptureCount,
    decoded: CaptureDecode,
) -> TsharkReport {
    let invocations = invocation_receipts(&prepared, &inspection, &counted, &decoded);
    let diagnostics = phase_diagnostics(&inspection, &counted, &decoded);
    let (source, tool) = build_tool_receipt(prepared, inspection, invocations, diagnostics);
    TsharkReport {
        schema_version: 2,
        source,
        source_packet_count: counted.receipt,
        provenance: Provenance {
            source_change_verified: true,
            tool_derived: true,
            tls_decryption: if tool.profile.tls_keylog.is_some() {
                "explicit_keylog"
            } else {
                "disabled"
            }
            .to_owned(),
            physical_byte_ranges: "not_reported".to_owned(),
        },
        tool,
        output_sha256: decoded.output_sha256,
        packets: decoded.packets,
    }
}

fn invocation_receipts(
    prepared: &PreparedCapture,
    inspection: &ToolInspection,
    counted: &CaptureCount,
    decoded: &CaptureDecode,
) -> Vec<InvocationReceipt> {
    vec![
        invocation_receipt(
            "version",
            &[OsString::from("-n"), OsString::from("-v")],
            &prepared.source.path,
            None,
        ),
        invocation_receipt(
            "plugins",
            &inspection.plugin_args,
            &prepared.source.path,
            None,
        ),
        invocation_receipt(
            "preferences",
            &inspection.preferences_args,
            &prepared.source.path,
            None,
        ),
        invocation_receipt(
            "packet_count",
            &counted.arguments,
            &prepared.source.path,
            None,
        ),
        invocation_receipt(
            "decode",
            &decoded.arguments,
            &prepared.source.path,
            prepared
                .keylog
                .as_ref()
                .map(|snapshot| snapshot.path.as_path()),
        ),
    ]
}

fn phase_diagnostics(
    inspection: &ToolInspection,
    counted: &CaptureCount,
    decoded: &CaptureDecode,
) -> Vec<Diagnostic> {
    let mut diagnostics = Vec::new();
    add_diagnostic(
        &mut diagnostics,
        "version",
        &inspection.version_output.stderr,
    );
    add_diagnostic(
        &mut diagnostics,
        "plugins",
        &inspection.plugin_output.stderr,
    );
    add_diagnostic(
        &mut diagnostics,
        "preferences",
        &inspection.preferences_output.stderr,
    );
    add_diagnostic(&mut diagnostics, "packet_count", &counted.stderr);
    add_diagnostic(&mut diagnostics, "decode", &decoded.stderr);
    diagnostics
}

fn build_tool_receipt(
    prepared: PreparedCapture,
    inspection: ToolInspection,
    invocations: Vec<InvocationReceipt>,
    diagnostics: Vec<Diagnostic>,
) -> (SourceIdentity, ToolReceipt) {
    let plugin_inventory_sha256 = sha256(&inspection.plugin_output.stdout);
    let version_output_sha256 = sha256(&inspection.version_output.stdout);
    let effective_preferences_sha256 = sha256(&inspection.preferences_output.stdout);
    let source = prepared.source.identity;
    let tool = ToolReceipt {
        executable_requested: prepared.executable_requested,
        executable: prepared.executable.path.to_string_lossy().into_owned(),
        executable_bytes: prepared.executable_bytes,
        executable_sha256: prepared.executable_sha256,
        version: inspection.version,
        budgets: BudgetReceipt {
            timeout_seconds: prepared.timeout_seconds,
            combined_input_bytes: prepared.input_maximum,
            metadata_stdout_bytes_per_phase: prepared.metadata_maximum,
            json_output_bytes: prepared.output_maximum,
            diagnostic_bytes_per_phase: prepared.diagnostic_maximum,
        },
        profile: ProfileReceipt {
            name: PROFILE.to_owned(),
            preferences_sha256: prepared.profile.preferences_sha256,
            name_resolution: "disabled_by_-n".to_owned(),
            reassembly_preferences: REASSEMBLY_PREFERENCES
                .iter()
                .map(|preference| (*preference).to_owned())
                .collect(),
            process_environment: "Linux_user_mount_pid_network_ipc_uts_namespaces; unprivileged_UID; no_capabilities; no_new_privileges; seccomp_network_denial; read_only_descriptor_inputs; private_home_xdg_and_temp; private_empty_extcap_directory; C_locale; UTC; fixed_system_PATH".to_owned(),
            tls_keylog: prepared.keylog.map(|snapshot| snapshot.identity),
        },
        plugins: inspection.plugins,
        plugin_inventory_sha256,
        version_output_sha256,
        effective_preferences_sha256,
        effective_preferences_count: inspection.effective_preferences_count,
        verified_profile_preferences: inspection.verified_profile_preferences,
        invocations,
        diagnostics,
    };
    (source, tool)
}

fn invocation_receipt(
    phase: &'static str,
    arguments: &[OsString],
    source_snapshot: &Path,
    keylog_snapshot: Option<&Path>,
) -> InvocationReceipt {
    let keylog_argument =
        keylog_snapshot.map(|path| OsString::from(format!("tls.keylog_file:{}", path.display())));
    let argv = arguments
        .iter()
        .map(|argument| {
            if argument == source_snapshot.as_os_str() {
                "<source-snapshot>".to_owned()
            } else if keylog_argument
                .as_ref()
                .is_some_and(|expected| expected.as_os_str() == argument.as_os_str())
            {
                "tls.keylog_file:<keylog-snapshot>".to_owned()
            } else {
                argument.to_string_lossy().into_owned()
            }
        })
        .collect();
    InvocationReceipt {
        phase: phase.to_owned(),
        argv,
    }
}

fn add_diagnostic(diagnostics: &mut Vec<Diagnostic>, phase: &'static str, stderr: &[u8]) {
    if stderr.is_empty() {
        return;
    }
    diagnostics.push(Diagnostic {
        phase: phase.to_owned(),
        message: String::from_utf8_lossy(stderr).into_owned(),
        sha256: sha256(stderr),
    });
}
