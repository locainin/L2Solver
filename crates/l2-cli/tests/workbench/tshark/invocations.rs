use super::{assert_error_contains, fixture, produce, run};
use l2_workbench::{sha256, tshark::TsharkReport};
use std::{error::Error, fs};

#[test]
fn glossary_inspection_accepts_older_parser_and_records_evidence() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n", &super::packets(1))?;

    let report: TsharkReport = serde_json::from_value(produce(&options)?)?;

    for (phase, glossary) in [("plugins", "plugins"), ("preferences", "currentprefs")] {
        let invocation = report
            .tool
            .invocations
            .iter()
            .find(|invocation| invocation.phase == phase)
            .ok_or("glossary invocation missing")?;
        assert!(
            invocation.argv.iter().map(String::as_str).eq([
                "-G",
                glossary,
                "-n",
                "-C",
                report.tool.profile.name.as_str(),
            ]),
            "incorrect arguments for {phase}: {:?}",
            invocation.argv
        );
    }
    assert_eq!(report.tool.plugins.len(), 1);
    assert_eq!(
        report.tool.plugin_inventory_sha256,
        sha256(b"fixture.so\t1.0\tdissector\tfixture.so\n")
    );
    assert_eq!(
        report.tool.effective_preferences_sha256,
        sha256(super::super::super::PREFERENCES.as_bytes())
    );
    assert_eq!(
        report
            .tool
            .verified_profile_preferences
            .get("gui.packet_list_show_related")
            .map(String::as_str),
        Some("FALSE")
    );
    report.validate()?;
    Ok(())
}

#[test]
fn glossary_inspection_reports_inventory_and_preference_failures() -> Result<(), Box<dyn Error>> {
    for (glossary, phase) in [
        ("plugins", "plugin inventory"),
        ("currentprefs", "effective preferences"),
    ] {
        let directory = tempfile::tempdir()?;
        let options = fixture(directory.path(), b"1\n", &super::packets(1))?;
        fs::write(directory.path().join(format!("{glossary}.fail")), b"")?;
        let mut output = Vec::new();

        let error = match run(&options, &mut output) {
            Ok(_) => return Err(format!("{phase} failure was accepted").into()),
            Err(error) => error.to_string(),
        };
        assert!(error.contains(phase), "missing {phase} in {error}");
        assert!(
            error.contains(&format!("fixture {glossary} failed")),
            "missing child diagnostic in {error}"
        );
        assert!(output.is_empty(), "receipt emitted after {phase} failed");
    }
    Ok(())
}

fn decode_arguments(report: &mut TsharkReport) -> Result<&mut Vec<String>, Box<dyn Error>> {
    Ok(&mut report
        .tool
        .invocations
        .iter_mut()
        .find(|invocation| invocation.phase == "decode")
        .ok_or("decode invocation missing")?
        .argv)
}

#[test]
fn consumer_receipts_missing_required_options() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n", &super::packets(1))?;
    let report: TsharkReport = serde_json::from_value(produce(&options)?)?;

    for option in ["-n", "-2", "-q", "-C", "-r", "-T", "--no-duplicate-keys"] {
        let mut incomplete = report.clone();
        let arguments = decode_arguments(&mut incomplete)?;
        let position = arguments
            .iter()
            .position(|argument| argument == option)
            .ok_or("required decode option missing from the producer")?;
        arguments.remove(position);

        assert_error_contains(incomplete.validate(), "decode invocation")?;
    }
    Ok(())
}

#[test]
fn consumer_changed_profile_source_format() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n", &super::packets(1))?;
    let report: TsharkReport = serde_json::from_value(produce(&options)?)?;

    for (option, changed_value) in [
        ("-C", "different-profile"),
        ("-r", "different-capture.pcap"),
        ("-T", "text"),
    ] {
        let mut changed = report.clone();
        let arguments = decode_arguments(&mut changed)?;
        let position = arguments
            .iter()
            .position(|argument| argument == option)
            .ok_or("required decode option missing from the producer")?;
        *arguments
            .get_mut(position + 1)
            .ok_or("decode option value missing")? = changed_value.to_owned();

        assert_error_contains(changed.validate(), "decode invocation")?;
    }
    Ok(())
}

#[test]
fn consumer_keylog_without_declared() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n", &super::packets(1))?;
    let report: TsharkReport = serde_json::from_value(produce(&options)?)?;

    for keylog in [
        "tls.keylog_file:<keylog-snapshot>",
        "tls.keylog_file:undeclared-keylog",
    ] {
        let mut changed = report.clone();
        decode_arguments(&mut changed)?.extend(["-o".to_owned(), keylog.to_owned()]);

        assert_error_contains(changed.validate(), "decode invocation")?;
    }
    Ok(())
}

#[test]
fn consumer_requires_recorded_snapshot_binding() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let mut options = fixture(directory.path(), b"1\n", &super::packets(1))?;
    let keylog = directory.path().join("keys.log");
    fs::write(&keylog, b"# Explicit keylog fixture\n")?;
    options.tls_keylog = Some(keylog);
    let report: TsharkReport = serde_json::from_value(produce(&options)?)?;
    // The producer's declared keylog and sanitized invocation form a valid receipt
    report.validate()?;

    let mut missing = report.clone();
    decode_arguments(&mut missing)?
        .retain(|argument| argument != "-o" && !argument.starts_with("tls.keylog_file:"));
    assert_error_contains(missing.validate(), "decode invocation")?;

    for keylog in ["tls.keylog_file:", "tls.keylog_file:different-keylog"] {
        let mut changed = report.clone();
        *decode_arguments(&mut changed)?
            .iter_mut()
            .find(|argument| argument.starts_with("tls.keylog_file:"))
            .ok_or("producer keylog option missing")? = keylog.to_owned();

        assert_error_contains(changed.validate(), "decode invocation")?;
    }
    Ok(())
}

#[test]
fn consumer_uses_profile_name_invocations() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n", &super::packets(1))?;
    let mut report: TsharkReport = serde_json::from_value(produce(&options)?)?;
    let profile = std::mem::replace(
        &mut report.tool.profile.name,
        "alternate-profile".to_owned(),
    );
    for invocation in &mut report.tool.invocations {
        for argument in &mut invocation.argv {
            if argument == &profile {
                *argument = "alternate-profile".to_owned();
            }
        }
    }

    report.validate()?;
    Ok(())
}

#[test]
fn uses_stable_offline_profile() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let options = fixture(directory.path(), b"1\n", &super::packets(1))?;
    let report: TsharkReport = serde_json::from_value(produce(&options)?)?;

    assert_eq!(report.tool.profile.name, "l2solver-offline");
    assert!(report.tool.invocations.iter().all(|invocation| {
        invocation
            .argv
            .windows(2)
            .filter(|arguments| arguments.first().is_some_and(|argument| argument == "-C"))
            .all(|arguments| {
                arguments
                    .get(1)
                    .is_some_and(|name| name == "l2solver-offline")
            })
    }));
    Ok(())
}
