use std::process::Command;

#[test]
fn extract_help_describes_recovery_and_optional_enrichment()
-> Result<(), Box<dyn std::error::Error>> {
    let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["extract", "--help"])
        .output()?;
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    let text = String::from_utf8(output.stdout)?
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    for detail in [
        "complete native HTTP bodies",
        "FTP transfer candidates",
        "Recursively validated archive members",
        "published with their parent archives",
        "TShark",
        "PATH",
        "safe generated names",
        "TShark objects do not include packet provenance; native provenance is retained in the export reports",
        "CAPTURE.export",
        "--output",
        "Matching owned output is reused",
        "--refresh replaces it atomically",
        "Standard input",
        "Incomplete native analysis",
        "TShark is missing",
        "object export fails",
        "available artifacts are still published",
        "summary.txt shows native and TShark status separately",
        "TShark enrichment is optional",
        "--require-tshark",
        "Packets outside discovery scope are reported without failing extraction",
        "Select the search effort: fast, normal, or deep",
        "default: normal",
        "Progress defaults to automatic terminal detection",
        "Choose progress output: auto, always, never, or json",
        "--refresh recomputes results",
        "--no-cache skips reads and writes",
        "--strict-cache checks cached content in full",
        "--memory-limit",
        "--cache-max-bytes",
        "KB/MB/GB/TB",
        "KiB/MiB/GiB/TiB",
        "default: 512MiB",
        "default: 2GiB",
        "--jobs",
        "--quiet",
        "--verbose",
        "--progress",
        "Examples:",
        "status 3",
    ] {
        assert!(text.contains(detail), "missing {detail}: {text}");
    }
    assert!(
        text.split_whitespace().count() <= 320,
        "help is too long: {text}"
    );
    assert!(!text.contains("must not already exist"));
    Ok(())
}

#[test]
fn root_help_lists_extract_and_keeps_export_alias_hidden() -> Result<(), Box<dyn std::error::Error>>
{
    let root = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .arg("--help")
        .output()?;
    assert!(root.status.success());
    let root_text = String::from_utf8(root.stdout)?;
    let extract_line = root_text
        .lines()
        .find(|line| line.trim_start().starts_with("extract "))
        .ok_or("root help does not list extract")?;
    assert!(extract_line.contains("Recover artifacts from a PCAP/PCAPNG capture"));
    assert!(!extract_line.contains('`'));
    assert!(
        !root_text
            .lines()
            .any(|line| line.trim_start().starts_with("export "))
    );
    assert!(root_text.contains("l2solver extract traffic.pcapng -o recovered/"));
    assert!(!root_text.contains("[aliases: export]"));
    let legacy = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["export", "--help"])
        .output()?;
    assert!(legacy.status.success());
    assert!(String::from_utf8(legacy.stdout)?.contains("--require-tshark"));
    Ok(())
}
