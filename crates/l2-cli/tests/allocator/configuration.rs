use std::{env, process::Command};

#[test]
fn released_pages_have_no_allocator_decay_delay() -> Result<(), Box<dyn std::error::Error>> {
    // Listing tests initializes the linked allocator without starting another test run
    let output = Command::new(env::current_exe()?)
        .arg("--list")
        .env_remove("LD_PRELOAD")
        .env_remove("MALLOC_CONF")
        .env("_RJEM_MALLOC_CONF", "confirm_conf:true")
        .output()?;
    assert!(output.status.success(), "allocator diagnostic child failed");
    let diagnostic = String::from_utf8(output.stderr)?;
    for option in ["dirty_decay_ms", "muzzy_decay_ms"] {
        let prefix = format!("-- Set conf value: {option}:");
        // Later settings override earlier defaults, so inspect the last accepted value
        let value = diagnostic
            .lines()
            .filter_map(|line| line.split_once(&prefix).map(|(_, value)| value.trim()))
            .next_back();
        assert_eq!(
            value,
            Some("0"),
            "{option} must allow immediate reclamation of unused pages"
        );
    }
    Ok(())
}
