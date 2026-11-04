use std::{error::Error, process::Command};

#[test]
fn cache_commands_manage_only_the_selected_xdg_roots() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let cache_home = temporary.path().join("cache");
    let state_home = temporary.path().join("state");
    let sentinel = temporary.path().join("keep");
    std::fs::write(&sentinel, b"unrelated")?;
    for command in ["stats", "prune", "clear", "stats"] {
        let output = Command::new(env!("CARGO_BIN_EXE_l2solver"))
            .args(["cache", command])
            .env("XDG_CACHE_HOME", &cache_home)
            .env("XDG_STATE_HOME", &state_home)
            .output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_ne!(output.stdout.len(), 0);
        assert_eq!(std::fs::read(&sentinel)?, b"unrelated");
    }
    assert!(cache_home.join("l2solver").is_dir());
    assert!(state_home.join("l2solver").is_dir());
    Ok(())
}
