use std::{
    error::Error,
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

fn refine(
    source: &Path,
    output: &Path,
    progress: &str,
    refresh: bool,
) -> Result<Output, Box<dyn Error>> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_l2solver"));
    command
        .arg("refine")
        .arg(source)
        .arg("--output")
        .arg(output)
        .args([
            "--profile",
            "fast",
            "--no-cache",
            "--quiet",
            "--progress",
            progress,
        ]);
    if refresh {
        command.arg("--refresh");
    }
    let result = command.output()?;
    assert!(
        matches!(result.status.code(), Some(0 | 3)),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(result)
}

#[test]
fn refresh_notice() -> Result<(), Box<dyn Error>> {
    for progress in ["never", "json"] {
        let temporary = tempfile::tempdir()?;
        let source = temporary.path().join("input.bin");
        let output = temporary.path().join("output");
        fs::write(&source, b"independent input")?;
        let mut original = None;
        for refresh in [false, true] {
            let result = refine(&source, &output, progress, refresh)?;
            if !refresh {
                original = Some(fs::read(output.join("manifest.json"))?);
                continue;
            }
            let diagnostic = String::from_utf8(result.stderr)?;
            let retained = if progress == "json" {
                let events = diagnostic
                    .lines()
                    .map(serde_json::from_str)
                    .collect::<Result<Vec<serde_json::Value>, _>>()?;
                let notice = events
                    .iter()
                    .find(|event| {
                        event.get("type").and_then(serde_json::Value::as_str)
                            == Some("retained_output")
                    })
                    .ok_or("retained output event is missing")?;
                assert!(notice.get("path_bytes").is_none());
                assert_eq!(
                    notice
                        .get("disk_retention")
                        .and_then(serde_json::Value::as_str),
                    Some("until_explicit_removal")
                );
                PathBuf::from(
                    notice
                        .get("path")
                        .and_then(serde_json::Value::as_str)
                        .ok_or("retained path is missing")?,
                )
            } else {
                assert!(diagnostic.contains("occupies disk space"));
                PathBuf::from(
                    diagnostic
                        .lines()
                        .find_map(|line| line.strip_prefix("Previous output retained at "))
                        .ok_or("retained output notice is missing")?,
                )
            };
            assert_eq!(
                fs::read(retained.join("manifest.json"))?.as_slice(),
                original.as_deref().ok_or("original manifest missing")?
            );
        }
    }
    Ok(())
}

#[cfg(unix)]
#[test]
fn non_utf8_notice() -> Result<(), Box<dyn Error>> {
    use std::{
        ffi::{OsStr, OsString},
        os::unix::ffi::{OsStrExt, OsStringExt},
    };

    for progress in ["never", "json"] {
        let temporary = tempfile::tempdir()?;
        let directory = temporary.path().join(OsStr::from_bytes(b"case-\xff"));
        fs::create_dir(&directory)?;
        let source = directory.join("input.bin");
        let output = directory.join("output");
        fs::write(&source, b"independent input")?;
        refine(&source, &output, progress, false)?;
        let original = fs::read(output.join("manifest.json"))?;
        let result = refine(&source, &output, progress, true)?;
        let retained = fs::read_dir(&directory)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?
            .into_iter()
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.as_bytes().starts_with(b".l2solver-"))
            })
            .ok_or("retained output is missing")?;
        let diagnostic = String::from_utf8(result.stderr)?;
        if progress == "json" {
            let events = diagnostic
                .lines()
                .map(serde_json::from_str)
                .collect::<Result<Vec<serde_json::Value>, _>>()?;
            let notice = events
                .iter()
                .find(|event| {
                    event.get("type").and_then(serde_json::Value::as_str) == Some("retained_output")
                })
                .ok_or("retained output event is missing")?;
            let bytes = notice
                .get("path_bytes")
                .and_then(serde_json::Value::as_array)
                .ok_or("exact path bytes are missing")?
                .iter()
                .map(|byte| {
                    byte.as_u64()
                        .ok_or("invalid path byte")
                        .and_then(|byte| u8::try_from(byte).map_err(|_| "invalid path byte"))
                })
                .collect::<Result<Vec<_>, _>>()?;
            assert_eq!(PathBuf::from(OsString::from_vec(bytes)), retained);
        } else {
            assert!(diagnostic.contains(r"case-\xFF/"), "{diagnostic}");
            let name = retained
                .file_name()
                .and_then(OsStr::to_str)
                .ok_or("retained output name is not text")?;
            assert!(diagnostic.contains(name), "{diagnostic}");
        }
        assert_eq!(fs::read(retained.join("manifest.json"))?, original);
    }
    Ok(())
}
