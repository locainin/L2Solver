#[cfg(target_os = "linux")]
use super::super::{
    inspection::inspect_tool,
    preparation::{CapturePreparation, prepare_capture_from},
};
use super::validate;
use std::io;

#[cfg(target_os = "linux")]
#[test]
fn affected_version_metadata_gate() -> Result<(), Box<dyn std::error::Error>> {
    use std::{fs, os::unix::fs::PermissionsExt};
    let directory = tempfile::tempdir()?;
    let capture = directory.path().join("input.pcap");
    let executable = directory.path().join("tshark");
    let marker = directory.path().join("metadata-started");
    fs::write(&capture, b"capture fixture")?;
    fs::write(
        &executable,
        format!(
            "#!/bin/sh\nif [ \"$2\" = '-v' ]; then printf 'TShark (Wireshark) 4.6.8\\n'; exit 0; fi\nprintf started > '{}'\nexit 1\n",
            marker.display()
        ),
    )?;
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700))?;
    let prepared = prepare_capture_from(
        CapturePreparation {
            capture,
            executable,
            keylog: None,
            timeout: std::time::Duration::from_secs(5),
            timeout_seconds: 5,
            input_maximum: 1024,
            metadata_maximum: 1024,
            output_maximum: 1024,
            diagnostic_maximum: 1024,
        },
        None,
    )?;
    let error = inspect_tool(&prepared)
        .err()
        .ok_or("affected version accepted")?;
    assert!(
        !marker.exists(),
        "metadata ran before the security version gate"
    );
    assert!(
        error
            .to_string()
            .contains("supported patched upstream release"),
        "{error}"
    );
    Ok(())
}

#[test]
fn patched_releases() -> io::Result<()> {
    for banner in [
        "TShark (Wireshark) 4.4.19 (Git v4.4.19)",
        "TShark (Wireshark) 4.6.9 (v4.6.9 packaged release)",
        "TShark 4.4.20",
        "TShark 4.6.10",
    ] {
        validate(banner)?;
    }
    Ok(())
}

#[test]
fn stable_release_banners() -> io::Result<()> {
    for banner in [
        "TShark (Wireshark) 4.4.19.",
        "TShark (Wireshark) 4.6.9.",
        "TShark (Wireshark) 4.4.19 (v4.4.19-0-gaeb82d6483db).",
        "TShark (Wireshark) 4.4.19 (Debian 4.4.19-1~deb12u1).",
        "TShark (Wireshark) 4.6.9 (Arch Linux build 3).",
        "TShark (Wireshark) 4.6.9 (v4.6.9 packaged release).",
        "TShark (Wireshark) 4.6.9 (prebuilt package).",
    ] {
        validate(banner)
            .map_err(|error| io::Error::new(error.kind(), format!("{banner}: {error}")))?;
    }
    Ok(())
}

#[test]
fn development_metadata_rejection() {
    for banner in [
        "TShark (Wireshark) 4.4.19 (v4.4.19rc0-5-gaeb82d6483db).",
        "TShark (Wireshark) 4.6.9 (Git v4.6.9RC1-0-gaeb82d6483db).",
        "TShark (Wireshark) 4.6.9 (Debian 4.6.9~rc1-1).",
        "TShark (Wireshark) 4.4.19 (v4.4.19-5-gaeb82d6483db).",
        "TShark (Wireshark) 4.4.19 (v4.4.19-0-gaeb82d6483db-dirty).",
        "TShark (Wireshark) 4.6.9 (development build).",
        "TShark (Wireshark) 4.6.9 (dev build).",
        "TShark (Wireshark) 4.6.9 (v4.6.9beta2).",
        "TShark (Wireshark) 4.6.9 (release candidate).",
        "TShark (Wireshark) 4.6.9 (pre-release build).",
        "TShark (Wireshark) 4.6.9 (nightly snapshot).",
        "TShark (Wireshark) 4.4.19..",
    ] {
        assert_eq!(
            validate(banner).err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported),
            "accepted unqualified banner: {banner}"
        );
    }
}

#[test]
fn affected_and_unknown_releases() {
    for banner in [
        "TShark (Wireshark) 4.4.18",
        "TShark (Wireshark) 4.6.4",
        "TShark (Wireshark) 4.6.8",
        "TShark 4.4.18 (vendor backport)",
        "TShark 4.5.99",
        "TShark 4.7.4",
        "TShark 5.0.0",
        "TShark 4.6.9rc1",
        "TShark 4.6.9-rc1",
        "TShark 4.6.09",
        "TShark 4.6.4294967296",
        "TShark 4.6.9.1",
        "TShark 4.6",
        "TShark 4.6.-9",
        "TShark 4.6.+9",
        "TShark fixture",
        "not TShark 4.6.9",
        "",
    ] {
        assert_eq!(
            validate(banner).err().map(|error| error.kind()),
            Some(io::ErrorKind::Unsupported),
            "accepted unqualified banner: {banner}"
        );
    }
}
