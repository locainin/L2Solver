use super::{clean_scope, deadline};
use crate::workbench::tshark::{
    ObjectExportBudget, ObjectExportStatus, objects, process,
    profile::{self, PROFILE},
};
use std::{
    collections::BTreeSet,
    error::Error,
    ffi::OsString,
    fs,
    io::{self, Write},
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn collision_guard() -> Result<(), Box<dyn Error>> {
    for (count, same_name, expected) in [
        (3, true, ObjectExportStatus::Complete),
        (3, false, ObjectExportStatus::Complete),
        (8, true, ObjectExportStatus::Partial),
    ] {
        let temporary = tempfile::tempdir()?;
        let profile = profile::create_profile(temporary.path(), Some(3))?;
        let config = profile::profile_environment(&profile)
            .into_iter()
            .find(|(name, _)| name == "WIRESHARK_CONFIG_DIR")
            .map(|(_, value)| std::path::PathBuf::from(value))
            .ok_or("profile directory missing")?;
        let preferences =
            fs::read_to_string(config.join("profiles").join(PROFILE).join("preferences"))?;
        let limit = preferences
            .lines()
            .find_map(|line| line.strip_prefix("gui.max_export_objects: "))
            .unwrap_or("1000")
            .parse::<usize>()?;
        let root = temporary.path().join("objects");
        let protocol = root.join("http");
        fs::create_dir_all(&protocol)?;
        write_named_objects(&protocol, count, same_name, limit)?;
        if count > 3 {
            assert_eq!(fs::read_dir(&protocol)?.count(), 4);
            assert_eq!(fs::read_to_string(protocol.join("same(3).bin"))?, "7");
        }
        let output = process::run_streaming(
            Path::new("/bin/true"),
            &[],
            &[],
            process::StreamingPolicy {
                stderr_maximum: 1024,
                deadline: Instant::now() + Duration::from_secs(30),
                object_root: &root,
                protocol_directory_count: 1,
                object_budget: ObjectExportBudget {
                    temporary_bytes: 1024,
                    temporary_files: 3,
                },
                job: None,
            },
        );
        let result = objects::resolve_object_export(
            output,
            &root,
            &temporary.path().join("snapshot"),
            &[(String::from("http"), protocol)],
            deadline(),
            None,
            Some(&clean_scope()),
        )?;
        assert_eq!(
            result.status, expected,
            "count={count}, same_name={same_name}"
        );
        if expected == ObjectExportStatus::Partial {
            assert!(
                result
                    .issues
                    .iter()
                    .any(|issue| issue.contains("temporary files"))
            );
        }
    }
    Ok(())
}

fn write_named_objects(
    directory: &Path,
    count: usize,
    same_name: bool,
    limit: usize,
) -> io::Result<()> {
    for number in 0..count {
        let base = if same_name {
            String::from("same")
        } else {
            format!("object{number}")
        };
        for suffix in 0..limit {
            let name = if suffix == 0 {
                format!("{base}.bin")
            } else {
                format!("{base}({suffix}).bin")
            };
            let path = directory.join(name);
            if !path.exists() || suffix + 1 == limit {
                fs::write(path, number.to_string())?;
                break;
            }
        }
    }
    Ok(())
}

#[cfg(all(target_os = "linux", not(target_env = "uclibc")))]
#[test]
fn upstream_collision_bodies() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let capture = temporary.path().join("synthetic.pcap");
    write_capture(&capture)?;
    let profile = profile::create_profile(temporary.path(), Some(1001))?;
    let environment = profile::profile_environment(&profile);
    let preferences = match Command::new("tshark")
        .args(["-G", "currentprefs", "-n", "-C", PROFILE])
        .envs(environment.iter().cloned())
        .output()
    {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        result => result?,
    };
    assert!(
        preferences.status.success(),
        "{}",
        String::from_utf8_lossy(&preferences.stderr)
    );
    profile::verify_effective_preferences(&preferences.stdout, &profile)?;
    let root = temporary.path().join("objects");
    let protocol = root.join("http");
    fs::create_dir_all(&protocol)?;
    let mut export = OsString::from("http,");
    export.push(&protocol);
    let arguments = vec![
        "-n".into(),
        "-q".into(),
        "-C".into(),
        PROFILE.into(),
        "-r".into(),
        capture.into_os_string(),
        "--export-objects".into(),
        export,
    ];
    let deadline = Instant::now() + Duration::from_secs(30);
    let output = process::run_streaming(
        Path::new("tshark"),
        &arguments,
        &environment,
        process::StreamingPolicy {
            stderr_maximum: 1024,
            deadline,
            object_root: &root,
            protocol_directory_count: 1,
            object_budget: ObjectExportBudget {
                temporary_bytes: 64 * 1024,
                temporary_files: 1001,
            },
            job: None,
        },
    );
    let result = objects::resolve_object_export(
        output,
        &root,
        &temporary.path().join("snapshot"),
        &[(String::from("http"), protocol)],
        deadline,
        None,
        Some(&clean_scope()),
    )?;
    assert_eq!(
        result.status,
        ObjectExportStatus::Complete,
        "{:?}",
        result.issues
    );
    let (_, objects) = result.directories.first().ok_or("snapshot missing")?;
    let bodies = fs::read_dir(objects)?
        .map(|entry| fs::read(entry?.path()))
        .collect::<Result<BTreeSet<_>, _>>()?;
    let expected = (0..1001)
        .map(|number| format!("object-{number:04}").into_bytes())
        .collect::<BTreeSet<_>>();
    assert_eq!(bodies, expected);
    assert_eq!(fs::read_dir(objects)?.count(), 1001);
    Ok(())
}

fn write_capture(path: &Path) -> Result<(), Box<dyn Error>> {
    let mut file = fs::File::create(path)?;
    file.write_all(&[
        0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0, 1, 0, 0, 0,
    ])?;
    let request = b"GET /same.bin HTTP/1.1\r\nHost: example.invalid\r\n\r\n";
    let mut number = 0_u32;
    for index in 0..1001_u16 {
        let port = 40_000 + index;
        let body = format!("object-{index:04}");
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/octet-stream\r\n\r\n{body}",
            body.len()
        );
        let acknowledgement = 101 + u32::try_from(request.len())?;
        for packet in [
            frame(port, false, 100, 0, 2, b"")?,
            frame(port, true, 1000, 101, 0x12, b"")?,
            frame(port, false, 101, 1001, 0x18, request)?,
            frame(port, true, 1001, acknowledgement, 0x18, response.as_bytes())?,
        ] {
            number += 1;
            let length = u32::try_from(packet.len())?;
            file.write_all(&number.to_le_bytes())?;
            file.write_all(&0_u32.to_le_bytes())?;
            file.write_all(&length.to_le_bytes())?;
            file.write_all(&length.to_le_bytes())?;
            file.write_all(&packet)?;
        }
    }
    Ok(())
}

fn frame(
    port: u16,
    server: bool,
    sequence: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let (source, destination, source_port, destination_port) = if server {
        ([192, 0, 2, 2], [192, 0, 2, 1], 80_u16, port)
    } else {
        ([192, 0, 2, 1], [192, 0, 2, 2], port, 80_u16)
    };
    let mut tcp = Vec::new();
    tcp.extend(source_port.to_be_bytes());
    tcp.extend(destination_port.to_be_bytes());
    tcp.extend(sequence.to_be_bytes());
    tcp.extend(ack.to_be_bytes());
    tcp.extend([0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    tcp.extend(payload);
    let mut pseudo = Vec::new();
    pseudo.extend(source);
    pseudo.extend(destination);
    pseudo.extend([0, 6]);
    pseudo.extend(u16::try_from(tcp.len())?.to_be_bytes());
    pseudo.extend(&tcp);
    tcp.get_mut(16..18)
        .ok_or("TCP checksum field missing")?
        .copy_from_slice(&checksum(&pseudo).to_be_bytes());
    let mut ip = vec![0x45, 0];
    ip.extend(u16::try_from(20 + tcp.len())?.to_be_bytes());
    ip.extend([0, 1, 0, 0, 64, 6, 0, 0]);
    ip.extend(source);
    ip.extend(destination);
    let sum = checksum(&ip);
    ip.get_mut(10..12)
        .ok_or("IP checksum field missing")?
        .copy_from_slice(&sum.to_be_bytes());
    let mut result = vec![2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 0, 1, 8, 0];
    result.extend(ip);
    result.extend(tcp);
    Ok(result)
}

fn checksum(bytes: &[u8]) -> u16 {
    let sum = bytes.iter().enumerate().fold(0_u16, |sum, (index, byte)| {
        let word = u16::from(*byte) << if index % 2 == 0 { 8 } else { 0 };
        let (sum, carry) = sum.overflowing_add(word);
        sum.wrapping_add(u16::from(carry))
    });
    !sum
}
