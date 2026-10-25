#[path = "../../crates/l2-workbench/tests/endpoint/support.rs"]
mod fixtures;

use std::{
    error::Error,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

struct SeedFile {
    name: &'static str,
    bytes: Vec<u8>,
}

/// Generate generic positive endpoint inputs under a caller-selected ignored directory
///
/// # Errors
/// Returns an error when fixtures fail to build, the output path is invalid, or any seed exists
pub fn write_seed_files(directory: &Path) -> Result<Vec<PathBuf>, Box<dyn Error>> {
    let seeds = build_seed_files()?;
    fs::create_dir_all(directory)?;
    let paths = seed_paths(directory, &seeds);
    reject_existing_paths(&paths)?;
    write_all_new(&paths, &seeds)?;
    Ok(paths)
}

fn build_seed_files() -> Result<Vec<SeedFile>, Box<dyn Error>> {
    let mut usn_v3 = 1_u64.to_le_bytes().to_vec();
    usn_v3.extend_from_slice(&fixtures::usn_v3_record(9, "seed-v3.bin")?);
    Ok(vec![
        SeedFile {
            name: "usn-v2.bin",
            bytes: fixtures::usn_v2_record(7, "seed-v2.bin")?,
        },
        SeedFile {
            name: "usn-v3-device-buffer.bin",
            bytes: usn_v3,
        },
        SeedFile {
            name: "mft-file.bin",
            bytes: fixtures::mft_record(100)?,
        },
        SeedFile {
            name: "evtx-envelope.evtx",
            bytes: fixtures::evtx_file()?,
        },
        SeedFile {
            name: "event.xml",
            bytes: fixtures::sysmon_event_xml().into_bytes(),
        },
        SeedFile {
            name: "strace.log",
            bytes: fixtures::strace_sendto_line("192.0.2.10:40000->198.51.100.20:53", b"SEED"),
        },
    ])
}

fn seed_paths(directory: &Path, seeds: &[SeedFile]) -> Vec<PathBuf> {
    seeds.iter().map(|seed| directory.join(seed.name)).collect()
}

fn reject_existing_paths(paths: &[PathBuf]) -> Result<(), Box<dyn Error>> {
    for path in paths {
        match fs::symlink_metadata(path) {
            Ok(_) => return Err("refusing to replace an existing endpoint seed".into()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(())
}

fn write_all_new(paths: &[PathBuf], seeds: &[SeedFile]) -> Result<(), Box<dyn Error>> {
    let mut created = Vec::with_capacity(paths.len());
    for (path, seed) in paths.iter().zip(seeds) {
        if let Err(error) = write_new(path, &seed.bytes) {
            for created_path in created {
                let _ = fs::remove_file(created_path);
            }
            return Err(error.into());
        }
        created.push(path);
    }
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(bytes) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
}
