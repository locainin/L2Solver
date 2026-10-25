use crc32fast::hash as crc32;
use l2_workbench::evidence::Case;
use std::{
    error::Error,
    fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
};

pub fn run(args: &[&str], input: &[u8]) -> Result<Output, Box<dyn Error>> {
    let mut child = Command::new(env!("CARGO_BIN_EXE_l2solver"))
        .args(["workbench"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    if let Some(mut pipe) = child.stdin.take()
        && let Err(error) = pipe.write_all(input)
        && error.kind() != io::ErrorKind::BrokenPipe
    {
        return Err(error.into());
    }
    Ok(child.wait_with_output()?)
}

pub fn empty_capture() -> Vec<u8> {
    let mut bytes = vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0];
    bytes.extend_from_slice(&[0; 8]);
    bytes.extend_from_slice(&65_535_u32.to_le_bytes());
    bytes.extend_from_slice(&1_u32.to_le_bytes());
    bytes
}

pub fn capture_with_truncated_record() -> Vec<u8> {
    let mut bytes = empty_capture();
    for value in [0_u32, 0, 14, 14] {
        bytes.extend_from_slice(&value.to_le_bytes());
    }
    bytes.push(0);
    bytes
}

pub fn save_case(directory: &Path, name: &str, case: &Case) -> Result<PathBuf, Box<dyn Error>> {
    let path = directory.join(name);
    fs::write(&path, case.to_json()?)?;
    Ok(path)
}

pub fn path_arg(path: &Path) -> Result<&str, io::Error> {
    path.to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "test path is not UTF-8"))
}

pub fn ipv4_header_frame(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut frame = vec![0; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    frame.extend_from_slice(&[0x45, 0x00]);
    frame.extend_from_slice(&20_u16.to_be_bytes());
    frame.extend_from_slice(&1_u16.to_be_bytes());
    frame.extend_from_slice(&0_u16.to_be_bytes());
    frame.extend_from_slice(&[64, 17, 0, 0]);
    frame.extend_from_slice(&source);
    frame.extend_from_slice(&destination);
    frame
}

pub fn stored_zip(name: &[u8], content: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    stored_zip_entries(&[(name, content)])
}

pub fn stored_zip_entries(entries: &[(&[u8], &[u8])]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    let mut directory = Vec::new();
    for (name, content) in entries {
        let name_length = u16::try_from(name.len())?;
        let content_length = u32::try_from(content.len())?;
        let checksum = crc32(content);
        let local_offset = u32::try_from(bytes.len())?;

        push_u32(&mut bytes, 0x0403_4b50);
        push_u16(&mut bytes, 20);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u16(&mut bytes, 0);
        push_u32(&mut bytes, checksum);
        push_u32(&mut bytes, content_length);
        push_u32(&mut bytes, content_length);
        push_u16(&mut bytes, name_length);
        push_u16(&mut bytes, 0);
        bytes.extend_from_slice(name);
        bytes.extend_from_slice(content);

        push_u32(&mut directory, 0x0201_4b50);
        push_u16(&mut directory, 20);
        push_u16(&mut directory, 20);
        push_u16(&mut directory, 0);
        push_u16(&mut directory, 0);
        push_u16(&mut directory, 0);
        push_u16(&mut directory, 0);
        push_u32(&mut directory, checksum);
        push_u32(&mut directory, content_length);
        push_u32(&mut directory, content_length);
        push_u16(&mut directory, name_length);
        push_u16(&mut directory, 0);
        push_u16(&mut directory, 0);
        push_u16(&mut directory, 0);
        push_u16(&mut directory, 0);
        push_u32(&mut directory, 0);
        push_u32(&mut directory, local_offset);
        directory.extend_from_slice(name);
    }

    let directory_offset = u32::try_from(bytes.len())?;
    let directory_length = u32::try_from(directory.len())?;
    bytes.extend_from_slice(&directory);
    push_u32(&mut bytes, 0x0605_4b50);
    push_u16(&mut bytes, 0);
    push_u16(&mut bytes, 0);
    let entry_count = u16::try_from(entries.len())?;
    push_u16(&mut bytes, entry_count);
    push_u16(&mut bytes, entry_count);
    push_u32(&mut bytes, directory_length);
    push_u32(&mut bytes, directory_offset);
    push_u16(&mut bytes, 0);
    Ok(bytes)
}

fn push_u16(bytes: &mut Vec<u8>, value: u16) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}
