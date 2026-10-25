use l2_workbench::endpoint::{
    parse_event_xml, parse_evtx_envelope, parse_mft, parse_strace, parse_usn_device_buffer,
    parse_usn_records,
};
use l2solver_fuzz::endpoint_seeds::write_seed_files;
use std::{error::Error, fs, path::Path};

#[test]
fn generator_parser_endpoint_seed_files() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let output = temporary.path().join("endpoint-seeds");

    let paths = write_seed_files(&output)?;

    assert_eq!(paths.len(), 6);
    let v2_bytes = read_seed(&output, "usn-v2.bin")?;
    let v2 = parse_usn_records(&v2_bytes)?;
    assert_eq!(v2.records.len(), 1);
    assert_eq!(
        v2.records.first().map(|record| record.major_version),
        Some(2)
    );

    let v3_bytes = read_seed(&output, "usn-v3-device-buffer.bin")?;
    let v3 = parse_usn_device_buffer(&v3_bytes)?;
    assert_eq!(v3.next_usn, Some(1));
    assert_eq!(v3.records.len(), 1);
    assert_eq!(
        v3.records.first().map(|record| record.major_version),
        Some(3)
    );

    let mft_bytes = read_seed(&output, "mft-file.bin")?;
    assert_eq!(parse_mft(&mft_bytes)?.records.len(), 1);

    let evtx_bytes = read_seed(&output, "evtx-envelope.evtx")?;
    assert_eq!(parse_evtx_envelope(&evtx_bytes)?.records.len(), 1);

    let xml_bytes = read_seed(&output, "event.xml")?;
    assert_eq!(parse_event_xml(&xml_bytes)?.events.len(), 1);

    let strace_bytes = read_seed(&output, "strace.log")?;
    let trace = parse_strace(&strace_bytes)?;
    assert_eq!(trace.events.len(), 1);
    assert_eq!(
        trace.events.first().map(|event| event.bytes.as_slice()),
        Some(b"SEED".as_slice())
    );
    Ok(())
}

#[test]
fn existing_seed_no_overwrite() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let output = temporary.path().join("endpoint-seeds");
    fs::create_dir(&output)?;
    let existing = output.join("mft-file.bin");
    fs::write(&existing, b"keep this existing file")?;

    assert!(write_seed_files(&output).is_err());

    assert_eq!(fs::read(existing)?, b"keep this existing file");
    assert!(!output.join("usn-v2.bin").exists());
    Ok(())
}

fn read_seed(directory: &Path, name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(fs::read(directory.join(name))?)
}
