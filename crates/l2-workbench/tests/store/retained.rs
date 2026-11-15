use super::{capture, frames, sha256};
use l2_workbench::store::{Options, Store};
use std::{
    error::Error,
    fs,
    io::{Cursor, Read, Seek, SeekFrom, Write},
};

#[test]
fn retained_descriptor_identity() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let bytes = capture(&[frames::tcp(false, 100, 2, b"capture")?])?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let receipt = store.ingest("capture.pcap", Cursor::new(&bytes))?;
    let path = temporary
        .path()
        .join("sources")
        .join(format!("{}.pcap", sha256(&bytes)));
    let moved = temporary.path().join("old-source");
    let mut held = store.open_retained_source(&receipt)?;

    // A replacement path cannot redirect an already opened descriptor
    fs::rename(&path, &moved)?;
    fs::write(&path, vec![0; bytes.len()])?;
    let mut observed = Vec::new();
    held.read_to_end(&mut observed)?;
    assert_eq!(observed, bytes);
    assert!(held.write_all(b"x").is_err());

    // A different writer can still change the inode behind a read-only descriptor
    let mut changed = bytes.clone();
    *changed.first_mut().ok_or("empty capture")? ^= 1;
    fs::write(&moved, &changed)?;
    held.seek(SeekFrom::Start(0))?;
    observed.clear();
    held.read_to_end(&mut observed)?;
    assert_eq!(observed, changed);
    Ok(())
}

#[test]
fn retained_descriptor_rejects_invalid_receipt_and_length() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let bytes = capture(&[frames::tcp(false, 100, 2, b"capture")?])?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let receipt = store.ingest("capture.pcap", Cursor::new(&bytes))?;
    let mut invalid = receipt.clone();
    invalid.packets += 1;
    assert!(store.open_retained_source(&invalid).is_err());

    let path = temporary
        .path()
        .join("sources")
        .join(format!("{}.pcap", sha256(&bytes)));
    fs::write(path, b"short")?;
    assert!(store.open_retained_source(&receipt).is_err());
    Ok(())
}
