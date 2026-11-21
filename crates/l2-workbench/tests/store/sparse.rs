use crate::frames;
use l2_workbench::{
    sha256,
    storage::SparseWriter,
    store::{Options, Store},
};
use std::{
    error::Error,
    fs,
    io::{self, Cursor, Read, Seek, SeekFrom, Write},
};

#[test]
fn mixed_and_trailing_zeroes() -> Result<(), Box<dyn Error>> {
    let mut file = tempfile::NamedTempFile::new()?;
    let mut mixed = vec![0; 2 * 1024 * 1024];
    *mixed.first_mut().ok_or("missing first byte")? = 17;
    *mixed.last_mut().ok_or("missing last byte")? = 29;
    let trailing = vec![0; 128 * 1024];
    let mut expected = mixed.clone();
    expected.extend_from_slice(&trailing);

    let mut writer = SparseWriter::new(file.as_file_mut(), u64::try_from(expected.len())?)?;
    writer.write_all(&mixed)?;
    writer.write_all(&trailing)?;
    assert_eq!(writer.finish()?, u64::try_from(expected.len())?);

    assert_eq!(
        fs::metadata(file.path())?.len(),
        u64::try_from(expected.len())?
    );
    assert_eq!(fs::read(file.path())?, expected);
    assert_sparse_if_supported(file.path())?;
    Ok(())
}

#[test]
fn dense_bytes() -> Result<(), Box<dyn Error>> {
    let mut file = tempfile::NamedTempFile::new()?;
    let bytes = vec![0x5a; 256 * 1024];
    let mut writer = SparseWriter::new(file.as_file_mut(), u64::try_from(bytes.len())?)?;
    writer.write_all(&bytes)?;
    assert_eq!(writer.finish()?, u64::try_from(bytes.len())?);
    assert_eq!(fs::read(file.path())?, bytes);
    Ok(())
}

#[test]
fn limit_before_write() -> Result<(), Box<dyn Error>> {
    let mut file = tempfile::NamedTempFile::new()?;
    let path = file.path().to_owned();
    let mut writer = SparseWriter::new(file.as_file_mut(), 5)?;
    writer.write_all(b"abc")?;
    let Err(error) = writer.write_all(b"def") else {
        return Err("limit accepted an oversized dense chunk".into());
    };
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert!(writer.write_all(&[0; 3]).is_err());
    assert_eq!(fs::read(&path)?, b"abc");
    writer.write_all(b"de")?;
    assert_eq!(writer.finish()?, 5);
    assert_eq!(fs::read(path)?, b"abcde");
    Ok(())
}

#[test]
fn zero_limit() -> Result<(), Box<dyn Error>> {
    let mut file = tempfile::NamedTempFile::new()?;
    let mut writer = SparseWriter::new(file.as_file_mut(), 0)?;
    writer.write_all(&[])?;
    assert!(writer.write_all(&[0]).is_err());
    assert_eq!(writer.finish()?, 0);
    assert_eq!(fs::metadata(file.path())?.len(), 0);
    Ok(())
}

#[test]
fn rejects_existing_file_or_offset() -> Result<(), Box<dyn Error>> {
    let mut file = tempfile::NamedTempFile::new()?;
    file.write_all(b"evidence")?;
    file.rewind()?;
    assert!(SparseWriter::new(file.as_file_mut(), 100).is_err());
    assert_eq!(fs::read(file.path())?, b"evidence");

    let mut empty = tempfile::NamedTempFile::new()?;
    empty.seek(SeekFrom::Start(1))?;
    assert!(SparseWriter::new(empty.as_file_mut(), 100).is_err());
    assert_eq!(fs::metadata(empty.path())?.len(), 0);
    Ok(())
}

#[cfg(unix)]
#[test]
fn rejects_append_mode() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::NamedTempFile::new()?;
    let mut file = fs::OpenOptions::new().append(true).open(temporary.path())?;
    assert!(SparseWriter::new(&mut file, 100).is_err());
    Ok(())
}

#[test]
fn sparse_capture_retained() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let bytes = padded_capture()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let receipt = store.ingest_with_limit(
        "sparse.pcapng",
        Cursor::new(&bytes),
        u64::try_from(bytes.len())?,
    )?;
    assert_eq!(receipt.bytes, u64::try_from(bytes.len())?);
    assert_eq!(receipt.packets, 1);
    assert_eq!(receipt.source_id, format!("sha256:{}", sha256(&bytes)));
    let retained = temporary
        .path()
        .join("sources")
        .join(format!("{}.pcap", sha256(&bytes)));
    assert_eq!(fs::read(&retained)?, bytes);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&retained)?.permissions().mode() & 0o077, 0);
    }
    assert_sparse_if_supported(&retained)?;
    store.verify_sources()?;
    Ok(())
}

#[test]
fn import_limit_rollback() -> Result<(), Box<dyn Error>> {
    let temporary = tempfile::tempdir()?;
    let bytes = padded_capture()?;
    let mut store = Store::create(temporary.path(), Options::default())?;
    let limit = u64::try_from(bytes.len())? - 1;
    let Err(error) =
        store.ingest_with_limit("limited.pcapng", ShortReads(Cursor::new(&bytes)), limit)
    else {
        return Err("capture above limit was accepted".into());
    };
    assert!(error.to_string().contains("storage byte limit"), "{error}");
    assert_eq!(store.inventory()?.sources, 0);
    assert_eq!(store.inventory()?.packets, 0);
    assert_eq!(fs::read_dir(temporary.path().join("sources"))?.count(), 0);

    let receipt = store.ingest_with_limit(
        "retry.pcapng",
        ShortReads(Cursor::new(&bytes)),
        u64::try_from(bytes.len())?,
    )?;
    assert_eq!(receipt.bytes, u64::try_from(bytes.len())?);
    assert_eq!(store.inventory()?.packets, 1);
    store.verify_sources()?;
    Ok(())
}

struct ShortReads<R>(R);

impl<R: Read> Read for ShortReads<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let length = bytes.len().min(8192);
        self.0.read(bytes.split_at_mut(length).0)
    }
}

fn padded_capture() -> Result<Vec<u8>, Box<dyn Error>> {
    let packet = frames::tcp(false, 100, 2, b"sparse capture")?;
    let metadata = packet.metadata();
    let time = l2_capture::CaptureTimestamp::new(
        1,
        l2_capture::TimestampResolution::MICROSECOND,
        0,
        l2_capture::TimestampSource::Unknown,
    );
    let packet = l2_capture::CapturedFrame::new(
        packet.bytes().to_vec(),
        l2_capture::CaptureMetadata::new(
            metadata.interface(),
            metadata.original_len(),
            None,
            Some(time),
            metadata.direction(),
            metadata.vlan(),
            metadata.fcs(),
        )
        .with_link_type(metadata.link_type()),
    )?;
    let metadata = packet.metadata();
    let config = l2_pcap::InterfaceConfig::new_with_link_type(
        metadata.link_type(),
        65_535,
        time.resolution(),
        time.offset_seconds(),
        metadata.fcs(),
    )?;
    let mut writer = l2_pcap::PcapNgWriter::new(Vec::new(), 1_048_576)?;
    writer.add_interface_and_write_frame(metadata.interface(), config, &packet)?;
    writer.finish()?;
    let mut bytes = writer.into_inner();
    let block_length = 512 * 1024_u32;
    for _ in 0..8 {
        bytes.extend_from_slice(&0x4000_0bad_u32.to_le_bytes());
        bytes.extend_from_slice(&block_length.to_le_bytes());
        let body_length = usize::try_from(block_length)? - 12;
        bytes.resize(bytes.len() + body_length, 0);
        bytes.extend_from_slice(&block_length.to_le_bytes());
    }
    Ok(bytes)
}

#[cfg(unix)]
fn assert_sparse_if_supported(path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::MetadataExt;
    let mut probe = tempfile::NamedTempFile::new_in(path.parent().ok_or("missing parent")?)?;
    let length = fs::metadata(path)?.len();
    probe.seek(SeekFrom::Start(length - 1))?;
    probe.write_all(&[1])?;
    if probe.as_file().metadata()?.blocks() * 512 < length / 2 {
        let metadata = fs::metadata(path)?;
        assert!(
            metadata.blocks() * 512 < length / 2,
            "retained file was not sparse"
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn assert_sparse_if_supported(_path: &std::path::Path) -> Result<(), Box<dyn Error>> {
    Ok(())
}
