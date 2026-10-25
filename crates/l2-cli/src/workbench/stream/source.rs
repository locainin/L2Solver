use super::model::Source;
use crate::{
    input,
    workbench::{capture::HashingReader, label},
};
use l2_pcap::{CaptureLimits, CaptureSource};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    io::{BufReader, Read, Seek, SeekFrom},
    path::Path,
};

pub(super) fn scan(file: &mut (impl Read + Seek), path: &Path) -> Result<Source, Box<dyn Error>> {
    let source_length = file.seek(SeekFrom::End(0))?;
    if source_length > CaptureLimits::STREAMING.max_input_bytes() {
        return Err("streaming source exceeds the supported file-offset range".into());
    }
    file.seek(SeekFrom::Start(0))?;
    let mut hash = Sha256::new();
    let mut length = 0;
    let mut frames = 0_u32;
    let collection_summary = {
        let reader = HashingReader {
            inner: BufReader::new(file),
            hash: &mut hash,
            length: &mut length,
        };
        let mut source = CaptureSource::with_limits(reader, CaptureLimits::STREAMING)
            .map_err(|error| input::capture_error(path, error))?;
        while source
            .next_packet()
            .map_err(|error| input::capture_error(path, error))?
            .is_some()
        {
            frames = frames
                .checked_add(1)
                .ok_or("capture record numbering overflow")?;
        }
        source.collection_summary()
    };
    Ok(Source {
        id: format!("sha256:{:x}", hash.finalize()),
        label: label(path, "capture").to_owned(),
        length,
        frames,
        collection_summary,
    })
}
