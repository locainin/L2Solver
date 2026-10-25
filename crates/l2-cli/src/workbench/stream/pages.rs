use super::model::{Manifest, Page};
use crate::workbench::{bundle_budget::charge_document, capture::HashingReader};
use l2_pcap::{CaptureLimits, CaptureSource};
use l2_workbench::{
    investigation::{BuildInput, Record, RecordWindow, build_window},
    sha256,
};
use sha2::{Digest, Sha256};
use std::{
    error::Error,
    fs::{self, File},
    io::{BufReader, Read, Seek, SeekFrom, Write},
    path::Path,
};

const PAGE_BYTES: usize = 512 * 1024;
const CONTEXT_BYTES: usize = 256 * 1024;
const MAX_PAGES: usize = 16_384;

pub(super) fn write_pages(
    file: &mut (impl Read + Seek),
    directory: &Path,
    manifest: &mut Manifest,
    maximum: u16,
) -> Result<u64, Box<dyn Error>> {
    file.seek(SeekFrom::Start(0))?;
    fs::create_dir(directory.join("pages"))?;
    let mut hash = Sha256::new();
    let mut length = 0;
    let mut number = 0_u32;
    let mut primary = Vec::new();
    let mut context = Vec::new();
    let mut bytes = 0;
    let mut disk_bytes = 0;
    {
        let reader = HashingReader {
            inner: BufReader::new(file),
            hash: &mut hash,
            length: &mut length,
        };
        let mut capture = CaptureSource::with_limits(reader, CaptureLimits::STREAMING)?;
        while let Some(frame) = capture.next_packet()? {
            number = number
                .checked_add(1)
                .ok_or("capture record numbering overflow")?;
            if !primary.is_empty()
                && (primary.len() == usize::from(maximum)
                    || bytes + frame.bytes().len() > PAGE_BYTES)
            {
                emit(
                    directory,
                    manifest,
                    &mut context,
                    &mut primary,
                    &mut disk_bytes,
                )?;
                bytes = 0;
            }
            if frame.bytes().len() > PAGE_BYTES {
                return Err("one capture record exceeds the page byte budget".into());
            }
            bytes += frame.bytes().len();
            primary.push(Record { number, frame });
        }
    }
    if !primary.is_empty() {
        emit(
            directory,
            manifest,
            &mut context,
            &mut primary,
            &mut disk_bytes,
        )?;
    }
    if number != manifest.source.frames
        || length != manifest.source.length
        || format!("sha256:{:x}", hash.finalize()) != manifest.source.id
    {
        return Err("capture changed between source verification and streaming analysis".into());
    }
    File::open(directory.join("pages"))?.sync_all()?;
    Ok(disk_bytes)
}

fn emit(
    directory: &Path,
    manifest: &mut Manifest,
    context: &mut Vec<Record>,
    primary: &mut Vec<Record>,
    disk_bytes: &mut u64,
) -> Result<(), Box<dyn Error>> {
    if manifest.pages.len() == MAX_PAGES {
        return Err("streaming bundle exceeds the page budget".into());
    }
    let first_record = primary.first().ok_or("empty primary page")?.number;
    let last_record = primary.last().ok_or("empty primary page")?.number;
    let mut records = std::mem::take(context);
    records.append(primary);
    let context_first_record = records.first().ok_or("empty record window")?.number;
    let mut result = build_window(
        BuildInput {
            label: &manifest.source.label,
            length: manifest.source.length,
            sha256_hex: manifest
                .source
                .id
                .strip_prefix("sha256:")
                .ok_or("invalid source identity")?,
            records: &records,
            frames_seen: u64::from(manifest.source.frames),
        },
        RecordWindow {
            first: context_first_record,
            last: last_record,
        },
    )?;
    l2_workbench::capture_collection::apply_to_case(
        &mut result,
        &manifest.source.id,
        manifest.source.collection_summary,
    )?;
    let packet_nodes = result
        .case
        .nodes()
        .iter()
        .filter(|node| node.kind == "packet")
        .count();
    manifest.raw_collection_complete &= packet_nodes == records.len();
    manifest.analysis_complete &= result.complete;
    let document = result.case.to_json()?;
    *disk_bytes = charge_document(*disk_bytes, document.len())?;
    let path = format!("pages/{:06}.json", manifest.pages.len() + 1);
    let mut output = File::create_new(directory.join(&path))?;
    output.write_all(&document)?;
    output.sync_all()?;
    manifest.pages.push(Page {
        path,
        sha256: sha256(&document),
        first_record,
        last_record,
        context_first_record,
        packet_nodes,
        collection_complete: result.complete,
    });
    // Carry only a contiguous suffix, so original record gaps are never hidden
    let mut retained_bytes = 0;
    let keep = records
        .iter()
        .rev()
        .take(usize::from(manifest.context_records))
        .take_while(|record| {
            retained_bytes += record.frame.bytes().len();
            retained_bytes <= CONTEXT_BYTES
        })
        .count();
    let split = records.len() - keep;
    *context = records.split_off(split);
    Ok(())
}

#[cfg(test)]
#[path = "../../../tests/workbench/stream/pages.rs"]
mod tests;
