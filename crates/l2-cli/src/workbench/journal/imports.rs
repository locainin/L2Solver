//! Bound external files before adding source-scoped journal observations

use l2_workbench::{
    journal::Journal,
    store::{Options, Store},
};
use sha2::{Digest, Sha256};
use std::{error::Error, io::Read, path::Path};

pub(super) fn events(
    journal: &mut Journal,
    case: Option<&Path>,
    index: Option<&Path>,
    cache_mib: u32,
) -> Result<u64, Box<dyn Error>> {
    if let Some(index) = index {
        journal.import_index_events(&Store::open(index, Options { cache_mib })?)
    } else if let Some(case) = case {
        journal.import_case_events(&super::super::load(case)?)
    } else {
        journal.import_base_events()
    }
}

pub(super) fn tshark_report(
    journal: &mut Journal,
    report_path: &Path,
    source_path: &Path,
    max_report_mib: u64,
    max_source_mib: u64,
) -> Result<String, Box<dyn Error>> {
    let report_budget = usize::try_from(mib_bytes(max_report_mib)?)?;
    let report =
        super::super::read_bounded(crate::input::regular_no_follow(report_path)?, report_budget)?;
    let (source_sha256, source_length) = hash_source(source_path, mib_bytes(max_source_mib)?)?;
    journal.import_tshark_report(&report, &source_sha256, source_length)
}

fn hash_source(path: &Path, maximum: u64) -> Result<(String, u64), Box<dyn Error>> {
    let mut input = crate::input::regular_no_follow(path)?;
    let expected_length = input.metadata()?.len();
    if expected_length > maximum {
        return Err(format!("capture exceeds the configured {maximum}-byte source limit").into());
    }

    let mut digest = Sha256::new();
    let mut length = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024].into_boxed_slice();
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        length = length
            .checked_add(u64::try_from(count)?)
            .ok_or("capture length exceeds the supported range")?;
        if length > maximum {
            return Err(
                format!("capture exceeds the configured {maximum}-byte source limit").into(),
            );
        }
        digest.update(
            buffer
                .get(..count)
                .ok_or("capture reader exceeded its fixed buffer")?,
        );
    }
    if length != expected_length || input.metadata()?.len() != expected_length {
        return Err("capture changed while its source identity was being checked".into());
    }
    Ok((format!("{:x}", digest.finalize()), length))
}

fn mib_bytes(mib: u64) -> Result<u64, Box<dyn Error>> {
    mib.checked_mul(1024 * 1024)
        .ok_or_else(|| "MiB budget exceeds the supported range".into())
}
