//! Present bounded maintenance of the shared recovery cache

use crate::arguments::{CacheCommand, RecoveryOptions};
use l2_workbench::job::cache::Cache;
use std::{error::Error, io::Write};

pub fn run(command: &CacheCommand, output: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let maximum = match command {
        CacheCommand::Prune {
            max_bytes: Some(bytes),
        } => *bytes,
        _ => RecoveryOptions::default().cache_max_bytes,
    };
    let cache = Cache::from_environment(maximum)?;
    match command {
        CacheCommand::Stats => {
            let stats = cache.stats()?;
            writeln!(output, "Cache entries: {}", stats.entries)?;
            writeln!(
                output,
                "Cached stage bytes: {} ({})",
                stats.entry_bytes,
                indicatif::HumanBytes(stats.entry_bytes)
            )?;
            writeln!(output, "Job checkpoints: {}", stats.checkpoints)?;
            if stats.over_limit_bytes != 0 {
                writeln!(
                    output,
                    "Active data above cache limit: {}",
                    indicatif::HumanBytes(stats.over_limit_bytes)
                )?;
            }
        }
        CacheCommand::Prune { .. } | CacheCommand::Clear => {
            let result = if matches!(command, CacheCommand::Clear) {
                cache.clear()?
            } else {
                cache.prune()?
            };
            writeln!(
                output,
                "Removed {} cache entries ({} bytes)",
                result.removed_entries, result.removed_bytes
            )?;
            writeln!(
                output,
                "Retained {} bytes; {} active leases and {} checkpoint pins skipped",
                result.remaining_bytes, result.skipped_locked, result.skipped_checkpoints
            )?;
        }
    }
    Ok(())
}
