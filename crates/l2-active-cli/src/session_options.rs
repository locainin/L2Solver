//! Prepare shared helper selection and bounded collection limits

#[cfg(test)]
#[path = "../tests/cli/session_options.rs"]
mod tests;

use std::{
    env, io,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use l2_active::Limits;

use super::{Error, SessionArgs};

pub fn limits(options: &SessionArgs) -> Result<Limits, Error> {
    Limits::new(
        Duration::from_millis(options.timeout_ms),
        options.max_received_packets,
        options.max_received_bytes,
    )
    .map_err(Error::Plan)
}

pub fn helper(path: Option<&Path>) -> Result<PathBuf, Error> {
    match path {
        Some(path) => Ok(path.to_path_buf()),
        None => Ok(env::current_exe()
            .map_err(Error::Helper)?
            .with_file_name("l2solver-active-helper")),
    }
}

pub fn deadline(limits: Limits) -> Result<Instant, Error> {
    Instant::now()
        .checked_add(limits.timeout())
        .ok_or(Error::Run(l2_active::RunError::DeadlineOverflow))
}

pub fn finish<T>(
    result: Result<T, l2_active::RunError>,
    close: io::Result<()>,
) -> Result<(T, Option<io::Error>), Error> {
    match (result, close) {
        // Keep collected evidence even when the helper cannot confirm close
        (Ok(report), close) => Ok((report, close.err())),
        (Err(preparation), Ok(())) => Err(Error::Run(preparation)),
        (Err(preparation), Err(close)) => Err(Error::Cleanup { preparation, close }),
    }
}
