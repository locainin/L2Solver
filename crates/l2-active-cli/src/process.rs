//! One process-scoped cancellation handler for the standalone entry points

use std::{
    io::Write,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use super::{ActiveArgs, ActiveOutcome, Error, execute};

/// Install the process Ctrl-C handler and execute one active command
///
/// This is intended for a process that has not installed another Ctrl-C
/// handler. Embedding applications can instead call [`execute`] with their
/// existing cancellation token
///
/// # Errors
/// Returns an error if signal installation or command execution fails
pub fn execute_process(args: &ActiveArgs, output: &mut impl Write) -> Result<ActiveOutcome, Error> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let signal = Arc::clone(&cancelled);
    ctrlc::set_handler(move || signal.store(true, Ordering::Release)).map_err(Error::Signal)?;
    execute(args, &cancelled, output)
}
