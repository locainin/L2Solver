use std::fmt;
use std::sync::{Arc, Mutex, OnceLock};

use l2_workbench::job::Job;

static TARGET: OnceLock<Arc<Mutex<HandlerTarget>>> = OnceLock::new();
static HANDLER_INSTALL: OnceLock<Result<(), String>> = OnceLock::new();

#[derive(Debug, Default)]
pub(super) struct HandlerTarget {
    pub(super) active_job: Option<Job>,
    pub(super) first_interrupt_seen: bool,
}

/// Errors returned while installing or activating cooperative cancellation
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CancellationError {
    /// Another part of the process installed an incompatible Ctrl+C handler
    HandlerInstall(String),
    /// A worker was already registered with the process handler
    AlreadyActive,
    /// Shared handler state was poisoned by a panicking worker
    LockPoisoned,
}

impl fmt::Display for CancellationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HandlerInstall(error) => {
                write!(formatter, "could not install Ctrl+C handler: {error}")
            }
            Self::AlreadyActive => {
                formatter.write_str("a recovery job is already registered for cancellation")
            }
            Self::LockPoisoned => formatter.write_str("Ctrl+C handler state is poisoned"),
        }
    }
}

impl std::error::Error for CancellationError {}

/// Process-wide Ctrl+C handler that targets the currently active recovery job
#[derive(Clone, Debug)]
pub struct CancellationHandler {
    target: Arc<Mutex<HandlerTarget>>,
}

impl CancellationHandler {
    /// Installs the process handler once and returns a reusable controller
    ///
    /// Repeated calls share one global callback, so separate recovery commands do not replace
    /// one another's signal handling
    ///
    /// # Errors
    /// Returns [`CancellationError::HandlerInstall`] if another handler already owns Ctrl+C
    pub fn install() -> Result<Self, CancellationError> {
        let target =
            Arc::clone(TARGET.get_or_init(|| Arc::new(Mutex::new(HandlerTarget::default()))));
        let install_result = HANDLER_INSTALL.get_or_init(|| {
            let callback_target = Arc::clone(&target);
            ctrlc::set_handler(move || handle_interrupt(&callback_target))
                .map_err(|error| error.to_string())
        });
        if let Err(error) = install_result {
            return Err(CancellationError::HandlerInstall(error.clone()));
        }
        Ok(Self { target })
    }

    /// Registers the job that should receive the next cooperative cancellation request
    ///
    /// # Errors
    /// Returns [`CancellationError::AlreadyActive`] if another job is currently registered, or
    /// [`CancellationError::LockPoisoned`] if handler state cannot be accessed
    pub fn activate(&self, job: Job) -> Result<ActiveCancellation, CancellationError> {
        let mut target = self
            .target
            .lock()
            .map_err(|_| CancellationError::LockPoisoned)?;
        if target.active_job.is_some() {
            return Err(CancellationError::AlreadyActive);
        }
        target.active_job = Some(job);
        target.first_interrupt_seen = false;
        drop(target);
        Ok(ActiveCancellation {
            target: Arc::clone(&self.target),
            active: true,
        })
    }
}

/// Registration guard that clears the active job when recovery ends
#[must_use = "keep this registration alive while the recovery job runs"]
#[derive(Debug)]
pub struct ActiveCancellation {
    target: Arc<Mutex<HandlerTarget>>,
    active: bool,
}

impl ActiveCancellation {
    /// Clears the active job and reports handler-state failures
    ///
    /// # Errors
    /// Returns [`CancellationError::LockPoisoned`] if handler state cannot be accessed
    pub fn finish(mut self) -> Result<(), CancellationError> {
        self.clear()?;
        self.active = false;
        Ok(())
    }

    fn clear(&self) -> Result<(), CancellationError> {
        let mut target = self
            .target
            .lock()
            .map_err(|_| CancellationError::LockPoisoned)?;
        target.active_job = None;
        target.first_interrupt_seen = false;
        drop(target);
        Ok(())
    }
}

impl Drop for ActiveCancellation {
    fn drop(&mut self) {
        if self.active {
            // Drop cannot return lock errors, so poisoned state remains untouched
            if let Ok(mut target) = self.target.lock() {
                target.active_job = None;
                target.first_interrupt_seen = false;
            }
        }
    }
}

fn handle_interrupt(target: &Arc<Mutex<HandlerTarget>>) {
    let Ok(mut target) = target.lock() else {
        // A poisoned handler cannot identify the active job, so stop with interrupt status
        std::process::exit(130);
    };

    if !record_interrupt(&mut target) {
        drop(target);
        std::process::exit(130);
    }
}

pub(super) fn record_interrupt(target: &mut HandlerTarget) -> bool {
    if target.first_interrupt_seen {
        return false;
    }

    target.first_interrupt_seen = true;
    if let Some(job) = &target.active_job {
        job.request_cancel();
    }
    true
}
