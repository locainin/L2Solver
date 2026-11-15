//! Validate bounded capture and child-process resources before creating a workspace

use serde::{Deserialize, Serialize};
use std::{error::Error, fmt, num::NonZeroU64, time::Duration};

/// Capacity observed for the machine and the workspace at planning time
///
/// Observations can become stale; the plan is not a reservation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HostCapacity {
    /// Host available memory limited by any finite cgroup headroom
    pub memory_bytes: u64,
    /// Bytes available to the current user on the workspace filesystem
    pub workspace_bytes: u64,
    /// Task slots available under the host and any finite parent cgroup limit
    pub tasks: u64,
    /// Allocation granule used when the kernel rounds temporary filesystem sizes
    pub allocation_granule: NonZeroU64,
}

impl HostCapacity {
    /// Select half the observed memory headroom for an automatic child limit
    #[must_use]
    pub const fn automatic_child_memory(self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.memory_bytes / 2)
    }

    /// Select fewer than the available task slots for an automatic child limit
    #[must_use]
    pub const fn automatic_child_tasks(self) -> Option<NonZeroU64> {
        NonZeroU64::new(self.tasks / 2)
    }
}

/// Return available bytes after leaving at least one eighth for other work
#[must_use]
pub const fn workspace_capacity(available_bytes: u64) -> u64 {
    after_reserve(available_bytes)
}

const fn after_reserve(available: u64) -> u64 {
    available - available.div_ceil(8)
}

/// Source sizes known before the workspace is created
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InputSize {
    /// Capture length, or none for a stream whose length is not known yet
    pub capture_bytes: Option<u64>,
    /// Length of the optional key log
    pub keylog_bytes: u64,
}

/// Independent limits applied to a capture and its optional child process
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResourceLimits {
    /// Logical length of the capture, including sparse regions
    pub capture_bytes: NonZeroU64,
    /// Aggregate bytes available to the capture snapshot and both disk copies of objects
    pub temporary_bytes: NonZeroU64,
    /// Aggregate bytes of temporary exported objects
    pub object_bytes: NonZeroU64,
    /// Number of temporary exported objects
    pub object_files: NonZeroU64,
    /// Child cgroup memory limit
    pub child_memory_bytes: NonZeroU64,
    /// Child cgroup swap limit; zero disables swap
    pub child_swap_bytes: u64,
    /// Maximum child tasks
    pub child_tasks: NonZeroU64,
    /// Time available to the child workflow
    pub timeout: Duration,
    /// Maximum size of the child's temporary filesystem
    pub tmpfs_bytes: NonZeroU64,
    /// Maximum size of the child's shared-memory filesystem
    pub shm_bytes: NonZeroU64,
}

/// Whether an object byte limit is a default or an operator request
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectLimitMode {
    /// Lower the default object limit when the observed capacity needs it
    Automatic,
    /// Reject an object limit that cannot fit without silently changing it
    Explicit,
}

/// A validated resource selection; limits remain private until validation succeeds
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResourcePlan {
    limits: ResourceLimits,
}

/// Why a resource selection could not be admitted
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourcePlanError {
    /// A limit was zero where forbidden, or used an unbounded sentinel
    InvalidLimit(&'static str),
    /// A request exceeds its available capacity or an administrative ceiling
    LimitExceeded {
        /// Resource and unit that was checked
        resource: &'static str,
        /// Requested amount
        requested: u128,
        /// Largest admissible amount
        maximum: u128,
    },
    /// Adding source lengths would exceed the supported size representation
    InputSizeOverflow,
}

impl fmt::Display for ResourcePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit(resource) => write!(formatter, "invalid {resource} limit"),
            Self::LimitExceeded {
                resource,
                requested,
                maximum,
            } => write!(
                formatter,
                "{resource} requires {requested}, exceeding the available limit {maximum}"
            ),
            Self::InputSizeOverflow => formatter.write_str("capture and key log sizes overflow"),
        }
    }
}

impl Error for ResourcePlanError {}

impl ResourcePlan {
    /// Validate one selection against observed capacity and optional administrative ceilings
    ///
    /// A known capture uses its actual length for workspace admission. An unknown stream
    /// reserves its entire logical capture limit. The object default can be reduced to fit,
    /// while an explicit object request must fit without alteration
    /// Copying must enforce the same observed source lengths used here
    ///
    /// # Errors
    /// Rejects invalid, overflowing, or infeasible limits
    pub fn new(
        capacity: HostCapacity,
        input: InputSize,
        mut limits: ResourceLimits,
        admin: Option<ResourceLimits>,
        object_mode: ObjectLimitMode,
    ) -> Result<Self, ResourcePlanError> {
        validate_finite(&limits)?;
        if let Some(ceiling) = admin {
            validate_finite(&ceiling)?;
            check_admin(&limits, &ceiling)?;
        }

        // The capture reader and retained-source index use a signed file offset
        check_limit(
            "capture bytes",
            limits.capture_bytes.get(),
            l2_pcap::ABSOLUTE_MAX_INPUT_BYTES,
        )?;
        // Leave room outside the child for the parent process and other work
        check_limit(
            "temporary storage bytes",
            limits.temporary_bytes.get(),
            workspace_capacity(capacity.workspace_bytes),
        )?;
        check_limit(
            "child memory bytes",
            limits.child_memory_bytes.get(),
            after_reserve(capacity.memory_bytes),
        )?;
        check_limit("child tasks", limits.child_tasks.get(), capacity.tasks)?;

        // Unknown streams must be able to fit their entire logical capture limit
        let source_bytes = input
            .capture_bytes
            .unwrap_or_else(|| limits.capture_bytes.get());
        check_limit("capture bytes", source_bytes, limits.capture_bytes.get())?;
        let snapshot_bytes = source_bytes
            .checked_add(input.keylog_bytes)
            .ok_or(ResourcePlanError::InputSizeOverflow)?;
        check_limit(
            "capture and key log bytes",
            snapshot_bytes,
            limits.temporary_bytes.get(),
        )?;
        let storage_left = limits.temporary_bytes.get() - snapshot_bytes;

        // The kernel rounds each mount up and the child memory limit down to whole pages
        let granule = capacity.allocation_granule.get();
        let tmpfs_total = round_up(limits.tmpfs_bytes.get(), granule)
            .and_then(|temporary| {
                round_up(limits.shm_bytes.get(), granule)
                    .and_then(|shared| temporary.checked_add(shared))
            })
            .ok_or(ResourcePlanError::InvalidLimit(
                "temporary filesystem bytes",
            ))?;
        let memory_limit = limits.child_memory_bytes.get();
        let tmpfs_budget = (memory_limit - memory_limit % granule) / 2;
        check_limit("temporary filesystem bytes", tmpfs_total, tmpfs_budget)?;
        let memory_left = tmpfs_budget - tmpfs_total;
        // Reserve only whole pages so the object mount cannot round past its allowance
        let object_memory_maximum = memory_left - memory_left % granule;
        // Private and staged object copies can exist at the same time on disk
        let mut object_maximum = (storage_left / 2).min(object_memory_maximum);
        if let Some(ceiling) = admin {
            object_maximum = object_maximum.min(ceiling.object_bytes.get());
        }
        // Only the automatic default may be reduced without operator input
        match object_mode {
            ObjectLimitMode::Automatic => {
                limits.object_bytes = NonZeroU64::new(
                    limits.object_bytes.get().min(object_maximum),
                )
                .ok_or(ResourcePlanError::LimitExceeded {
                    resource: "object bytes",
                    requested: 1,
                    maximum: 0,
                })?;
            }
            ObjectLimitMode::Explicit => {
                check_limit("object bytes", limits.object_bytes.get(), object_maximum)?;
            }
        }
        Ok(Self { limits })
    }

    /// Return the selected limits after all checks and automatic adjustment
    #[must_use]
    pub const fn limits(&self) -> &ResourceLimits {
        &self.limits
    }
}

fn validate_finite(limits: &ResourceLimits) -> Result<(), ResourcePlanError> {
    for (resource, value) in [
        ("capture bytes", limits.capture_bytes.get()),
        ("temporary storage bytes", limits.temporary_bytes.get()),
        ("object bytes", limits.object_bytes.get()),
        ("object files", limits.object_files.get()),
        ("child memory bytes", limits.child_memory_bytes.get()),
        ("child swap bytes", limits.child_swap_bytes),
        ("child tasks", limits.child_tasks.get()),
        ("temporary filesystem bytes", limits.tmpfs_bytes.get()),
        ("shared-memory filesystem bytes", limits.shm_bytes.get()),
    ] {
        if value == u64::MAX {
            return Err(ResourcePlanError::InvalidLimit(resource));
        }
    }
    let runtime_micros = limits.timeout.as_micros();
    if runtime_micros == 0 || runtime_micros >= u128::from(u64::MAX) {
        return Err(ResourcePlanError::InvalidLimit("timeout"));
    }
    Ok(())
}

const fn round_up(value: u64, granule: u64) -> Option<u64> {
    let remainder = value % granule;
    if remainder == 0 {
        Some(value)
    } else {
        value.checked_add(granule - remainder)
    }
}

fn check_admin(limits: &ResourceLimits, ceiling: &ResourceLimits) -> Result<(), ResourcePlanError> {
    for (resource, value, maximum) in [
        (
            "capture bytes",
            limits.capture_bytes.get(),
            ceiling.capture_bytes.get(),
        ),
        (
            "temporary storage bytes",
            limits.temporary_bytes.get(),
            ceiling.temporary_bytes.get(),
        ),
        (
            "object files",
            limits.object_files.get(),
            ceiling.object_files.get(),
        ),
        (
            "child memory bytes",
            limits.child_memory_bytes.get(),
            ceiling.child_memory_bytes.get(),
        ),
        (
            "child swap bytes",
            limits.child_swap_bytes,
            ceiling.child_swap_bytes,
        ),
        (
            "child tasks",
            limits.child_tasks.get(),
            ceiling.child_tasks.get(),
        ),
        (
            "temporary filesystem bytes",
            limits.tmpfs_bytes.get(),
            ceiling.tmpfs_bytes.get(),
        ),
        (
            "shared-memory filesystem bytes",
            limits.shm_bytes.get(),
            ceiling.shm_bytes.get(),
        ),
    ] {
        check_limit(resource, value, maximum)?;
    }
    if limits.timeout > ceiling.timeout {
        return Err(ResourcePlanError::LimitExceeded {
            resource: "timeout nanoseconds",
            requested: limits.timeout.as_nanos(),
            maximum: ceiling.timeout.as_nanos(),
        });
    }
    Ok(())
}

fn check_limit(
    resource: &'static str,
    requested: u64,
    maximum: u64,
) -> Result<(), ResourcePlanError> {
    if requested > maximum {
        return Err(ResourcePlanError::LimitExceeded {
            resource,
            requested: u128::from(requested),
            maximum: u128::from(maximum),
        });
    }
    Ok(())
}
