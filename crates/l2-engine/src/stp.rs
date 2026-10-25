//! Passive STP root observation over decoded codec frames

use crate::clock::{ClockError, MonoTime};
use l2_capture::InterfaceId;
use l2_codecs::{BridgeId, StpFrame};
use std::{collections::BTreeMap, fmt, time::Duration};

/// Absolute ceiling for interface samples retained by one observer
pub const ABSOLUTE_MAX_STP_SAMPLES: usize = 4_096;

/// Result of one passive STP observation update
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StpUpdate {
    /// The observation did not change the currently visible root
    Unchanged,
    /// The latest visible root differs from the previous visible root
    RootChanged {
        /// Root before the update, if any sample was visible
        previous: Option<BridgeId>,
        /// Root after the update, if a sample is visible
        current: Option<BridgeId>,
    },
    /// The previous visible root disappeared because its sample aged out
    RootAged {
        /// Root that no longer has a live observation
        root: BridgeId,
    },
    /// A link-down event removed the sample that supplied the previous root
    InterfaceRemoved {
        /// Root before removing the interface sample
        previous: Option<BridgeId>,
        /// Root after removing the interface sample
        current: Option<BridgeId>,
    },
}

/// Errors from passive STP observation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StpObserverError {
    /// The age interval must be representable and nonzero
    InvalidAge,
    /// An observation was supplied before the previous observation
    TimeWentBackwards {
        /// Last accepted observation instant
        previous: MonoTime,
        /// Rejected observation instant
        current: MonoTime,
    },
    /// Checked monotonic subtraction failed
    Clock(ClockError),
    /// The observer's monotonic sample-order counter is exhausted
    SampleSequenceExhausted,
    /// The observer has reached its configured interface-sample limit
    SampleLimitReached { limit: usize },
    /// A requested interface-sample capacity is outside the safe range
    InvalidSampleCapacity { capacity: usize, max: usize },
}

impl fmt::Display for StpObserverError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAge => {
                formatter.write_str("STP observation age must be nonzero and fit in nanoseconds")
            }
            Self::TimeWentBackwards { previous, current } => {
                write!(
                    formatter,
                    "STP observation time moved backwards from {previous} to {current}"
                )
            }
            Self::Clock(error) => error.fmt(formatter),
            Self::SampleSequenceExhausted => {
                formatter.write_str("STP observation sequence counter is exhausted")
            }
            Self::SampleLimitReached { limit } => {
                write!(
                    formatter,
                    "STP observer has reached its sample limit of {limit}"
                )
            }
            Self::InvalidSampleCapacity { capacity, max } => {
                write!(
                    formatter,
                    "STP sample capacity {capacity} is outside 1..={max}"
                )
            }
        }
    }
}

impl std::error::Error for StpObserverError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Clock(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ClockError> for StpObserverError {
    fn from(error: ClockError) -> Self {
        Self::Clock(error)
    }
}

#[derive(Clone, Copy, Debug)]
struct Sample {
    seen_at: MonoTime,
    order: u64,
    root: BridgeId,
}

/// Bounded passive STP/RSTP root tracker
///
/// The observer intentionally does not run a spanning-tree election. It keeps
/// the latest decoded root advertisement per capture interface and reports
/// changes or expiry in arrival order. This makes vendor behavior visible
/// without granting a protocol module active control
pub struct StpObserver {
    max_age_nanos: u64,
    max_samples: usize,
    samples: BTreeMap<InterfaceId, Sample>,
    current_root: Option<BridgeId>,
    last_time: Option<MonoTime>,
    next_order: u64,
    root_changes: u64,
}

impl StpObserver {
    /// Construct a passive observer with a checked sample lifetime
    ///
    /// # Errors
    /// Returns [`StpObserverError::InvalidAge`] for zero or unrepresentable
    /// durations
    pub fn new(max_age: Duration) -> Result<Self, StpObserverError> {
        Self::with_capacity(max_age, ABSOLUTE_MAX_STP_SAMPLES)
    }

    /// Construct a passive observer with checked age and sample limits
    ///
    /// # Errors
    /// Returns [`StpObserverError::InvalidAge`] for zero or unrepresentable
    /// durations, or [`StpObserverError::InvalidSampleCapacity`] for an
    /// invalid interface-sample capacity
    pub fn with_capacity(max_age: Duration, max_samples: usize) -> Result<Self, StpObserverError> {
        let max_age_nanos = u64::try_from(max_age.as_nanos())
            .ok()
            .filter(|nanos| *nanos > 0)
            .ok_or(StpObserverError::InvalidAge)?;
        if max_samples == 0 || max_samples > ABSOLUTE_MAX_STP_SAMPLES {
            return Err(StpObserverError::InvalidSampleCapacity {
                capacity: max_samples,
                max: ABSOLUTE_MAX_STP_SAMPLES,
            });
        }
        Ok(Self {
            max_age_nanos,
            max_samples,
            samples: BTreeMap::new(),
            current_root: None,
            last_time: None,
            next_order: 0,
            root_changes: 0,
        })
    }

    /// Return the configured lifetime used for passive samples
    #[must_use]
    pub const fn max_age(&self) -> Duration {
        Duration::from_nanos(self.max_age_nanos)
    }

    /// Return the currently visible root advertisement
    #[must_use]
    pub const fn current_root(&self) -> Option<BridgeId> {
        self.current_root
    }

    /// Return the number of interfaces with unexpired tree advertisements
    #[must_use]
    pub fn sample_count(&self) -> usize {
        self.samples.len()
    }

    /// Return the count of actual visible-root transitions
    #[must_use]
    pub const fn root_changes(&self) -> u64 {
        self.root_changes
    }

    /// Return the latest unexpired root seen on one capture interface
    #[must_use]
    pub fn interface_root(&self, interface: InterfaceId) -> Option<BridgeId> {
        self.samples.get(&interface).map(|sample| sample.root)
    }

    /// Observe one decoded STP/RSTP frame at a monotonic engine instant
    ///
    /// Topology-change notifications do not carry a root identifier and are
    /// retained by the codec caller without changing this root view
    ///
    /// # Errors
    /// Returns a time-ordering error without changing the observer
    pub fn observe(
        &mut self,
        at: MonoTime,
        interface: InterfaceId,
        frame: &StpFrame<'_>,
    ) -> Result<StpUpdate, StpObserverError> {
        self.validate_time(at)?;
        let previous = self.current_root;
        if let Some(root) = frame.root {
            // A new interface sample is checked before stale samples are
            // removed so a rejected update cannot mutate the observer
            if !self.samples.contains_key(&interface)
                && self.live_sample_count(at) >= self.max_samples
            {
                return Err(StpObserverError::SampleLimitReached {
                    limit: self.max_samples,
                });
            }
            let order = self
                .next_order
                .checked_add(1)
                .ok_or(StpObserverError::SampleSequenceExhausted)?;
            self.expire_samples(at);
            self.samples.insert(
                interface,
                Sample {
                    seen_at: at,
                    order,
                    root,
                },
            );
            self.next_order = order;
        } else {
            // A topology-change notification has no root sample and must not
            // consume the sample-order counter
            self.expire_samples(at);
        }
        let current = self.select_latest_root();
        self.current_root = current;
        self.last_time = Some(at);
        Ok(self.root_update(previous, current, UpdateCause::Observation))
    }

    /// Expire observations at a monotonic instant
    ///
    /// A sample expires when its age reaches the configured maximum. The
    /// method keeps the last accepted time even when no sample expires
    ///
    /// # Errors
    /// Returns a time-ordering error without changing observer state
    pub fn expire(&mut self, at: MonoTime) -> Result<StpUpdate, StpObserverError> {
        self.validate_time(at)?;
        let previous = self.current_root;
        self.expire_samples(at);
        let current = self.select_latest_root();
        self.current_root = current;
        self.last_time = Some(at);
        Ok(self.root_update(previous, current, UpdateCause::Age))
    }

    /// Remove one interface's observation after a verified link-down event
    ///
    /// # Errors
    /// Returns a time-ordering error without changing observer state
    pub fn interface_down(
        &mut self,
        at: MonoTime,
        interface: InterfaceId,
    ) -> Result<StpUpdate, StpObserverError> {
        self.validate_time(at)?;
        let previous = self.current_root;
        self.expire_samples(at);
        self.samples.remove(&interface);
        let current = self.select_latest_root();
        self.current_root = current;
        self.last_time = Some(at);
        Ok(self.root_update(previous, current, UpdateCause::InterfaceDown))
    }

    fn validate_time(&self, at: MonoTime) -> Result<(), StpObserverError> {
        if let Some(previous) = self.last_time
            && at < previous
        {
            return Err(StpObserverError::TimeWentBackwards {
                previous,
                current: at,
            });
        }
        Ok(())
    }

    fn expire_samples(&mut self, at: MonoTime) {
        let max_age_nanos = self.max_age_nanos;
        self.samples
            .retain(|_, sample| at.nanos() - sample.seen_at.nanos() < max_age_nanos);
    }

    fn select_latest_root(&self) -> Option<BridgeId> {
        self.samples
            .values()
            .max_by_key(|sample| (sample.seen_at, sample.order))
            .map(|sample| sample.root)
    }

    fn root_update(
        &mut self,
        previous: Option<BridgeId>,
        current: Option<BridgeId>,
        cause: UpdateCause,
    ) -> StpUpdate {
        if previous == current {
            return StpUpdate::Unchanged;
        }
        self.root_changes = self.root_changes.saturating_add(1);
        if matches!(cause, UpdateCause::Age)
            && let (Some(root), None) = (previous, current)
        {
            return StpUpdate::RootAged { root };
        }
        if matches!(cause, UpdateCause::InterfaceDown) {
            return StpUpdate::InterfaceRemoved { previous, current };
        }
        StpUpdate::RootChanged { previous, current }
    }
}

impl StpObserver {
    fn live_sample_count(&self, at: MonoTime) -> usize {
        self.samples
            .values()
            .filter(|sample| at.nanos() - sample.seen_at.nanos() < self.max_age_nanos)
            .count()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UpdateCause {
    Observation,
    Age,
    InterfaceDown,
}
