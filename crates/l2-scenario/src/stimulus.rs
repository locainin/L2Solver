//! Fixed-size stimulus descriptions and dispatched virtual events

/// One planned packet, identified by its owning protocol plan sequence
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Stimulus {
    sequence: u64,
    at_millis: u64,
    frame_bytes: u64,
}

impl Stimulus {
    /// Describe work for admission without copying or allocating frame bytes
    ///
    /// [`crate::Schedule::new`] validates nonzero sequence and byte count
    #[must_use]
    pub const fn new(sequence: u64, at_millis: u64, frame_bytes: u64) -> Self {
        Self {
            sequence,
            at_millis,
            frame_bytes,
        }
    }

    /// Return the protocol plan sequence used to resolve frame material
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.sequence
    }

    /// Return the scheduled offset in virtual milliseconds
    #[must_use]
    pub const fn at_millis(self) -> u64 {
        self.at_millis
    }

    /// Return the complete frame size charged as one packet
    #[must_use]
    pub const fn frame_bytes(self) -> u64 {
        self.frame_bytes
    }
}

/// A scheduled stimulus released for a modeled backend to process
///
/// Dispatch proves scheduler accounting, never physical transmission
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Dispatch(pub(crate) Stimulus);

impl Dispatch {
    /// Return the protocol plan sequence of this dispatch
    #[must_use]
    pub const fn sequence(self) -> u64 {
        self.0.sequence()
    }

    /// Return the virtual clock offset at dispatch
    #[must_use]
    pub const fn at_millis(self) -> u64 {
        self.0.at_millis()
    }

    /// Return the charged complete frame size
    #[must_use]
    pub const fn frame_bytes(self) -> u64 {
        self.0.frame_bytes()
    }
}
