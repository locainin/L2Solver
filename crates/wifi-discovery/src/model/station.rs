//! Station inventory records and conservative association updates

use serde::Serialize;
use wifi_core::MacAddress;

/// One station address and conservative BSSID association
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct Station {
    address: MacAddress,
    associated_bssid: Option<MacAddress>,
    association_changed: bool,
    first_sequence: u64,
    last_sequence: u64,
    frames: u64,
}

impl Station {
    pub(crate) const fn new(
        address: MacAddress,
        associated_bssid: Option<MacAddress>,
        sequence: u64,
    ) -> Self {
        Self {
            address,
            associated_bssid,
            association_changed: false,
            first_sequence: sequence,
            last_sequence: sequence,
            frames: 1,
        }
    }

    #[must_use]
    pub const fn address(self) -> MacAddress {
        self.address
    }

    #[must_use]
    pub const fn associated_bssid(self) -> Option<MacAddress> {
        self.associated_bssid
    }

    /// Return whether more than one concrete BSSID was associated with the station
    #[must_use]
    pub const fn association_changed(self) -> bool {
        self.association_changed
    }

    #[must_use]
    pub const fn first_sequence(self) -> u64 {
        self.first_sequence
    }

    #[must_use]
    pub const fn last_sequence(self) -> u64 {
        self.last_sequence
    }

    #[must_use]
    pub const fn frames(self) -> u64 {
        self.frames
    }

    pub(crate) fn observe(&mut self, bssid: Option<MacAddress>, sequence: u64) {
        if let Some(bssid) = bssid {
            // Keep the newest concrete association for the current inventory view
            self.association_changed |= self
                .associated_bssid
                .is_some_and(|current| current != bssid);
            self.associated_bssid = Some(bssid);
        }
        self.last_sequence = sequence;
        self.frames = self.frames.saturating_add(1);
    }
}
