//! Bounded access-point, station, and diagnostic storage

use crate::model::AccessPointObservation;
use crate::{
    AccessPoint, Diagnostic, DiagnosticKind, ObservationContext, ObservationStatus, Station,
};
use wifi_core::MacAddress;

use super::Survey;

impl Survey {
    pub(super) fn store_access_point(&mut self, observation: AccessPointObservation) -> bool {
        let bssid = observation.bssid;
        if let Some(existing) = self.access_points.get_mut(&bssid) {
            existing.update(observation);
            return true;
        }
        if self.access_points.len() == self.limits.access_points {
            self.inventory_incomplete = true;
            return false;
        }
        self.access_points
            .insert(bssid, AccessPoint::from_observation(observation));
        true
    }

    pub(super) fn store_station(
        &mut self,
        address: MacAddress,
        bssid: Option<MacAddress>,
        sequence: u64,
    ) -> bool {
        // Group and unspecified receivers do not identify a station
        if !address.is_usable_unicast() {
            return true;
        }
        if let Some(existing) = self.stations.get_mut(&address) {
            existing.observe(bssid, sequence);
            return true;
        }
        if self.stations.len() == self.limits.stations {
            self.inventory_incomplete = true;
            return false;
        }
        self.stations
            .insert(address, Station::new(address, bssid, sequence));
        true
    }

    pub(super) fn diagnostic(
        &mut self,
        context: ObservationContext,
        kind: DiagnosticKind,
        message: String,
        normal_status: ObservationStatus,
    ) -> ObservationStatus {
        if self.diagnostics.len() == self.limits.diagnostics {
            self.inventory_incomplete = true;
            return ObservationStatus::ResourceLimited;
        }
        self.diagnostics
            .push(Diagnostic::new(context.sequence(), kind, message));
        normal_status
    }

    pub fn access_points(
        &self,
    ) -> impl DoubleEndedIterator<Item = &AccessPoint> + ExactSizeIterator {
        self.access_points.values()
    }

    pub fn stations(&self) -> impl DoubleEndedIterator<Item = &Station> + ExactSizeIterator {
        self.stations.values()
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub const fn inventory_incomplete(&self) -> bool {
        self.inventory_incomplete
    }
}
