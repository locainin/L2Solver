//! Access-point inventory records and observation updates

use super::{PmfStatus, SecurityEvidence, SecurityMode, fingerprint::SecurityFingerprint};
use serde::Serialize;
use wifi_core::MacAddress;

/// One AP/BSSID derived from beacon or probe-response evidence
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AccessPoint {
    bssid: MacAddress,
    ssid: Option<Vec<u8>>,
    // Keep one conflicting value without allowing unbounded identity growth
    ssid_conflict: Option<Vec<u8>>,
    channel: Option<u16>,
    observed_channels: Vec<u16>,
    // Retain this derived flag in the serialized inventory for schema compatibility
    channel_changed: bool,
    channel_inconsistent: bool,
    frequency_mhz: Option<u16>,
    signal_dbm: Option<i8>,
    security: SecurityEvidence,
    #[serde(skip)]
    security_fingerprint: Option<SecurityFingerprint>,
    first_sequence: u64,
    last_sequence: u64,
    frames: u64,
}

impl AccessPoint {
    #[must_use]
    pub const fn bssid(&self) -> MacAddress {
        self.bssid
    }

    #[must_use]
    pub fn ssid(&self) -> Option<&[u8]> {
        self.ssid.as_deref()
    }

    /// Return one conflicting SSID retained for the same BSSID
    #[must_use]
    pub fn ssid_conflict(&self) -> Option<&[u8]> {
        self.ssid_conflict.as_deref()
    }

    /// Return whether one BSSID advertised more than one visible SSID
    #[must_use]
    pub const fn ssid_inconsistent(&self) -> bool {
        self.ssid_conflict.is_some()
    }

    #[must_use]
    pub const fn channel(&self) -> Option<u16> {
        self.channel
    }

    /// Return every distinct channel retained in canonical order
    #[must_use]
    pub fn observed_channels(&self) -> &[u16] {
        &self.observed_channels
    }

    /// Return whether the advertised channel changed during this survey
    #[must_use]
    pub const fn channel_changed(&self) -> bool {
        self.channel_changed
    }

    /// Return whether capture and advertisement channel sources disagreed
    #[must_use]
    pub const fn channel_inconsistent(&self) -> bool {
        self.channel_inconsistent
    }

    #[must_use]
    pub const fn frequency_mhz(&self) -> Option<u16> {
        self.frequency_mhz
    }

    #[must_use]
    pub const fn signal_dbm(&self) -> Option<i8> {
        self.signal_dbm
    }

    #[must_use]
    pub const fn security(&self) -> SecurityMode {
        self.security.mode()
    }

    #[must_use]
    pub const fn tkip(&self) -> bool {
        self.security.tkip()
    }

    #[must_use]
    pub const fn wps(&self) -> bool {
        self.security.wps()
    }

    #[must_use]
    pub const fn pmf_capable(&self) -> bool {
        matches!(
            self.security.pmf(),
            PmfStatus::Capable | PmfStatus::Required
        )
    }

    #[must_use]
    pub const fn pmf_required(&self) -> bool {
        matches!(self.security.pmf(), PmfStatus::Required)
    }

    #[must_use]
    pub const fn security_complete(&self) -> bool {
        self.security.complete()
    }

    #[must_use]
    pub const fn security_inconsistent(&self) -> bool {
        self.security.inconsistent()
    }

    #[must_use]
    pub const fn first_sequence(&self) -> u64 {
        self.first_sequence
    }

    #[must_use]
    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    #[must_use]
    pub const fn frames(&self) -> u64 {
        self.frames
    }

    pub fn update(&mut self, observed: AccessPointObservation) {
        let security_conflict = self.security_conflicts_with(&observed);
        if let Some(observed_ssid) = observed.ssid {
            match self.ssid.as_ref() {
                None => self.ssid = Some(observed_ssid),
                Some(current) if current != &observed_ssid => {
                    // Preserve the first identity and one concrete conflicting value
                    if self.ssid_conflict.is_none() {
                        self.ssid_conflict = Some(observed_ssid);
                    }
                }
                Some(_) => {}
            }
        }
        if let Some(observed_channel) = observed.channel {
            if !self.observed_channels.contains(&observed_channel) {
                self.observed_channels.push(observed_channel);
                self.observed_channels.sort_unstable();
            }
            self.channel_changed = self.observed_channels.len() > 1;
            // The latest channel represents the end of the observed interval
            self.channel = Some(observed_channel);
        }
        self.channel_inconsistent |= observed.channel_inconsistent;
        self.frequency_mhz = observed.frequency_mhz.or(self.frequency_mhz);
        self.signal_dbm = observed.signal_dbm.or(self.signal_dbm);
        self.security = self.security.merged(observed.security);
        if security_conflict {
            self.security = self.security.mark_inconsistent();
        }
        if self.security_fingerprint.is_none() {
            self.security_fingerprint
                .clone_from(&observed.security_fingerprint);
        }
        self.last_sequence = observed.sequence;
        self.frames = self.frames.saturating_add(1);
    }

    pub(crate) fn security_conflicts_with(&self, observed: &AccessPointObservation) -> bool {
        self.security_fingerprint
            .as_ref()
            .zip(observed.security_fingerprint.as_ref())
            .is_some_and(|(current, next)| current != next)
    }

    pub(crate) fn from_observation(observation: AccessPointObservation) -> Self {
        Self {
            bssid: observation.bssid,
            ssid: observation.ssid,
            ssid_conflict: None,
            channel: observation.channel,
            observed_channels: observation.channel.into_iter().collect(),
            channel_changed: false,
            channel_inconsistent: observation.channel_inconsistent,
            frequency_mhz: observation.frequency_mhz,
            signal_dbm: observation.signal_dbm,
            security: observation.security,
            security_fingerprint: observation.security_fingerprint,
            first_sequence: observation.sequence,
            last_sequence: observation.sequence,
            frames: 1,
        }
    }
}

pub struct AccessPointObservation {
    pub bssid: MacAddress,
    pub ssid: Option<Vec<u8>>,
    pub channel: Option<u16>,
    pub channel_inconsistent: bool,
    pub frequency_mhz: Option<u16>,
    pub signal_dbm: Option<i8>,
    pub security: SecurityEvidence,
    pub(crate) security_fingerprint: Option<SecurityFingerprint>,
    pub sequence: u64,
}
