use crate::AuditError;
use serde::{Deserialize, Serialize};
use wifi_core::MacAddress;
use wifi_discovery::SecurityMode;

const MAX_NETWORKS: usize = 256;
const MAX_BSSIDS_PER_NETWORK: usize = 256;
const MAX_SECURITY_MODES: usize = 16;
const MAX_CHANNELS_PER_NETWORK: usize = 256;

/// Protected management frame expectation
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum PmfRequirement {
    Optional,
    Capable,
    Required,
}

/// Expected properties for one SSID
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WirelessNetworkPolicy {
    ssid: Vec<u8>,
    allowed_bssids: Vec<MacAddress>,
    security_modes: Vec<SecurityMode>,
    pmf: PmfRequirement,
    wps_allowed: bool,
    allowed_channels: Vec<u16>,
}

impl WirelessNetworkPolicy {
    /// Create policy for one nonempty SSID
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the SSID is outside the 1..=32 octet range
    pub fn new(ssid: Vec<u8>) -> Result<Self, AuditError> {
        if ssid.is_empty() || ssid.len() > 32 {
            return Err(AuditError::InvalidPolicy(
                "SSID length must be in 1..=32 octets",
            ));
        }
        Ok(Self {
            ssid,
            allowed_bssids: Vec::new(),
            security_modes: Vec::new(),
            pmf: PmfRequirement::Optional,
            wps_allowed: false,
            allowed_channels: Vec::new(),
        })
    }

    /// Set the bounded allowlist of BSSIDs
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the list exceeds its resource ceiling
    pub fn with_allowed_bssids(mut self, mut values: Vec<MacAddress>) -> Result<Self, AuditError> {
        validate_count("BSSIDs", values.len(), MAX_BSSIDS_PER_NETWORK)?;
        values.sort();
        values.dedup();
        self.allowed_bssids = values;
        Ok(self)
    }

    /// Set the bounded set of accepted security modes
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] when the list exceeds its resource ceiling
    pub fn with_security_modes(
        mut self,
        mut values: Vec<SecurityMode>,
    ) -> Result<Self, AuditError> {
        validate_count("security modes", values.len(), MAX_SECURITY_MODES)?;
        values.sort();
        values.dedup();
        self.security_modes = values;
        Ok(self)
    }

    #[must_use]
    pub const fn with_pmf(mut self, value: PmfRequirement) -> Self {
        self.pmf = value;
        self
    }

    #[must_use]
    pub const fn with_wps_allowed(mut self, value: bool) -> Self {
        self.wps_allowed = value;
        self
    }

    /// Set the bounded set of accepted radio channels
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] for channel zero or an oversized list
    pub fn with_allowed_channels(mut self, mut values: Vec<u16>) -> Result<Self, AuditError> {
        validate_count("channels", values.len(), MAX_CHANNELS_PER_NETWORK)?;
        if values.contains(&0) {
            return Err(AuditError::InvalidPolicy("wireless channel cannot be zero"));
        }
        values.sort_unstable();
        values.dedup();
        self.allowed_channels = values;
        Ok(self)
    }

    pub(crate) fn validate(&self) -> Result<(), AuditError> {
        let checked = Self::new(self.ssid.clone())?
            .with_allowed_bssids(self.allowed_bssids.clone())?
            .with_security_modes(self.security_modes.clone())?
            .with_allowed_channels(self.allowed_channels.clone())?;
        if checked.allowed_bssids.len() != self.allowed_bssids.len()
            || checked.security_modes.len() != self.security_modes.len()
            || checked.allowed_channels.len() != self.allowed_channels.len()
        {
            return Err(AuditError::InvalidPolicy(
                "duplicate network expectations are not permitted",
            ));
        }
        Ok(())
    }

    pub(crate) fn ssid(&self) -> &[u8] {
        &self.ssid
    }

    pub(crate) fn allowed_bssids(&self) -> &[MacAddress] {
        &self.allowed_bssids
    }

    pub(crate) fn security_modes(&self) -> &[SecurityMode] {
        &self.security_modes
    }

    pub(crate) const fn pmf(&self) -> PmfRequirement {
        self.pmf
    }

    pub(crate) const fn wps_allowed(&self) -> bool {
        self.wps_allowed
    }

    pub(crate) fn allowed_channels(&self) -> &[u16] {
        &self.allowed_channels
    }
}

/// Wireless expectations across all surveyed SSIDs
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WirelessPolicy {
    networks: Vec<WirelessNetworkPolicy>,
    unlisted_ssids_forbidden: bool,
}

impl WirelessPolicy {
    /// Create a checked policy with unique SSIDs
    ///
    /// # Errors
    ///
    /// Returns [`AuditError`] for duplicate SSIDs, invalid network policies, or
    /// an oversized network list
    pub fn new(mut networks: Vec<WirelessNetworkPolicy>) -> Result<Self, AuditError> {
        validate_count("networks", networks.len(), MAX_NETWORKS)?;
        for network in &networks {
            network.validate()?;
        }
        networks.sort_by(|left, right| left.ssid.cmp(&right.ssid));
        if networks.windows(2).any(|pair| {
            pair.first()
                .zip(pair.get(1))
                .is_some_and(|(left, right)| left.ssid == right.ssid)
        }) {
            return Err(AuditError::InvalidPolicy("duplicate SSID policy"));
        }
        Ok(Self {
            networks,
            unlisted_ssids_forbidden: false,
        })
    }

    #[must_use]
    pub const fn with_unlisted_ssids_forbidden(mut self, value: bool) -> Self {
        self.unlisted_ssids_forbidden = value;
        self
    }

    pub(crate) fn validate(&self) -> Result<(), AuditError> {
        let checked = Self::new(self.networks.clone())?;
        if checked.networks.len() != self.networks.len() {
            return Err(AuditError::InvalidPolicy("duplicate SSID policy"));
        }
        Ok(())
    }

    pub(crate) fn network(&self, ssid: &[u8]) -> Option<&WirelessNetworkPolicy> {
        self.networks.iter().find(|network| network.ssid() == ssid)
    }

    pub(crate) const fn unlisted_ssids_forbidden(&self) -> bool {
        self.unlisted_ssids_forbidden
    }
}

const fn validate_count(
    field: &'static str,
    count: usize,
    maximum: usize,
) -> Result<(), AuditError> {
    if count > maximum {
        return Err(AuditError::PolicyLimit {
            field,
            count,
            maximum,
        });
    }
    Ok(())
}
