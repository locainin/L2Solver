use wifi_audit::{PmfRequirement, WirelessNetworkPolicy, WirelessPolicy};
use wifi_core::MacAddress;

use super::frames::EXPECTED_AP;

// Build the policy used by the compliant and rogue-network scenarios
pub fn policy_with_pmf(pmf: PmfRequirement) -> Result<WirelessPolicy, Box<dyn std::error::Error>> {
    let network = WirelessNetworkPolicy::new(b"Corp".to_vec())?
        .with_allowed_bssids(vec![MacAddress::new(EXPECTED_AP)])?
        .with_security_modes(vec![wifi_discovery::SecurityMode::Wpa3Personal])?
        .with_pmf(pmf)
        .with_wps_allowed(false)
        .with_allowed_channels(vec![36])?;
    Ok(WirelessPolicy::new(vec![network])?.with_unlisted_ssids_forbidden(true))
}

pub fn policy() -> Result<WirelessPolicy, Box<dyn std::error::Error>> {
    policy_with_pmf(PmfRequirement::Required)
}
