use wifi_codecs::{AkmSuite, CipherSuite, PmfMode, SecurityProfile, SecurityProtocol};

use crate::{PmfStatus, SecurityMode, model::fingerprint::SecurityFingerprint};

pub struct SecuritySummary {
    pub mode: SecurityMode,
    pub tkip: bool,
    pub pmf: PmfStatus,
    pub(crate) fingerprint: SecurityFingerprint,
}

pub fn summarize(
    privacy: bool,
    profiles: &[SecurityProfile],
    absence_is_complete: bool,
) -> SecuritySummary {
    let pmf_capable = profiles
        .iter()
        .any(|profile| profile.pmf() != PmfMode::Disabled);
    let pmf_required = profiles
        .iter()
        .any(|profile| profile.pmf() == PmfMode::Required);
    let tkip = profiles.iter().any(|profile| {
        profile.group_cipher() == CipherSuite::Tkip
            || profile.pairwise_ciphers().contains(&CipherSuite::Tkip)
    });
    let has_wpa = profiles
        .iter()
        .any(|profile| profile.protocol() == SecurityProtocol::WpaLegacy);
    let has_rsn = profiles
        .iter()
        .any(|profile| profile.protocol() == SecurityProtocol::Rsn);
    let mode = match (has_wpa, has_rsn) {
        (true, true) => SecurityMode::WpaMixedLegacy,
        (true, false) => SecurityMode::WpaLegacy,
        (false, true) => rsn_mode(profiles),
        (false, false) if !absence_is_complete => SecurityMode::Unknown,
        (false, false) if privacy => SecurityMode::Wep,
        (false, false) => SecurityMode::Open,
    };
    let pmf = if !absence_is_complete && profiles.is_empty() {
        PmfStatus::Unknown
    } else if pmf_required {
        PmfStatus::Required
    } else if pmf_capable {
        PmfStatus::Capable
    } else {
        PmfStatus::Disabled
    };
    SecuritySummary {
        mode,
        tkip,
        pmf,
        fingerprint: SecurityFingerprint::from_profiles(profiles, mode),
    }
}

fn rsn_mode(profiles: &[SecurityProfile]) -> SecurityMode {
    let rsn_profiles = || {
        profiles
            .iter()
            .filter(|profile| profile.protocol() == SecurityProtocol::Rsn)
    };
    let has_psk = rsn_profiles().any(|profile| profile.akms().contains(&AkmSuite::Psk));
    let has_sae = rsn_profiles()
        .flat_map(SecurityProfile::akms)
        .any(|akm| matches!(akm, AkmSuite::Sae | AkmSuite::FtSae));
    let has_enterprise = rsn_profiles().flat_map(SecurityProfile::akms).any(|akm| {
        matches!(
            akm,
            AkmSuite::Ieee8021x | AkmSuite::FtIeee8021x | AkmSuite::SuiteB | AkmSuite::SuiteB192
        )
    });
    let has_owe = rsn_profiles().any(|profile| profile.akms().contains(&AkmSuite::Owe));
    let has_suite_b = rsn_profiles()
        .flat_map(SecurityProfile::akms)
        .any(|akm| matches!(akm, AkmSuite::SuiteB | AkmSuite::SuiteB192));
    let has_tkip =
        rsn_profiles().any(|profile| profile.pairwise_ciphers().contains(&CipherSuite::Tkip));
    if has_psk && has_sae {
        SecurityMode::Wpa2Wpa3PersonalTransition
    } else if has_sae {
        SecurityMode::Wpa3Personal
    } else if has_owe {
        SecurityMode::Owe
    } else if has_suite_b {
        SecurityMode::Wpa3Enterprise
    } else if has_enterprise {
        SecurityMode::Wpa2Enterprise
    } else if has_psk {
        SecurityMode::Wpa2Personal
    } else if has_tkip {
        SecurityMode::WpaMixedLegacy
    } else {
        SecurityMode::UnknownProtected
    }
}
