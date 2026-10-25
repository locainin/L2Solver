use wifi_codecs::{AkmSuite, CipherSuite, PmfMode, SecurityProfile, SecurityProtocol};

use super::SecurityMode;

// A normal advertisement has at most a small number of security elements
pub const MAX_SECURITY_PROFILES: usize = 16;

// A profile keeps policy-relevant selectors while excluding ephemeral PMKIDs
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct SecurityProfileFingerprint {
    protocol: SecurityProtocol,
    group_cipher: CipherSuite,
    pairwise_ciphers: Vec<CipherSuite>,
    akms: Vec<AkmSuite>,
    pmf: PmfMode,
}

impl SecurityProfileFingerprint {
    fn from_profile(profile: &SecurityProfile) -> Self {
        // Suites are sets on the wire even when their order differs
        let mut pairwise_ciphers = profile.pairwise_ciphers().to_vec();
        pairwise_ciphers.sort_unstable();
        pairwise_ciphers.dedup();
        let mut akms = profile.akms().to_vec();
        akms.sort_unstable();
        akms.dedup();
        Self {
            protocol: profile.protocol(),
            group_cipher: profile.group_cipher(),
            pairwise_ciphers,
            akms,
            pmf: profile.pmf(),
        }
    }
}

// A bounded set of profiles gives stable comparisons across element ordering
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct SecurityFingerprint {
    mode: SecurityMode,
    profiles: Vec<SecurityProfileFingerprint>,
}

impl SecurityFingerprint {
    pub fn from_profiles(profiles: &[SecurityProfile], mode: SecurityMode) -> Self {
        // Profile order does not carry policy meaning
        let mut normalized: Vec<_> = profiles
            .iter()
            .map(SecurityProfileFingerprint::from_profile)
            .collect();
        normalized.sort_unstable();
        normalized.dedup();
        Self {
            mode,
            profiles: normalized,
        }
    }
}
