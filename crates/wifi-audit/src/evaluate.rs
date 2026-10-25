use crate::{
    Assessment, AuditError, Coverage, CoverageStatus, Exposure, Finding, PmfRequirement, Severity,
    Verdict, WirelessPolicy, catalog::active_catalog, model::FindingInput,
};
use wifi_core::MacAddress;
use wifi_discovery::{AccessPoint, ChannelCoverage, SecurityMode, Survey};

const MAX_RADIO_COVERAGE: usize = 256;

/// Compare passive wireless inventory with explicit expectations
///
/// # Errors
///
/// Returns [`AuditError`] when deserialized policy state violates its limits
pub fn assess(
    survey: &Survey,
    policy: &WirelessPolicy,
    channel_coverage: &[ChannelCoverage],
) -> Result<Assessment, AuditError> {
    // Deserialized policy receives the same checks as programmatic policy
    policy.validate()?;
    if channel_coverage.len() > MAX_RADIO_COVERAGE {
        return Err(AuditError::AssessmentLimit {
            field: "radio coverage",
            count: channel_coverage.len(),
            maximum: MAX_RADIO_COVERAGE,
        });
    }
    let mut exposures = Vec::new();
    let mut findings = Vec::new();
    for access_point in survey.access_points() {
        // Inventory exposure and policy assertions stay separate in reports
        assess_exposures(access_point, &mut exposures);
        assess_policy(access_point, policy, &mut findings);
    }
    let coverage = coverage(survey, channel_coverage);
    Ok(Assessment::new(exposures, findings, coverage))
}

fn assess_exposures(access_point: &AccessPoint, output: &mut Vec<Exposure>) {
    let evidence = evidence(access_point);
    let bssid = access_point.bssid();
    if access_point.ssid_inconsistent() {
        output.push(exposure(
            "WIFI-IDENTITY-DRIFT",
            Severity::High,
            "One BSSID advertised conflicting SSID identities",
            bssid,
            &evidence,
        ));
    }
    if access_point.channel_changed() {
        output.push(exposure(
            "WIFI-CHANNEL-DRIFT",
            Severity::Low,
            "Access point channel changed during the survey",
            bssid,
            &evidence,
        ));
    }
    if access_point.security_inconsistent() {
        output.push(exposure(
            "WIFI-SECURITY-DRIFT",
            Severity::High,
            "Access point security advertisement changed during the survey",
            bssid,
            &evidence,
        ));
    }
    if let Some((id, severity, title)) = security_exposure(access_point.security()) {
        output.push(exposure(id, severity, title, bssid, &evidence));
    }
    if access_point.tkip() {
        output.push(exposure(
            "WIFI-ENC-TKIP",
            Severity::High,
            "TKIP cipher advertised",
            bssid,
            &evidence,
        ));
    }
    if access_point.security_complete()
        && pmf_is_applicable(access_point.security())
        && !access_point.pmf_capable()
    {
        // PMF absence is meaningful only for a complete RSN advertisement
        output.push(exposure(
            "WIFI-PMF-001",
            Severity::Medium,
            "Protected management frames are not advertised",
            bssid,
            &evidence,
        ));
    }
    if access_point.wps() {
        output.push(exposure(
            "WIFI-WPS-001",
            Severity::Medium,
            "WPS is advertised",
            bssid,
            &evidence,
        ));
    }
}

const fn security_exposure(mode: SecurityMode) -> Option<(&'static str, Severity, &'static str)> {
    match mode {
        SecurityMode::Open => Some((
            "WIFI-ENC-OPEN",
            Severity::High,
            "Open wireless network observed",
        )),
        SecurityMode::Wep => Some((
            "WIFI-ENC-WEP",
            Severity::Critical,
            "WEP-protected wireless network observed",
        )),
        SecurityMode::WpaLegacy => Some((
            "WIFI-ENC-WPA",
            Severity::High,
            "Legacy WPA network observed",
        )),
        SecurityMode::WpaMixedLegacy => Some((
            "WIFI-ENC-MIXED",
            Severity::High,
            "Legacy WPA compatibility remains advertised",
        )),
        SecurityMode::Wpa2Wpa3PersonalTransition => Some((
            "WIFI-ENC-TRANSITION",
            Severity::Medium,
            "WPA2/WPA3 personal transition mode observed",
        )),
        _ => None,
    }
}

fn assess_policy(access_point: &AccessPoint, policy: &WirelessPolicy, output: &mut Vec<Finding>) {
    let Some(ssid) = access_point.ssid() else {
        // A hidden identity cannot be matched to a named policy entry
        if policy.unlisted_ssids_forbidden() {
            output.push(finding(
                "WIFI-SSID-HIDDEN-001",
                Verdict::Potential,
                Severity::High,
                "Hidden or unavailable SSID cannot be matched to policy",
                "a policy-listed SSID",
                "SSID was absent from the retained advertisement",
                access_point,
            ));
        }
        return;
    };
    let Some(network) = policy.network(ssid) else {
        if policy.unlisted_ssids_forbidden() {
            output.push(finding(
                "WIFI-SSID-POLICY-001",
                Verdict::Fail,
                Severity::High,
                "Unlisted SSID observed",
                "only policy-listed SSIDs",
                &format!("SSID {}", display_ssid(ssid)),
                access_point,
            ));
        }
        return;
    };

    assess_bssid(access_point, network.allowed_bssids(), output);
    assess_security(access_point, network.security_modes(), output);
    assess_pmf(access_point, network.pmf(), output);
    assess_wps(access_point, network.wps_allowed(), output);
    assess_channel(access_point, network.allowed_channels(), output);
}

fn assess_bssid(access_point: &AccessPoint, allowed: &[MacAddress], output: &mut Vec<Finding>) {
    if !allowed.is_empty() && !allowed.contains(&access_point.bssid()) {
        output.push(finding(
            "WIFI-ROGUE-001",
            Verdict::Potential,
            Severity::Critical,
            "SSID observed from an unapproved BSSID",
            "an approved BSSID",
            &format!("BSSID {}", display_mac(access_point.bssid())),
            access_point,
        ));
    }
}

fn assess_security(
    access_point: &AccessPoint,
    allowed: &[SecurityMode],
    output: &mut Vec<Finding>,
) {
    if allowed.is_empty() {
        return;
    }
    if access_point.security() == SecurityMode::Unknown {
        // Missing security evidence cannot establish a definite failure
        output.push(finding(
            "WIFI-SEC-UNKNOWN-001",
            Verdict::Potential,
            Severity::High,
            "Wireless security mode could not be established",
            &format!("one of {allowed:?}"),
            "security advertisement was incomplete or malformed",
            access_point,
        ));
    } else if !allowed.contains(&access_point.security()) {
        // UnknownProtected remains potential because its selector is unclassified
        output.push(finding(
            "WIFI-SEC-POLICY-001",
            evidence_verdict(access_point),
            Severity::Critical,
            "Wireless security mode differs from policy",
            &format!("one of {allowed:?}"),
            &format!("{:?}", access_point.security()),
            access_point,
        ));
    }
}

fn assess_pmf(access_point: &AccessPoint, requirement: PmfRequirement, output: &mut Vec<Finding>) {
    let mismatch = match requirement {
        PmfRequirement::Optional => false,
        PmfRequirement::Capable => !access_point.pmf_capable(),
        PmfRequirement::Required => !access_point.pmf_required(),
    };
    if mismatch {
        let (verdict, observed) = if pmf_is_incompatible(access_point.security()) {
            // Open and legacy-only modes cannot make a meaningful PMF claim
            (
                Verdict::Potential,
                format!("PMF is not applicable to {:?}", access_point.security()),
            )
        } else if pmf_is_applicable(access_point.security()) {
            (
                evidence_verdict(access_point),
                if access_point.pmf_capable() {
                    "PMF capable but not required".to_owned()
                } else {
                    "PMF not advertised".to_owned()
                },
            )
        } else {
            // Incomplete or unfamiliar modes cannot establish PMF applicability
            (
                Verdict::Potential,
                format!(
                    "PMF applicability could not be established for {:?}",
                    access_point.security()
                ),
            )
        };
        output.push(finding(
            "WIFI-PMF-POLICY-001",
            verdict,
            Severity::High,
            "Protected management frame policy mismatch",
            &format!("PMF {requirement:?}"),
            &observed,
            access_point,
        ));
    }
}

const fn pmf_is_applicable(mode: SecurityMode) -> bool {
    matches!(
        mode,
        SecurityMode::Wpa2Personal
            | SecurityMode::Wpa2Enterprise
            | SecurityMode::Wpa3Personal
            | SecurityMode::Wpa3Enterprise
            | SecurityMode::Wpa2Wpa3PersonalTransition
            | SecurityMode::Owe
    )
}

const fn pmf_is_incompatible(mode: SecurityMode) -> bool {
    matches!(
        mode,
        SecurityMode::Open
            | SecurityMode::Wep
            | SecurityMode::WpaLegacy
            | SecurityMode::WpaMixedLegacy
    )
}

fn assess_wps(access_point: &AccessPoint, allowed: bool, output: &mut Vec<Finding>) {
    if access_point.wps() && !allowed {
        output.push(finding(
            "WIFI-WPS-POLICY-001",
            Verdict::Fail,
            Severity::High,
            "WPS violates wireless policy",
            "WPS disabled",
            "WPS advertised",
            access_point,
        ));
    }
}

fn assess_channel(access_point: &AccessPoint, allowed: &[u16], output: &mut Vec<Finding>) {
    if allowed.is_empty() {
        return;
    }
    if access_point.observed_channels().is_empty() {
        // Unknown channel evidence stays potential rather than failing policy
        output.push(finding(
            "WIFI-CHANNEL-UNKNOWN-001",
            Verdict::Potential,
            Severity::Medium,
            "Access point channel could not be established",
            &format!("one of {allowed:?}"),
            "no trustworthy channel metadata was retained",
            access_point,
        ));
        return;
    }
    let unexpected = access_point
        .observed_channels()
        .iter()
        .copied()
        .filter(|channel| !allowed.contains(channel))
        .collect::<Vec<_>>();
    if !unexpected.is_empty() {
        output.push(finding(
            "WIFI-CHANNEL-POLICY-001",
            if access_point.channel_inconsistent() {
                Verdict::Potential
            } else {
                Verdict::Fail
            },
            Severity::Medium,
            "Access point advertised an unexpected channel",
            &format!("one of {allowed:?}"),
            &format!("observed channels {unexpected:?}"),
            access_point,
        ));
    }
}

fn coverage(survey: &Survey, channel_coverage: &[ChannelCoverage]) -> Vec<Coverage> {
    // Passive coverage describes evidence quality rather than protection state
    let mut output = vec![Coverage::new(
        "WIFI-PASSIVE-SURVEY",
        if survey.inventory_incomplete()
            || !survey.diagnostics().is_empty()
            || has_incomplete_advertisements(survey)
        {
            CoverageStatus::Incomplete
        } else if survey.access_points().len() == 0 {
            CoverageStatus::NotTested
        } else {
            CoverageStatus::Tested
        },
        passive_reason(survey),
    )];
    append_channel_coverage(channel_coverage, &mut output);
    for descriptor in active_catalog() {
        // Static active entries remain visible without granting radio authority
        output.push(Coverage::new(
            descriptor.id(),
            CoverageStatus::NotTested,
            "active radio control and controlled-agent execution are unavailable".into(),
        ));
    }
    output
}

fn append_channel_coverage(channel_coverage: &[ChannelCoverage], output: &mut Vec<Coverage>) {
    if channel_coverage.is_empty() {
        output.push(Coverage::new(
            "WIFI-CHANNEL-COVERAGE",
            CoverageStatus::NotTested,
            "no explicit radio schedule or dwell evidence".into(),
        ));
        return;
    }
    let mut details = Vec::with_capacity(channel_coverage.len());
    // Zero scheduled or observed time cannot support an absence claim
    let zero_duration =
        |item: &ChannelCoverage| item.total_scheduled_ns() == 0 || item.observed_ns() == 0;
    for item in channel_coverage {
        details.push(format!(
            "radio {}: {} basis points across {} frequencies",
            item.radio(),
            item.coverage_basis_points(),
            item.channels().len()
        ));
    }
    let status = if channel_coverage.iter().all(zero_duration) {
        CoverageStatus::NotTested
    } else if channel_coverage.iter().any(zero_duration) {
        CoverageStatus::Incomplete
    } else {
        CoverageStatus::Tested
    };
    let reason = match status {
        CoverageStatus::Tested => details.join("; "),
        CoverageStatus::NotTested => format!(
            "zero positive radio observation duration was recorded; {}",
            details.join("; ")
        ),
        CoverageStatus::Incomplete => format!(
            "one or more radios have zero observation duration; {}",
            details.join("; ")
        ),
        CoverageStatus::NotApplicable => "channel coverage is not applicable".into(),
    };
    output.push(Coverage::new("WIFI-CHANNEL-COVERAGE", status, reason));
}

fn passive_reason(survey: &Survey) -> String {
    if survey.inventory_incomplete() {
        "wireless inventory reached a configured resource limit".into()
    } else if !survey.diagnostics().is_empty() {
        format!(
            "decoded wireless inventory with {} quality diagnostics",
            survey.diagnostics().len()
        )
    } else if has_incomplete_advertisements(survey) {
        "one or more access-point advertisements are incomplete or internally inconsistent".into()
    } else if survey.access_points().len() == 0 {
        "no access-point advertisement was decoded".into()
    } else {
        format!(
            "decoded {} access points and {} stations",
            survey.access_points().len(),
            survey.stations().len()
        )
    }
}

fn has_incomplete_advertisements(survey: &Survey) -> bool {
    survey.access_points().any(|access_point| {
        !access_point.security_complete()
            || access_point.ssid().is_none()
            || access_point.ssid_inconsistent()
            || access_point.channel().is_none()
            || access_point.channel_changed()
            || access_point.channel_inconsistent()
    })
}

const fn evidence_verdict(access_point: &AccessPoint) -> Verdict {
    if access_point.security_complete() {
        Verdict::Fail
    } else {
        Verdict::Potential
    }
}

fn exposure(
    id: &'static str,
    severity: Severity,
    title: &str,
    bssid: MacAddress,
    evidence: &[u64],
) -> Exposure {
    Exposure::new(id, severity, title.into(), bssid, evidence.to_vec())
}

fn finding(
    id: &'static str,
    verdict: Verdict,
    severity: Severity,
    title: &str,
    expected: &str,
    observed: &str,
    access_point: &AccessPoint,
) -> Finding {
    Finding::new(FindingInput {
        id,
        verdict,
        severity,
        title: title.into(),
        expected: expected.into(),
        observed: observed.into(),
        bssid: access_point.bssid(),
        evidence_sequences: evidence(access_point),
    })
}

fn evidence(access_point: &AccessPoint) -> Vec<u64> {
    // First and last observations bound drift evidence without retaining all frames
    if access_point.first_sequence() == access_point.last_sequence() {
        vec![access_point.first_sequence()]
    } else {
        vec![access_point.first_sequence(), access_point.last_sequence()]
    }
}

fn display_ssid(ssid: &[u8]) -> String {
    // Network-controlled bytes never reach a terminal as raw control codes
    let mut output = String::new();
    for byte in ssid {
        for escaped in std::ascii::escape_default(*byte) {
            output.push(char::from(escaped));
        }
    }
    output
}

fn display_mac(address: MacAddress) -> String {
    let [first, second, third, fourth, fifth, sixth] = address.octets();
    format!("{first:02x}:{second:02x}:{third:02x}:{fourth:02x}:{fifth:02x}:{sixth:02x}")
}
