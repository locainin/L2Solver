//! Small bounded parsers used by the observation flow

use crate::ObservationStatus;
use wifi_codecs::{ElementKind, InformationElement};

pub(super) fn ssid(elements: &[InformationElement<'_>]) -> Result<Option<Vec<u8>>, &'static str> {
    let mut matches = elements
        .iter()
        .filter(|element| element.kind() == ElementKind::Ssid);
    let Some(element) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err("SSID element appears more than once");
    }
    if element.bytes().len() > 32 {
        return Err("SSID exceeds the 32-octet protocol limit");
    }
    if element.bytes().is_empty() {
        return Ok(None);
    }
    Ok(Some(element.bytes().to_vec()))
}

pub(super) fn ds_channel(elements: &[InformationElement<'_>]) -> Result<Option<u16>, &'static str> {
    let mut matches = elements
        .iter()
        .filter(|element| element.kind() == ElementKind::DsParameter);
    let Some(element) = matches.next() else {
        return Ok(None);
    };
    if matches.next().is_some() {
        return Err("DS Parameter Set appears more than once");
    }
    let [channel] = element.bytes() else {
        return Err("DS Parameter Set must contain exactly one channel octet");
    };
    if *channel == 0 || *channel > 233 {
        return Err("DS Parameter Set channel is outside 1..=233");
    }
    Ok(Some(u16::from(*channel)))
}

pub(super) const fn channel_from_frequency(frequency_mhz: u16) -> Option<u16> {
    if frequency_mhz == 2_484 {
        return Some(14);
    }
    let delta = match frequency_mhz {
        2_412..=2_472 => frequency_mhz - 2_407,
        5_005..=5_895 => frequency_mhz - 5_000,
        5_955..=7_115 => frequency_mhz - 5_950,
        _ => return None,
    };
    if delta % 5 == 0 {
        Some(delta / 5)
    } else {
        None
    }
}

pub(super) const fn combine_status(
    left: ObservationStatus,
    right: ObservationStatus,
) -> ObservationStatus {
    if status_rank(left) >= status_rank(right) {
        left
    } else {
        right
    }
}

const fn status_rank(status: ObservationStatus) -> u8 {
    match status {
        ObservationStatus::Observed => 0,
        ObservationStatus::Protected => 1,
        ObservationStatus::Unsupported => 2,
        ObservationStatus::NonCanonical => 3,
        ObservationStatus::Incomplete => 4,
        ObservationStatus::Malformed => 5,
        ObservationStatus::ResourceLimited => 6,
    }
}
