//! Capture selection, frame classification, and observation state transitions

use super::{
    Survey,
    parsing::{channel_from_frequency, combine_status, ds_channel, ssid},
};
use crate::{
    DiagnosticKind, ObservationContext, ObservationStatus, SecurityEvidence, SecurityMode,
    WirelessInput,
    model::{AccessPointObservation, fingerprint::MAX_SECURITY_PROFILES},
    security::summarize,
};
use wifi_codecs::{
    BeaconBody, ElementKind, InformationElement, ManagementBody, ManagementError, ManagementFrame,
    SecurityProfile, parse_management, parse_security,
};
use wifi_core::{FrameKind, MacAddress, ManagementSubtype, WifiFrame};

impl Survey {
    /// Observe one explicitly typed wireless capture record
    pub fn observe(
        &mut self,
        input: WirelessInput<'_>,
        context: ObservationContext,
    ) -> ObservationStatus {
        if let Err(status) = self.validate_context(context) {
            return status;
        }
        let input_quality = self.capture_quality(context);
        if input_quality == ObservationStatus::ResourceLimited {
            return input_quality;
        }
        let selected = match self.select_input(input, context, input_quality) {
            Ok(Some(selected)) => selected,
            Ok(None) => return input_quality,
            Err(status) => return combine_status(input_quality, status),
        };
        let frame = match wifi_core::decode(selected.bytes) {
            Ok(frame) => frame,
            Err(wifi_core::DecodeError::UnsupportedVersion(_)) => {
                let status = self.diagnostic(
                    context,
                    DiagnosticKind::WifiMac,
                    "unsupported 802.11 protocol version".into(),
                    ObservationStatus::Unsupported,
                );
                return combine_status(selected.quality, status);
            }
            Err(error) => {
                let status = self.diagnostic(
                    context,
                    DiagnosticKind::WifiMac,
                    error.to_string(),
                    ObservationStatus::Malformed,
                );
                return combine_status(selected.quality, status);
            }
        };
        combine_status(
            selected.quality,
            self.observe_frame(&frame, selected.radio, context),
        )
    }

    fn validate_context(&mut self, context: ObservationContext) -> Result<(), ObservationStatus> {
        let order_regressed = match (
            self.last_sequence,
            self.last_monotonic_ns,
            context.monotonic_ns(),
        ) {
            // Timed capture sources use their local monotonic clock as the primary order
            (Some(previous_sequence), Some(previous_time), Some(current_time)) => {
                (current_time, context.sequence()) < (previous_time, previous_sequence)
            }
            // Untimed sources use the stable source sequence instead
            (Some(previous_sequence), _, _) => context.sequence() < previous_sequence,
            (None, _, _) => false,
        };
        if order_regressed {
            return Err(self.diagnostic(
                context,
                DiagnosticKind::Capture,
                "observation order regressed".into(),
                ObservationStatus::NonCanonical,
            ));
        }

        // Commit ordering only after every context invariant has passed
        self.last_sequence = Some(context.sequence());
        self.last_monotonic_ns = context.monotonic_ns();
        Ok(())
    }

    fn capture_quality(&mut self, context: ObservationContext) -> ObservationStatus {
        if !context.capture_truncated() {
            return ObservationStatus::Observed;
        }
        self.diagnostic(
            context,
            DiagnosticKind::Capture,
            "capture retained fewer bytes than the original wireless frame".into(),
            ObservationStatus::Incomplete,
        )
    }

    fn select_input<'a>(
        &mut self,
        input: WirelessInput<'a>,
        context: ObservationContext,
        quality: ObservationStatus,
    ) -> Result<Option<SelectedWireless<'a>>, ObservationStatus> {
        match input {
            WirelessInput::Ieee80211(bytes) => Ok(Some(SelectedWireless {
                bytes,
                radio: RadioMetadata::default(),
                quality,
            })),
            WirelessInput::Radiotap(bytes) => {
                let frame = wifi_radiotap::decode(bytes).map_err(|error| {
                    self.diagnostic(
                        context,
                        DiagnosticKind::Radiotap,
                        error.to_string(),
                        ObservationStatus::Malformed,
                    )
                })?;
                self.select_radiotap(&frame, context, quality)
            }
        }
    }

    fn select_radiotap<'a>(
        &mut self,
        frame: &wifi_radiotap::RadiotapFrame<'a>,
        context: ObservationContext,
        mut quality: ObservationStatus,
    ) -> Result<Option<SelectedWireless<'a>>, ObservationStatus> {
        if frame.fields().zero_length_psdu().is_some() {
            if frame.wifi_bytes().is_empty() {
                return Ok(None);
            }
            return Err(self.diagnostic(
                context,
                DiagnosticKind::Radiotap,
                "radiotap declares a zero-length PSDU but payload bytes follow".into(),
                ObservationStatus::NonCanonical,
            ));
        }
        if !frame.metadata_complete() {
            let field = frame
                .first_unsupported_field()
                .map_or_else(|| "unknown".into(), |value| value.to_string());
            let status = self.diagnostic(
                context,
                DiagnosticKind::Radiotap,
                format!("radiotap metadata is incomplete at field {field}"),
                ObservationStatus::NonCanonical,
            );
            quality = combine_status(quality, status);
            if quality == ObservationStatus::ResourceLimited {
                return Err(quality);
            }
        }
        let flags = frame.fields().flags();
        if flags.is_some_and(wifi_radiotap::RadiotapFlags::bad_fcs) {
            return Err(self.diagnostic(
                context,
                DiagnosticKind::Radiotap,
                "radiotap reports a bad frame check sequence".into(),
                ObservationStatus::Malformed,
            ));
        }
        // A truncated capture may end before the FCS even when the original
        // PSDU carried one, so the retained suffix cannot be removed safely
        let bytes = if flags.is_some_and(wifi_radiotap::RadiotapFlags::has_fcs)
            && !context.capture_truncated()
        {
            frame
                .wifi_bytes()
                .split_last_chunk::<4>()
                .map(|(body, _)| body)
        } else {
            Some(frame.wifi_bytes())
        }
        .ok_or_else(|| {
            self.diagnostic(
                context,
                DiagnosticKind::Radiotap,
                "radiotap marks an FCS that is not present".into(),
                ObservationStatus::Malformed,
            )
        })?;
        Ok(Some(SelectedWireless {
            bytes,
            radio: RadioMetadata {
                frequency_mhz: frame
                    .fields()
                    .channel()
                    .map(wifi_radiotap::Channel::frequency_mhz),
                signal_dbm: frame.fields().signal_dbm(),
            },
            quality,
        }))
    }

    fn observe_frame(
        &mut self,
        frame: &WifiFrame<'_>,
        radio: RadioMetadata,
        context: ObservationContext,
    ) -> ObservationStatus {
        match frame.kind() {
            FrameKind::Management(ManagementSubtype::Beacon | ManagementSubtype::ProbeResponse) => {
                self.observe_access_point(frame, radio, context)
            }
            FrameKind::Management(_) => self.observe_management_station(frame, context),
            FrameKind::Data(_) => self.observe_data_station(frame, context),
            FrameKind::Control(_) | FrameKind::Extension(_) => ObservationStatus::Observed,
        }
    }

    fn observe_access_point(
        &mut self,
        frame: &WifiFrame<'_>,
        radio: RadioMetadata,
        context: ObservationContext,
    ) -> ObservationStatus {
        let Some(bssid) = frame.address3() else {
            return self.diagnostic(
                context,
                DiagnosticKind::Management,
                "management frame has no BSSID".into(),
                ObservationStatus::Malformed,
            );
        };
        if !bssid.is_usable_unicast() {
            return self.diagnostic(
                context,
                DiagnosticKind::Management,
                "management advertisement has no usable unicast BSSID".into(),
                ObservationStatus::NonCanonical,
            );
        }
        let decoded = match self.decode_advertisement(frame, bssid, radio, context) {
            Ok(decoded) => decoded,
            Err(status) => return status,
        };
        let (ManagementBody::Beacon(beacon) | ManagementBody::ProbeResponse(beacon)) =
            decoded.body()
        else {
            return ObservationStatus::Unsupported;
        };
        self.observe_beacon(bssid, beacon, radio, context)
    }

    fn decode_advertisement<'a>(
        &mut self,
        frame: &WifiFrame<'a>,
        bssid: MacAddress,
        radio: RadioMetadata,
        context: ObservationContext,
    ) -> Result<ManagementFrame<'a>, ObservationStatus> {
        match parse_management(frame) {
            Ok(decoded) => Ok(decoded),
            Err(ManagementError::ProtectedBody) => {
                if self.store_partial_access_point(bssid, radio, context.sequence()) {
                    Err(ObservationStatus::Protected)
                } else {
                    Err(ObservationStatus::ResourceLimited)
                }
            }
            Err(error) => {
                if !self.store_partial_access_point(bssid, radio, context.sequence()) {
                    return Err(ObservationStatus::ResourceLimited);
                }
                Err(self.diagnostic(
                    context,
                    DiagnosticKind::Management,
                    error.to_string(),
                    ObservationStatus::Malformed,
                ))
            }
        }
    }

    fn observe_beacon(
        &mut self,
        bssid: MacAddress,
        beacon: &BeaconBody<'_>,
        radio: RadioMetadata,
        context: ObservationContext,
    ) -> ObservationStatus {
        let (profiles, malformed_security) =
            match self.security_profiles(beacon.elements(), context) {
                Ok(result) => result,
                Err(status) => return status,
            };
        let advertisement_complete = !malformed_security && !context.capture_truncated();
        let summary = summarize(
            beacon.capability() & 0x0010 != 0,
            &profiles,
            advertisement_complete,
        );
        // Unknown selectors remain valid evidence but cannot support a definite policy result
        let security_complete =
            advertisement_complete && !matches!(summary.mode, SecurityMode::UnknownProtected);
        let mut status = if malformed_security {
            ObservationStatus::Malformed
        } else {
            ObservationStatus::Observed
        };
        let ssid = match self.advertisement_ssid(beacon.elements(), context, &mut status) {
            Ok(value) => value,
            Err(status) => return status,
        };
        let (channel, channel_inconsistent) =
            match self.advertisement_channel(beacon.elements(), radio, context, &mut status) {
                Ok(value) => value,
                Err(status) => return status,
            };
        let security = SecurityEvidence::new(
            summary.mode,
            summary.tkip,
            beacon
                .elements()
                .iter()
                .any(|element| element.kind() == ElementKind::Wps),
            summary.pmf,
        )
        .with_complete(security_complete);
        self.commit_access_point(
            AccessPointObservation {
                bssid,
                ssid,
                channel,
                channel_inconsistent,
                frequency_mhz: radio.frequency_mhz,
                signal_dbm: radio.signal_dbm,
                security,
                security_fingerprint: advertisement_complete.then_some(summary.fingerprint),
                sequence: context.sequence(),
            },
            status,
            context,
        )
    }

    fn advertisement_ssid(
        &mut self,
        elements: &[InformationElement<'_>],
        context: ObservationContext,
        status: &mut ObservationStatus,
    ) -> Result<Option<Vec<u8>>, ObservationStatus> {
        match ssid(elements) {
            Ok(value) => Ok(value),
            Err(message) => {
                let diagnostic = self.diagnostic(
                    context,
                    DiagnosticKind::Management,
                    message.into(),
                    ObservationStatus::NonCanonical,
                );
                if diagnostic == ObservationStatus::ResourceLimited {
                    return Err(diagnostic);
                }
                *status = combine_status(*status, diagnostic);
                Ok(None)
            }
        }
    }

    fn advertisement_channel(
        &mut self,
        elements: &[InformationElement<'_>],
        radio: RadioMetadata,
        context: ObservationContext,
        status: &mut ObservationStatus,
    ) -> Result<(Option<u16>, bool), ObservationStatus> {
        match ds_channel(elements) {
            Ok(advertised) => {
                let captured = radio.frequency_mhz.and_then(channel_from_frequency);
                let inconsistent = advertised
                    .zip(captured)
                    .is_some_and(|(advertised, captured)| advertised != captured);
                if let (Some(advertised), Some(captured)) = (advertised, captured)
                    && inconsistent
                {
                    let diagnostic = self.diagnostic(
                        context,
                        DiagnosticKind::Management,
                        format!(
                            "DS advertised channel {advertised} differs from radiotap channel {captured}"
                        ),
                        ObservationStatus::NonCanonical,
                    );
                    if diagnostic == ObservationStatus::ResourceLimited {
                        return Err(diagnostic);
                    }
                    *status = combine_status(*status, diagnostic);
                }
                Ok((advertised.or(captured), inconsistent))
            }
            Err(message) => {
                let diagnostic = self.diagnostic(
                    context,
                    DiagnosticKind::Management,
                    message.into(),
                    ObservationStatus::NonCanonical,
                );
                if diagnostic == ObservationStatus::ResourceLimited {
                    return Err(diagnostic);
                }
                *status = combine_status(*status, diagnostic);
                Ok((radio.frequency_mhz.and_then(channel_from_frequency), false))
            }
        }
    }

    fn commit_access_point(
        &mut self,
        observation: AccessPointObservation,
        mut status: ObservationStatus,
        context: ObservationContext,
    ) -> ObservationStatus {
        let bssid = observation.bssid;
        let security_conflict = self
            .access_points
            .get(&bssid)
            .is_some_and(|item| item.security_conflicts_with(&observation));
        if !self.store_access_point(observation) {
            return ObservationStatus::ResourceLimited;
        }
        if security_conflict {
            let diagnostic = self.diagnostic(
                context,
                DiagnosticKind::Security,
                "BSSID advertised inconsistent security profiles".into(),
                ObservationStatus::NonCanonical,
            );
            status = combine_status(status, diagnostic);
        }
        status
    }

    fn store_partial_access_point(
        &mut self,
        bssid: MacAddress,
        radio: RadioMetadata,
        sequence: u64,
    ) -> bool {
        self.store_access_point(AccessPointObservation {
            bssid,
            ssid: None,
            channel: radio.frequency_mhz.and_then(channel_from_frequency),
            channel_inconsistent: false,
            frequency_mhz: radio.frequency_mhz,
            signal_dbm: radio.signal_dbm,
            security: SecurityEvidence::unknown(),
            security_fingerprint: None,
            sequence,
        })
    }

    fn security_profiles(
        &mut self,
        elements: &[InformationElement<'_>],
        context: ObservationContext,
    ) -> Result<(Vec<SecurityProfile>, bool), ObservationStatus> {
        let mut profiles = Vec::new();
        let mut malformed = false;
        for element in elements
            .iter()
            .filter(|element| matches!(element.kind(), ElementKind::Rsn | ElementKind::Wpa))
        {
            if profiles.len() == MAX_SECURITY_PROFILES {
                let status = self.diagnostic(
                    context,
                    DiagnosticKind::Security,
                    "security advertisement has too many security profiles".into(),
                    ObservationStatus::Malformed,
                );
                if status == ObservationStatus::ResourceLimited {
                    return Err(status);
                }
                malformed = true;
                break;
            }
            match parse_security(element) {
                Ok(profile) => profiles.push(profile),
                Err(error) => {
                    malformed = true;
                    let status = self.diagnostic(
                        context,
                        DiagnosticKind::Security,
                        error.to_string(),
                        ObservationStatus::Malformed,
                    );
                    if status == ObservationStatus::ResourceLimited {
                        return Err(status);
                    }
                }
            }
        }
        Ok((profiles, malformed))
    }

    fn observe_management_station(
        &mut self,
        frame: &WifiFrame<'_>,
        context: ObservationContext,
    ) -> ObservationStatus {
        let Some((address, bssid)) = management_station(frame) else {
            return ObservationStatus::Unsupported;
        };
        if self.store_station(address, bssid, context.sequence()) {
            if frame.control().protected() {
                ObservationStatus::Protected
            } else {
                ObservationStatus::Observed
            }
        } else {
            ObservationStatus::ResourceLimited
        }
    }

    fn observe_data_station(
        &mut self,
        frame: &WifiFrame<'_>,
        context: ObservationContext,
    ) -> ObservationStatus {
        let pair = match (frame.control().to_ds(), frame.control().from_ds()) {
            (true, false) => frame.transmitter().zip(frame.receiver().map(Some)),
            (false, true) => frame.receiver().zip(frame.transmitter().map(Some)),
            (false, false) => frame
                .transmitter()
                .map(|station| (station, frame.address3())),
            (true, true) => None,
        };
        let Some((station, associated)) = pair else {
            return ObservationStatus::Unsupported;
        };
        if self.store_station(station, associated, context.sequence()) {
            ObservationStatus::Observed
        } else {
            ObservationStatus::ResourceLimited
        }
    }
}

/// Select the non-AP participant from an infrastructure management frame
fn management_station(frame: &WifiFrame<'_>) -> Option<(MacAddress, Option<MacAddress>)> {
    let FrameKind::Management(subtype) = frame.kind() else {
        return None;
    };
    match subtype {
        // Probe requests are sent by stations and normally use a wildcard BSSID
        ManagementSubtype::ProbeRequest => frame.transmitter().map(|address| (address, None)),
        // Requests carry the station in Address 2 and the target BSSID in Address 3
        ManagementSubtype::AssociationRequest | ManagementSubtype::ReassociationRequest => frame
            .transmitter()
            .map(|address| (address, frame.address3())),
        // Responses carry the station in Address 1 and the BSSID in Address 3
        ManagementSubtype::AssociationResponse | ManagementSubtype::ReassociationResponse => {
            frame.receiver().map(|address| (address, frame.address3()))
        }
        // Either peer can originate these frames; the BSSID identifies the AP side
        ManagementSubtype::Authentication
        | ManagementSubtype::Disassociation
        | ManagementSubtype::Deauthentication
        | ManagementSubtype::Action => infrastructure_management_station(frame),
        // Beacons and probe responses take the AP path; unknown subtypes are not
        // assigned a station identity without a known address role
        ManagementSubtype::Beacon
        | ManagementSubtype::ProbeResponse
        | ManagementSubtype::Other(_) => None,
    }
}

fn infrastructure_management_station(
    frame: &WifiFrame<'_>,
) -> Option<(MacAddress, Option<MacAddress>)> {
    let bssid = frame.address3()?;
    let receiver = frame.receiver()?;
    let transmitter = frame.transmitter()?;
    if transmitter == bssid {
        Some((receiver, Some(bssid)))
    } else if receiver == bssid {
        Some((transmitter, Some(bssid)))
    } else {
        None
    }
}

#[derive(Clone, Copy, Default)]
struct RadioMetadata {
    frequency_mhz: Option<u16>,
    signal_dbm: Option<i8>,
}

struct SelectedWireless<'a> {
    bytes: &'a [u8],
    radio: RadioMetadata,
    quality: ObservationStatus,
}
