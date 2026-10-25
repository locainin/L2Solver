pub use wifi_codecs::{
    AkmSuite, CipherSuite, ElementKind, InformationElement, MAX_SECURITY_LIST_ENTRIES,
    ManagementBody, ManagementError, PmfMode, SecurityError, SecurityProtocol, parse_management,
    parse_security,
};
use wifi_core::decode;

pub struct SecurityProfile;

impl SecurityProfile {
    #[must_use]
    pub fn new(
        _protocol: SecurityProtocol,
        _group_cipher: CipherSuite,
        _pairwise_ciphers: Vec<CipherSuite>,
        _akms: Vec<AkmSuite>,
        _pmf: PmfMode,
    ) -> Self {
        Self
    }
}

pub mod security {
    include!("../src/security.rs");

    #[test]
    fn security_list_limits() {
        use crate::SecurityError;

        let exact_bytes = 16_u16.to_le_bytes();
        let mut exact = Cursor::new(&exact_bytes);
        assert_eq!(list_count(&mut exact, "pairwise cipher"), Ok(16));

        let over_bytes = 17_u16.to_le_bytes();
        let mut over = Cursor::new(&over_bytes);
        assert_eq!(
            list_count(&mut over, "pairwise cipher"),
            Err(SecurityError::ListLimit {
                context: "pairwise cipher",
                count: 17,
                maximum: 16,
            })
        );
    }

    #[test]
    fn pmkid_list_limits() {
        use crate::SecurityError;

        let mut exact = vec![16, 0];
        exact.extend_from_slice(&vec![0; 16 * 16]);
        assert_eq!(parse_optional_pmkids(&mut Cursor::new(&exact)), Ok(()));

        let mut over = vec![17, 0];
        over.extend_from_slice(&vec![0; 17 * 16]);
        assert_eq!(
            parse_optional_pmkids(&mut Cursor::new(&over)),
            Err(SecurityError::ListLimit {
                context: "PMKID",
                count: 17,
                maximum: 16,
            })
        );

        assert_eq!(
            parse_optional_pmkids(&mut Cursor::new(&[1, 0])),
            Err(SecurityError::Truncated {
                context: "PMKID list",
                needed: 18,
                available: 2,
            })
        );

        let mut one = vec![1, 0];
        one.extend_from_slice(&[0; 16]);
        assert_eq!(parse_optional_pmkids(&mut Cursor::new(&one)), Ok(()));

        let group = [0, 0, 0, 0, 0, 0];
        assert_eq!(parse_optional_pmkids(&mut Cursor::new(&group)), Ok(()));
        assert_eq!(
            ensure_empty(&Cursor::new(&[1])),
            Err(SecurityError::TrailingBytes(1))
        );
    }

    #[test]
    fn security_ie_tail() {
        use crate::{PmfMode, SecurityError, SecurityProtocol};

        for (capabilities, expected) in [
            (0_u16, Ok(PmfMode::Disabled)),
            (0x0080, Ok(PmfMode::Capable)),
            (0x0040, Err(SecurityError::InvalidPmf)),
            (0x00c0, Ok(PmfMode::Required)),
        ] {
            let bytes = capabilities.to_le_bytes();
            assert_eq!(
                parse_tail(&mut Cursor::new(&bytes), SecurityProtocol::Rsn),
                expected
            );
        }

        assert_eq!(
            parse_tail(&mut Cursor::new(&[1, 0]), SecurityProtocol::WpaLegacy),
            Ok(PmfMode::Disabled)
        );
    }
}

fn management_frame(subtype: u8, body: &[u8]) -> Vec<u8> {
    let frame_control = u16::from(subtype) << 4;
    let mut bytes = Vec::from(frame_control.to_le_bytes());
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(&[0xff; 6]);
    bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 1]);
    bytes.extend_from_slice(&[0x02, 0, 0, 0, 0, 2]);
    bytes.extend_from_slice(&[0, 0]);
    bytes.extend_from_slice(body);
    bytes
}

fn rsn_ie() -> Vec<u8> {
    let mut body = Vec::from(1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x0f, 0xac, 2]);
    body.extend_from_slice(&0x00c0_u16.to_le_bytes());
    let mut ie = vec![48, u8::try_from(body.len()).unwrap_or_default()];
    ie.extend_from_slice(&body);
    ie
}

#[test]
fn beacon_exposes_fixed_fields_rsn() -> Result<(), Box<dyn std::error::Error>> {
    let mut body = Vec::from(42_u64.to_le_bytes());
    body.extend_from_slice(&100_u16.to_le_bytes());
    body.extend_from_slice(&0x0010_u16.to_le_bytes());
    body.extend_from_slice(&[0, 4]);
    body.extend_from_slice(b"Corp");
    body.extend_from_slice(&[3, 1, 6]);
    body.extend_from_slice(&rsn_ie());
    let bytes = management_frame(8, &body);
    let frame = decode(&bytes)?;

    let decoded = parse_management(&frame)?;
    let ManagementBody::Beacon(beacon) = decoded.body() else {
        return Err("beacon body was not recognized".into());
    };
    assert_eq!(beacon.timestamp(), 42);
    assert_eq!(beacon.beacon_interval(), 100);
    assert_eq!(beacon.capability(), 0x0010);
    assert_eq!(beacon.elements().len(), 3);
    assert_eq!(
        beacon
            .elements()
            .first()
            .map(wifi_codecs::InformationElement::kind),
        Some(ElementKind::Ssid)
    );

    let security = beacon
        .elements()
        .iter()
        .find(|element| element.kind() == ElementKind::Rsn)
        .ok_or("missing RSN element")?;
    assert_eq!(security.id(), 48);
    let security = parse_security(security)?;
    assert_eq!(security.protocol(), SecurityProtocol::Rsn);
    assert_eq!(security.group_cipher(), CipherSuite::Ccmp128);
    assert_eq!(security.pairwise_ciphers(), &[CipherSuite::Ccmp128]);
    assert_eq!(security.akms(), &[AkmSuite::Psk]);
    assert_eq!(security.pmf(), PmfMode::Required);
    Ok(())
}

#[test]
fn assessment_information_elements_are_typed() -> Result<(), Box<dyn std::error::Error>> {
    let raw = [
        7, 3, b'U', b'S', b' ', 11, 1, 0, 45, 1, 0, 52, 1, 0, 54, 1, 0, 127, 1, 0, 191, 1, 0, 192,
        1, 0, 221, 4, 0x00, 0x50, 0xf2, 1, 221, 4, 0x00, 0x50, 0xf2, 4, 244, 1, 0, 255, 2, 35, 0,
        255, 2, 108, 0,
    ];
    let bytes = management_frame(4, &raw);
    let frame = decode(&bytes)?;
    let decoded = parse_management(&frame)?;
    let ManagementBody::ProbeRequest(probe) = decoded.body() else {
        return Err("probe request was not recognized".into());
    };
    let kinds: Vec<_> = probe
        .elements()
        .iter()
        .map(wifi_codecs::InformationElement::kind)
        .collect();

    for expected in [
        ElementKind::Country,
        ElementKind::BssLoad,
        ElementKind::HtCapabilities,
        ElementKind::NeighborReport,
        ElementKind::MobilityDomain,
        ElementKind::ExtendedCapabilities,
        ElementKind::VhtCapabilities,
        ElementKind::VhtOperation,
        ElementKind::Wpa,
        ElementKind::Wps,
        ElementKind::RsnExtension,
        ElementKind::HeCapabilities,
        ElementKind::EhtCapabilities,
    ] {
        assert!(kinds.contains(&expected), "missing {expected:?}");
    }
    Ok(())
}

#[test]
fn malformed_element_length_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = management_frame(4, &[0, 5, b'a']);
    let frame = decode(&bytes)?;

    assert!(matches!(
        parse_management(&frame),
        Err(ManagementError::TruncatedElement { .. })
    ));
    Ok(())
}

#[test]
fn management_action_frames() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = management_frame(13, &[7, 9]);
    let frame = decode(&bytes)?;
    let decoded = parse_management(&frame)?;
    let ManagementBody::Action(action) = decoded.body() else {
        return Err("action body was not recognized".into());
    };
    assert_eq!(action.category, 7);
    assert_eq!(action.action, 9);
    assert!(action.payload.is_empty());
    Ok(())
}

#[test]
fn fixed_error() -> Result<(), Box<dyn std::error::Error>> {
    let bytes = management_frame(8, &[]);
    let frame = decode(&bytes)?;
    assert_eq!(
        parse_management(&frame),
        Err(ManagementError::TruncatedBody {
            context: "beacon fixed fields",
            needed: 12,
            available: 0,
        })
    );
    Ok(())
}

#[test]
fn protected_management_body_not_parsed() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = management_frame(12, &[1, 0]);
    let control = bytes.get_mut(1).ok_or("missing frame flags")?;
    *control |= 0x40;
    let frame = decode(&bytes)?;

    assert_eq!(
        parse_management(&frame),
        Err(ManagementError::ProtectedBody)
    );
    Ok(())
}

#[test]
fn fixed_management_subtypes_enforce_lengths() -> Result<(), Box<dyn std::error::Error>> {
    let cases = [
        (0_u8, 4_usize),
        (1, 6),
        (2, 10),
        (3, 6),
        (5, 12),
        (10, 2),
        (11, 6),
        (12, 2),
        (13, 2),
    ];
    for (subtype, required) in cases {
        let body = vec![0_u8; required];
        assert!(parse_management(&decode(&management_frame(subtype, &body))?).is_ok());
        if let Some(shorter) = body.get(..required.saturating_sub(1)) {
            assert!(matches!(
                parse_management(&decode(&management_frame(subtype, shorter))?),
                Err(ManagementError::TruncatedBody { .. })
            ));
        }
    }
    Ok(())
}

#[test]
fn non_management_frame_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = management_frame(0, &[]);
    let first = bytes.get_mut(0).ok_or("missing frame control")?;
    *first = 0x08;
    let frame = decode(&bytes)?;

    assert_eq!(
        parse_management(&frame),
        Err(ManagementError::NotManagement)
    );
    Ok(())
}

#[test]
fn rsn_suite_count_is_bounded() -> Result<(), Box<dyn std::error::Error>> {
    let mut body = Vec::from(1_u16.to_le_bytes());
    body.extend_from_slice(&[0, 0x0f, 0xac, 4]);
    body.extend_from_slice(&17_u16.to_le_bytes());
    let mut raw = vec![48, u8::try_from(body.len()).unwrap_or_default()];
    raw.extend_from_slice(&body);
    let bytes = management_frame(4, &raw);
    let frame = decode(&bytes)?;
    let decoded = parse_management(&frame)?;
    let ManagementBody::ProbeRequest(probe) = decoded.body() else {
        return Err("probe request was not recognized".into());
    };
    let element = probe.elements().first().ok_or("missing RSN element")?;

    assert!(parse_security(element).is_err());
    Ok(())
}

#[test]
fn wpa_capabilities() -> Result<(), Box<dyn std::error::Error>> {
    let mut body = vec![0x00, 0x50, 0xf2, 1];
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x50, 0xf2, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x50, 0xf2, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x50, 0xf2, 2]);
    let mut raw = vec![221, u8::try_from(body.len())?];
    raw.extend_from_slice(&body);

    let bytes = management_frame(4, &raw);
    let frame = decode(&bytes)?;
    let decoded = parse_management(&frame)?;
    let ManagementBody::ProbeRequest(probe) = decoded.body() else {
        return Err("probe request was not recognized".into());
    };
    let element = probe.elements().first().ok_or("missing WPA element")?;
    let security = parse_security(element)?;
    assert_eq!(security.protocol(), SecurityProtocol::WpaLegacy);
    assert_eq!(security.group_cipher(), CipherSuite::Ccmp128);
    assert_eq!(security.pairwise_ciphers(), &[CipherSuite::Ccmp128]);
    assert_eq!(security.akms(), &[AkmSuite::Psk]);
    assert_eq!(security.pmf(), PmfMode::Disabled);
    Ok(())
}

#[test]
fn wpa_optional_capabilities_are_accepted() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        wpa_protocol(&[0x34, 0x12])?,
        Ok(SecurityProtocol::WpaLegacy)
    );
    Ok(())
}

#[test]
fn wpa_capabilities_tail_two_bytes() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(wpa_protocol(&[0x34])?, Err(SecurityError::TrailingBytes(1)));
    assert_eq!(
        wpa_protocol(&[0x34, 0x12, 0x56])?,
        Err(SecurityError::TrailingBytes(3))
    );
    Ok(())
}

fn wpa_protocol(
    tail: &[u8],
) -> Result<Result<SecurityProtocol, SecurityError>, Box<dyn std::error::Error>> {
    let mut body = vec![0x00, 0x50, 0xf2, 1];
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x50, 0xf2, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x50, 0xf2, 4]);
    body.extend_from_slice(&1_u16.to_le_bytes());
    body.extend_from_slice(&[0x00, 0x50, 0xf2, 2]);
    body.extend_from_slice(tail);
    let mut raw = vec![221, u8::try_from(body.len())?];
    raw.extend_from_slice(&body);

    let bytes = management_frame(4, &raw);
    let frame = decode(&bytes)?;
    let decoded = parse_management(&frame)?;
    let ManagementBody::ProbeRequest(probe) = decoded.body() else {
        return Err("probe request was not recognized".into());
    };
    let element = probe.elements().first().ok_or("missing WPA element")?;
    Ok(parse_security(element).map(|profile| profile.protocol()))
}

#[test]
fn management_errors() {
    assert_eq!(
        ManagementError::NotManagement.to_string(),
        "802.11 frame is not management traffic"
    );
    assert_eq!(
        SecurityError::InvalidPmf.to_string(),
        "PMF required bit set without PMF capability"
    );
}
