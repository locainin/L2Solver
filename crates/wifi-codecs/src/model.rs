use serde::{Deserialize, Serialize};
use wifi_core::{MacAddress, ManagementSubtype};

/// Information element classes used by passive wireless assessment
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum ElementKind {
    Ssid,
    SupportedRates,
    DsParameter,
    Country,
    BssLoad,
    HtCapabilities,
    HtOperation,
    Rsn,
    ExtendedSupportedRates,
    NeighborReport,
    MobilityDomain,
    ExtendedCapabilities,
    VhtCapabilities,
    VhtOperation,
    RsnExtension,
    HeCapabilities,
    HeOperation,
    EhtCapabilities,
    EhtOperation,
    Wpa,
    Wps,
    VendorSpecific,
    Extension(u8),
    Unknown(u8),
}

/// One borrowed information element value
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct InformationElement<'a> {
    id: u8,
    bytes: &'a [u8],
    kind: ElementKind,
}

impl<'a> InformationElement<'a> {
    pub(crate) const fn new(id: u8, bytes: &'a [u8], kind: ElementKind) -> Self {
        Self { id, bytes, kind }
    }

    #[must_use]
    pub const fn id(&self) -> u8 {
        self.id
    }

    #[must_use]
    pub const fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    #[must_use]
    pub const fn kind(&self) -> ElementKind {
        self.kind
    }
}

/// Fixed beacon or probe-response fields followed by elements
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BeaconBody<'a> {
    timestamp: u64,
    beacon_interval: u16,
    capability: u16,
    elements: Vec<InformationElement<'a>>,
}

impl<'a> BeaconBody<'a> {
    pub(crate) const fn new(
        timestamp: u64,
        beacon_interval: u16,
        capability: u16,
        elements: Vec<InformationElement<'a>>,
    ) -> Self {
        Self {
            timestamp,
            beacon_interval,
            capability,
            elements,
        }
    }

    #[must_use]
    pub const fn timestamp(&self) -> u64 {
        self.timestamp
    }

    #[must_use]
    pub const fn beacon_interval(&self) -> u16 {
        self.beacon_interval
    }

    #[must_use]
    pub const fn capability(&self) -> u16 {
        self.capability
    }

    #[must_use]
    pub fn elements(&self) -> &[InformationElement<'a>] {
        &self.elements
    }
}

/// Management body whose complete payload is an element sequence
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ElementsBody<'a> {
    elements: Vec<InformationElement<'a>>,
}

impl<'a> ElementsBody<'a> {
    pub(crate) const fn new(elements: Vec<InformationElement<'a>>) -> Self {
        Self { elements }
    }

    #[must_use]
    pub fn elements(&self) -> &[InformationElement<'a>] {
        &self.elements
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssociationRequestBody<'a> {
    pub capability: u16,
    pub listen_interval: u16,
    pub elements: Vec<InformationElement<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssociationResponseBody<'a> {
    pub capability: u16,
    pub status: u16,
    pub association_id: u16,
    pub elements: Vec<InformationElement<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReassociationRequestBody<'a> {
    pub capability: u16,
    pub listen_interval: u16,
    pub current_access_point: MacAddress,
    pub elements: Vec<InformationElement<'a>>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationBody<'a> {
    pub algorithm: u16,
    pub sequence: u16,
    pub status: u16,
    pub elements: Vec<InformationElement<'a>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReasonBody<'a> {
    pub reason: u16,
    pub trailing: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ActionBody<'a> {
    pub category: u8,
    pub action: u8,
    pub payload: &'a [u8],
}

/// Typed body for one management subtype
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ManagementBody<'a> {
    AssociationRequest(AssociationRequestBody<'a>),
    AssociationResponse(AssociationResponseBody<'a>),
    ReassociationRequest(ReassociationRequestBody<'a>),
    ReassociationResponse(AssociationResponseBody<'a>),
    ProbeRequest(ElementsBody<'a>),
    ProbeResponse(BeaconBody<'a>),
    Beacon(BeaconBody<'a>),
    Authentication(AuthenticationBody<'a>),
    Disassociation(ReasonBody<'a>),
    Deauthentication(ReasonBody<'a>),
    Action(ActionBody<'a>),
    Other(&'a [u8]),
}

/// One decoded management body tied to its original subtype
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagementFrame<'a> {
    subtype: ManagementSubtype,
    body: ManagementBody<'a>,
}

impl<'a> ManagementFrame<'a> {
    pub(crate) const fn new(subtype: ManagementSubtype, body: ManagementBody<'a>) -> Self {
        Self { subtype, body }
    }

    #[must_use]
    pub const fn subtype(&self) -> ManagementSubtype {
        self.subtype
    }

    #[must_use]
    pub const fn body(&self) -> &ManagementBody<'a> {
        &self.body
    }
}

/// Security protocol carried by a decoded element
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum SecurityProtocol {
    Rsn,
    WpaLegacy,
}

/// Cipher selector with unknown values preserved exactly
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum CipherSuite {
    UseGroup,
    Wep40,
    Tkip,
    Ccmp128,
    Wep104,
    Gcmp128,
    Gcmp256,
    Ccmp256,
    BipCmac128,
    Unknown([u8; 4]),
}

/// Authentication and key-management selector
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum AkmSuite {
    Ieee8021x,
    Psk,
    FtIeee8021x,
    FtPsk,
    Sae,
    FtSae,
    SuiteB,
    SuiteB192,
    Owe,
    Unknown([u8; 4]),
}

/// Protected management frame policy derived from RSN capabilities
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
pub enum PmfMode {
    Disabled,
    Capable,
    Required,
}

/// Bounded security suites advertised by one RSN or WPA element
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SecurityProfile {
    protocol: SecurityProtocol,
    group_cipher: CipherSuite,
    pairwise_ciphers: Vec<CipherSuite>,
    akms: Vec<AkmSuite>,
    pmf: PmfMode,
}

impl SecurityProfile {
    pub(crate) const fn new(
        protocol: SecurityProtocol,
        group_cipher: CipherSuite,
        pairwise_ciphers: Vec<CipherSuite>,
        akms: Vec<AkmSuite>,
        pmf: PmfMode,
    ) -> Self {
        Self {
            protocol,
            group_cipher,
            pairwise_ciphers,
            akms,
            pmf,
        }
    }

    #[must_use]
    pub const fn protocol(&self) -> SecurityProtocol {
        self.protocol
    }

    #[must_use]
    pub const fn group_cipher(&self) -> CipherSuite {
        self.group_cipher
    }

    #[must_use]
    pub fn pairwise_ciphers(&self) -> &[CipherSuite] {
        &self.pairwise_ciphers
    }

    #[must_use]
    pub fn akms(&self) -> &[AkmSuite] {
        &self.akms
    }

    #[must_use]
    pub const fn pmf(&self) -> PmfMode {
        self.pmf
    }
}
