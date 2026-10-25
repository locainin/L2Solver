use core::fmt;

/// Failure while reading or normalizing Linux wireless state
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DiscoveryError {
    Netlink(String),
    MissingAttribute(&'static str),
    InvalidValue {
        field: &'static str,
        reason: &'static str,
    },
    ResourceLimit {
        field: &'static str,
        count: usize,
        maximum: usize,
    },
    DuplicateIdentity {
        field: &'static str,
        value: u32,
    },
    UnknownPhy {
        interface: u32,
        phy: u32,
    },
}

impl fmt::Display for DiscoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Netlink(reason) => write!(formatter, "nl80211 discovery failed: {reason}"),
            Self::MissingAttribute(field) => write!(formatter, "nl80211 response lacks {field}"),
            Self::InvalidValue { field, reason } => {
                write!(formatter, "invalid nl80211 {field}: {reason}")
            }
            Self::ResourceLimit {
                field,
                count,
                maximum,
            } => write!(
                formatter,
                "nl80211 {field} count {count} exceeds limit {maximum}"
            ),
            Self::DuplicateIdentity { field, value } => {
                write!(formatter, "duplicate nl80211 {field} identity {value}")
            }
            Self::UnknownPhy { interface, phy } => write!(
                formatter,
                "nl80211 interface {interface} refers to unknown physical radio {phy}"
            ),
        }
    }
}

impl std::error::Error for DiscoveryError {}
