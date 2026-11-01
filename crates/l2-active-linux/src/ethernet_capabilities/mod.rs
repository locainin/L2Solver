//! Read-only, identity-scoped Ethernet capability evidence

#[cfg(target_os = "linux")]
mod decode;
#[cfg(target_os = "linux")]
mod transport;
#[cfg(target_os = "linux")]
mod wire;

use std::{io, sync::atomic::AtomicBool, time::Instant};

#[cfg(target_os = "linux")]
use std::time::Duration;

use l2_capture::LinuxInterfaceIdentity;

use crate::InterfaceSelector;
#[cfg(target_os = "linux")]
use crate::{netlink, pin::PinnedInterface};

/// A kernel response, an unavailable query, or an explicitly unknown result
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Capability<T> {
    /// The kernel reported this value at the time of the query
    Reported(T),
    /// The kernel rejected this query as unsupported
    Unsupported,
    /// Access to the query was denied
    Denied,
    /// The value could not be established
    Unknown(UnknownReason),
}

/// Why a capability could not be established
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownReason {
    /// The kernel did not report this feature name
    NotReported,
    /// The generic ethtool family was unavailable
    KernelApiUnavailable,
    /// The response did not follow the expected protocol
    InvalidResponse,
    /// The query failed for another reason, with an OS code when available
    QueryFailed(Option<i32>),
}

/// The three bitmaps returned by the kernel for one named netdev feature
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeatureFlags {
    /// The bit in `dev->hw_features`, not proof of physical delivery
    pub hw: bool,
    /// The bit in `dev->wanted_features`
    pub wanted: bool,
    /// The bit in `dev->features`
    pub active: bool,
}

/// VLAN feature bits reported for the selected netdevice
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VlanOffloads {
    /// 802.1Q receive tag parsing
    pub ctag_rx: Capability<FeatureFlags>,
    /// 802.1Q transmit tag insertion
    pub ctag_tx: Capability<FeatureFlags>,
    /// 802.1Q receive VLAN filtering
    pub ctag_filter: Capability<FeatureFlags>,
    /// 802.1ad receive tag parsing
    pub stag_rx: Capability<FeatureFlags>,
    /// 802.1ad transmit tag insertion
    pub stag_tx: Capability<FeatureFlags>,
    /// 802.1ad receive VLAN filtering
    pub stag_filter: Capability<FeatureFlags>,
}

/// Socket timestamping flags and associated PTP clock reported by the kernel
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimestampCapabilities {
    /// The software transmit timestamp flag
    pub tx_software: Capability<bool>,
    /// The software receive timestamp flag
    pub rx_software: Capability<bool>,
    /// The hardware transmit timestamp flag
    pub tx_hardware: Capability<bool>,
    /// The hardware receive timestamp flag
    pub rx_hardware: Capability<bool>,
    /// PTP clock index, or no associated clock when the reply omits it
    pub phc_index: Capability<Option<u32>>,
}

/// Snapshot of read-only ethtool evidence for the selected interface
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EthernetCapabilities {
    /// Namespace and interface identity held throughout the query
    pub identity: LinuxInterfaceIdentity,
    /// Kernel VLAN offload feature bitmaps
    pub vlan: VlanOffloads,
    /// Kernel-advertised timestamping flags
    pub timestamps: TimestampCapabilities,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy)]
enum Unavailable {
    Unsupported,
    Denied,
    Unknown(UnknownReason),
}

#[cfg(target_os = "linux")]
impl Unavailable {
    const fn capability<T>(self) -> Capability<T> {
        match self {
            Self::Unsupported => Capability::Unsupported,
            Self::Denied => Capability::Denied,
            Self::Unknown(reason) => Capability::Unknown(reason),
        }
    }
}

#[cfg(target_os = "linux")]
impl VlanOffloads {
    const fn unavailable(reason: Unavailable) -> Self {
        Self {
            ctag_rx: reason.capability(),
            ctag_tx: reason.capability(),
            ctag_filter: reason.capability(),
            stag_rx: reason.capability(),
            stag_tx: reason.capability(),
            stag_filter: reason.capability(),
        }
    }
}

#[cfg(target_os = "linux")]
impl TimestampCapabilities {
    const fn unavailable(reason: Unavailable) -> Self {
        Self {
            tx_software: reason.capability(),
            rx_software: reason.capability(),
            tx_hardware: reason.capability(),
            rx_hardware: reason.capability(),
            phc_index: reason.capability(),
        }
    }
}

/// Query advertised offload and timestamp features without changing the interface
///
/// The identity must be from the caller's selected interface snapshot. The
/// result reports kernel state, not physical delivery or actual timestamps
///
/// # Errors
/// Returns an error if cancelled, the deadline expires, or the selected
/// interface cannot be pinned and revalidated
#[cfg(target_os = "linux")]
pub fn discover(
    selector: &InterfaceSelector,
    expected: LinuxInterfaceIdentity,
    deadline: Instant,
    cancelled: &AtomicBool,
) -> io::Result<EthernetCapabilities> {
    // One ceiling covers all three netlink requests and identity checks
    let ceiling = Instant::now()
        .checked_add(Duration::from_secs(2))
        .ok_or_else(|| io::Error::other("capability deadline overflow"))?;
    let deadline = deadline.min(ceiling);
    netlink::check_control(deadline, cancelled)?;
    let pinned = PinnedInterface::open(selector)?;
    if pinned.identity != expected {
        return Err(io::Error::other("selected interface identity changed"));
    }
    let family = match wire::family(deadline, cancelled) {
        Ok(family) => Ok(family),
        Err(error) => Err(classify(error, true)?),
    };
    let (vlan, timestamps) = match family {
        Ok(family) => {
            let vlan = match wire::features(family, expected.ifindex(), deadline, cancelled)
                .and_then(|bytes| decode::features(&bytes, expected.ifindex()))
            {
                Ok(report) => report,
                Err(error) => VlanOffloads::unavailable(classify(error, false)?),
            };
            let timestamps = match wire::timestamps(family, expected.ifindex(), deadline, cancelled)
                .and_then(|bytes| decode::timestamps(&bytes, expected.ifindex()))
            {
                Ok(report) => report,
                Err(error) => TimestampCapabilities::unavailable(classify(error, false)?),
            };
            (vlan, timestamps)
        }
        Err(reason) => (
            VlanOffloads::unavailable(reason),
            TimestampCapabilities::unavailable(reason),
        ),
    };
    // Reject the snapshot if the name was rebound during either query
    pinned.revalidate(selector)?;
    netlink::check_control(deadline, cancelled)?;
    Ok(EthernetCapabilities {
        identity: expected,
        vlan,
        timestamps,
    })
}

/// Report that the Linux ethtool query is unavailable on this platform
///
/// # Errors
/// Returns [`io::ErrorKind::Unsupported`] on non-Linux systems
#[cfg(not(target_os = "linux"))]
pub fn discover(
    _selector: &InterfaceSelector,
    _expected: LinuxInterfaceIdentity,
    _deadline: Instant,
    _cancelled: &AtomicBool,
) -> io::Result<EthernetCapabilities> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "ethtool capability discovery requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn classify(error: io::Error, family_query: bool) -> io::Result<Unavailable> {
    if matches!(
        error.kind(),
        io::ErrorKind::Interrupted | io::ErrorKind::TimedOut
    ) {
        return Err(error);
    }
    Ok(match error.raw_os_error() {
        Some(nix::libc::EPERM | nix::libc::EACCES) => Unavailable::Denied,
        Some(nix::libc::EOPNOTSUPP) => Unavailable::Unsupported,
        Some(nix::libc::ENOENT) if family_query => {
            Unavailable::Unknown(UnknownReason::KernelApiUnavailable)
        }
        _ if error.kind() == io::ErrorKind::InvalidData => {
            Unavailable::Unknown(UnknownReason::InvalidResponse)
        }
        code => Unavailable::Unknown(UnknownReason::QueryFailed(code)),
    })
}

#[cfg(all(test, target_os = "linux"))]
#[path = "../../tests/ethernet_capabilities/query.rs"]
mod query_tests;

#[cfg(all(test, target_os = "linux"))]
#[path = "../../tests/ethernet_capabilities/decode.rs"]
mod decode_tests;
