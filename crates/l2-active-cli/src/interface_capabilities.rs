//! Read-only wireless evidence for one selected Linux interface

use std::io;

#[cfg(target_os = "linux")]
use std::{
    future::Future,
    thread,
    time::{Duration, Instant},
};

use l2_active_linux::{InterfaceInfo, InterfaceSelector};
use serde::Serialize;
#[cfg(target_os = "linux")]
use wifi_linux::{DiscoveryError, WirelessInventory, WirelessMode};

// Bound the kernel query without treating a timeout as an unsupported feature
#[cfg(target_os = "linux")]
const INVENTORY_TIMEOUT: Duration = Duration::from_secs(1);

#[derive(Debug, Serialize)]
pub struct Mode {
    pub(crate) name: &'static str,
    pub(crate) kernel_value: Option<u32>,
}

#[cfg(target_os = "linux")]
impl From<WirelessMode> for Mode {
    fn from(mode: WirelessMode) -> Self {
        Self {
            name: mode.as_str(),
            kernel_value: match mode {
                WirelessMode::Other(value) => Some(value),
                _ => None,
            },
        }
    }
}

#[derive(Debug, Serialize)]
pub struct WirelessCapabilities {
    #[serde(rename = "wireless_status")]
    pub(crate) status: &'static str,
    #[serde(rename = "wireless_reason")]
    pub(crate) reason: Option<String>,
    #[serde(rename = "wireless_detail")]
    pub(crate) detail: Option<String>,
    #[serde(rename = "wireless_phy_id")]
    pub(crate) phy_id: Option<u32>,
    #[serde(rename = "wireless_phy_name")]
    pub(crate) phy_name: Option<String>,
    #[serde(rename = "wireless_current_mode")]
    pub(crate) current_mode: Option<Mode>,
    #[serde(rename = "wireless_supported_modes")]
    pub(crate) supported_modes: Vec<Mode>,
    pub(crate) monitor_mode: &'static str,
    #[serde(rename = "wireless_injection")]
    pub(crate) injection: &'static str,
}

#[cfg(target_os = "linux")]
impl WirelessCapabilities {
    fn unavailable(status: &'static str, reason: &'static str, detail: Option<String>) -> Self {
        Self {
            status,
            reason: Some(reason.to_owned()),
            detail,
            phy_id: None,
            phy_name: None,
            current_mode: None,
            supported_modes: Vec::new(),
            monitor_mode: "unknown",
            injection: "unknown",
        }
    }
}

/// Read wireless evidence, then confirm the selected interface still has the same identity
#[cfg(target_os = "linux")]
pub fn discover(
    selector: &InterfaceSelector,
    before: &InterfaceInfo,
) -> io::Result<WirelessCapabilities> {
    let inventory = bounded_query(INVENTORY_TIMEOUT, wifi_linux::discover);
    let after = l2_active_linux::discover(selector)?;
    if before.identity() != after.identity() {
        return Err(io::Error::other(
            "selected interface changed during wireless discovery",
        ));
    }
    match inventory {
        Ok(inventory) => from_inventory(before.name(), before.identity().ifindex(), &inventory),
        Err(error) => Ok(from_failure(error)),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn discover(
    _selector: &InterfaceSelector,
    _before: &InterfaceInfo,
) -> io::Result<WirelessCapabilities> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "wireless discovery requires Linux",
    ))
}

#[cfg(target_os = "linux")]
fn from_inventory(
    name: &str,
    ifindex: u32,
    inventory: &WirelessInventory,
) -> io::Result<WirelessCapabilities> {
    let Some(interface) = inventory
        .interfaces()
        .iter()
        .find(|interface| interface.index() == ifindex)
    else {
        return Ok(WirelessCapabilities::unavailable(
            "not_reported",
            "interface_not_in_nl80211_dump",
            None,
        ));
    };
    if interface.name() != name {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "nl80211 interface name did not match selected identity",
        ));
    }
    // The inventory validates this interface-to-radio relationship
    let phy = inventory
        .phys()
        .iter()
        .find(|phy| phy.id() == interface.phy())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing wireless radio"))?;
    let mut supported_modes = Vec::new();
    supported_modes
        .try_reserve_exact(phy.modes().len())
        .map_err(io::Error::other)?;
    supported_modes.extend(phy.modes().iter().copied().map(Mode::from));
    Ok(WirelessCapabilities {
        status: "reported",
        reason: None,
        detail: None,
        phy_id: Some(phy.id()),
        phy_name: phy.name().map(str::to_owned),
        current_mode: Some(interface.mode().into()),
        supported_modes,
        monitor_mode: phy.monitor_mode().as_str(),
        // An advertised interface mode does not prove packet injection works
        injection: "unknown",
    })
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
enum QueryFailure {
    Timeout,
    Discovery(DiscoveryError),
    Runtime(io::Error),
    WorkerPanicked,
}

#[cfg(target_os = "linux")]
fn from_failure(error: QueryFailure) -> WirelessCapabilities {
    let (reason, detail) = match error {
        QueryFailure::Timeout => ("nl80211_timeout", None),
        QueryFailure::Discovery(error) => ("nl80211_error", Some(bounded_detail(&error))),
        QueryFailure::Runtime(error) => ("runtime_error", Some(bounded_detail(&error))),
        QueryFailure::WorkerPanicked => ("worker_failed", None),
    };
    WirelessCapabilities::unavailable("unknown", reason, detail)
}

#[cfg(target_os = "linux")]
fn bounded_detail(error: &impl std::fmt::Display) -> String {
    const MAX_DETAIL_CHARS: usize = 256;
    let detail = error.to_string();
    let mut chars = detail.chars();
    let mut limited: String = chars.by_ref().take(MAX_DETAIL_CHARS).collect();
    if chars.next().is_some() {
        limited.push('…');
    }
    limited
}

#[cfg(target_os = "linux")]
fn bounded_query<F, Fut>(timeout: Duration, query: F) -> Result<WirelessInventory, QueryFailure>
where
    F: FnOnce() -> Fut + Send,
    Fut: Future<Output = Result<WirelessInventory, DiscoveryError>>,
{
    // A dedicated thread also permits the synchronous API inside another Tokio runtime
    let deadline = Instant::now() + timeout;
    thread::scope(|scope| {
        let worker = thread::Builder::new()
            .name("wireless-inventory".into())
            .spawn_scoped(scope, move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(QueryFailure::Runtime)?;
                runtime.block_on(async {
                    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), query())
                        .await
                        .map_err(|_| QueryFailure::Timeout)?
                        .map_err(QueryFailure::Discovery)
                })
            })
            .map_err(QueryFailure::Runtime)?;
        let result = worker.join().map_err(|_| QueryFailure::WorkerPanicked)?;
        // Synchronous work can finish late before the async timer gets polled again
        if Instant::now() >= deadline {
            return Err(QueryFailure::Timeout);
        }
        result
    })
}

#[cfg(all(test, target_os = "linux"))]
#[path = "../tests/interface_capabilities/mapping.rs"]
mod tests;
