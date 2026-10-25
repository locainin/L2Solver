use std::future::Future;

use crate::model::{
    MAX_BANDS_PER_PHY, MAX_INTERFACES, MAX_MODES_PER_PHY, MAX_PHYS, validate_count,
};
use crate::{
    CapabilityState, DiscoveryError, InterfaceInfo, PhyCapabilities, WirelessInventory,
    WirelessMode,
    normalize::{band, interface_mode, supported_mode},
};
use futures::TryStreamExt;
use tokio::task::{AbortHandle, JoinHandle};
use wl_nl80211::{
    Nl80211Attr, Nl80211Error, Nl80211Message,
    packet_core::{NLM_F_DUMP_INTR, NetlinkPayload},
};

const MAX_PHYSICAL_DUMP_RECORDS: usize = 4_096;

/// Query Linux `nl80211` without changing radio or interface state
///
/// Injection remains [`CapabilityState::Unknown`] until a separate physical
/// qualification proves that the driver and hardware transmit injected frames
///
/// # Errors
///
/// Returns [`DiscoveryError`] when netlink I/O fails or kernel state cannot be
/// normalized within the resource limits
pub async fn discover() -> Result<WirelessInventory, DiscoveryError> {
    let (mut connection, handle, _) =
        wl_nl80211::new_connection().map_err(|error| DiscoveryError::Netlink(error.to_string()))?;
    // A dump is complete only after its explicit kernel terminator is checked
    connection.set_forward_done(true);
    let connection_task = tokio::spawn(connection);

    collect_with_connection(connection_task, collect(&handle)).await
}

async fn collect_with_connection<T>(
    task: JoinHandle<()>,
    collection: impl Future<Output = Result<T, DiscoveryError>>,
) -> Result<T, DiscoveryError> {
    // Abort the worker if the caller drops discovery before cleanup can finish
    let _abort_on_drop = AbortOnDrop(task.abort_handle());
    let result = collection.await;
    finish_connection(task).await?;
    result
}

async fn finish_connection(task: JoinHandle<()>) -> Result<(), DiscoveryError> {
    task.abort();
    // Keep task cleanup separate from the result classification checked by the tests
    let outcome = match task.await {
        Ok(()) => ConnectionOutcome::Completed,
        // Discovery owns this task and deliberately stops it after collection
        Err(error) if error.is_cancelled() => ConnectionOutcome::Cancelled,
        Err(error) => ConnectionOutcome::Failed(error.to_string()),
    };
    connection_result(outcome)
}

enum ConnectionOutcome {
    Completed,
    Cancelled,
    Failed(String),
}

fn connection_result(outcome: ConnectionOutcome) -> Result<(), DiscoveryError> {
    match outcome {
        ConnectionOutcome::Completed | ConnectionOutcome::Cancelled => Ok(()),
        ConnectionOutcome::Failed(reason) => Err(DiscoveryError::Netlink(format!(
            "connection worker failed: {reason}"
        ))),
    }
}

struct AbortOnDrop(AbortHandle);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn collect(handle: &wl_nl80211::Nl80211Handle) -> Result<WirelessInventory, DiscoveryError> {
    // Split wiphy dumps may emit several records for one physical radio
    let mut physical = PhysicalAccumulator::new();
    let mut physical_stream = handle.wireless_physic().get().execute().await;
    loop {
        match physical_stream.try_next().await {
            Ok(Some(message)) => physical.merge(message.payload.attributes)?,
            Ok(None) => {
                validate_dump_termination(None)?;
                break;
            }
            Err(error) => {
                validate_dump_termination(Some(error))?;
                break;
            }
        }
    }

    // Interface dumps are one record per interface and have a direct ceiling
    let mut interfaces = InterfaceAccumulator::new();
    let mut interface_stream = handle.interface().get(Vec::new()).execute().await;
    loop {
        match interface_stream.try_next().await {
            Ok(Some(message)) => interfaces.push(message.payload)?,
            Ok(None) => {
                validate_dump_termination(None)?;
                break;
            }
            Err(error) => {
                validate_dump_termination(Some(error))?;
                break;
            }
        }
    }

    WirelessInventory::new(physical.finish()?, interfaces.finish())
}

fn validate_dump_termination(error: Option<Nl80211Error>) -> Result<(), DiscoveryError> {
    let Some(Nl80211Error::UnexpectedMessage(message)) = error else {
        return Err(DiscoveryError::Netlink(error.map_or_else(
            || String::from("response stream ended without NLMSG_DONE"),
            |error| error.to_string(),
        )));
    };
    let (header, payload) = message.into_parts();
    let NetlinkPayload::Done(done) = payload else {
        return Err(DiscoveryError::Netlink(format!(
            "unexpected netlink response while awaiting NLMSG_DONE: {payload:?}"
        )));
    };
    if header.flags & NLM_F_DUMP_INTR != 0 {
        return Err(DiscoveryError::Netlink(String::from(
            "kernel marked the netlink dump interrupted",
        )));
    }
    if done.code != 0 {
        return Err(DiscoveryError::Netlink(format!(
            "netlink dump completed with status {}",
            done.code
        )));
    }
    Ok(())
}

#[derive(Clone)]
struct RawPhy {
    id: u32,
    name: Option<String>,
    modes: Vec<WirelessMode>,
    bands: Vec<crate::Band>,
    iftype_evidence: bool,
}

struct PhysicalAccumulator {
    records: Vec<RawPhy>,
    fragments: usize,
}

impl PhysicalAccumulator {
    fn new() -> Self {
        Self {
            records: Vec::with_capacity(MAX_PHYS),
            fragments: 0,
        }
    }

    fn merge(&mut self, attributes: Vec<Nl80211Attr>) -> Result<(), DiscoveryError> {
        let next_fragments =
            self.fragments
                .checked_add(1)
                .ok_or(DiscoveryError::ResourceLimit {
                    field: "physical dump records",
                    count: usize::MAX,
                    maximum: MAX_PHYSICAL_DUMP_RECORDS,
                })?;
        validate_count(
            "physical dump records",
            next_fragments,
            MAX_PHYSICAL_DUMP_RECORDS,
        )?;
        let id = unique_attribute_u32(
            &attributes,
            |attribute| match attribute {
                Nl80211Attr::Wiphy(value) => Some(*value),
                _ => None,
            },
            "physical radio ID",
        )?
        .ok_or(DiscoveryError::MissingAttribute("physical radio ID"))?;
        let position = self.records.iter().position(|item| item.id == id);
        let mut candidate = if let Some(position) = position {
            self.records
                .get(position)
                .cloned()
                .ok_or(DiscoveryError::MissingAttribute("physical radio record"))?
        } else {
            validate_count("physical radios", self.records.len() + 1, MAX_PHYS)?;
            RawPhy::new(id)
        };
        // A malformed fragment cannot leave part of its fields behind
        candidate.merge(attributes)?;
        if let Some(position) = position {
            let existing = self
                .records
                .get_mut(position)
                .ok_or(DiscoveryError::MissingAttribute("physical radio record"))?;
            *existing = candidate;
        } else {
            self.records.push(candidate);
        }
        self.fragments = next_fragments;
        Ok(())
    }

    fn finish(self) -> Result<Vec<PhyCapabilities>, DiscoveryError> {
        self.records.into_iter().map(RawPhy::finish).collect()
    }
}

struct InterfaceAccumulator {
    records: Vec<InterfaceInfo>,
}

impl InterfaceAccumulator {
    fn new() -> Self {
        Self {
            records: Vec::with_capacity(MAX_INTERFACES),
        }
    }

    fn push(&mut self, record: Nl80211Message) -> Result<(), DiscoveryError> {
        validate_count("interfaces", self.records.len() + 1, MAX_INTERFACES)?;
        self.records.push(interface(record.attributes)?);
        Ok(())
    }

    fn finish(self) -> Vec<InterfaceInfo> {
        self.records
    }
}

impl RawPhy {
    const fn new(id: u32) -> Self {
        Self {
            id,
            name: None,
            modes: Vec::new(),
            bands: Vec::new(),
            iftype_evidence: false,
        }
    }

    fn merge(&mut self, attributes: Vec<Nl80211Attr>) -> Result<(), DiscoveryError> {
        for attribute in attributes {
            match attribute {
                Nl80211Attr::WiphyName(value) => {
                    if value.is_empty() || value.len() > 64 || value.contains('\0') {
                        return Err(DiscoveryError::InvalidValue {
                            field: "physical radio name",
                            reason: "name must be 1..=64 bytes without NUL",
                        });
                    }
                    // Split records describe one snapshot, not a last-writer-wins rename
                    if self.name.as_ref().is_some_and(|name| name != &value) {
                        return Err(DiscoveryError::InvalidValue {
                            field: "physical radio name",
                            reason: "conflicting names for one physical radio",
                        });
                    }
                    self.name = Some(value);
                }
                Nl80211Attr::SupportedIftypes(values) => {
                    self.iftype_evidence = true;
                    for mode in values.into_iter().map(supported_mode) {
                        add_mode(&mut self.modes, mode)?;
                    }
                }
                Nl80211Attr::SoftwareIftypes(values) => {
                    self.iftype_evidence = true;
                    for mode in values.into_iter().map(interface_mode) {
                        add_mode(&mut self.modes, mode)?;
                    }
                }
                Nl80211Attr::WiphyBands(values) => {
                    for value in values {
                        let value = band(value)?;
                        if let Some(existing) = self
                            .bands
                            .iter_mut()
                            .find(|existing| existing.kind() == value.kind())
                        {
                            existing.merge(value)?;
                        } else {
                            validate_count(
                                "bands per physical radio",
                                self.bands.len() + 1,
                                MAX_BANDS_PER_PHY,
                            )?;
                            self.bands.push(value);
                        }
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<PhyCapabilities, DiscoveryError> {
        let monitor_mode = if self.modes.contains(&WirelessMode::Monitor) {
            CapabilityState::Supported
        } else if self.iftype_evidence {
            CapabilityState::Unsupported
        } else {
            CapabilityState::Unknown
        };
        PhyCapabilities::new_with_monitor_mode(
            self.id,
            self.name,
            self.modes,
            self.bands,
            monitor_mode,
            CapabilityState::Unknown,
        )
    }
}

fn add_mode(modes: &mut Vec<WirelessMode>, mode: WirelessMode) -> Result<(), DiscoveryError> {
    if modes.contains(&mode) {
        return Ok(());
    }
    validate_count(
        "modes per physical radio",
        modes.len() + 1,
        MAX_MODES_PER_PHY,
    )?;
    modes.push(mode);
    Ok(())
}

fn interface(attributes: Vec<Nl80211Attr>) -> Result<InterfaceInfo, DiscoveryError> {
    let mut index = None;
    let mut name = None;
    let mut phy = None;
    let mut mode = None;
    for attribute in attributes {
        match attribute {
            Nl80211Attr::IfIndex(value) => set_once(&mut index, value, "interface index")?,
            Nl80211Attr::IfName(value) => set_once(&mut name, value, "interface name")?,
            Nl80211Attr::Wiphy(value) => set_once(&mut phy, value, "physical radio ID")?,
            Nl80211Attr::IfType(value) => {
                set_once(&mut mode, interface_mode(value), "interface mode")?;
            }
            _ => {}
        }
    }
    InterfaceInfo::new(
        index.ok_or(DiscoveryError::MissingAttribute("interface index"))?,
        name.ok_or(DiscoveryError::MissingAttribute("interface name"))?,
        phy.ok_or(DiscoveryError::MissingAttribute("physical radio ID"))?,
        mode.ok_or(DiscoveryError::MissingAttribute("interface mode"))?,
    )
}

fn unique_attribute_u32(
    attributes: &[Nl80211Attr],
    predicate: impl Fn(&Nl80211Attr) -> Option<u32>,
    field: &'static str,
) -> Result<Option<u32>, DiscoveryError> {
    let mut output = None;
    for value in attributes.iter().filter_map(&predicate) {
        set_once(&mut output, value, field)?;
    }
    Ok(output)
}

fn set_once<T>(
    target: &mut Option<T>,
    value: T,
    field: &'static str,
) -> Result<(), DiscoveryError> {
    if target.is_some() {
        return Err(DiscoveryError::InvalidValue {
            field,
            reason: "attribute appears more than once",
        });
    }
    *target = Some(value);
    Ok(())
}

#[cfg(test)]
#[path = "../tests/discover/mod.rs"]
mod tests;
