use super::{Result, invalid};
use l2_capture::{
    CaptureLocator, CaptureMetadata, CaptureTimestamp, Direction, FcsStatus, InterfaceId, LinkType,
    LinuxInterfaceIdentity, TimestampResolution, TimestampSource, VlanAuxData,
};
use serde::{Deserialize, Serialize};

/// Repeated capture metadata is stored once rather than expanded for every packet
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Context {
    section: u32,
    interface: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    linux_interface: Option<[u64; 5]>,
    link_type: u16,
    direction: u8,
    vlan: Option<[u16; 2]>,
    fcs: Option<u8>,
    clock: Option<Clock>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Clock {
    radix: u8,
    exponent: u8,
    offset: i64,
    captured: bool,
}

impl Context {
    pub(super) fn from_metadata(metadata: &CaptureMetadata) -> Self {
        Self {
            section: metadata.interface().section,
            interface: metadata.interface().index,
            linux_interface: metadata.linux_interface().map(|identity| {
                [
                    identity.namespace_device(),
                    identity.namespace_inode(),
                    identity.interface_device(),
                    identity.interface_inode(),
                    u64::from(identity.ifindex()),
                ]
            }),
            link_type: metadata.link_type().raw(),
            direction: match metadata.direction() {
                Direction::Unknown => 0,
                Direction::Inbound => 1,
                Direction::Outbound => 2,
            },
            vlan: metadata.vlan().map(|vlan| [vlan.tpid, vlan.tci]),
            fcs: match metadata.fcs() {
                FcsStatus::Unknown => None,
                FcsStatus::Absent => Some(0),
                FcsStatus::Present { length } => Some(length.get()),
            },
            clock: metadata.timestamp().map(|time| Clock {
                radix: time.resolution().radix(),
                exponent: time.resolution().exponent(),
                offset: time.offset_seconds(),
                captured: time.source() == TimestampSource::CaptureFile,
            }),
        }
    }

    pub(super) fn metadata(
        &self,
        original: u32,
        ticks: Option<&[u8]>,
        locator: CaptureLocator,
    ) -> Result<CaptureMetadata> {
        let timestamp = match (&self.clock, ticks) {
            (None, None) => None,
            (Some(clock), Some(ticks)) => {
                let ticks = u64::from_be_bytes(ticks.try_into()?);
                let resolution = match clock.radix {
                    2 => TimestampResolution::binary(clock.exponent)?,
                    10 => TimestampResolution::decimal(clock.exponent)?,
                    _ => return Err(invalid("invalid indexed clock radix")),
                };
                Some(CaptureTimestamp::new(
                    ticks,
                    resolution,
                    clock.offset,
                    if clock.captured {
                        TimestampSource::CaptureFile
                    } else {
                        TimestampSource::Unknown
                    },
                ))
            }
            _ => return Err(invalid("indexed clock and tick fields disagree")),
        };
        let direction = match self.direction {
            0 => Direction::Unknown,
            1 => Direction::Inbound,
            2 => Direction::Outbound,
            _ => return Err(invalid("invalid indexed direction")),
        };
        let fcs = match self.fcs {
            None => FcsStatus::Unknown,
            Some(0) => FcsStatus::Absent,
            Some(length) => FcsStatus::present(length)?,
        };
        let vlan = self.vlan.map(|[tpid, tci]| VlanAuxData { tpid, tci });
        let metadata = CaptureMetadata::new(
            InterfaceId {
                section: self.section,
                index: self.interface,
            },
            original,
            Some(locator),
            timestamp,
            direction,
            vlan,
            fcs,
        )
        .with_link_type(LinkType::from_raw(self.link_type));
        // File-supplied identities stay source declarations after indexing
        match self.linux_interface {
            Some(
                [
                    namespace_device,
                    namespace_inode,
                    interface_device,
                    interface_inode,
                    ifindex,
                ],
            ) => Ok(metadata.with_linux_interface(LinuxInterfaceIdentity::new(
                namespace_device,
                namespace_inode,
                interface_device,
                interface_inode,
                u32::try_from(ifindex)?,
            )?)),
            None => Ok(metadata),
        }
    }
}
