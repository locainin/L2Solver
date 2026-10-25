//! Public PCAPNG interface and option records retained by the reader

use l2_capture::{
    FcsStatus, InterfaceId, LinkType, LinuxInterfaceIdentity, MetadataError, TimestampResolution,
};

/// An option value retained exactly for inspection and evidence generation
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PcapNgOption {
    /// Numeric option code from the capture file
    pub code: u16,
    /// Value bytes without alignment padding
    pub value: Vec<u8>,
}

/// Metadata declared by one PCAPNG interface description block
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InterfaceDescription {
    /// Section-scoped interface identifier
    pub id: InterfaceId,
    /// Checked PCAP link-layer type
    pub link_type: LinkType,
    /// Interface snapshot length, where zero means no declared limit
    pub snaplen: u32,
    /// Resolution used by timestamps for this interface
    pub timestamp_resolution: TimestampResolution,
    /// Signed seconds added to timestamps for this interface
    pub timestamp_offset_seconds: i64,
    /// FCS length in bytes declared by the interface description; zero means explicitly absent
    pub fcs_length: Option<u8>,
    pub(crate) linux_interface: Option<LinuxInterfaceIdentity>,
    pub(crate) unknown_options: Vec<PcapNgOption>,
}

impl InterfaceDescription {
    /// Return the checked data-link type declared by this interface
    #[must_use]
    pub const fn link_type(&self) -> LinkType {
        self.link_type
    }

    /// Return the original PCAPNG link-layer field declared by this interface
    #[must_use]
    pub const fn link_type_raw(&self) -> u16 {
        self.link_type.raw()
    }

    /// Return the Linux identity declared by this source file
    ///
    /// A file declaration does not validate the current host's kernel objects
    #[must_use]
    pub const fn linux_interface(&self) -> Option<LinuxInterfaceIdentity> {
        self.linux_interface
    }

    /// Borrow unknown option records retained from this interface description
    #[must_use]
    pub fn unknown_options(&self) -> &[PcapNgOption] {
        &self.unknown_options
    }

    pub(crate) fn fcs_status(&self) -> Result<FcsStatus, MetadataError> {
        self.fcs_length.map_or(Ok(FcsStatus::Unknown), |length| {
            if length == 0 {
                Ok(FcsStatus::Absent)
            } else {
                FcsStatus::present(length)
            }
        })
    }
}
