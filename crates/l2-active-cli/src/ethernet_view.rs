//! Present kernel-advertised VLAN offload and timestamp capabilities

use std::{fmt, io::Write};

use l2_active_linux::ethernet_capabilities::{
    Capability, EthernetCapabilities, FeatureFlags, UnknownReason,
};
use serde::Serialize;

use super::Error;

#[cfg(test)]
#[path = "../tests/ethernet_view/mapping.rs"]
mod tests;

#[derive(Serialize)]
pub struct EthernetView {
    vlan_offload: VlanOffloadView,
    hardware_timestamps: TimestampView,
}

impl EthernetView {
    pub fn new(evidence: EthernetCapabilities) -> Self {
        let vlan = evidence.vlan;
        let timestamps = evidence.timestamps;
        Self {
            vlan_offload: VlanOffloadView {
                ctag_rx: Value::new(vlan.ctag_rx, Flags::from),
                ctag_tx: Value::new(vlan.ctag_tx, Flags::from),
                ctag_filter: Value::new(vlan.ctag_filter, Flags::from),
                stag_rx: Value::new(vlan.stag_rx, Flags::from),
                stag_tx: Value::new(vlan.stag_tx, Flags::from),
                stag_filter: Value::new(vlan.stag_filter, Flags::from),
            },
            hardware_timestamps: TimestampView {
                tx_software: Value::new(timestamps.tx_software, std::convert::identity),
                rx_software: Value::new(timestamps.rx_software, std::convert::identity),
                tx_hardware: Value::new(timestamps.tx_hardware, std::convert::identity),
                rx_hardware: Value::new(timestamps.rx_hardware, std::convert::identity),
                phc_index: Value::new(timestamps.phc_index, Phc),
            },
        }
    }

    pub fn write_text(&self, output: &mut impl Write) -> Result<(), Error> {
        writeln!(output, "Kernel VLAN offload evidence:").map_err(Error::Output)?;
        for (name, value) in [
            ("ctag_rx", &self.vlan_offload.ctag_rx),
            ("ctag_tx", &self.vlan_offload.ctag_tx),
            ("ctag_filter", &self.vlan_offload.ctag_filter),
            ("stag_rx", &self.vlan_offload.stag_rx),
            ("stag_tx", &self.vlan_offload.stag_tx),
            ("stag_filter", &self.vlan_offload.stag_filter),
        ] {
            value.write_text(name, output)?;
        }
        writeln!(output, "Kernel timestamp evidence:").map_err(Error::Output)?;
        for (name, value) in [
            ("tx_software", &self.hardware_timestamps.tx_software),
            ("rx_software", &self.hardware_timestamps.rx_software),
            ("tx_hardware", &self.hardware_timestamps.tx_hardware),
            ("rx_hardware", &self.hardware_timestamps.rx_hardware),
        ] {
            value.write_text(name, output)?;
        }
        self.hardware_timestamps
            .phc_index
            .write_text("phc_index", output)
    }
}

#[derive(Serialize)]
struct VlanOffloadView {
    ctag_rx: Value<Flags>,
    ctag_tx: Value<Flags>,
    ctag_filter: Value<Flags>,
    stag_rx: Value<Flags>,
    stag_tx: Value<Flags>,
    stag_filter: Value<Flags>,
}

#[derive(Serialize)]
struct TimestampView {
    tx_software: Value<bool>,
    rx_software: Value<bool>,
    tx_hardware: Value<bool>,
    rx_hardware: Value<bool>,
    phc_index: Value<Phc>,
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum Value<T> {
    Reported {
        value: T,
    },
    Unsupported,
    Denied,
    Unknown {
        reason: &'static str,
        #[serde(skip_serializing_if = "Option::is_none")]
        os_error: Option<i32>,
    },
}

impl<T> Value<T> {
    fn new<S>(capability: Capability<S>, convert: impl FnOnce(S) -> T) -> Self {
        match capability {
            Capability::Reported(value) => Self::Reported {
                value: convert(value),
            },
            Capability::Unsupported => Self::Unsupported,
            Capability::Denied => Self::Denied,
            Capability::Unknown(reason) => {
                let (reason, os_error) = match reason {
                    UnknownReason::NotReported => ("not_reported", None),
                    UnknownReason::KernelApiUnavailable => ("kernel_api_unavailable", None),
                    UnknownReason::InvalidResponse => ("invalid_response", None),
                    UnknownReason::QueryFailed(code) => ("query_failed", code),
                };
                Self::Unknown { reason, os_error }
            }
        }
    }
}

impl<T: fmt::Display> Value<T> {
    fn write_text(&self, name: &str, output: &mut impl Write) -> Result<(), Error> {
        match self {
            Self::Reported { value } => writeln!(output, "  {name}: reported {value}"),
            Self::Unsupported => writeln!(output, "  {name}: unsupported"),
            Self::Denied => writeln!(output, "  {name}: denied"),
            Self::Unknown {
                reason,
                os_error: None,
            } => writeln!(output, "  {name}: unknown ({reason})"),
            Self::Unknown {
                reason,
                os_error: Some(code),
            } => writeln!(output, "  {name}: unknown ({reason}, OS error {code})"),
        }
        .map_err(Error::Output)
    }
}

#[derive(Serialize)]
struct Flags {
    hw: bool,
    wanted: bool,
    active: bool,
}

impl From<FeatureFlags> for Flags {
    fn from(value: FeatureFlags) -> Self {
        Self {
            hw: value.hw,
            wanted: value.wanted,
            active: value.active,
        }
    }
}

impl fmt::Display for Flags {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            output,
            "hw={} wanted={} active={}",
            self.hw, self.wanted, self.active
        )
    }
}

#[derive(Serialize)]
#[serde(transparent)]
struct Phc(Option<u32>);

impl fmt::Display for Phc {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(index) => write!(output, "{index}"),
            None => output.write_str("none"),
        }
    }
}
