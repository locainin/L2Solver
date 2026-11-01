//! Read-only presentation of one kernel-selected interface

use std::{io::Write, net::Ipv4Addr};

use l2_active_linux::{InterfaceInfo, ethernet_capabilities::EthernetCapabilities};
use serde::Serialize;

use super::{
    Error, OutputFormat, ethernet_view::EthernetView, interface_capabilities::WirelessCapabilities,
    interface_view::InterfaceView, mac::format_mac,
};

#[derive(Serialize)]
struct Address {
    address: Ipv4Addr,
    netmask: Ipv4Addr,
}

#[derive(Serialize)]
struct Report<'a> {
    status: &'static str,
    operation: &'static str,
    #[serde(flatten)]
    interface: InterfaceView<'a>,
    mac: String,
    mtu: u32,
    hardware_type: u16,
    up: bool,
    ethernet_link_type: bool,
    ipv4: Vec<Address>,
    raw_packet_permission: &'static str,
    #[serde(flatten)]
    wireless: &'a WirelessCapabilities,
    #[serde(flatten)]
    ethernet: EthernetView,
}

pub fn write(
    info: &InterfaceInfo,
    wireless: &WirelessCapabilities,
    ethernet: EthernetCapabilities,
    format: OutputFormat,
    output: &mut impl Write,
) -> Result<(), Error> {
    match format {
        OutputFormat::Text => write_text(info, wireless, ethernet, output),
        OutputFormat::Json => {
            let mut ipv4 = Vec::new();
            ipv4.try_reserve_exact(info.ipv4_assignments().len())
                .map_err(|_| Error::Allocation)?;
            ipv4.extend(info.ipv4_assignments().iter().map(|item| Address {
                address: item.address(),
                netmask: item.netmask(),
            }));
            let report = Report {
                status: "ok",
                operation: "capabilities",
                interface: InterfaceView::new(info.name(), info.identity(), info.vlan()),
                mac: format_mac(info.mac()),
                mtu: info.mtu(),
                hardware_type: info.hardware_type(),
                up: info.is_up(),
                ethernet_link_type: info.is_ethernet(),
                ipv4,
                raw_packet_permission: "not_checked",
                wireless,
                ethernet: EthernetView::new(ethernet),
            };
            serde_json::to_writer(&mut *output, &report).map_err(Error::Json)?;
            writeln!(output).map_err(Error::Output)
        }
    }
}

fn write_text(
    info: &InterfaceInfo,
    wireless: &WirelessCapabilities,
    ethernet: EthernetCapabilities,
    output: &mut impl Write,
) -> Result<(), Error> {
    writeln!(
        output,
        "Interface: {} (index {})",
        info.name().escape_debug(),
        info.identity().ifindex()
    )
    .map_err(Error::Output)?;
    InterfaceView::new(info.name(), info.identity(), info.vlan()).write_text(output)?;
    writeln!(
        output,
        "Link: {}  MAC: {}  MTU: {}  hardware type: {}",
        if info.is_up() { "up" } else { "down" },
        format_mac(info.mac()),
        info.mtu(),
        info.hardware_type()
    )
    .map_err(Error::Output)?;
    writeln!(
        output,
        "Ethernet link type: {}",
        if info.is_ethernet() { "yes" } else { "no" }
    )
    .map_err(Error::Output)?;
    for address in info.ipv4_assignments() {
        writeln!(
            output,
            "IPv4: {}  netmask: {}",
            address.address(),
            address.netmask()
        )
        .map_err(Error::Output)?;
    }
    writeln!(output, "Wireless inventory: {}", wireless.status).map_err(Error::Output)?;
    if let Some(reason) = &wireless.reason {
        writeln!(output, "Wireless reason: {}", reason.escape_debug()).map_err(Error::Output)?;
    }
    if let Some(detail) = &wireless.detail {
        writeln!(output, "Wireless detail: {}", detail.escape_debug()).map_err(Error::Output)?;
    }
    if let Some(phy_id) = wireless.phy_id {
        writeln!(
            output,
            "Wireless radio: {} ({})",
            phy_id,
            wireless
                .phy_name
                .as_deref()
                .unwrap_or("unnamed")
                .escape_debug()
        )
        .map_err(Error::Output)?;
    }
    if let Some(mode) = &wireless.current_mode {
        writeln!(output, "Current wireless mode: {}", mode.name).map_err(Error::Output)?;
    }
    for mode in &wireless.supported_modes {
        if let Some(value) = mode.kernel_value {
            writeln!(output, "Supported wireless mode: {} ({value})", mode.name)
                .map_err(Error::Output)?;
        } else {
            writeln!(output, "Supported wireless mode: {}", mode.name).map_err(Error::Output)?;
        }
    }
    writeln!(
        output,
        "Monitor mode: {}  wireless injection: {}",
        wireless.monitor_mode, wireless.injection
    )
    .map_err(Error::Output)?;
    EthernetView::new(ethernet).write_text(output)?;
    writeln!(output, "Raw packet permission: not checked").map_err(Error::Output)
}
