//! Capture-interface listing with read-only wireless capability enrichment

use std::{error::Error, io::Write};

#[cfg(feature = "live")]
use std::collections::BTreeSet;

#[cfg(feature = "live")]
pub fn run(output: &mut impl Write, diagnostic: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    let mut names: BTreeSet<String> = l2_live::interfaces()?.into_iter().collect();
    let wireless = wireless_inventory();
    if let Ok(inventory) = &wireless {
        names.extend(
            inventory
                .interfaces()
                .iter()
                .map(|interface| interface.name().to_owned()),
        );
    }

    writeln!(output, "NAME\tTYPE\tMODE\tPHY\tMONITOR\tINJECTION")?;
    for name in names {
        if let Ok(inventory) = &wireless
            && let Some(interface) = inventory
                .interfaces()
                .iter()
                .find(|interface| interface.name() == name)
        {
            let phy = inventory
                .phys()
                .iter()
                .find(|phy| phy.id() == interface.phy());
            let phy_name = phy
                .and_then(wifi_linux::PhyCapabilities::name)
                .map_or_else(|| format!("phy{}", interface.phy()), str::to_owned);
            let monitor = phy.map_or("unknown", |value| value.monitor_mode().as_str());
            let injection = phy.map_or("unknown", |value| value.injection().as_str());
            writeln!(
                output,
                "{}\twifi\t{}\t{}\t{}\t{}",
                name.escape_debug(),
                interface.mode().as_str(),
                phy_name.escape_debug(),
                monitor,
                injection
            )?;
            continue;
        }
        writeln!(output, "{}\tcapture\t-\t-\t-\t-", name.escape_debug())?;
    }

    if let Err(error) = wireless {
        writeln!(
            diagnostic,
            "warning: wireless capability discovery unavailable: {}",
            error.to_string().escape_debug()
        )?;
    }
    Ok(true)
}

#[cfg(feature = "live")]
fn wireless_inventory() -> Result<wifi_linux::WirelessInventory, Box<dyn Error>> {
    // The short-lived current-thread runtime keeps interface listing synchronous
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()?;
    Ok(runtime.block_on(wifi_linux::discover())?)
}

#[cfg(not(feature = "live"))]
pub fn run(_output: &mut impl Write, _diagnostic: &mut impl Write) -> Result<bool, Box<dyn Error>> {
    Err("live capture is optional; build with cargo build -p l2-cli --features live".into())
}
