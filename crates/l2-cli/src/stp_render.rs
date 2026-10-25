//! Compact STP changes keep protocol identifiers readable in a terminal

use crate::render;
use l2_codecs::BridgeId;
use l2_engine::StpUpdate;
use std::io::{self, Write};

pub fn update(output: &mut impl Write, change: StpUpdate) -> io::Result<()> {
    match change {
        StpUpdate::Unchanged => write!(output, "advertisement unchanged"),
        StpUpdate::RootChanged { previous, current } => {
            write!(output, "root ")?;
            root(output, previous)?;
            write!(output, " -> ")?;
            root(output, current)
        }
        StpUpdate::RootAged { root: expired } => {
            write!(output, "observation expired: ")?;
            root(output, Some(expired))
        }
        StpUpdate::InterfaceRemoved { previous, current } => {
            write!(output, "interface removed: ")?;
            root(output, previous)?;
            write!(output, " -> ")?;
            root(output, current)
        }
    }
}

pub fn root(output: &mut impl Write, bridge: Option<BridgeId>) -> io::Result<()> {
    if let Some(bridge) = bridge {
        render::mac(output, bridge.mac)?;
        write!(
            output,
            " (priority={} extension={})",
            bridge.priority, bridge.system_id_extension
        )
    } else {
        write!(output, "none")
    }
}
