use super::{input, read_bounded};
use crate::arguments::MessagesArgs;
use l2_workbench::{
    hypothesis::workflow::{WorkflowPlan, run_reconstructed},
    reconstruction::Reconstructor,
    store::{Flow, Store},
};
use std::{
    error::Error,
    io::{self, Write},
    path::Path,
};

/// Reconstruct one complete indexed TCP tuple before extracting candidate messages
pub(super) fn run(
    store: &Store,
    args: &MessagesArgs,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let flow = selected_flow(store, args.flow)?;
    if flow.protocol != 6 {
        return Err(invalid_input(
            "message workflows require an indexed TCP flow",
        ));
    }
    let mut plan = read_plan(&args.plan, args.max_plan_bytes)?;
    plan.limits = args.limits();

    // Only packet rows assigned to this indexed tuple enter reconstruction
    let mut reconstructor = Reconstructor::with_limits(plan.limits.reconstruction)?;
    store.visit_flow_frames(args.flow, |packet, frame| {
        if packet.source_id != flow.source_id {
            return Err(invalid_input(
                "indexed flow packet belongs to another retained source",
            ));
        }
        reconstructor.observe_selected(packet.number, &frame)?;
        Ok(())
    })?;
    let reconstruction = reconstructor.finish()?;
    if reconstruction.frames != flow.packets {
        return Err(invalid_input(
            "indexed flow packet count changed during reconstruction",
        ));
    }

    let report = run_reconstructed(&flow.source_id, &reconstruction, &plan)?;
    serde_json::to_writer(output, &report)?;
    Ok(!report.partial)
}

fn selected_flow(store: &Store, flow_id: i64) -> Result<Flow, Box<dyn Error>> {
    let mut selected = None;
    store.visit_flows(flow_id - 1, Some(1), |flow| {
        if flow.id == flow_id {
            selected = Some(flow);
        }
        Ok(())
    })?;
    selected.ok_or_else(|| invalid_input("indexed flow does not exist"))
}

fn read_plan(path: &Path, maximum: usize) -> Result<WorkflowPlan, Box<dyn Error>> {
    if maximum == 0 {
        return Err(invalid_input("workflow plan byte budget must be positive"));
    }
    // The shared bounded reader probes one extra byte to detect an oversized plan
    maximum
        .checked_add(1)
        .ok_or_else(|| invalid_input("workflow plan byte budget cannot be represented"))?;
    let bytes = read_bounded(input::regular_no_follow(path)?, maximum)?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn invalid_input(message: &'static str) -> Box<dyn Error> {
    io::Error::new(io::ErrorKind::InvalidInput, message).into()
}
