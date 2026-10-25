//! Deterministic PNG pixel classification against complete fixed-point model output

mod columns;
mod mask;
mod receipt;

use super::{load, selected};
use crate::arguments::ImageReachabilityArgs;
use l2_workbench::{
    artifact::{self, PixelConnectivity, ReachableRgbSet},
    evidence::{Case, Edge, EvidenceStatus},
};
use receipt::{MaskDescriptor, ReceiptContext};
use serde_json::json;
use std::{error::Error, io::Write};

struct AnalysisArtifacts {
    receipt: Vec<u8>,
    mask: Vec<u8>,
    mask_sha256: String,
    input_sha256: String,
    width: u32,
    height: u32,
    pixel_count: usize,
    reachable_pixel_count: usize,
    unreachable_pixel_count: usize,
    component_count: usize,
    column_group_count: usize,
}

pub(super) fn run(
    args: &ImageReachabilityArgs,
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let mut case = load(&args.case)?;
    let artifacts = analyze(&case, args)?;
    retain_results(&mut case, args, &artifacts)?;
    case.add_limitation(
        "Model mismatch does not establish hidden data, text, intent, source codec history, or malicious behavior",
    )?;
    case.write_json(output)?;
    Ok(case.collection_complete())
}

fn analyze(case: &Case, args: &ImageReachabilityArgs) -> Result<AnalysisArtifacts, Box<dyn Error>> {
    let (input, bytes) = selected::bytes(case, args.node)?;
    let input_blob = input
        .blob
        .as_deref()
        .ok_or("selected PNG node has no retained blob identifier")?;
    let image = artifact::decode_png_pixels(bytes, args.png_limits())?;
    let reachable = ReachableRgbSet::enumerate(args.model.model(), args.enumeration_limits())?;
    let report = artifact::analyze_rgb_reachability(
        &image,
        &reachable,
        PixelConnectivity::from(args.connectivity),
        args.analysis_limits(),
    )?;

    let remaining_report_bytes = args
        .max_report_bytes
        .get()
        .saturating_sub(report.report_bytes());
    let column_groups = columns::group(
        image.width(),
        report.unreachable_pixels(),
        args.minimum_blank_column_gap.get(),
        args.max_analysis_work_bytes.get(),
        remaining_report_bytes,
    )?;
    let mask = mask::encode_pbm(
        image.width(),
        image.height(),
        report.unreachable_pixels(),
        args.max_mask_bytes.get(),
    )?;
    let mask_sha256 = l2_workbench::sha256(&mask);
    let receipt = receipt::encode(&ReceiptContext {
        input_node: args.node,
        input_blob,
        input_length: bytes.len(),
        args,
        image: &image,
        reachable: &reachable,
        report: &report,
        column_groups: &column_groups,
        mask: MaskDescriptor {
            format: "netpbm_p4",
            black_pixel_meaning: "rgb_not_produced_by_selected_model",
            length: mask.len(),
            sha256: &mask_sha256,
        },
    })?;

    Ok(AnalysisArtifacts {
        receipt,
        mask,
        mask_sha256,
        input_sha256: image.source_sha256().to_owned(),
        width: image.width(),
        height: image.height(),
        pixel_count: image.pixel_count(),
        reachable_pixel_count: report.reachable_pixel_count(),
        unreachable_pixel_count: report.unreachable_pixel_count(),
        component_count: report.components().len(),
        column_group_count: column_groups.len(),
    })
}

fn retain_results(
    case: &mut Case,
    args: &ImageReachabilityArgs,
    artifacts: &AnalysisArtifacts,
) -> Result<(), Box<dyn Error>> {
    let receipt_node = add_receipt_node(case, args, artifacts)?;
    let mask_node = add_mask_node(case, args.node, receipt_node, artifacts)?;
    let analysis_node = add_analysis_node(case, args, receipt_node, mask_node, artifacts)?;
    add_result_edges(case, args.node, receipt_node, mask_node, analysis_node)
}

fn add_receipt_node(
    case: &mut Case,
    args: &ImageReachabilityArgs,
    artifacts: &AnalysisArtifacts,
) -> Result<u64, Box<dyn Error>> {
    Ok(case.add_bytes_node(
        "image_reachability_receipt",
        &artifacts.receipt,
        Vec::new(),
        json!({
            "input_node":args.node,
            "input_sha256":artifacts.input_sha256,
            "model":args.model.receipt_name(),
            "connectivity":args.connectivity.receipt_name(),
            "unreachable_pixel_count":artifacts.unreachable_pixel_count,
            "component_count":artifacts.component_count,
            "column_group_count":artifacts.column_group_count,
            "representation":"json_blob",
            "semantic_inference":"none"
        }),
    )?)
}

fn add_mask_node(
    case: &mut Case,
    input_node: u64,
    receipt_node: u64,
    artifacts: &AnalysisArtifacts,
) -> Result<u64, Box<dyn Error>> {
    Ok(case.add_bytes_node(
        "image_reachability_mask",
        &artifacts.mask,
        Vec::new(),
        json!({
            "input_node":input_node,
            "receipt_node":receipt_node,
            "width":artifacts.width,
            "height":artifacts.height,
            "format":"netpbm_p4",
            "media_type":"image/x-portable-bitmap",
            "black_pixel_meaning":"rgb_not_produced_by_selected_model",
            "length":artifacts.mask.len(),
            "sha256":artifacts.mask_sha256
        }),
    )?)
}

fn add_analysis_node(
    case: &mut Case,
    args: &ImageReachabilityArgs,
    receipt_node: u64,
    mask_node: u64,
    artifacts: &AnalysisArtifacts,
) -> Result<u64, Box<dyn Error>> {
    Ok(case.add_node(
        "image_reachability_analysis",
        None,
        Vec::new(),
        json!({
            "input_node":args.node,
            "receipt_node":receipt_node,
            "mask_node":mask_node,
            "input_sha256":artifacts.input_sha256,
            "width":artifacts.width,
            "height":artifacts.height,
            "pixel_count":artifacts.pixel_count,
            "model":args.model.receipt_name(),
            "connectivity":args.connectivity.receipt_name(),
            "reachable_pixel_count":artifacts.reachable_pixel_count,
            "unreachable_pixel_count":artifacts.unreachable_pixel_count,
            "component_count":artifacts.component_count,
            "minimum_blank_column_gap":args.minimum_blank_column_gap.get(),
            "column_group_count":artifacts.column_group_count,
            "classification":"rgb_values_outside_complete_model_output_set",
            "semantic_inference":"none"
        }),
    )?)
}

fn add_result_edges(
    case: &mut Case,
    input_node: u64,
    receipt_node: u64,
    mask_node: u64,
    analysis_node: u64,
) -> Result<(), Box<dyn Error>> {
    for (from, to, relation, reason) in [
        (
            input_node,
            receipt_node,
            "tested_by",
            "The receipt records complete model enumeration and exact classification of every decoded RGB pixel",
        ),
        (
            receipt_node,
            mask_node,
            "produced_mask",
            "Each black PBM pixel maps to one coordinate classified outside the selected model output set",
        ),
        (
            receipt_node,
            analysis_node,
            "describes",
            "The receipt contains exact coordinates, components, column groups, model parameters, and resource limits",
        ),
        (
            input_node,
            analysis_node,
            "classified_by_model",
            "The summary counts are deterministic results for the exact retained PNG bytes and named fixed-point model",
        ),
    ] {
        case.add_edge(Edge {
            from,
            to,
            relation: relation.to_owned(),
            status: EvidenceStatus::Observed,
            reason: reason.to_owned(),
        })?;
    }
    Ok(())
}
