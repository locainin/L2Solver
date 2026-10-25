use super::support::run;
use l2_workbench::evidence::Case;
use png::{BitDepth, ColorType, Encoder};
use serde_json::Value;
use std::error::Error;

#[test]
fn image_reachability_pixels_components_relationships() -> Result<(), Box<dyn Error>> {
    let png = encode_rgb_png(
        5,
        2,
        &[
            0, 0, 1, // Outside the named fixed-point conversion image
            128, 128, 128, 128, 128, 128, 128, 128, 128, 0, 0,
            1, // A two-column blank gap separates this group
            128, 128, 128, 0, 0, 1, // Diagonally connected to the first pixel
            128, 128, 128, 128, 128, 128, 128, 128, 128,
        ],
    )?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_png", &png, Vec::new(), serde_json::json!({}))?;

    let output = run(
        &[
            "image-reachability",
            "-",
            "--node",
            &input.to_string(),
            "--connectivity",
            "eight",
            "--minimum-blank-column-gap",
            "2",
        ],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let receipt_node = result
        .nodes()
        .iter()
        .find(|node| node.kind == "image_reachability_receipt")
        .ok_or("missing image reachability receipt")?;
    let receipt_blob = receipt_node
        .blob
        .as_deref()
        .and_then(|blob| result.blobs().iter().find(|candidate| candidate.id == blob))
        .ok_or("missing image reachability receipt bytes")?;
    let receipt: Value = serde_json::from_slice(&receipt_blob.bytes)?;
    assert_image_receipt(&receipt, input);
    assert_image_graph(&result, input, receipt_node.id)?;
    Ok(())
}

fn assert_image_receipt(receipt: &Value, input: u64) {
    assert_eq!(
        receipt.pointer("/input/node"),
        Some(&serde_json::json!(input))
    );
    assert_eq!(receipt.pointer("/image/width"), Some(&serde_json::json!(5)));
    assert_eq!(
        receipt.pointer("/image/height"),
        Some(&serde_json::json!(2))
    );
    assert_eq!(
        receipt.pointer("/model/name"),
        Some(&Value::String("libjpeg_bt601_full_range".to_owned()))
    );
    assert_eq!(
        receipt.pointer("/model/coefficients/red_cr"),
        Some(&serde_json::json!(91_881))
    );
    assert_eq!(
        receipt.pointer("/model/coefficients/green_cb"),
        Some(&serde_json::json!(-22_554))
    );
    assert_eq!(
        receipt.pointer("/analysis/connectivity"),
        Some(&Value::String("eight".to_owned()))
    );
    assert_eq!(
        receipt.pointer("/analysis/reachable_pixel_count"),
        Some(&serde_json::json!(7))
    );
    assert_eq!(
        receipt.pointer("/analysis/unreachable_pixel_count"),
        Some(&serde_json::json!(3))
    );
    assert_eq!(
        receipt.pointer("/analysis/unreachable_coordinates"),
        Some(&serde_json::json!([[0, 0], [1, 1], [4, 0]]))
    );
    assert_eq!(
        receipt.pointer("/analysis/components/0"),
        Some(&serde_json::json!({
            "pixel_start":0,
            "pixel_count":2,
            "bounds":{"min_x":0,"min_y":0,"max_x":1,"max_y":1}
        }))
    );
    assert_eq!(
        receipt.pointer("/analysis/column_groups"),
        Some(&serde_json::json!([
            {
                "start_x":0,
                "end_x_exclusive":2,
                "occupied_column_count":2,
                "unreachable_pixel_count":2,
                "min_y":0,
                "max_y":1
            },
            {
                "start_x":4,
                "end_x_exclusive":5,
                "occupied_column_count":1,
                "unreachable_pixel_count":1,
                "min_y":0,
                "max_y":0
            }
        ]))
    );
    assert_eq!(
        receipt.pointer("/interpretation"),
        Some(&Value::String(
            "complete_fixed_point_rgb_membership_test".to_owned()
        ))
    );
}

fn assert_image_graph(case: &Case, input: u64, receipt_node: u64) -> Result<(), Box<dyn Error>> {
    let analysis = case
        .nodes()
        .iter()
        .find(|node| node.kind == "image_reachability_analysis")
        .ok_or("missing image reachability analysis")?;
    assert_eq!(
        analysis.details.get("unreachable_pixel_count"),
        Some(&serde_json::json!(3))
    );
    assert!(case.edges().iter().any(|edge| {
        edge.from == input && edge.to == receipt_node && edge.relation == "tested_by"
    }));
    assert!(case.edges().iter().any(|edge| {
        edge.from == receipt_node && edge.to == analysis.id && edge.relation == "describes"
    }));
    let mask = case
        .nodes()
        .iter()
        .find(|node| node.kind == "image_reachability_mask")
        .ok_or("missing image reachability mask")?;
    let mask_bytes = mask
        .blob
        .as_deref()
        .and_then(|blob| case.blobs().iter().find(|candidate| candidate.id == blob))
        .ok_or("missing image reachability mask bytes")?;
    assert_eq!(mask_bytes.bytes, b"P4\n5 2\n\x88\x40");
    assert!(case.edges().iter().any(|edge| {
        edge.from == receipt_node && edge.to == mask.id && edge.relation == "produced_mask"
    }));
    assert!(
        case.limitations().iter().any(|limitation| {
            limitation.contains("does not establish hidden data, text, intent")
        })
    );
    Ok(())
}

#[test]
fn image_reachability_model_enumeration_budget() -> Result<(), Box<dyn Error>> {
    let png = encode_rgb_png(1, 1, &[128, 128, 128])?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_png", &png, Vec::new(), serde_json::json!({}))?;

    let output = run(
        &[
            "image-reachability",
            "-",
            "--node",
            &input.to_string(),
            "--max-conversion-samples",
            "1",
        ],
        &case.to_json()?,
    )?;

    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("conversion model requires 16777216 samples; maximum is 1")
    );
    Ok(())
}

#[test]
fn image_reachability_mask_without_inventing() -> Result<(), Box<dyn Error>> {
    let png = encode_rgb_png(1, 1, &[128, 128, 128])?;
    let mut case = Case::new();
    let input = case.add_bytes_node("candidate_png", &png, Vec::new(), serde_json::json!({}))?;

    let output = run(
        &["image-reachability", "-", "--node", &input.to_string()],
        &case.to_json()?,
    )?;

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result = Case::from_json(&output.stdout)?;
    let analysis = result
        .nodes()
        .iter()
        .find(|node| node.kind == "image_reachability_analysis")
        .ok_or("missing image reachability analysis")?;
    assert_eq!(
        analysis.details.get("unreachable_pixel_count"),
        Some(&serde_json::json!(0))
    );
    assert_eq!(
        analysis.details.get("component_count"),
        Some(&serde_json::json!(0))
    );
    assert_eq!(
        analysis.details.get("column_group_count"),
        Some(&serde_json::json!(0))
    );
    let mask = result
        .nodes()
        .iter()
        .find(|node| node.kind == "image_reachability_mask")
        .and_then(|node| node.blob.as_deref())
        .and_then(|blob| result.blobs().iter().find(|candidate| candidate.id == blob))
        .ok_or("missing image reachability mask bytes")?;
    assert_eq!(mask.bytes, b"P4\n1 1\n\0");
    Ok(())
}

fn encode_rgb_png(width: u32, height: u32, pixels: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::new();
    {
        let mut encoder = Encoder::new(&mut bytes, width, height);
        encoder.set_color(ColorType::Rgb);
        encoder.set_depth(BitDepth::Eight);
        let mut writer = encoder.write_header()?;
        writer.write_image_data(pixels)?;
        writer.finish()?;
    }
    Ok(bytes)
}
