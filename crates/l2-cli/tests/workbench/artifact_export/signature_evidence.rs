use std::{error::Error, path::Path};

use l2_workbench::evidence::{Case, Edge, EvidenceStatus};
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn signature_extension_requires_the_canonical_source_and_fields() -> TestResult {
    let mut bytes = Vec::new();
    let mut encoder = png::Encoder::new(&mut bytes, 1, 1);
    encoder.set_color(png::ColorType::Rgb);
    encoder.set_depth(png::BitDepth::Eight);
    encoder.write_header()?.write_image_data(&[1, 2, 3])?;

    for change in ["none", "digest", "blob", "coordinates", "range", "pattern"] {
        let mut case = Case::new();
        let input = case.add_bytes_node("record_object", &bytes, Vec::new(), json!({}))?;
        let blob = case
            .node(input)
            .and_then(|node| node.blob.clone())
            .ok_or("record blob is missing")?;
        let report = l2_workbench::artifact::scan_file_signatures(&bytes);
        let signature = report
            .matches
            .iter()
            .find(|item| item.extensions.contains(&"png"))
            .ok_or("PNG signature is missing")?;
        let mut details = serde_json::to_value(signature)?;
        let object = details
            .as_object_mut()
            .ok_or("signature is not an object")?;
        object.insert("input_node".to_owned(), json!(input));
        object.insert("input_blob".to_owned(), json!(blob));
        object.insert("input_sha256".to_owned(), json!(report.source_sha256));
        object.insert(
            "coordinate_base".to_owned(),
            json!("zero_based_from_byte_0_of_input_blob"),
        );
        match change {
            "digest" => {
                object.insert("input_sha256".to_owned(), json!("0".repeat(64)));
            }
            "blob" => {
                object.insert("input_blob".to_owned(), json!("sha256:other"));
            }
            "coordinates" => {
                object.insert(
                    "coordinate_base".to_owned(),
                    json!("another_coordinate_base"),
                );
            }
            "range" => {
                object
                    .get_mut("range")
                    .and_then(Value::as_object_mut)
                    .ok_or("signature range is not an object")?
                    .insert("extra".to_owned(), json!(true));
            }
            "pattern" => {
                object.insert("pattern_hex".to_owned(), json!("incorrect"));
            }
            "none" => {}
            _ => return Err("unexpected test case".into()),
        }
        let evidence = case.add_node("file_signature_match", Some(&blob), Vec::new(), details)?;
        case.add_edge(Edge {
            from: input,
            to: evidence,
            relation: "contains_signature".to_owned(),
            status: EvidenceStatus::Observed,
            reason: "Signature bytes were observed in the input object".to_owned(),
        })?;

        let selected = super::super::select_artifacts(&case, None)?;
        let artifact = selected.first().ok_or("record was not selected")?;
        let provenance = artifact.provenance().first().ok_or("missing provenance")?;
        let extension = Path::new(artifact.file_name())
            .extension()
            .and_then(std::ffi::OsStr::to_str);
        if change == "none" {
            assert_eq!(extension, Some("png"));
            assert_eq!(provenance.extension_evidence_node, Some(evidence));
        } else {
            assert_eq!(extension, Some("bin"), "change: {change}");
            assert_eq!(provenance.extension_evidence_node, None, "change: {change}");
        }
    }
    Ok(())
}
