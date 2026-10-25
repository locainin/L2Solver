//! Compact exact JSON receipt for RGB reachability analysis

use super::columns::ColumnGroup;
use crate::{arguments::ImageReachabilityArgs, output::BoundedWriter};
use l2_workbench::artifact::{
    CanonicalPixelLayout, PixelComponent, PixelCoordinate, PngPixelImage, ReachableRgbSet,
    RgbReachabilityReport,
};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use std::{error::Error, io};

#[derive(Clone, Copy, Serialize)]
pub(super) struct MaskDescriptor<'a> {
    pub(super) format: &'static str,
    pub(super) black_pixel_meaning: &'static str,
    pub(super) length: usize,
    pub(super) sha256: &'a str,
}

pub(super) struct ReceiptContext<'a> {
    pub(super) input_node: u64,
    pub(super) input_blob: &'a str,
    pub(super) input_length: usize,
    pub(super) args: &'a ImageReachabilityArgs,
    pub(super) image: &'a PngPixelImage,
    pub(super) reachable: &'a ReachableRgbSet,
    pub(super) report: &'a RgbReachabilityReport,
    pub(super) column_groups: &'a [ColumnGroup],
    pub(super) mask: MaskDescriptor<'a>,
}

#[derive(Serialize)]
struct Receipt<'a> {
    schema_version: u32,
    input: Input<'a>,
    image: Image<'a>,
    model: Model,
    limits: Limits,
    enumeration: Enumeration,
    analysis: Analysis<'a>,
    mask: MaskDescriptor<'a>,
    interpretation: &'static str,
    semantic_inference: &'static str,
}

#[derive(Serialize)]
struct Input<'a> {
    node: u64,
    blob: &'a str,
    length: usize,
    sha256: &'a str,
}

#[derive(Serialize)]
struct Image<'a> {
    width: u32,
    height: u32,
    pixel_count: usize,
    source_color_type: &'a str,
    source_bit_depth_bits: u8,
    canonical_layout: &'static str,
    alpha_handling: &'static str,
}

#[derive(Serialize)]
struct Model {
    name: &'static str,
    coefficients: ModelCoefficients,
    chroma_offset: u8,
    fractional_bits: u8,
    rounding_bias: i32,
    signed_shift_semantics: &'static str,
}

#[derive(Serialize)]
struct ModelCoefficients {
    y: i32,
    red_cr: i32,
    green_cb: i32,
    green_cr: i32,
    blue_cb: i32,
}

#[derive(Serialize)]
struct Limits {
    png: PngLimits,
    enumeration: EnumerationLimits,
    analysis: AnalysisLimits,
    column_grouping: ColumnGroupingLimits,
    receipt: ReceiptLimits,
    mask: MaskLimits,
}

#[derive(Serialize)]
struct PngLimits {
    #[serde(rename = "max_input_bytes")]
    input_bytes: usize,
    #[serde(rename = "max_width")]
    width: u32,
    #[serde(rename = "max_height")]
    height: u32,
    #[serde(rename = "max_pixels")]
    pixels: usize,
    #[serde(rename = "max_pixel_bytes")]
    pixel_bytes: usize,
    #[serde(rename = "max_work_buffer_bytes")]
    work_buffer_bytes: usize,
    #[serde(rename = "max_decoder_memory_bytes")]
    decoder_memory_bytes: usize,
}

#[derive(Serialize)]
struct EnumerationLimits {
    max_conversion_samples: u64,
    max_set_bytes: usize,
}

#[derive(Serialize)]
struct AnalysisLimits {
    #[serde(rename = "max_pixels")]
    pixels: usize,
    #[serde(rename = "max_work_bytes")]
    work_bytes: usize,
    #[serde(rename = "max_report_bytes")]
    report_bytes: usize,
}

#[derive(Serialize)]
struct ColumnGroupingLimits {
    minimum_blank_column_gap: u32,
    max_work_bytes: usize,
    max_report_bytes: usize,
}

#[derive(Serialize)]
struct ReceiptLimits {
    max_bytes: usize,
}

#[derive(Serialize)]
struct MaskLimits {
    max_bytes: usize,
}

#[derive(Serialize)]
struct Enumeration {
    conversion_samples_tested: u64,
    unique_reachable_rgb_count: usize,
    membership_set_bytes: usize,
    complete_domain: bool,
}

#[derive(Serialize)]
struct Analysis<'a> {
    connectivity: &'static str,
    reachable_pixel_count: usize,
    unreachable_pixel_count: usize,
    component_count: usize,
    minimum_blank_column_gap: u32,
    column_group_count: usize,
    unreachable_coordinates: CoordinateList<'a>,
    components: ComponentList<'a>,
    column_groups: &'a [ColumnGroup],
}

struct CoordinateList<'a>(&'a [PixelCoordinate]);

impl Serialize for CoordinateList<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for coordinate in self.0 {
            sequence.serialize_element(&[coordinate.x, coordinate.y])?;
        }
        sequence.end()
    }
}

struct ComponentList<'a>(&'a [PixelComponent]);

impl Serialize for ComponentList<'_> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for component in self.0 {
            sequence.serialize_element(&Component {
                pixel_start: component.pixel_start,
                pixel_count: component.pixel_count,
                bounds: Bounds {
                    min_x: component.bounds.min_x,
                    min_y: component.bounds.min_y,
                    max_x: component.bounds.max_x,
                    max_y: component.bounds.max_y,
                },
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct Component {
    pixel_start: usize,
    pixel_count: usize,
    bounds: Bounds,
}

#[derive(Serialize)]
struct Bounds {
    min_x: u32,
    min_y: u32,
    max_x: u32,
    max_y: u32,
}

pub(super) fn encode(context: &ReceiptContext<'_>) -> Result<Vec<u8>, Box<dyn Error>> {
    let receipt = make_receipt(context);
    let maximum = context.args.max_receipt_bytes.get();

    // Count before allocation so a caller budget cannot be crossed by vector growth
    let mut counter = BoundedWriter::named(io::sink(), maximum, "image reachability receipt");
    serde_json::to_writer(&mut counter, &receipt)?;
    let encoded_length = counter.written();

    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(encoded_length)
        .map_err(|_| "could not allocate the image reachability receipt")?;
    if bytes.capacity() > maximum {
        return Err(format!(
            "image reachability receipt allocated {} bytes; maximum is {maximum}",
            bytes.capacity()
        )
        .into());
    }
    serde_json::to_writer(&mut bytes, &receipt)?;
    if bytes.len() != encoded_length {
        return Err("image reachability receipt changed between serialization passes".into());
    }
    Ok(bytes)
}

fn make_receipt<'a>(context: &'a ReceiptContext<'a>) -> Receipt<'a> {
    let args = context.args;
    Receipt {
        schema_version: 1,
        input: Input {
            node: context.input_node,
            blob: context.input_blob,
            length: context.input_length,
            sha256: context.image.source_sha256(),
        },
        image: Image {
            width: context.image.width(),
            height: context.image.height(),
            pixel_count: context.image.pixel_count(),
            source_color_type: context.image.source_color_type_name(),
            source_bit_depth_bits: context.image.source_bit_depth_bits(),
            canonical_layout: match context.image.layout() {
                CanonicalPixelLayout::Rgb8 => "rgb8",
                CanonicalPixelLayout::Rgba8 => "rgba8",
            },
            alpha_handling: "ignored_for_rgb_membership",
        },
        model: model_receipt(args),
        limits: limits_receipt(args),
        enumeration: Enumeration {
            conversion_samples_tested: l2_workbench::artifact::TOTAL_YCBCR_INPUTS,
            unique_reachable_rgb_count: context.reachable.unique_color_count(),
            membership_set_bytes: context.reachable.storage_bytes(),
            complete_domain: true,
        },
        analysis: analysis_receipt(args, context.report, context.column_groups),
        mask: context.mask,
        interpretation: "complete_fixed_point_rgb_membership_test",
        semantic_inference: "none",
    }
}

const fn model_receipt(args: &ImageReachabilityArgs) -> Model {
    let model = args.model.model();
    let coefficients = model.coefficients();
    Model {
        name: args.model.receipt_name(),
        coefficients: ModelCoefficients {
            y: coefficients.y,
            red_cr: coefficients.red_cr,
            green_cb: coefficients.green_cb,
            green_cr: coefficients.green_cr,
            blue_cb: coefficients.blue_cb,
        },
        chroma_offset: model.chroma_offset(),
        fractional_bits: model.fractional_bits(),
        rounding_bias: model.rounding_bias(),
        signed_shift_semantics: "arithmetic_right_shift_before_u8_clamp",
    }
}

const fn limits_receipt(args: &ImageReachabilityArgs) -> Limits {
    let png = args.png_limits();
    let enumeration = args.enumeration_limits();
    let analysis = args.analysis_limits();
    Limits {
        png: PngLimits {
            input_bytes: png.max_input_bytes,
            width: png.max_width,
            height: png.max_height,
            pixels: png.max_pixels,
            pixel_bytes: png.max_pixel_bytes,
            work_buffer_bytes: png.max_work_buffer_bytes,
            decoder_memory_bytes: png.max_decoder_memory_bytes,
        },
        enumeration: EnumerationLimits {
            max_conversion_samples: enumeration.max_conversion_samples,
            max_set_bytes: enumeration.max_set_bytes,
        },
        analysis: AnalysisLimits {
            pixels: analysis.max_pixels,
            work_bytes: analysis.max_work_bytes,
            report_bytes: analysis.max_report_bytes,
        },
        column_grouping: ColumnGroupingLimits {
            minimum_blank_column_gap: args.minimum_blank_column_gap.get(),
            max_work_bytes: analysis.max_work_bytes,
            max_report_bytes: analysis.max_report_bytes,
        },
        receipt: ReceiptLimits {
            max_bytes: args.max_receipt_bytes.get(),
        },
        mask: MaskLimits {
            max_bytes: args.max_mask_bytes.get(),
        },
    }
}

fn analysis_receipt<'a>(
    args: &ImageReachabilityArgs,
    report: &'a RgbReachabilityReport,
    column_groups: &'a [ColumnGroup],
) -> Analysis<'a> {
    Analysis {
        connectivity: args.connectivity.receipt_name(),
        reachable_pixel_count: report.reachable_pixel_count(),
        unreachable_pixel_count: report.unreachable_pixel_count(),
        component_count: report.components().len(),
        minimum_blank_column_gap: args.minimum_blank_column_gap.get(),
        column_group_count: column_groups.len(),
        unreachable_coordinates: CoordinateList(report.unreachable_pixels()),
        components: ComponentList(report.components()),
        column_groups,
    }
}
