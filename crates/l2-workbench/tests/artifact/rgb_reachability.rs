use l2_workbench::artifact::{
    self, FixedPointYcbcrCoefficients, FixedPointYcbcrModel, FixedPointYcbcrModelError,
    PixelConnectivity, PixelReachabilityLimits, PngPixelLimits, ReachableRgbLimits, RgbColor,
    RgbReachabilityError,
};
use png::{BitDepth, ColorType};
use std::error::Error;

use super::image_support::encode_png;

#[test]
fn fixed_point_scale_rounding_clamp() -> Result<(), Box<dyn Error>> {
    let jpeg = FixedPointYcbcrModel::JPEG_BT601_FULL_RANGE;
    assert_eq!(jpeg.convert(128, 128, 128).channels(), [128, 128, 128]);
    assert_eq!(jpeg.convert(0, 0, 0).channels(), [0, 136, 0]);
    assert_eq!(jpeg.convert(255, 255, 255).channels(), [255, 121, 255]);

    let libjpeg = FixedPointYcbcrModel::LIBJPEG_BT601_FULL_RANGE;
    assert_eq!(libjpeg.convert(128, 128, 128).channels(), [128, 128, 128]);
    assert_eq!(
        libjpeg.coefficients(),
        FixedPointYcbcrCoefficients {
            y: 65_536,
            red_cr: 91_881,
            green_cb: -22_554,
            green_cr: -46_802,
            blue_cb: 116_130,
        }
    );
    assert_eq!(libjpeg.fractional_bits(), 16);
    assert_eq!(libjpeg.rounding_bias(), 32_768);

    let luma_only = FixedPointYcbcrModel::new(
        FixedPointYcbcrCoefficients {
            y: 1,
            red_cr: 0,
            green_cb: 0,
            green_cr: 0,
            blue_cb: 0,
        },
        128,
        0,
        0,
    )?;
    assert_eq!(luma_only.convert(73, 0, 255).channels(), [73, 73, 73]);
    assert!(matches!(
        FixedPointYcbcrModel::new(
            FixedPointYcbcrCoefficients {
                y: 1,
                red_cr: 0,
                green_cb: 0,
                green_cr: 0,
                blue_cb: 0,
            },
            128,
            32,
            0,
        ),
        Err(FixedPointYcbcrModelError::FractionalBitsTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn complete_model_generated_rgb_color() -> Result<(), Box<dyn Error>> {
    let model = FixedPointYcbcrModel::JPEG_BT601_FULL_RANGE;
    let set = artifact::ReachableRgbSet::enumerate(model, ReachableRgbLimits::default())?;

    for y in 0..=u8::MAX {
        for cb in 0..=u8::MAX {
            for cr in 0..=u8::MAX {
                assert!(set.contains(model.convert(y, cb, cr)));
            }
        }
    }
    assert!(set.unique_color_count() > 0);
    assert!(set.unique_color_count() <= 1 << 24);
    Ok(())
}

#[test]
fn reachability_per_connectivity_changes_components() -> Result<(), Box<dyn Error>> {
    let model = FixedPointYcbcrModel::JPEG_BT601_FULL_RANGE;
    let set = artifact::ReachableRgbSet::enumerate(model, ReachableRgbLimits::default())?;
    let unreachable = RgbColor::new(0, 0, 1);
    assert!(!set.contains(unreachable));
    let reachable = model.convert(100, 128, 128);

    let first = encode_rgb_image(
        3,
        2,
        &[
            unreachable,
            reachable,
            reachable,
            reachable,
            unreachable,
            reachable,
        ],
    )?;
    let moved = encode_rgb_image(
        3,
        2,
        &[
            reachable,
            unreachable,
            reachable,
            unreachable,
            reachable,
            reachable,
        ],
    )?;
    let first = artifact::decode_png_pixels(&first, PngPixelLimits::default())?;
    let moved = artifact::decode_png_pixels(&moved, PngPixelLimits::default())?;

    let four = artifact::analyze_rgb_reachability(
        &first,
        &set,
        PixelConnectivity::Four,
        PixelReachabilityLimits::default(),
    )?;
    assert_eq!(four.reachable_pixel_count(), 4);
    assert_eq!(four.unreachable_pixel_count(), 2);
    assert_eq!(four.components().len(), 2);
    assert!(
        four.unreachable_pixels()
            .contains(&artifact::PixelCoordinate { x: 0, y: 0 })
    );
    assert!(
        four.unreachable_pixels()
            .contains(&artifact::PixelCoordinate { x: 1, y: 1 })
    );

    let moved_eight = artifact::analyze_rgb_reachability(
        &moved,
        &set,
        PixelConnectivity::Eight,
        PixelReachabilityLimits::default(),
    )?;
    assert_eq!(moved_eight.reachable_pixel_count(), 4);
    assert_eq!(moved_eight.unreachable_pixel_count(), 2);
    assert_eq!(moved_eight.components().len(), 1);
    assert_eq!(moved_eight.unreachable_pixels().len(), 2);
    assert!(
        moved_eight
            .unreachable_pixels()
            .contains(&artifact::PixelCoordinate { x: 1, y: 0 })
    );
    assert!(
        moved_eight
            .unreachable_pixels()
            .contains(&artifact::PixelCoordinate { x: 0, y: 1 })
    );
    assert!(moved_eight.report_bytes() <= PixelReachabilityLimits::default().max_report_bytes);
    assert_eq!(moved_eight.source_sha256(), moved.source_sha256());
    assert_eq!(moved_eight.model(), model);
    Ok(())
}

#[test]
fn reachability_incomplete_enumeration_budget_exhaustion() -> Result<(), Box<dyn Error>> {
    let model = FixedPointYcbcrModel::JPEG_BT601_FULL_RANGE;
    assert!(matches!(
        artifact::ReachableRgbSet::enumerate(
            model,
            ReachableRgbLimits {
                max_conversion_samples: 1,
                ..ReachableRgbLimits::default()
            }
        ),
        Err(RgbReachabilityError::ConversionBudgetExceeded { .. })
    ));

    let set = artifact::ReachableRgbSet::enumerate(model, ReachableRgbLimits::default())?;
    let unreachable = RgbColor::new(0, 0, 1);
    assert!(!set.contains(unreachable));
    let png = encode_rgb_image(1, 1, &[unreachable])?;
    let image = artifact::decode_png_pixels(&png, PngPixelLimits::default())?;
    assert!(matches!(
        artifact::analyze_rgb_reachability(
            &image,
            &set,
            PixelConnectivity::Four,
            PixelReachabilityLimits {
                max_report_bytes: 1,
                ..PixelReachabilityLimits::default()
            }
        ),
        Err(RgbReachabilityError::ReportBudgetExceeded { .. })
    ));
    Ok(())
}

fn encode_rgb_image(
    width: u32,
    height: u32,
    colors: &[RgbColor],
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = Vec::with_capacity(colors.len().saturating_mul(3));
    for color in colors {
        bytes.extend_from_slice(&color.channels());
    }
    encode_png(
        width,
        height,
        ColorType::Rgb,
        BitDepth::Eight,
        &bytes,
        None,
        None,
    )
}
