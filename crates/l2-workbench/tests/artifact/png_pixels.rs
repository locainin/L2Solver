use l2_workbench::artifact::{self, CanonicalPixelLayout, PngPixelDecodeError, PngPixelLimits};
use png::{BitDepth, ColorType};
use std::error::Error;

use super::image_support::{encode_png, structural_png};

#[test]
fn png_pixels_grayscale_palette_sources() -> Result<(), Box<dyn Error>> {
    let grayscale = encode_png(
        2,
        1,
        ColorType::Grayscale,
        BitDepth::One,
        &[0b0100_0000],
        None,
        None,
    )?;
    let decoded = artifact::decode_png_pixels(&grayscale, PngPixelLimits::default())?;
    assert_eq!(decoded.layout(), CanonicalPixelLayout::Rgb8);
    assert_eq!(decoded.source_color_type(), ColorType::Grayscale);
    assert_eq!(decoded.source_bit_depth(), BitDepth::One);
    assert_eq!(decoded.source_color_type_name(), "grayscale");
    assert_eq!(decoded.source_bit_depth_bits(), 1);
    assert_eq!(decoded.pixel(0, 0).map(|pixel| pixel.rgb), Some([0, 0, 0]));
    assert_eq!(
        decoded.pixel(1, 0).map(|pixel| pixel.rgb),
        Some([255, 255, 255])
    );
    assert_eq!(decoded.source_sha256(), l2_workbench::sha256(&grayscale));
    assert_eq!((decoded.width(), decoded.height()), (2, 1));

    let palette = encode_png(
        2,
        1,
        ColorType::Indexed,
        BitDepth::Two,
        &[0b0001_1000],
        Some(&[10, 20, 30, 40, 50, 60]),
        Some(&[255, 0]),
    )?;
    let decoded = artifact::decode_png_pixels(&palette, PngPixelLimits::default())?;
    assert_eq!(decoded.layout(), CanonicalPixelLayout::Rgba8);
    assert_eq!(decoded.source_color_type(), ColorType::Indexed);
    assert_eq!(decoded.source_bit_depth(), BitDepth::Two);
    assert_eq!(
        decoded.pixel(0, 0).map(|pixel| (pixel.rgb, pixel.alpha)),
        Some(([10, 20, 30], Some(255)))
    );
    assert_eq!(
        decoded.pixel(1, 0).map(|pixel| (pixel.rgb, pixel.alpha)),
        Some(([40, 50, 60], Some(0)))
    );
    Ok(())
}

#[test]
fn png_pixels_bit_alpha_sources() -> Result<(), Box<dyn Error>> {
    let sixteen_bit = encode_png(
        1,
        1,
        ColorType::Rgb,
        BitDepth::Sixteen,
        &[0x12, 0x34, 0xab, 0xcd, 0xfe, 0xdc],
        None,
        None,
    )?;
    let decoded = artifact::decode_png_pixels(&sixteen_bit, PngPixelLimits::default())?;
    assert_eq!(
        decoded.pixel(0, 0).map(|pixel| pixel.rgb),
        Some([0x12, 0xab, 0xfe])
    );

    let gray_alpha = encode_png(
        1,
        1,
        ColorType::GrayscaleAlpha,
        BitDepth::Eight,
        &[42, 17],
        None,
        None,
    )?;
    let decoded = artifact::decode_png_pixels(&gray_alpha, PngPixelLimits::default())?;
    assert_eq!(decoded.layout(), CanonicalPixelLayout::Rgba8);
    assert_eq!(
        decoded.pixel(0, 0).map(|pixel| (pixel.rgb, pixel.alpha)),
        Some(([42, 42, 42], Some(17)))
    );

    let rgba = encode_png(
        1,
        1,
        ColorType::Rgba,
        BitDepth::Eight,
        &[1, 2, 3, 4],
        None,
        None,
    )?;
    let decoded = artifact::decode_png_pixels(&rgba, PngPixelLimits::default())?;
    assert_eq!(decoded.layout(), CanonicalPixelLayout::Rgba8);
    assert_eq!(
        decoded.pixel(0, 0).map(|pixel| (pixel.rgb, pixel.alpha)),
        Some(([1, 2, 3], Some(4)))
    );
    Ok(())
}

#[test]
fn png_pixels_pixel_byte_budgets() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        artifact::decode_png_pixels(b"not a png", PngPixelLimits::default()),
        Err(PngPixelDecodeError::DecodeFailed { .. })
    ));

    let png = encode_png(
        2,
        1,
        ColorType::Rgb,
        BitDepth::Eight,
        &[0, 0, 0, 1, 1, 1],
        None,
        None,
    )?;
    let width_budget = PngPixelLimits {
        max_width: 1,
        ..PngPixelLimits::default()
    };
    assert!(matches!(
        artifact::decode_png_pixels(&png, width_budget),
        Err(PngPixelDecodeError::DimensionLimitExceeded { .. })
    ));

    let pixel_budget = PngPixelLimits {
        max_pixels: 1,
        ..PngPixelLimits::default()
    };
    assert!(matches!(
        artifact::decode_png_pixels(&png, pixel_budget),
        Err(PngPixelDecodeError::PixelLimitExceeded { .. })
    ));

    let input_budget = PngPixelLimits {
        max_input_bytes: png.len() - 1,
        ..PngPixelLimits::default()
    };
    assert!(matches!(
        artifact::decode_png_pixels(&png, input_budget),
        Err(PngPixelDecodeError::InputTooLarge { .. })
    ));

    let decoded_byte_budget = PngPixelLimits {
        max_pixel_bytes: 5,
        ..PngPixelLimits::default()
    };
    assert!(matches!(
        artifact::decode_png_pixels(&png, decoded_byte_budget),
        Err(PngPixelDecodeError::PixelBufferLimitExceeded { .. })
    ));

    let grayscale = encode_png(
        2,
        1,
        ColorType::Grayscale,
        BitDepth::Eight,
        &[10, 20],
        None,
        None,
    )?;
    let work_budget = PngPixelLimits {
        max_work_buffer_bytes: 7,
        ..PngPixelLimits::default()
    };
    assert!(matches!(
        artifact::decode_png_pixels(&grayscale, work_budget),
        Err(PngPixelDecodeError::WorkBufferLimitExceeded { .. })
    ));

    let invalid_limits = PngPixelLimits {
        max_pixels: 0,
        ..PngPixelLimits::default()
    };
    assert!(matches!(
        artifact::decode_png_pixels(&png, invalid_limits),
        Err(PngPixelDecodeError::InvalidLimits)
    ));
    Ok(())
}

#[test]
fn png_pixels_without_image_data() -> Result<(), Box<dyn Error>> {
    let no_image_data = structural_png(&[])?;
    assert!(matches!(
        artifact::decode_png_pixels(&no_image_data, PngPixelLimits::default()),
        Err(PngPixelDecodeError::DecodeFailed { .. })
    ));

    let invalid_compressed_data = [0_u8, 1, 2];
    let invalid_zlib = structural_png(&[(*b"IDAT", invalid_compressed_data.as_slice())])?;
    assert!(matches!(
        artifact::decode_png_pixels(&invalid_zlib, PngPixelLimits::default()),
        Err(PngPixelDecodeError::DecodeFailed { .. })
    ));
    Ok(())
}
