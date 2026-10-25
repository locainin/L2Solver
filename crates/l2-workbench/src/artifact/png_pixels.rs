use core::fmt;
use std::io::Cursor;

/// Default ceiling for the encoded PNG byte stream
pub const MAX_PNG_PIXEL_INPUT_BYTES: usize = 16 * 1024 * 1024;
/// Default ceiling for the number of decoded pixels
pub const MAX_PNG_PIXELS: usize = 16 * 1024 * 1024;
/// Default ceiling for the canonical pixel buffer
pub const MAX_PNG_PIXEL_BYTES: usize = 64 * 1024 * 1024;
/// Default ceiling for temporary pixel buffers during normalization
pub const MAX_PNG_PIXEL_WORK_BYTES: usize = 128 * 1024 * 1024;
/// Default ceiling for allocations made inside the PNG decoder
pub const MAX_PNG_DECODER_BYTES: usize = 64 * 1024 * 1024;

/// Resource budgets for decoding one static PNG image
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PngPixelLimits {
    /// Largest encoded PNG accepted by the decoder
    pub max_input_bytes: usize,
    /// Largest width accepted from IHDR
    pub max_width: u32,
    /// Largest height accepted from IHDR
    pub max_height: u32,
    /// Largest number of decoded pixels
    pub max_pixels: usize,
    /// Largest retained canonical RGB or RGBA buffer
    pub max_pixel_bytes: usize,
    /// Largest combined pixel buffers while normalizing decoded data
    pub max_work_buffer_bytes: usize,
    /// Best-effort memory ceiling passed to the PNG decoder
    pub max_decoder_memory_bytes: usize,
}

impl Default for PngPixelLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: MAX_PNG_PIXEL_INPUT_BYTES,
            max_width: u32::MAX,
            max_height: u32::MAX,
            max_pixels: MAX_PNG_PIXELS,
            max_pixel_bytes: MAX_PNG_PIXEL_BYTES,
            max_work_buffer_bytes: MAX_PNG_PIXEL_WORK_BYTES,
            max_decoder_memory_bytes: MAX_PNG_DECODER_BYTES,
        }
    }
}

/// Byte layout retained for every decoded pixel
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CanonicalPixelLayout {
    /// Three consecutive bytes hold red, green, and blue
    Rgb8,
    /// Four consecutive bytes hold red, green, blue, and alpha
    Rgba8,
}

impl CanonicalPixelLayout {
    /// Number of bytes retained for one pixel
    #[must_use]
    pub const fn channels(self) -> usize {
        match self {
            Self::Rgb8 => 3,
            Self::Rgba8 => 4,
        }
    }
}

/// One decoded pixel with its color channels and optional alpha observation
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PngPixel {
    /// Red, green, and blue channels after PNG bit-depth normalization
    pub rgb: [u8; 3],
    /// Source alpha channel when the decoded image has one
    pub alpha: Option<u8>,
}

/// Decoded pixels bound to the exact encoded PNG source bytes
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PngPixelImage {
    source_sha256: String,
    width: u32,
    height: u32,
    source_color_type: png::ColorType,
    source_bit_depth: png::BitDepth,
    layout: CanonicalPixelLayout,
    pixels: Vec<u8>,
}

impl PngPixelImage {
    /// SHA-256 digest of the exact encoded source bytes
    #[must_use]
    pub fn source_sha256(&self) -> &str {
        &self.source_sha256
    }

    /// Source image width in pixels
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Source image height in pixels
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Color type declared by the source PNG
    #[must_use]
    pub const fn source_color_type(&self) -> png::ColorType {
        self.source_color_type
    }

    /// Stable source color-type name for evidence receipts
    #[must_use]
    pub const fn source_color_type_name(&self) -> &'static str {
        match self.source_color_type {
            png::ColorType::Grayscale => "grayscale",
            png::ColorType::Rgb => "rgb",
            png::ColorType::Indexed => "indexed",
            png::ColorType::GrayscaleAlpha => "grayscale_alpha",
            png::ColorType::Rgba => "rgba",
        }
    }

    /// Bit depth declared by the source PNG
    #[must_use]
    pub const fn source_bit_depth(&self) -> png::BitDepth {
        self.source_bit_depth
    }

    /// Source channel depth expressed as a bit count
    #[must_use]
    pub const fn source_bit_depth_bits(&self) -> u8 {
        match self.source_bit_depth {
            png::BitDepth::One => 1,
            png::BitDepth::Two => 2,
            png::BitDepth::Four => 4,
            png::BitDepth::Eight => 8,
            png::BitDepth::Sixteen => 16,
        }
    }

    /// Canonical byte layout used for decoded pixels
    #[must_use]
    pub const fn layout(&self) -> CanonicalPixelLayout {
        self.layout
    }

    /// Exact canonical pixel bytes in row-major order
    #[must_use]
    pub fn pixel_bytes(&self) -> &[u8] {
        &self.pixels
    }

    /// Number of decoded pixels
    #[must_use]
    pub const fn pixel_count(&self) -> usize {
        self.pixels.len() / self.layout.channels()
    }

    /// Read a pixel by its zero-based image coordinate
    #[must_use]
    pub fn pixel(&self, x: u32, y: u32) -> Option<PngPixel> {
        if x >= self.width || y >= self.height {
            return None;
        }

        // Checked arithmetic keeps coordinate conversion safe on narrow targets
        let pixel_index = usize::try_from(y)
            .ok()?
            .checked_mul(usize::try_from(self.width).ok()?)?
            .checked_add(usize::try_from(x).ok()?)?;
        let start = pixel_index.checked_mul(self.layout.channels())?;
        let end = start.checked_add(self.layout.channels())?;
        let channels = self.pixels.get(start..end)?;
        let rgb = [*channels.first()?, *channels.get(1)?, *channels.get(2)?];
        let alpha = match self.layout {
            CanonicalPixelLayout::Rgb8 => None,
            CanonicalPixelLayout::Rgba8 => Some(*channels.get(3)?),
        };
        Some(PngPixel { rgb, alpha })
    }
}

/// Invalid, malformed, unsupported, or over-budget PNG pixel decoding
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PngPixelDecodeError {
    /// One or more configured decoding limits were zero
    InvalidLimits,
    /// The encoded input exceeded its configured byte limit
    InputTooLarge { length: usize, maximum: usize },
    /// IHDR dimensions exceeded the configured width or height limit
    DimensionLimitExceeded {
        width: u32,
        height: u32,
        maximum_width: u32,
        maximum_height: u32,
    },
    /// The width and height product exceeded the configured pixel limit
    PixelLimitExceeded { pixels: usize, maximum: usize },
    /// A required pixel buffer exceeded its configured byte limit
    PixelBufferLimitExceeded { required: usize, maximum: usize },
    /// Temporary pixel buffers exceeded their configured byte limit
    WorkBufferLimitExceeded { required: usize, maximum: usize },
    /// The PNG decoder could not read or validate the source image
    DecodeFailed { message: String },
    /// Animated PNG data needs an explicit frame-selection policy
    AnimatedPngUnsupported,
    /// The decoder returned a color or bit-depth layout outside the normalizer
    UnsupportedDecodedLayout,
    /// An allocation could not be reserved within the configured budget
    AllocationFailed,
}

impl fmt::Display for PngPixelDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("PNG pixel limits must be positive"),
            Self::InputTooLarge { length, maximum } => write!(
                formatter,
                "PNG input has {length} bytes; maximum is {maximum}"
            ),
            Self::DimensionLimitExceeded {
                width,
                height,
                maximum_width,
                maximum_height,
            } => write!(
                formatter,
                "PNG dimensions {width}x{height} exceed maximum {maximum_width}x{maximum_height}"
            ),
            Self::PixelLimitExceeded { pixels, maximum } => {
                write!(formatter, "PNG has {pixels} pixels; maximum is {maximum}")
            }
            Self::PixelBufferLimitExceeded { required, maximum } => write!(
                formatter,
                "PNG pixel buffer requires {required} bytes; maximum is {maximum}"
            ),
            Self::WorkBufferLimitExceeded { required, maximum } => write!(
                formatter,
                "PNG pixel normalization requires {required} work bytes; maximum is {maximum}"
            ),
            Self::DecodeFailed { message } => write!(formatter, "PNG decoding failed: {message}"),
            Self::AnimatedPngUnsupported => {
                formatter.write_str("animated PNG requires an explicit frame-selection policy")
            }
            Self::UnsupportedDecodedLayout => {
                formatter.write_str("PNG decoder returned an unsupported pixel layout")
            }
            Self::AllocationFailed => formatter.write_str("PNG pixel buffer allocation failed"),
        }
    }
}

impl std::error::Error for PngPixelDecodeError {}

/// Decode one bounded static PNG into row-major canonical 8-bit RGB or RGBA
///
/// Grayscale samples are expanded to RGB, palette transparency becomes alpha,
/// and sixteen-bit channels retain their high byte. APNG is rejected because
/// selecting one frame without a caller policy would hide source behavior
///
/// # Errors
/// Returns an error for malformed data, unsupported animated content, failed
/// allocation, or any configured input, dimension, pixel, or buffer limit
pub fn decode_png_pixels(
    bytes: &[u8],
    limits: PngPixelLimits,
) -> Result<PngPixelImage, PngPixelDecodeError> {
    validate_limits(bytes, limits)?;

    let mut png_decoder = new_decoder(bytes, limits);
    let header = read_png_header(&mut png_decoder, limits)?;
    let (width, height) = (header.width, header.height);

    let mut reader =
        png_decoder
            .read_info()
            .map_err(|error| PngPixelDecodeError::DecodeFailed {
                message: error.to_string(),
            })?;

    let plan = output_plan(&reader, header.pixel_count, limits)?;
    let pixels = decode_frame(&mut reader, header, plan, limits)?;

    Ok(PngPixelImage {
        source_sha256: crate::sha256(bytes),
        width,
        height,
        source_color_type: header.color_type,
        source_bit_depth: header.bit_depth,
        layout: plan.layout,
        pixels,
    })
}

#[derive(Clone, Copy)]
struct PngHeader {
    width: u32,
    height: u32,
    color_type: png::ColorType,
    bit_depth: png::BitDepth,
    pixel_count: usize,
}

#[derive(Clone, Copy)]
struct PngOutputPlan {
    color_type: png::ColorType,
    layout: CanonicalPixelLayout,
    output_channels: usize,
    canonical_bytes: usize,
    decoder_buffer_bytes: usize,
}

fn new_decoder(bytes: &[u8], limits: PngPixelLimits) -> png::Decoder<Cursor<&[u8]>> {
    // Text and ICC metadata do not change channel observations
    let mut decoder = png::Decoder::new_with_limits(
        Cursor::new(bytes),
        png::Limits {
            bytes: limits.max_decoder_memory_bytes,
        },
    );
    decoder.set_ignore_text_chunk(true);
    decoder.set_ignore_iccp_chunk(true);
    decoder.set_transformations(png::Transformations::normalize_to_color8());
    decoder
}

fn read_png_header(
    decoder: &mut png::Decoder<Cursor<&[u8]>>,
    limits: PngPixelLimits,
) -> Result<PngHeader, PngPixelDecodeError> {
    let header = decoder
        .read_header_info()
        .map_err(|error| PngPixelDecodeError::DecodeFailed {
            message: error.to_string(),
        })?;
    if header.width == 0 || header.height == 0 {
        return Err(PngPixelDecodeError::DecodeFailed {
            message: "PNG dimensions must be positive".to_owned(),
        });
    }
    if header.width > limits.max_width || header.height > limits.max_height {
        return Err(PngPixelDecodeError::DimensionLimitExceeded {
            width: header.width,
            height: header.height,
            maximum_width: limits.max_width,
            maximum_height: limits.max_height,
        });
    }

    // Header limits run before decoder row buffers are allocated
    let pixel_count = usize::try_from(header.width)
        .ok()
        .and_then(|width| {
            usize::try_from(header.height)
                .ok()
                .and_then(|height| width.checked_mul(height))
        })
        .ok_or(PngPixelDecodeError::PixelLimitExceeded {
            pixels: usize::MAX,
            maximum: limits.max_pixels,
        })?;
    if pixel_count > limits.max_pixels {
        return Err(PngPixelDecodeError::PixelLimitExceeded {
            pixels: pixel_count,
            maximum: limits.max_pixels,
        });
    }

    Ok(PngHeader {
        width: header.width,
        height: header.height,
        color_type: header.color_type,
        bit_depth: header.bit_depth,
        pixel_count,
    })
}

fn output_plan<R: std::io::BufRead + std::io::Seek>(
    reader: &png::Reader<R>,
    pixel_count: usize,
    limits: PngPixelLimits,
) -> Result<PngOutputPlan, PngPixelDecodeError> {
    // APNG needs a caller-selected frame before its pixels can be reported
    if reader.info().animation_control.is_some() {
        return Err(PngPixelDecodeError::AnimatedPngUnsupported);
    }
    let (color_type, bit_depth) = reader.output_color_type();
    if bit_depth != png::BitDepth::Eight {
        return Err(PngPixelDecodeError::UnsupportedDecodedLayout);
    }
    let (layout, output_channels) = match color_type {
        png::ColorType::Grayscale => (CanonicalPixelLayout::Rgb8, 1_usize),
        png::ColorType::GrayscaleAlpha => (CanonicalPixelLayout::Rgba8, 2_usize),
        png::ColorType::Rgb => (CanonicalPixelLayout::Rgb8, 3_usize),
        png::ColorType::Rgba => (CanonicalPixelLayout::Rgba8, 4_usize),
        png::ColorType::Indexed => return Err(PngPixelDecodeError::UnsupportedDecodedLayout),
    };
    let canonical_bytes = pixel_count.checked_mul(layout.channels()).ok_or(
        PngPixelDecodeError::PixelBufferLimitExceeded {
            required: usize::MAX,
            maximum: limits.max_pixel_bytes,
        },
    )?;
    if canonical_bytes > limits.max_pixel_bytes {
        return Err(PngPixelDecodeError::PixelBufferLimitExceeded {
            required: canonical_bytes,
            maximum: limits.max_pixel_bytes,
        });
    }
    let decoder_buffer_bytes =
        reader
            .output_buffer_size()
            .ok_or(PngPixelDecodeError::PixelBufferLimitExceeded {
                required: usize::MAX,
                maximum: limits.max_pixel_bytes,
            })?;
    if decoder_buffer_bytes > limits.max_pixel_bytes {
        return Err(PngPixelDecodeError::PixelBufferLimitExceeded {
            required: decoder_buffer_bytes,
            maximum: limits.max_pixel_bytes,
        });
    }

    // Grayscale output needs a second buffer while channels are expanded
    let required_work_bytes = if output_channels < layout.channels() {
        decoder_buffer_bytes.checked_add(canonical_bytes).ok_or(
            PngPixelDecodeError::WorkBufferLimitExceeded {
                required: usize::MAX,
                maximum: limits.max_work_buffer_bytes,
            },
        )?
    } else {
        decoder_buffer_bytes
    };
    if required_work_bytes > limits.max_work_buffer_bytes {
        return Err(PngPixelDecodeError::WorkBufferLimitExceeded {
            required: required_work_bytes,
            maximum: limits.max_work_buffer_bytes,
        });
    }

    Ok(PngOutputPlan {
        color_type,
        layout,
        output_channels,
        canonical_bytes,
        decoder_buffer_bytes,
    })
}

fn decode_frame<R: std::io::BufRead + std::io::Seek>(
    reader: &mut png::Reader<R>,
    header: PngHeader,
    plan: PngOutputPlan,
    limits: PngPixelLimits,
) -> Result<Vec<u8>, PngPixelDecodeError> {
    // The frame buffer has its own allocation budget outside decoder internals
    let mut frame_pixels = Vec::new();
    frame_pixels
        .try_reserve_exact(plan.decoder_buffer_bytes)
        .map_err(|_| PngPixelDecodeError::AllocationFailed)?;
    if frame_pixels.capacity() > limits.max_pixel_bytes {
        return Err(PngPixelDecodeError::PixelBufferLimitExceeded {
            required: frame_pixels.capacity(),
            maximum: limits.max_pixel_bytes,
        });
    }
    if frame_pixels.capacity() > limits.max_work_buffer_bytes {
        return Err(PngPixelDecodeError::WorkBufferLimitExceeded {
            required: frame_pixels.capacity(),
            maximum: limits.max_work_buffer_bytes,
        });
    }
    frame_pixels.resize(plan.decoder_buffer_bytes, 0);
    let frame = reader.next_frame(&mut frame_pixels).map_err(|error| {
        PngPixelDecodeError::DecodeFailed {
            message: error.to_string(),
        }
    })?;
    if frame.width != header.width
        || frame.height != header.height
        || frame.color_type != plan.color_type
    {
        return Err(PngPixelDecodeError::UnsupportedDecodedLayout);
    }
    if frame.buffer_size() > frame_pixels.len() {
        return Err(PngPixelDecodeError::UnsupportedDecodedLayout);
    }
    frame_pixels.truncate(frame.buffer_size());

    // Expanded RGB data is retained directly while grayscale receives explicit channels
    match plan.color_type {
        png::ColorType::Rgb | png::ColorType::Rgba => {
            if frame_pixels.len() != plan.canonical_bytes {
                return Err(PngPixelDecodeError::UnsupportedDecodedLayout);
            }
            Ok(frame_pixels)
        }
        png::ColorType::Grayscale | png::ColorType::GrayscaleAlpha => expand_grayscale(
            &frame_pixels,
            plan.canonical_bytes,
            plan.output_channels,
            frame_pixels.capacity(),
            limits,
        ),
        png::ColorType::Indexed => Err(PngPixelDecodeError::UnsupportedDecodedLayout),
    }
}

fn expand_grayscale(
    source_pixels: &[u8],
    canonical_bytes: usize,
    source_channels: usize,
    source_capacity: usize,
    limits: PngPixelLimits,
) -> Result<Vec<u8>, PngPixelDecodeError> {
    let mut expanded = Vec::new();
    expanded
        .try_reserve_exact(canonical_bytes)
        .map_err(|_| PngPixelDecodeError::AllocationFailed)?;
    let actual_work = source_capacity.checked_add(expanded.capacity()).ok_or(
        PngPixelDecodeError::WorkBufferLimitExceeded {
            required: usize::MAX,
            maximum: limits.max_work_buffer_bytes,
        },
    )?;
    if actual_work > limits.max_work_buffer_bytes {
        return Err(PngPixelDecodeError::WorkBufferLimitExceeded {
            required: actual_work,
            maximum: limits.max_work_buffer_bytes,
        });
    }
    if expanded.capacity() > limits.max_pixel_bytes {
        return Err(PngPixelDecodeError::PixelBufferLimitExceeded {
            required: expanded.capacity(),
            maximum: limits.max_pixel_bytes,
        });
    }

    // Replicate luminance and retain the original alpha sample when present
    for source in source_pixels.chunks_exact(source_channels) {
        let luminance = *source
            .first()
            .ok_or(PngPixelDecodeError::UnsupportedDecodedLayout)?;
        expanded.extend_from_slice(&[luminance, luminance, luminance]);
        if source_channels == 2 {
            expanded.push(
                *source
                    .get(1)
                    .ok_or(PngPixelDecodeError::UnsupportedDecodedLayout)?,
            );
        }
    }
    if expanded.len() != canonical_bytes {
        return Err(PngPixelDecodeError::UnsupportedDecodedLayout);
    }
    Ok(expanded)
}

const fn validate_limits(bytes: &[u8], limits: PngPixelLimits) -> Result<(), PngPixelDecodeError> {
    if limits.max_input_bytes == 0
        || limits.max_width == 0
        || limits.max_height == 0
        || limits.max_pixels == 0
        || limits.max_pixel_bytes == 0
        || limits.max_work_buffer_bytes == 0
        || limits.max_decoder_memory_bytes == 0
    {
        return Err(PngPixelDecodeError::InvalidLimits);
    }
    if bytes.len() > limits.max_input_bytes {
        return Err(PngPixelDecodeError::InputTooLarge {
            length: bytes.len(),
            maximum: limits.max_input_bytes,
        });
    }
    Ok(())
}
