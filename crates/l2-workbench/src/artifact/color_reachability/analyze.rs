use super::{FixedPointYcbcrModel, ReachableRgbSet, RgbColor};
use crate::artifact::PngPixelImage;
use core::fmt;
use std::mem::size_of;

/// Default ceiling for exact pixel coordinates and component metadata
pub const MAX_PIXEL_REACHABILITY_REPORT_BYTES: usize = 64 * 1024 * 1024;
/// Default ceiling for the work bitmap and active flood-fill stack
pub const MAX_PIXEL_REACHABILITY_WORK_BYTES: usize =
    super::TOTAL_RGB_COLORS * size_of::<usize>() + super::TOTAL_RGB_COLORS.div_ceil(8);

/// Resource budgets for pixel classification and connected-component analysis
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelReachabilityLimits {
    /// Largest decoded image accepted by the analyzer
    pub max_pixels: usize,
    /// Largest work bitmap and active flood-fill stack
    pub max_work_bytes: usize,
    /// Largest retained coordinates and component report
    pub max_report_bytes: usize,
}

impl Default for PixelReachabilityLimits {
    fn default() -> Self {
        Self {
            max_pixels: super::TOTAL_RGB_COLORS,
            max_work_bytes: MAX_PIXEL_REACHABILITY_WORK_BYTES,
            max_report_bytes: MAX_PIXEL_REACHABILITY_REPORT_BYTES,
        }
    }
}

/// Pixel adjacency rule used when counting unreachable color components
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PixelConnectivity {
    /// Pixels connect through shared edges
    Four,
    /// Pixels connect through shared edges or corners
    Eight,
}

/// Exact unsigned coordinate in a decoded image
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PixelCoordinate {
    /// Zero-based horizontal coordinate
    pub x: u32,
    /// Zero-based vertical coordinate
    pub y: u32,
}

/// Inclusive bounds around one connected component
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelBounds {
    /// Smallest horizontal coordinate in the component
    pub min_x: u32,
    /// Smallest vertical coordinate in the component
    pub min_y: u32,
    /// Largest horizontal coordinate in the component
    pub max_x: u32,
    /// Largest vertical coordinate in the component
    pub max_y: u32,
}

/// One component's range inside the report's coordinate array
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PixelComponent {
    /// Start offset into `RgbReachabilityReport::unreachable_pixels`
    pub pixel_start: usize,
    /// Number of coordinates in this component
    pub pixel_count: usize,
    /// Inclusive coordinate bounds for this component
    pub bounds: PixelBounds,
}

/// Source-bound record of RGB colors outside one complete conversion model
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RgbReachabilityReport {
    source_sha256: String,
    width: u32,
    height: u32,
    model: FixedPointYcbcrModel,
    connectivity: PixelConnectivity,
    reachable_pixel_count: usize,
    unreachable_pixels: Vec<PixelCoordinate>,
    components: Vec<PixelComponent>,
}

impl RgbReachabilityReport {
    /// SHA-256 digest of the exact encoded PNG source
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

    /// Exact fixed-point model applied to every RGB sample
    #[must_use]
    pub const fn model(&self) -> FixedPointYcbcrModel {
        self.model
    }

    /// Connectivity rule used for the component report
    #[must_use]
    pub const fn connectivity(&self) -> PixelConnectivity {
        self.connectivity
    }

    /// Number of pixels whose RGB value belongs to the enumerated set
    #[must_use]
    pub const fn reachable_pixel_count(&self) -> usize {
        self.reachable_pixel_count
    }

    /// Number of pixels whose RGB value is outside the enumerated set
    #[must_use]
    pub const fn unreachable_pixel_count(&self) -> usize {
        self.unreachable_pixels.len()
    }

    /// Exact coordinates, grouped into consecutive component ranges
    #[must_use]
    pub fn unreachable_pixels(&self) -> &[PixelCoordinate] {
        &self.unreachable_pixels
    }

    /// Connected components in the same order as their coordinate ranges
    #[must_use]
    pub fn components(&self) -> &[PixelComponent] {
        &self.components
    }

    /// Coordinates belonging to one component descriptor
    #[must_use]
    pub fn component_pixels(&self, component: &PixelComponent) -> Option<&[PixelCoordinate]> {
        let end = component.pixel_start.checked_add(component.pixel_count)?;
        self.unreachable_pixels.get(component.pixel_start..end)
    }

    /// Retained report bytes measured from the actual vector capacities
    #[must_use]
    pub const fn report_bytes(&self) -> usize {
        size_of::<Self>()
            .saturating_add(self.source_sha256.capacity())
            .saturating_add(
                self.unreachable_pixels
                    .capacity()
                    .saturating_mul(size_of::<PixelCoordinate>()),
            )
            .saturating_add(
                self.components
                    .capacity()
                    .saturating_mul(size_of::<PixelComponent>()),
            )
    }
}

/// Invalid, inconsistent, or over-budget RGB reachability analysis
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RgbReachabilityError {
    /// One or more configured analysis budgets were zero
    InvalidLimits,
    /// The model conversion count exceeded the configured complete-enumeration budget
    ConversionBudgetExceeded { required: u64, maximum: u64 },
    /// The complete RGB membership bitmap exceeded the configured byte budget
    SetBudgetExceeded { required: usize, maximum: usize },
    /// The decoded image exceeded the configured pixel budget
    PixelLimitExceeded { pixels: usize, maximum: usize },
    /// The analysis bitmap or flood-fill stack exceeded the work budget
    WorkBudgetExceeded { required: usize, maximum: usize },
    /// Exact coordinates and component descriptors exceeded the report budget
    ReportBudgetExceeded { required: usize, maximum: usize },
    /// The decoded image's canonical channel storage was inconsistent
    InvalidImageData,
    /// A bounded allocation could not be reserved
    AllocationFailed,
}

impl fmt::Display for RgbReachabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("RGB reachability limits must be positive"),
            Self::ConversionBudgetExceeded { required, maximum } => write!(
                formatter,
                "conversion model requires {required} samples; maximum is {maximum}"
            ),
            Self::SetBudgetExceeded { required, maximum } => write!(
                formatter,
                "reachable RGB set requires {required} bytes; maximum is {maximum}"
            ),
            Self::PixelLimitExceeded { pixels, maximum } => {
                write!(formatter, "image has {pixels} pixels; maximum is {maximum}")
            }
            Self::WorkBudgetExceeded { required, maximum } => write!(
                formatter,
                "reachability analysis requires {required} work bytes; maximum is {maximum}"
            ),
            Self::ReportBudgetExceeded { required, maximum } => write!(
                formatter,
                "reachability report requires {required} bytes; maximum is {maximum}"
            ),
            Self::InvalidImageData => {
                formatter.write_str("decoded image channel storage is inconsistent")
            }
            Self::AllocationFailed => formatter.write_str("RGB reachability allocation failed"),
        }
    }
}

impl std::error::Error for RgbReachabilityError {}

/// Classify each image pixel against a complete reachable RGB set
///
/// The report preserves source provenance, exact coordinates, counts, and
/// connectivity metadata. It does not infer labels or text from those pixels
///
/// # Errors
/// Returns an error when image channels are inconsistent, a budget is invalid
/// or exceeded, or an allocation cannot be reserved
pub fn analyze_rgb_reachability(
    image: &PngPixelImage,
    reachable: &ReachableRgbSet,
    connectivity: PixelConnectivity,
    limits: PixelReachabilityLimits,
) -> Result<RgbReachabilityReport, RgbReachabilityError> {
    validate_limits(limits)?;
    let (width, height, pixel_count) = image_dimensions(image, limits)?;
    let (mut candidate_bits, reachable_pixel_count) =
        classify_pixels(image, reachable, width, pixel_count, limits)?;

    let source_sha256 = image.source_sha256().to_owned();
    let base_report_bytes = size_of::<RgbReachabilityReport>()
        .checked_add(source_sha256.capacity())
        .ok_or(RgbReachabilityError::ReportBudgetExceeded {
            required: usize::MAX,
            maximum: limits.max_report_bytes,
        })?;
    if base_report_bytes > limits.max_report_bytes {
        return Err(RgbReachabilityError::ReportBudgetExceeded {
            required: base_report_bytes,
            maximum: limits.max_report_bytes,
        });
    }

    let (unreachable_pixels, components) = collect_components(
        &mut candidate_bits,
        width,
        height,
        connectivity,
        base_report_bytes,
        limits,
    )?;

    Ok(RgbReachabilityReport {
        source_sha256,
        width: image.width(),
        height: image.height(),
        model: reachable.model(),
        connectivity,
        reachable_pixel_count,
        unreachable_pixels,
        components,
    })
}

fn image_dimensions(
    image: &PngPixelImage,
    limits: PixelReachabilityLimits,
) -> Result<(usize, usize, usize), RgbReachabilityError> {
    let width =
        usize::try_from(image.width()).map_err(|_| RgbReachabilityError::InvalidImageData)?;
    let height =
        usize::try_from(image.height()).map_err(|_| RgbReachabilityError::InvalidImageData)?;
    let pixel_count = width
        .checked_mul(height)
        .ok_or(RgbReachabilityError::InvalidImageData)?;
    let expected_bytes = pixel_count
        .checked_mul(image.layout().channels())
        .ok_or(RgbReachabilityError::InvalidImageData)?;
    if pixel_count != image.pixel_count() || expected_bytes != image.pixel_bytes().len() {
        return Err(RgbReachabilityError::InvalidImageData);
    }
    if pixel_count > limits.max_pixels {
        return Err(RgbReachabilityError::PixelLimitExceeded {
            pixels: pixel_count,
            maximum: limits.max_pixels,
        });
    }
    Ok((width, height, pixel_count))
}

fn classify_pixels(
    image: &PngPixelImage,
    reachable: &ReachableRgbSet,
    width: usize,
    pixel_count: usize,
    limits: PixelReachabilityLimits,
) -> Result<(Vec<u8>, usize), RgbReachabilityError> {
    let mask_bytes = pixel_count.div_ceil(8);
    if mask_bytes > limits.max_work_bytes {
        return Err(RgbReachabilityError::WorkBudgetExceeded {
            required: mask_bytes,
            maximum: limits.max_work_bytes,
        });
    }
    let mut candidate_bits = Vec::new();
    candidate_bits
        .try_reserve_exact(mask_bytes)
        .map_err(|_| RgbReachabilityError::AllocationFailed)?;
    if candidate_bits.capacity() > limits.max_work_bytes {
        return Err(RgbReachabilityError::WorkBudgetExceeded {
            required: candidate_bits.capacity(),
            maximum: limits.max_work_bytes,
        });
    }
    candidate_bits.resize(mask_bytes, 0);

    // Every decision uses RGB values before component grouping
    let mut reachable_pixel_count = 0_usize;
    for pixel_index in 0..pixel_count {
        let x = u32::try_from(pixel_index % width)
            .map_err(|_| RgbReachabilityError::InvalidImageData)?;
        let y = u32::try_from(pixel_index / width)
            .map_err(|_| RgbReachabilityError::InvalidImageData)?;
        let pixel = image
            .pixel(x, y)
            .ok_or(RgbReachabilityError::InvalidImageData)?;
        let [red, green, blue] = pixel.rgb;
        if reachable.contains(RgbColor::new(red, green, blue)) {
            reachable_pixel_count += 1;
        } else {
            set_bit(&mut candidate_bits, pixel_index)?;
        }
    }
    Ok((candidate_bits, reachable_pixel_count))
}

fn collect_components(
    candidate_bits: &mut Vec<u8>,
    width: usize,
    height: usize,
    connectivity: PixelConnectivity,
    base_report_bytes: usize,
    limits: PixelReachabilityLimits,
) -> Result<(Vec<PixelCoordinate>, Vec<PixelComponent>), RgbReachabilityError> {
    let pixel_count = width
        .checked_mul(height)
        .ok_or(RgbReachabilityError::InvalidImageData)?;
    let mut unreachable_pixels = Vec::new();
    let mut components = Vec::new();
    let mut stack = Vec::new();

    // A marked bit means an unreachable pixel remains available to visit
    for pixel_index in 0..pixel_count {
        if !bit_is_set(candidate_bits, pixel_index) {
            continue;
        }
        let component = walk_component(
            pixel_index,
            candidate_bits,
            &mut stack,
            &mut unreachable_pixels,
            ComponentContext {
                width,
                height,
                connectivity,
                base_report_bytes,
                component_capacity: components.capacity(),
                limits,
            },
        )?;
        push_component(
            &mut components,
            component,
            base_report_bytes,
            unreachable_pixels.capacity(),
            limits.max_report_bytes,
        )?;
    }
    Ok((unreachable_pixels, components))
}

fn walk_component(
    start: usize,
    candidate_bits: &mut Vec<u8>,
    stack: &mut Vec<usize>,
    pixels: &mut Vec<PixelCoordinate>,
    context: ComponentContext,
) -> Result<PixelComponent, RgbReachabilityError> {
    clear_bit(candidate_bits, start)?;
    push_stack(
        stack,
        start,
        candidate_bits.capacity(),
        context.limits.max_work_bytes,
    )?;
    let (start_x, start_y) = coordinate(start, context.width)?;
    let mut bounds = PixelBounds {
        min_x: start_x,
        min_y: start_y,
        max_x: start_x,
        max_y: start_y,
    };
    let pixel_start = pixels.len();

    // Flood fill consumes bits so no image-sized component label map is needed
    while let Some(current) = stack.pop() {
        let point = coordinate(current, context.width)?;
        bounds.min_x = bounds.min_x.min(point.0);
        bounds.min_y = bounds.min_y.min(point.1);
        bounds.max_x = bounds.max_x.max(point.0);
        bounds.max_y = bounds.max_y.max(point.1);
        push_coordinate(
            pixels,
            point,
            context.base_report_bytes,
            context.component_capacity,
            context.limits.max_report_bytes,
        )?;
        for neighbor in neighbors(current, context.width, context.height, context.connectivity) {
            if bit_is_set(candidate_bits, neighbor) {
                clear_bit(candidate_bits, neighbor)?;
                push_stack(
                    stack,
                    neighbor,
                    candidate_bits.capacity(),
                    context.limits.max_work_bytes,
                )?;
            }
        }
    }

    let pixel_count = pixels
        .len()
        .checked_sub(pixel_start)
        .ok_or(RgbReachabilityError::InvalidImageData)?;
    Ok(PixelComponent {
        pixel_start,
        pixel_count,
        bounds,
    })
}

#[derive(Clone, Copy)]
struct ComponentContext {
    width: usize,
    height: usize,
    connectivity: PixelConnectivity,
    base_report_bytes: usize,
    component_capacity: usize,
    limits: PixelReachabilityLimits,
}

const fn validate_limits(limits: PixelReachabilityLimits) -> Result<(), RgbReachabilityError> {
    if limits.max_pixels == 0 || limits.max_work_bytes == 0 || limits.max_report_bytes == 0 {
        return Err(RgbReachabilityError::InvalidLimits);
    }
    Ok(())
}

fn coordinate(index: usize, width: usize) -> Result<(u32, u32), RgbReachabilityError> {
    let x = u32::try_from(index % width).map_err(|_| RgbReachabilityError::InvalidImageData)?;
    let y = u32::try_from(index / width).map_err(|_| RgbReachabilityError::InvalidImageData)?;
    Ok((x, y))
}

fn neighbors(
    index: usize,
    width: usize,
    height: usize,
    connectivity: PixelConnectivity,
) -> impl Iterator<Item = usize> {
    let x = index % width;
    let y = index / width;
    let left_column = x.checked_sub(1);
    let right_column = x.checked_add(1).filter(|next_x| *next_x < width);
    let left = left_column.and_then(|_| index.checked_sub(1));
    let right = right_column.and_then(|_| index.checked_add(1));
    let above = index.checked_sub(width);
    let below = y
        .checked_add(1)
        .filter(|next_y| *next_y < height)
        .and_then(|_| index.checked_add(width));
    let (upper_left, upper_right, lower_left, lower_right) = match connectivity {
        PixelConnectivity::Four => (None, None, None, None),
        PixelConnectivity::Eight => (
            above.and_then(|next| left_column.and_then(|_| next.checked_sub(1))),
            above.and_then(|next| right_column.and_then(|_| next.checked_add(1))),
            below.and_then(|next| left_column.and_then(|_| next.checked_sub(1))),
            below.and_then(|next| right_column.and_then(|_| next.checked_add(1))),
        ),
    };
    [
        left,
        right,
        above,
        below,
        upper_left,
        upper_right,
        lower_left,
        lower_right,
    ]
    .into_iter()
    .flatten()
}

fn bit_is_set(bitmap: &[u8], bit: usize) -> bool {
    bitmap
        .get(bit / 8)
        .is_some_and(|byte| byte & (1_u8 << (bit % 8)) != 0)
}

fn set_bit(bitmap: &mut [u8], bit: usize) -> Result<(), RgbReachabilityError> {
    let mask = 1_u8 << (bit % 8);
    let byte = bitmap
        .get_mut(bit / 8)
        .ok_or(RgbReachabilityError::InvalidImageData)?;
    *byte |= mask;
    Ok(())
}

fn clear_bit(bitmap: &mut [u8], bit: usize) -> Result<(), RgbReachabilityError> {
    let mask = 1_u8 << (bit % 8);
    let byte = bitmap
        .get_mut(bit / 8)
        .ok_or(RgbReachabilityError::InvalidImageData)?;
    *byte &= !mask;
    Ok(())
}

fn push_stack(
    stack: &mut Vec<usize>,
    pixel: usize,
    bitmap_capacity: usize,
    maximum_work_bytes: usize,
) -> Result<(), RgbReachabilityError> {
    let maximum_stack_items =
        maximum_work_bytes.saturating_sub(bitmap_capacity) / size_of::<usize>();
    let required_items =
        stack
            .len()
            .checked_add(1)
            .ok_or(RgbReachabilityError::WorkBudgetExceeded {
                required: usize::MAX,
                maximum: maximum_work_bytes,
            })?;
    if required_items > maximum_stack_items {
        return Err(RgbReachabilityError::WorkBudgetExceeded {
            required: bitmap_capacity
                .saturating_add(required_items.saturating_mul(size_of::<usize>())),
            maximum: maximum_work_bytes,
        });
    }
    if required_items > stack.capacity() {
        let doubled_capacity = stack
            .capacity()
            .checked_mul(2)
            .unwrap_or(maximum_stack_items);
        let target_capacity = required_items
            .max(doubled_capacity)
            .min(maximum_stack_items);
        stack
            .try_reserve_exact(target_capacity.saturating_sub(stack.len()))
            .map_err(|_| RgbReachabilityError::AllocationFailed)?;
        if stack.capacity() > maximum_stack_items {
            return Err(RgbReachabilityError::WorkBudgetExceeded {
                required: bitmap_capacity
                    .saturating_add(stack.capacity().saturating_mul(size_of::<usize>())),
                maximum: maximum_work_bytes,
            });
        }
    }
    stack.push(pixel);
    Ok(())
}

fn push_coordinate(
    pixels: &mut Vec<PixelCoordinate>,
    coordinate: (u32, u32),
    base_bytes: usize,
    component_capacity: usize,
    maximum_report_bytes: usize,
) -> Result<(), RgbReachabilityError> {
    reserve_report_item::<PixelCoordinate>(
        pixels,
        base_bytes,
        component_capacity.saturating_mul(size_of::<PixelComponent>()),
        maximum_report_bytes,
    )?;
    pixels.push(PixelCoordinate {
        x: coordinate.0,
        y: coordinate.1,
    });
    Ok(())
}

fn push_component(
    components: &mut Vec<PixelComponent>,
    component: PixelComponent,
    base_bytes: usize,
    pixel_capacity: usize,
    maximum_report_bytes: usize,
) -> Result<(), RgbReachabilityError> {
    reserve_report_item::<PixelComponent>(
        components,
        base_bytes,
        pixel_capacity.saturating_mul(size_of::<PixelCoordinate>()),
        maximum_report_bytes,
    )?;
    components.push(component);
    Ok(())
}

fn reserve_report_item<T>(
    items: &mut Vec<T>,
    fixed_bytes: usize,
    other_vector_bytes: usize,
    maximum_report_bytes: usize,
) -> Result<(), RgbReachabilityError> {
    let fixed_bytes = fixed_bytes.checked_add(other_vector_bytes).ok_or(
        RgbReachabilityError::ReportBudgetExceeded {
            required: usize::MAX,
            maximum: maximum_report_bytes,
        },
    )?;
    let available_bytes = maximum_report_bytes.checked_sub(fixed_bytes).ok_or(
        RgbReachabilityError::ReportBudgetExceeded {
            required: fixed_bytes,
            maximum: maximum_report_bytes,
        },
    )?;
    let maximum_items = available_bytes / size_of::<T>();
    let required_items =
        items
            .len()
            .checked_add(1)
            .ok_or(RgbReachabilityError::ReportBudgetExceeded {
                required: usize::MAX,
                maximum: maximum_report_bytes,
            })?;
    if required_items > maximum_items {
        return Err(RgbReachabilityError::ReportBudgetExceeded {
            required: fixed_bytes.saturating_add(required_items.saturating_mul(size_of::<T>())),
            maximum: maximum_report_bytes,
        });
    }
    let retained_bytes =
        fixed_bytes.saturating_add(items.capacity().saturating_mul(size_of::<T>()));
    if retained_bytes > maximum_report_bytes {
        return Err(RgbReachabilityError::ReportBudgetExceeded {
            required: retained_bytes,
            maximum: maximum_report_bytes,
        });
    }
    if required_items > items.capacity() {
        let doubled_capacity = items.capacity().checked_mul(2).unwrap_or(maximum_items);
        let target_capacity = required_items.max(doubled_capacity).min(maximum_items);
        items
            .try_reserve_exact(target_capacity.saturating_sub(items.len()))
            .map_err(|_| RgbReachabilityError::AllocationFailed)?;
        if items.capacity() > maximum_items {
            return Err(RgbReachabilityError::ReportBudgetExceeded {
                required: fixed_bytes
                    .saturating_add(items.capacity().saturating_mul(size_of::<T>())),
                maximum: maximum_report_bytes,
            });
        }
    }
    Ok(())
}
