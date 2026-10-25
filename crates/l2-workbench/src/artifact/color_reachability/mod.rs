mod analyze;
mod model;

pub use analyze::{
    MAX_PIXEL_REACHABILITY_REPORT_BYTES, MAX_PIXEL_REACHABILITY_WORK_BYTES, PixelBounds,
    PixelComponent, PixelConnectivity, PixelCoordinate, PixelReachabilityLimits,
    RgbReachabilityError, RgbReachabilityReport, analyze_rgb_reachability,
};
pub use model::{FixedPointYcbcrCoefficients, FixedPointYcbcrModel, FixedPointYcbcrModelError};

/// Number of eight-bit YCbCr triplets in the complete conversion domain
pub const TOTAL_YCBCR_INPUTS: u64 = 1_u64 << 24;
/// Number of byte-packed RGB colors in the complete output domain
pub const TOTAL_RGB_COLORS: usize = 1_usize << 24;
/// Byte length of a complete bit-per-color RGB membership set
pub const REACHABLE_RGB_SET_BYTES: usize = TOTAL_RGB_COLORS.div_ceil(8);
/// Default conversion work budget for complete model enumeration
pub const DEFAULT_RGB_CONVERSION_BUDGET: u64 = TOTAL_YCBCR_INPUTS;

/// Resource budgets for complete YCbCr-domain enumeration
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReachableRgbLimits {
    /// Largest number of YCbCr samples that may be evaluated
    pub max_conversion_samples: u64,
    /// Largest membership bitmap size accepted
    pub max_set_bytes: usize,
}

impl Default for ReachableRgbLimits {
    fn default() -> Self {
        Self {
            max_conversion_samples: DEFAULT_RGB_CONVERSION_BUDGET,
            max_set_bytes: REACHABLE_RGB_SET_BYTES,
        }
    }
}

/// One exact eight-bit red, green, and blue triplet
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RgbColor {
    red: u8,
    green: u8,
    blue: u8,
}

impl RgbColor {
    /// Create a color from its channel values
    #[must_use]
    pub const fn new(red: u8, green: u8, blue: u8) -> Self {
        Self { red, green, blue }
    }

    /// Read the color channels in red, green, blue order
    #[must_use]
    pub const fn channels(self) -> [u8; 3] {
        [self.red, self.green, self.blue]
    }

    /// Red channel value
    #[must_use]
    pub const fn red(self) -> u8 {
        self.red
    }

    /// Green channel value
    #[must_use]
    pub const fn green(self) -> u8 {
        self.green
    }

    /// Blue channel value
    #[must_use]
    pub const fn blue(self) -> u8 {
        self.blue
    }

    fn bitmap_index(self) -> usize {
        usize::from(self.red) << 16 | usize::from(self.green) << 8 | usize::from(self.blue)
    }
}

/// Complete RGB set produced by one explicit fixed-point model
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReachableRgbSet {
    model: FixedPointYcbcrModel,
    colors: Vec<u8>,
    unique_color_count: usize,
}

impl ReachableRgbSet {
    /// Enumerate every eight-bit YCbCr input for one conversion model
    ///
    /// The returned bitmap can be reused across any number of images that use
    /// the same model. A set is returned only after the whole domain is visited
    ///
    /// # Errors
    /// Returns an error when the sample count, bitmap size, or allocation
    /// exceeds its configured budget
    pub fn enumerate(
        model: FixedPointYcbcrModel,
        limits: ReachableRgbLimits,
    ) -> Result<Self, RgbReachabilityError> {
        if limits.max_conversion_samples == 0 || limits.max_set_bytes == 0 {
            return Err(RgbReachabilityError::InvalidLimits);
        }
        if limits.max_conversion_samples < TOTAL_YCBCR_INPUTS {
            return Err(RgbReachabilityError::ConversionBudgetExceeded {
                required: TOTAL_YCBCR_INPUTS,
                maximum: limits.max_conversion_samples,
            });
        }
        if limits.max_set_bytes < REACHABLE_RGB_SET_BYTES {
            return Err(RgbReachabilityError::SetBudgetExceeded {
                required: REACHABLE_RGB_SET_BYTES,
                maximum: limits.max_set_bytes,
            });
        }

        let mut colors = Vec::new();
        colors
            .try_reserve_exact(REACHABLE_RGB_SET_BYTES)
            .map_err(|_| RgbReachabilityError::AllocationFailed)?;
        if colors.capacity() > limits.max_set_bytes {
            return Err(RgbReachabilityError::SetBudgetExceeded {
                required: colors.capacity(),
                maximum: limits.max_set_bytes,
            });
        }
        colors.resize(REACHABLE_RGB_SET_BYTES, 0);
        let mut unique_color_count = 0_usize;

        // The input index encodes the full Y, Cb, and Cr Cartesian product
        for input in 0..TOTAL_YCBCR_INPUTS {
            let y = u8::try_from((input >> 16) & 0xff)
                .map_err(|_| RgbReachabilityError::InvalidImageData)?;
            let cb = u8::try_from((input >> 8) & 0xff)
                .map_err(|_| RgbReachabilityError::InvalidImageData)?;
            let cr =
                u8::try_from(input & 0xff).map_err(|_| RgbReachabilityError::InvalidImageData)?;
            let color = model.convert(y, cb, cr);
            if mark_color(&mut colors, color)? {
                unique_color_count = unique_color_count
                    .checked_add(1)
                    .ok_or(RgbReachabilityError::InvalidImageData)?;
            }
        }

        Ok(Self {
            model,
            colors,
            unique_color_count,
        })
    }

    /// The exact fixed-point conversion model used to build the set
    #[must_use]
    pub const fn model(&self) -> FixedPointYcbcrModel {
        self.model
    }

    /// Number of distinct RGB colors produced by the complete input domain
    #[must_use]
    pub const fn unique_color_count(&self) -> usize {
        self.unique_color_count
    }

    /// Test whether an RGB value is produced by at least one model input
    #[must_use]
    pub fn contains(&self, color: RgbColor) -> bool {
        let bit = color.bitmap_index();
        self.colors
            .get(bit / 8)
            .is_some_and(|byte| byte & (1_u8 << (bit % 8)) != 0)
    }

    /// Retained byte size of the complete membership bitmap
    #[must_use]
    pub const fn storage_bytes(&self) -> usize {
        self.colors.capacity()
    }
}

fn mark_color(bitmap: &mut [u8], color: RgbColor) -> Result<bool, RgbReachabilityError> {
    let bit = color.bitmap_index();
    let mask = 1_u8 << (bit % 8);
    let byte = bitmap
        .get_mut(bit / 8)
        .ok_or(RgbReachabilityError::InvalidImageData)?;
    let was_unmarked = *byte & mask == 0;
    *byte |= mask;
    Ok(was_unmarked)
}
