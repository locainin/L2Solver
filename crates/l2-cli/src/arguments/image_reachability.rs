use clap::{Args, ValueEnum};
use l2_workbench::artifact::{
    DEFAULT_RGB_CONVERSION_BUDGET, FixedPointYcbcrModel, MAX_PIXEL_REACHABILITY_REPORT_BYTES,
    MAX_PIXEL_REACHABILITY_WORK_BYTES, MAX_PNG_DECODER_BYTES, MAX_PNG_PIXEL_BYTES,
    MAX_PNG_PIXEL_INPUT_BYTES, MAX_PNG_PIXEL_WORK_BYTES, MAX_PNG_PIXELS, PixelConnectivity,
    PixelReachabilityLimits, PngPixelLimits, REACHABLE_RGB_SET_BYTES, ReachableRgbLimits,
};

// One PBM row may need a whole byte for a single pixel
const DEFAULT_REACHABILITY_MASK_BYTES: usize = MAX_PNG_PIXELS + 64;

/// Named fixed-point conversion model whose complete output set is tested
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ImageReachabilityModel {
    /// Sixteen-bit libjpeg-style full-range BT.601 conversion
    LibjpegBt601FullRange,
    /// Lower-precision eight-bit full-range BT.601 approximation
    JpegBt601FullRange8Bit,
}

impl ImageReachabilityModel {
    /// Exact model selected by this command-line value
    #[must_use]
    pub const fn model(self) -> FixedPointYcbcrModel {
        match self {
            Self::LibjpegBt601FullRange => FixedPointYcbcrModel::LIBJPEG_BT601_FULL_RANGE,
            Self::JpegBt601FullRange8Bit => FixedPointYcbcrModel::JPEG_BT601_FULL_RANGE,
        }
    }

    /// Stable name recorded in evidence receipts
    #[must_use]
    pub const fn receipt_name(self) -> &'static str {
        match self {
            Self::LibjpegBt601FullRange => "libjpeg_bt601_full_range",
            Self::JpegBt601FullRange8Bit => "jpeg_bt601_full_range_8_bit",
        }
    }
}
use std::{
    num::{NonZeroU32, NonZeroU64, NonZeroUsize},
    path::PathBuf,
};

/// Pixel adjacency used only for connected-component grouping
#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
pub enum ImageConnectivity {
    /// Shared edges connect pixels
    Four,
    /// Shared edges and corners connect pixels
    Eight,
}

impl From<ImageConnectivity> for PixelConnectivity {
    fn from(value: ImageConnectivity) -> Self {
        match value {
            ImageConnectivity::Four => Self::Four,
            ImageConnectivity::Eight => Self::Eight,
        }
    }
}

impl ImageConnectivity {
    /// Stable name recorded in evidence receipts
    #[must_use]
    pub const fn receipt_name(self) -> &'static str {
        match self {
            Self::Four => "four",
            Self::Eight => "eight",
        }
    }
}

/// Exact PNG RGB reachability analysis options
#[derive(Clone, Debug, PartialEq, Eq, Args)]
pub struct ImageReachabilityArgs {
    /// Evidence case containing the selected PNG byte node
    #[arg(value_name = "CASE", allow_hyphen_values = true)]
    pub case: PathBuf,
    /// Retained PNG byte node supplied to the decoder
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub node: u64,
    /// Named fixed-point conversion implementation to enumerate completely
    #[arg(long, default_value = "libjpeg-bt601-full-range")]
    pub model: ImageReachabilityModel,
    /// Pixel adjacency used to group unreachable RGB values
    #[arg(long, default_value = "four")]
    pub connectivity: ImageConnectivity,
    /// Consecutive empty columns required to split one occupied-column group
    #[arg(long, default_value = "1")]
    pub minimum_blank_column_gap: NonZeroU32,
    /// Maximum encoded PNG bytes accepted by the decoder
    #[arg(long, default_value = MAX_PNG_PIXEL_INPUT_BYTES.to_string())]
    pub max_input_bytes: NonZeroUsize,
    /// Maximum decoded image width
    #[arg(long, default_value_t = NonZeroU32::MAX)]
    pub max_width: NonZeroU32,
    /// Maximum decoded image height
    #[arg(long, default_value_t = NonZeroU32::MAX)]
    pub max_height: NonZeroU32,
    /// Maximum decoded and analyzed pixels
    #[arg(long, default_value = MAX_PNG_PIXELS.to_string())]
    pub max_pixels: NonZeroUsize,
    /// Maximum canonical RGB or RGBA bytes retained by the decoder
    #[arg(long, default_value = MAX_PNG_PIXEL_BYTES.to_string())]
    pub max_pixel_bytes: NonZeroUsize,
    /// Maximum temporary bytes used while normalizing PNG pixels
    #[arg(long, default_value = MAX_PNG_PIXEL_WORK_BYTES.to_string())]
    pub max_decode_work_bytes: NonZeroUsize,
    /// Memory ceiling supplied to the PNG decoder
    #[arg(long, default_value = MAX_PNG_DECODER_BYTES.to_string())]
    pub max_decoder_memory_bytes: NonZeroUsize,
    /// Maximum fixed-point YCbCr samples evaluated during complete enumeration
    #[arg(long, default_value = DEFAULT_RGB_CONVERSION_BUDGET.to_string())]
    pub max_conversion_samples: NonZeroU64,
    /// Maximum bytes retained for the reachable RGB membership set
    #[arg(long, default_value = REACHABLE_RGB_SET_BYTES.to_string())]
    pub max_reachable_set_bytes: NonZeroUsize,
    /// Maximum temporary bytes used by classification and component grouping
    #[arg(long, default_value = MAX_PIXEL_REACHABILITY_WORK_BYTES.to_string())]
    pub max_analysis_work_bytes: NonZeroUsize,
    /// Maximum in-memory bytes retained for coordinates and component metadata
    #[arg(long, default_value = MAX_PIXEL_REACHABILITY_REPORT_BYTES.to_string())]
    pub max_report_bytes: NonZeroUsize,
    /// Maximum encoded JSON receipt bytes; increase it to retain larger exact reports
    #[arg(long, default_value = MAX_PIXEL_REACHABILITY_REPORT_BYTES.to_string())]
    pub max_receipt_bytes: NonZeroUsize,
    /// Maximum bytes retained for the exact portable bitmap mask
    #[arg(long, default_value = DEFAULT_REACHABILITY_MASK_BYTES.to_string())]
    pub max_mask_bytes: NonZeroUsize,
    /// Write the updated case atomically to this path
    #[arg(long, value_name = "NEW_CASE")]
    pub output: Option<PathBuf>,
}

impl ImageReachabilityArgs {
    /// Build exact PNG decoder budgets recorded by the evidence receipt
    #[must_use]
    pub const fn png_limits(&self) -> PngPixelLimits {
        PngPixelLimits {
            max_input_bytes: self.max_input_bytes.get(),
            max_width: self.max_width.get(),
            max_height: self.max_height.get(),
            max_pixels: self.max_pixels.get(),
            max_pixel_bytes: self.max_pixel_bytes.get(),
            max_work_buffer_bytes: self.max_decode_work_bytes.get(),
            max_decoder_memory_bytes: self.max_decoder_memory_bytes.get(),
        }
    }

    /// Build complete-domain enumeration budgets recorded by the receipt
    #[must_use]
    pub const fn enumeration_limits(&self) -> ReachableRgbLimits {
        ReachableRgbLimits {
            max_conversion_samples: self.max_conversion_samples.get(),
            max_set_bytes: self.max_reachable_set_bytes.get(),
        }
    }

    /// Build classification and component budgets recorded by the receipt
    #[must_use]
    pub const fn analysis_limits(&self) -> PixelReachabilityLimits {
        PixelReachabilityLimits {
            max_pixels: self.max_pixels.get(),
            max_work_bytes: self.max_analysis_work_bytes.get(),
            max_report_bytes: self.max_report_bytes.get(),
        }
    }
}
