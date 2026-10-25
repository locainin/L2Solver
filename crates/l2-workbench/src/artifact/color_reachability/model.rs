use core::fmt;

/// Fixed-point multipliers used by one YCbCr-to-RGB conversion model
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedPointYcbcrCoefficients {
    /// Multiplier applied to the luma sample
    pub y: i32,
    /// Multiplier applied to centered Cr for red
    pub red_cr: i32,
    /// Multiplier applied to centered Cb for green
    pub green_cb: i32,
    /// Multiplier applied to centered Cr for green
    pub green_cr: i32,
    /// Multiplier applied to centered Cb for blue
    pub blue_cb: i32,
}

/// Explicit fixed-point conversion recipe for eight-bit YCbCr samples
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedPointYcbcrModel {
    coefficients: FixedPointYcbcrCoefficients,
    chroma_offset: u8,
    fractional_bits: u8,
    rounding_bias: i32,
}

impl FixedPointYcbcrModel {
    /// Full-range BT.601 integer conversion used by libjpeg-style decoders
    ///
    /// R = clamp((65536*Y + 91881*(Cr-128) + 32768) >> 16)
    /// G = clamp((65536*Y - 22554*(Cb-128) - 46802*(Cr-128) + 32768) >> 16)
    /// B = clamp((65536*Y + 116130*(Cb-128) + 32768) >> 16)
    pub const LIBJPEG_BT601_FULL_RANGE: Self = Self {
        coefficients: FixedPointYcbcrCoefficients {
            y: 65_536,
            red_cr: 91_881,
            green_cb: -22_554,
            green_cr: -46_802,
            blue_cb: 116_130,
        },
        chroma_offset: 128,
        fractional_bits: 16,
        rounding_bias: 32_768,
    };

    /// Common JPEG full-range BT.601 integer approximation
    ///
    /// R = clamp((256*Y + 359*(Cr-128) + 128) >> 8)
    /// G = clamp((256*Y - 88*(Cb-128) - 183*(Cr-128) + 128) >> 8)
    /// B = clamp((256*Y + 454*(Cb-128) + 128) >> 8)
    /// Signed shifts round negative intermediate values toward negative
    /// infinity before clamping each result to the eight-bit channel range
    pub const JPEG_BT601_FULL_RANGE: Self = Self {
        coefficients: FixedPointYcbcrCoefficients {
            y: 256,
            red_cr: 359,
            green_cb: -88,
            green_cr: -183,
            blue_cb: 454,
        },
        chroma_offset: 128,
        fractional_bits: 8,
        rounding_bias: 128,
    };

    /// Create a conversion model with caller-supplied integer coefficients
    ///
    /// The largest supported fractional shift is 31, which keeps the fixed
    /// scale representable and all sample products within signed 64-bit math
    ///
    /// # Errors
    /// Returns an error when `fractional_bits` exceeds 31
    pub const fn new(
        coefficients: FixedPointYcbcrCoefficients,
        chroma_offset: u8,
        fractional_bits: u8,
        rounding_bias: i32,
    ) -> Result<Self, FixedPointYcbcrModelError> {
        if fractional_bits > 31 {
            return Err(FixedPointYcbcrModelError::FractionalBitsTooLarge {
                value: fractional_bits,
                maximum: 31,
            });
        }
        Ok(Self {
            coefficients,
            chroma_offset,
            fractional_bits,
            rounding_bias,
        })
    }

    /// Multipliers recorded by this conversion model
    #[must_use]
    pub const fn coefficients(self) -> FixedPointYcbcrCoefficients {
        self.coefficients
    }

    /// Chroma sample midpoint subtracted before applying chroma multipliers
    #[must_use]
    pub const fn chroma_offset(self) -> u8 {
        self.chroma_offset
    }

    /// Number of fixed-point fractional bits removed after summation
    #[must_use]
    pub const fn fractional_bits(self) -> u8 {
        self.fractional_bits
    }

    /// Integer bias added before the fixed-point right shift
    #[must_use]
    pub const fn rounding_bias(self) -> i32 {
        self.rounding_bias
    }

    /// Convert one eight-bit YCbCr triplet using this exact integer model
    #[must_use]
    pub fn convert(self, y: u8, cb: u8, cr: u8) -> super::RgbColor {
        let blue_difference = i64::from(cb) - i64::from(self.chroma_offset);
        let red_difference = i64::from(cr) - i64::from(self.chroma_offset);
        let y_term = i64::from(y) * i64::from(self.coefficients.y);
        let rounding_bias = i64::from(self.rounding_bias);
        let shift = u32::from(self.fractional_bits);

        // Every multiply and sum stays within i64 for byte samples and i32 coefficients
        let red = y_term + red_difference * i64::from(self.coefficients.red_cr) + rounding_bias;
        let green = y_term
            + blue_difference * i64::from(self.coefficients.green_cb)
            + red_difference * i64::from(self.coefficients.green_cr)
            + rounding_bias;
        let blue = y_term + blue_difference * i64::from(self.coefficients.blue_cb) + rounding_bias;

        super::RgbColor::new(
            clamp_channel(red >> shift),
            clamp_channel(green >> shift),
            clamp_channel(blue >> shift),
        )
    }
}

/// Invalid configuration for a fixed-point color conversion model
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixedPointYcbcrModelError {
    /// The fixed-point right shift would exceed the supported signed scale
    FractionalBitsTooLarge { value: u8, maximum: u8 },
}

impl fmt::Display for FixedPointYcbcrModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FractionalBitsTooLarge { value, maximum } => write!(
                formatter,
                "fixed-point shift {value} exceeds maximum {maximum}"
            ),
        }
    }
}

impl std::error::Error for FixedPointYcbcrModelError {}

fn clamp_channel(value: i64) -> u8 {
    // Clamp before narrowing so the result always represents one byte
    u8::try_from(value.clamp(0, i64::from(u8::MAX))).unwrap_or(0)
}
