use core::fmt;

/// Configuration and accounting errors outside hostile packet parsing
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SurveyError {
    InvalidLimit {
        field: &'static str,
        value: usize,
        maximum: usize,
    },
    UnknownRadio(u16),
    InvalidFrequency {
        frequency_mhz: u16,
    },
    ChannelLimit {
        maximum: usize,
    },
    ArithmeticOverflow,
    DwellExceedsSchedule {
        radio: u16,
        observed_ns: u64,
        scheduled_ns: u64,
    },
}

impl fmt::Display for SurveyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit {
                field,
                value,
                maximum,
            } => write!(
                formatter,
                "wireless survey {field} limit {value} is outside 1..={maximum}"
            ),
            Self::UnknownRadio(radio) => {
                write!(formatter, "wireless radio {radio} has no schedule")
            }
            Self::InvalidFrequency { frequency_mhz } => {
                write!(
                    formatter,
                    "wireless frequency {frequency_mhz} MHz is invalid"
                )
            }
            Self::ChannelLimit { maximum } => {
                write!(formatter, "wireless channel records exceed limit {maximum}")
            }
            Self::ArithmeticOverflow => formatter.write_str("wireless survey arithmetic overflow"),
            Self::DwellExceedsSchedule {
                radio,
                observed_ns,
                scheduled_ns,
            } => write!(
                formatter,
                "radio {radio} dwell {observed_ns} ns exceeds schedule {scheduled_ns} ns"
            ),
        }
    }
}

impl std::error::Error for SurveyError {}
