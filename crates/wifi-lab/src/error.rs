use core::fmt;

/// Configuration, schedule, and bounded-resource failures in the wireless lab
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LabError {
    /// A configured resource count is outside the supported range
    InvalidLimit {
        field: &'static str,
        value: usize,
        maximum: usize,
    },
    /// A frequency of zero cannot identify a wireless channel
    InvalidFrequency { frequency_mhz: u16 },
    /// A dwell window must have positive duration
    ZeroLengthWindow { at_ns: u64 },
    /// A dwell window end must not precede its start
    WindowReversed { start_ns: u64, end_ns: u64 },
    /// A start plus duration did not fit in the timestamp representation
    TimeOverflow,
    /// Two windows on one radio overlap in time
    WindowOverlap {
        radio: u16,
        existing_start_ns: u64,
        existing_end_ns: u64,
        requested_start_ns: u64,
        requested_end_ns: u64,
    },
    /// A radio or air instance reached its window budget
    WindowLimit { maximum: usize },
    /// A virtual air reached its radio budget
    RadioLimit { maximum: usize },
    /// A radio identity is already registered
    DuplicateRadio { radio: u16 },
    /// A virtual air reached its raw-record budget
    RecordLimit { maximum: usize },
    /// A raw input is larger than the configured per-record budget
    FrameTooLarge { maximum: usize, actual: usize },
    /// Retaining another raw input would exceed the cumulative byte budget
    InputByteLimit { maximum: usize, attempted: usize },
    /// Delivering matching records would exceed the observation budget
    ObservationLimit { maximum: usize, attempted: usize },
    /// Cloning matching records would exceed the delivered-byte budget
    ObservedByteLimit { maximum: usize, attempted: usize },
    /// The configured total schedule cannot contain all tuned dwell
    DwellExceedsSchedule {
        radio: u16,
        dwell_ns: u64,
        scheduled_ns: u64,
    },
    /// A virtual air reached its unique-frequency budget
    ChannelLimit { maximum: usize },
    /// A checked count or timestamp calculation overflowed
    ArithmeticOverflow,
}

impl fmt::Display for LabError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidLimit {
                field,
                value,
                maximum,
            } => write!(
                formatter,
                "wireless lab {field} limit {value} is outside 1..={maximum}"
            ),
            Self::InvalidFrequency { frequency_mhz } => {
                write!(
                    formatter,
                    "wireless frequency {frequency_mhz} MHz is invalid"
                )
            }
            Self::ZeroLengthWindow { at_ns } => {
                write!(
                    formatter,
                    "wireless dwell window at {at_ns} ns has zero length"
                )
            }
            Self::WindowReversed { start_ns, end_ns } => write!(
                formatter,
                "wireless dwell window ends at {end_ns} ns before it starts at {start_ns} ns"
            ),
            Self::TimeOverflow => {
                formatter.write_str("wireless dwell timestamp arithmetic overflow")
            }
            Self::WindowOverlap {
                radio,
                existing_start_ns,
                existing_end_ns,
                requested_start_ns,
                requested_end_ns,
            } => write!(
                formatter,
                "radio {radio} dwell {requested_start_ns}..{requested_end_ns} ns overlaps {existing_start_ns}..{existing_end_ns} ns"
            ),
            Self::WindowLimit { maximum } => {
                write!(formatter, "wireless dwell windows exceed limit {maximum}")
            }
            Self::RadioLimit { maximum } => {
                write!(formatter, "virtual radios exceed limit {maximum}")
            }
            Self::DuplicateRadio { radio } => {
                write!(formatter, "virtual radio {radio} is already registered")
            }
            Self::RecordLimit { maximum } => {
                write!(formatter, "raw wireless records exceed limit {maximum}")
            }
            Self::FrameTooLarge { maximum, actual } => write!(
                formatter,
                "raw wireless input is {actual} bytes, exceeding limit {maximum}"
            ),
            Self::InputByteLimit { maximum, attempted } => write!(
                formatter,
                "raw wireless inputs require {attempted} bytes, exceeding limit {maximum}"
            ),
            Self::ObservationLimit { maximum, attempted } => write!(
                formatter,
                "wireless delivery requires {attempted} observations, exceeding limit {maximum}"
            ),
            Self::ObservedByteLimit { maximum, attempted } => write!(
                formatter,
                "wireless delivery requires {attempted} bytes, exceeding limit {maximum}"
            ),
            Self::DwellExceedsSchedule {
                radio,
                dwell_ns,
                scheduled_ns,
            } => write!(
                formatter,
                "radio {radio} dwell {dwell_ns} ns exceeds schedule {scheduled_ns} ns"
            ),
            Self::ChannelLimit { maximum } => {
                write!(formatter, "virtual frequencies exceed limit {maximum}")
            }
            Self::ArithmeticOverflow => formatter.write_str("wireless lab arithmetic overflow"),
        }
    }
}

impl std::error::Error for LabError {}
