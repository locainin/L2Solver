use super::model::{CarrierError, Rule, TimingStatus, Value};
use crate::measurement::Clock;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct Comparable<'a> {
    rule: &'a Rule,
    value: ComparableValue<'a>,
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ComparableValue<'a> {
    Bytes {
        bytes: &'a [u8],
    },
    Bits {
        order: super::model::BitOrder,
        bit_length: u64,
        packed: &'a [u8],
    },
    Unsigned {
        value: u64,
    },
    DnsLabel {
        comparison: &'a [u8],
    },
    Capitalization {
        pattern: &'a [u8],
    },
    Timing {
        delta_ticks: Option<u64>,
        status: TimingStatus,
        left_clock: Option<&'a Clock>,
        right_clock: Option<&'a Clock>,
    },
}

pub(super) fn exact_value_hash(rule: &Rule, value: &Value) -> Result<[u8; 32], CarrierError> {
    // Hash a fixed comparison shape instead of runtime hash state or serialized report metadata
    let comparable = Comparable {
        rule,
        value: comparable_value(value),
    };
    let encoded = serde_json::to_vec(&comparable).map_err(|_| CarrierError::Serialization)?;
    Ok(Sha256::digest(encoded).into())
}

fn comparable_value(value: &Value) -> ComparableValue<'_> {
    match value {
        Value::Bytes { bytes } => ComparableValue::Bytes { bytes },
        Value::Bits {
            order,
            bit_length,
            packed,
        } => ComparableValue::Bits {
            order: *order,
            bit_length: *bit_length,
            packed,
        },
        Value::Unsigned { value } => ComparableValue::Unsigned { value: *value },
        Value::DnsLabel { comparison, .. } => ComparableValue::DnsLabel { comparison },
        Value::Capitalization { pattern } => ComparableValue::Capitalization { pattern },
        // Timing relationships compare exact deltas and clocks; raw ticks stay on observations
        Value::Timing {
            delta_ticks,
            status,
            left_clock,
            right_clock,
            ..
        } => ComparableValue::Timing {
            delta_ticks: *delta_ticks,
            status: *status,
            left_clock: left_clock.as_ref(),
            right_clock: right_clock.as_ref(),
        },
    }
}

pub(super) fn equivalent_values(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::DnsLabel { comparison: a, .. }, Value::DnsLabel { comparison: b, .. }) => a == b,
        (
            Value::Timing {
                delta_ticks: Some(a),
                status: TimingStatus::Measured,
                left_clock: Some(clock_a),
                right_clock: Some(right_a),
                ..
            },
            Value::Timing {
                delta_ticks: Some(b),
                status: TimingStatus::Measured,
                left_clock: Some(clock_b),
                right_clock: Some(right_b),
                ..
            },
        ) => {
            a == b
                && same_clock(clock_a, right_a)
                && same_clock(clock_b, right_b)
                && same_clock(clock_a, clock_b)
        }
        (Value::Timing { .. }, Value::Timing { .. }) => false,
        _ => left == right,
    }
}

fn same_clock(left: &Clock, right: &Clock) -> bool {
    left.id == right.id
        && left.scope == right.scope
        && left.radix == right.radix
        && left.exponent == right.exponent
        && left.offset_seconds == right.offset_seconds
}
