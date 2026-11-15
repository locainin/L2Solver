use super::{DecodeBudget, longest_escaped_string};
use std::error::Error;

#[test]
fn escaped_wire_lengths() {
    for (wire, expected) in [
        (br#"["plain", 1]"#.as_slice(), 0),
        (br#"["a\nb", "x"]"#.as_slice(), 4),
        (br#"["ab\"cd", "\t"]"#.as_slice(), 6),
        (br#""a\"#.as_slice(), 2),
    ] {
        assert_eq!(longest_escaped_string(wire), expected, "{wire:?}");
    }
}

#[test]
fn vector_growth_admission() -> Result<(), Box<dyn Error>> {
    let mut budget = DecodeBudget::new(12, 0, b"")?;
    let mut values = Vec::<u8>::new();
    budget.reserve_one::<_, serde_json::Error>(&mut values)?;
    assert_eq!(values.capacity(), 4, "initial reservation");
    assert_eq!(budget.used, 4);

    values.push(1);
    budget.reserve_one::<_, serde_json::Error>(&mut values)?;
    assert_eq!(budget.used, 4, "an available slot needs no new charge");

    values.resize(4, 0);
    budget.reserve_one::<_, serde_json::Error>(&mut values)?;
    assert_eq!(values.capacity(), 8, "one geometric growth");
    assert_eq!(budget.used, 12, "both buffers remain charged during growth");
    Ok(())
}
