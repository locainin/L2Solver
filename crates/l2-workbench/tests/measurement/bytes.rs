use l2_workbench::measurement::{MAX_MEASURED_BYTES, MAX_SAMPLES, measure_bytes};
use std::error::Error;

#[test]
fn byte_profile_bitplanes_lengths_repeats() -> Result<(), Box<dyn Error>> {
    let samples: [&[u8]; 2] = [b"Aa\x00", b"bb"];
    let profile = measure_bytes(&samples)?;
    assert_eq!(profile.sample_lengths, [3, 2]);
    assert_eq!(profile.total_bytes, 5);
    assert_eq!(profile.ascii_uppercase, 1);
    assert_eq!(profile.ascii_lowercase, 3);
    assert_eq!(profile.adjacent_equal_pairs, 1);
    assert_eq!(profile.distinct_adjacent_pairs, 3);
    assert_eq!(profile.byte_counts.first(), Some(&1));
    assert_eq!(profile.byte_counts.get(usize::from(b'A')), Some(&1));
    assert_eq!(profile.byte_counts.get(usize::from(b'b')), Some(&2));
    assert_eq!(profile.bit_ones.first(), Some(&2));
    Ok(())
}

#[test]
fn byte_profile_oversized_excessive_sample() {
    let no_samples: [&[u8]; 0] = [];
    assert!(measure_bytes(&no_samples).is_err());

    let large = vec![0; MAX_MEASURED_BYTES + 1];
    assert!(measure_bytes(&[large.as_slice()]).is_err());

    let samples = vec![&[][..]; MAX_SAMPLES + 1];
    assert!(measure_bytes(&samples).is_err());
}
