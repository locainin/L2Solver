use super::{KeyTest, KeyTestStatus};

pub(super) fn test(
    input: &[u8],
    parent_candidate: usize,
    offset: usize,
    known: &[u8],
    key_length: usize,
) -> KeyTest {
    let mut report = KeyTest {
        parent_candidate,
        offset,
        key_length,
        inferred_key: Vec::new(),
        inference_bytes: 0,
        holdout_bytes: 0,
        status: KeyTestStatus::Untestable,
        first_mismatch: None,
    };
    let Some(encrypted) = input.get(offset..offset + known.len()) else {
        return report;
    };
    let mut inferred_key = vec![0; key_length];
    for (index, (cipher, plain)) in encrypted.iter().zip(known).take(key_length).enumerate() {
        if let Some(slot) = inferred_key.get_mut((offset + index) % key_length) {
            *slot = cipher ^ plain;
        }
    }
    // Withheld bytes test periodic consistency, not the authenticity of supplied plaintext
    let first_mismatch = encrypted
        .iter()
        .zip(known)
        .enumerate()
        .skip(key_length)
        .find_map(|(index, (cipher, plain))| {
            inferred_key
                .get((offset + index) % key_length)
                .filter(|key| cipher ^ *key != *plain)
                .map(|_| index)
        });
    report.inferred_key = inferred_key;
    report.inference_bytes = key_length;
    report.holdout_bytes = known.len() - key_length;
    report.status = if first_mismatch.is_none() {
        KeyTestStatus::Consistent
    } else {
        KeyTestStatus::Contradicted
    };
    report.first_mismatch = first_mismatch;
    report
}
