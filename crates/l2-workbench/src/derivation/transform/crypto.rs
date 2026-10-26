//! Bounded hash-counter and authenticated-decryption transformations

use super::{OutputBudget, check_output_size};
use crate::derivation::{
    AesGcmTagLayout, CounterByteOrder, CounterWidth, Operation, SeedCounterOrder, StepFailure,
};
use aes_gcm::{
    Aes128Gcm, Aes256Gcm, Nonce, Tag,
    aead::{AeadInOut, KeyInit},
    aes::cipher::consts::U12,
};
use scrypt::{Params as ScryptParams, scrypt};
use sha2::{Digest, Sha256};

const SHA256_BLOCK_BYTES: usize = 32;
const AES_GCM_TAG_BYTES: usize = 16;
const SCRYPT_RP_PRODUCT_LIMIT: u32 = 1 << 30;

pub(super) fn work_overhead(input_length: usize, operation: &Operation) -> Option<usize> {
    match operation {
        Operation::Sha256CounterXor {
            seed,
            counter_width,
            ..
        } => sha256_counter_xor_work_overhead(
            input_length,
            seed.as_literal_bytes()?.len(),
            *counter_width,
        ),
        Operation::AesGcmDecrypt {
            key,
            nonce,
            associated_data,
            ..
        } => key
            .as_literal_bytes()?
            .len()
            .checked_add(nonce.as_literal_bytes()?.len())?
            .checked_add(associated_data.as_literal_bytes()?.len())?
            .checked_add(AES_GCM_TAG_BYTES),
        Operation::ScryptDerive {
            salt, log_n, r, p, ..
        } => {
            let n = 1_usize.checked_shl(u32::from(*log_n))?;
            let r = usize::try_from(*r).ok()?;
            let p = usize::try_from(*p).ok()?;
            let block_bytes = r.checked_mul(128)?;
            // Estimate bytes as 128*N*r per p pass, plus B/T buffers and repeated password and salt reads
            n.checked_mul(block_bytes)?
                .checked_mul(p)?
                .checked_add(block_bytes.checked_mul(p)?)?
                .checked_add(block_bytes)?
                .checked_add(input_length.checked_mul(p)?)?
                .checked_add(salt.as_literal_bytes()?.len().checked_mul(p)?)
        }
        _ => Some(0),
    }
}

pub(super) fn sha256_counter_xor_work(
    input_length: usize,
    seed_length: usize,
    counter_width: CounterWidth,
) -> Option<usize> {
    input_length
        .checked_mul(2)?
        .checked_add(sha256_counter_xor_work_overhead(
            input_length,
            seed_length,
            counter_width,
        )?)
}

fn sha256_counter_xor_work_overhead(
    input_length: usize,
    seed_length: usize,
    counter_width: CounterWidth,
) -> Option<usize> {
    // Each SHA block hashes one copy of the seed and encoded counter
    seed_length
        .checked_add(counter_width.byte_length())?
        .checked_mul(input_length.div_ceil(SHA256_BLOCK_BYTES))
}

pub(super) fn validate_sha256_counter_xor_capacity(
    input_length: usize,
    initial_counter: u64,
    counter_width: CounterWidth,
) -> Result<(), StepFailure> {
    let maximum = counter_width.maximum_counter();
    if initial_counter > maximum {
        return Err(StepFailure::CounterValueOutOfRange {
            initial_counter,
            maximum,
        });
    }

    // Check the final counter before allocation so exhaustion keeps all input bytes
    let block_count = input_length.div_ceil(SHA256_BLOCK_BYTES);
    if block_count > 0 {
        let last_block_offset =
            u64::try_from(block_count - 1).map_err(|_| StepFailure::CounterExhausted)?;
        let last_counter = initial_counter
            .checked_add(last_block_offset)
            .ok_or(StepFailure::CounterExhausted)?;
        if last_counter > maximum {
            return Err(StepFailure::CounterExhausted);
        }
    }
    Ok(())
}

pub(super) fn scrypt_derive(
    password: &[u8],
    salt: &[u8],
    log_n: u8,
    r: u32,
    p: u32,
    output_length: usize,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    check_output_size(output_length, budget)?;

    // Reject unsupported sizes before output or ROMix buffers can be allocated
    if output_length == 0
        || output_length / 32 > u32::MAX as usize
        || r == 0
        || p == 0
        // The crate checks r*p in u32, so reject overflow before calling its constructor
        || r.checked_mul(p)
            .is_none_or(|product| product >= SCRYPT_RP_PRODUCT_LIMIT)
    {
        return Err(StepFailure::InvalidScryptParameters);
    }
    let params =
        ScryptParams::new(log_n, r, p).map_err(|_| StepFailure::InvalidScryptParameters)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(output_length)
        .map_err(|_| StepFailure::AllocationFailed)?;
    output.resize(output_length, 0);

    // The password stays in the input stream, while the requested derived bytes remain visible output
    scrypt(password, salt, &params, &mut output)
        .map_err(|_| StepFailure::InvalidScryptParameters)?;
    Ok(output)
}

pub(super) fn sha256_counter_xor(
    input: &[u8],
    seed: &[u8],
    initial_counter: u64,
    counter_width: CounterWidth,
    counter_byte_order: CounterByteOrder,
    seed_order: SeedCounterOrder,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    check_output_size(input.len(), budget)?;
    validate_sha256_counter_xor_capacity(input.len(), initial_counter, counter_width)?;

    let mut output = Vec::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| StepFailure::AllocationFailed)?;
    let encoded_counter_length = counter_width.byte_length();

    for (block_index, input_block) in input.chunks(SHA256_BLOCK_BYTES).enumerate() {
        let block_offset = u64::try_from(block_index).map_err(|_| StepFailure::CounterExhausted)?;
        let counter = initial_counter
            .checked_add(block_offset)
            .ok_or(StepFailure::CounterExhausted)?;
        let counter_bytes = match counter_byte_order {
            CounterByteOrder::BigEndian => counter.to_be_bytes(),
            CounterByteOrder::LittleEndian => counter.to_le_bytes(),
        };
        let mut digest = Sha256::new();

        // The two declared orders define the bytes hashed for each mask block
        if seed_order == SeedCounterOrder::SeedThenCounter {
            digest.update(seed);
        }
        update_counter(
            &mut digest,
            counter_bytes,
            encoded_counter_length,
            counter_byte_order,
        );
        if seed_order == SeedCounterOrder::CounterThenSeed {
            digest.update(seed);
        }

        let mask = digest.finalize();
        output.extend(
            input_block
                .iter()
                .copied()
                .zip(mask.iter().copied())
                .map(|(byte, mask_byte)| byte ^ mask_byte),
        );
    }

    Ok(output)
}

fn update_counter(
    digest: &mut Sha256,
    encoded_counter: [u8; 8],
    counter_length: usize,
    byte_order: CounterByteOrder,
) {
    let first_position = match byte_order {
        CounterByteOrder::BigEndian => 8 - counter_length,
        CounterByteOrder::LittleEndian => 0,
    };
    let last_position = first_position + counter_length;
    for (position, byte) in encoded_counter.into_iter().enumerate() {
        if position >= first_position && position < last_position {
            digest.update([byte]);
        }
    }
}

pub(super) fn aes_gcm_decrypt(
    input: &[u8],
    key: &[u8],
    nonce: &[u8],
    associated_data: &[u8],
    tag_layout: AesGcmTagLayout,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    if !matches!(key.len(), 16 | 32) || nonce.len() != 12 {
        return Err(StepFailure::InvalidAesGcmParameters);
    }

    let parts = gcm_input_parts(input, tag_layout)?;
    // A valid tag range guarantees sixteen removable bytes in the input
    let message_length = input.len() - AES_GCM_TAG_BYTES;
    check_output_size(message_length, budget)?;

    // Decrypt a private copy so rejected plaintext never reaches the report
    let mut plaintext = Vec::new();
    plaintext
        .try_reserve_exact(message_length)
        .map_err(|_| StepFailure::AllocationFailed)?;
    plaintext.extend_from_slice(parts.before_tag);
    plaintext.extend_from_slice(parts.after_tag);

    let nonce = Nonce::<U12>::try_from(nonce).map_err(|_| StepFailure::InvalidAesGcmParameters)?;
    let tag = Tag::try_from(parts.tag).map_err(|_| StepFailure::InvalidAesGcmLayout)?;
    authenticate_and_decrypt(&mut plaintext, key, &nonce, associated_data, &tag)?;

    Ok(plaintext)
}

struct GcmInputParts<'a> {
    before_tag: &'a [u8],
    after_tag: &'a [u8],
    tag: &'a [u8],
}

fn gcm_input_parts(
    input: &[u8],
    tag_layout: AesGcmTagLayout,
) -> Result<GcmInputParts<'_>, StepFailure> {
    match tag_layout {
        AesGcmTagLayout::Appended => {
            let ciphertext_length = input
                .len()
                .checked_sub(AES_GCM_TAG_BYTES)
                .ok_or(StepFailure::InvalidAesGcmLayout)?;
            let before_tag = input
                .get(..ciphertext_length)
                .ok_or(StepFailure::InvalidAesGcmLayout)?;
            let tag = input
                .get(ciphertext_length..)
                .ok_or(StepFailure::InvalidAesGcmLayout)?;
            Ok(GcmInputParts {
                before_tag,
                after_tag: &[],
                tag,
            })
        }
        AesGcmTagLayout::Detached { tag_offset } => {
            let tag_end = tag_offset
                .checked_add(AES_GCM_TAG_BYTES)
                .ok_or(StepFailure::InvalidAesGcmLayout)?;
            let before_tag = input
                .get(..tag_offset)
                .ok_or(StepFailure::InvalidAesGcmLayout)?;
            let tag = input
                .get(tag_offset..tag_end)
                .ok_or(StepFailure::InvalidAesGcmLayout)?;
            let after_tag = input
                .get(tag_end..)
                .ok_or(StepFailure::InvalidAesGcmLayout)?;
            Ok(GcmInputParts {
                before_tag,
                after_tag,
                tag,
            })
        }
    }
}

fn authenticate_and_decrypt(
    plaintext: &mut [u8],
    key: &[u8],
    nonce: &Nonce<U12>,
    associated_data: &[u8],
    tag: &Tag,
) -> Result<(), StepFailure> {
    // The caller checks for a 128-bit or 256-bit key before reaching this point
    let result = if key.len() == 16 {
        let cipher =
            Aes128Gcm::new_from_slice(key).map_err(|_| StepFailure::InvalidAesGcmParameters)?;
        cipher.decrypt_inout_detached(nonce, associated_data, plaintext.into(), tag)
    } else {
        let cipher =
            Aes256Gcm::new_from_slice(key).map_err(|_| StepFailure::InvalidAesGcmParameters)?;
        cipher.decrypt_inout_detached(nonce, associated_data, plaintext.into(), tag)
    };
    result.map_err(|_| StepFailure::AuthenticatedDecryptionFailed)
}
