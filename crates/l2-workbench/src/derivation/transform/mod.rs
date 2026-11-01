mod bits;
mod bytes;
mod codec;
mod compression;
mod crypto;

use super::{CounterByteOrder, CounterWidth, OperandRef, Operation, SeedCounterOrder, StepFailure};

pub use bits::select_bit_plane_chunks;
pub(super) use codec::base64_engine;

pub(super) fn crypto_work_overhead(input_length: usize, operation: &Operation) -> Option<usize> {
    crypto::work_overhead(input_length, operation)
}

pub fn sha256_counter_xor_work(
    input_length: usize,
    seed_length: usize,
    counter_width: CounterWidth,
) -> Option<usize> {
    crypto::sha256_counter_xor_work(input_length, seed_length, counter_width)
}

pub fn validate_sha256_counter_xor_capacity(
    input_length: usize,
    initial_counter: u64,
    counter_width: CounterWidth,
) -> Result<(), StepFailure> {
    crypto::validate_sha256_counter_xor_capacity(input_length, initial_counter, counter_width)
}

/// Apply the canonical SHA-256 counter-XOR primitive to one bounded byte prefix
pub fn preview_sha256_counter_xor(
    input: &[u8],
    seed: &[u8],
    initial_counter: u64,
    counter_width: CounterWidth,
    counter_byte_order: CounterByteOrder,
    seed_order: SeedCounterOrder,
) -> Result<Vec<u8>, StepFailure> {
    crypto::sha256_counter_xor(
        input,
        seed,
        initial_counter,
        counter_width,
        counter_byte_order,
        seed_order,
        OutputBudget {
            remaining_intermediate: input.len(),
            max_output: input.len(),
            max_intermediate: input.len(),
            max_key_bytes: seed.len(),
        },
    )
}

#[derive(Clone, Copy)]
pub(super) struct OutputBudget {
    pub remaining_intermediate: usize,
    pub max_output: usize,
    pub max_intermediate: usize,
    pub max_key_bytes: usize,
}

pub(super) fn apply(
    input: &[u8],
    operation: &Operation,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    let output = dispatch(input, operation, budget)?;
    check_output_size(output.len(), budget)?;
    Ok(output)
}

fn dispatch(
    input: &[u8],
    operation: &Operation,
    budget: OutputBudget,
) -> Result<Vec<u8>, StepFailure> {
    match operation {
        Operation::HexDecode {} => codec::hex_decode(input, budget),
        Operation::HexEncode { case } => codec::hex_encode(input, *case, budget),
        Operation::Base64Decode { alphabet, padding } => {
            codec::base64_decode(input, *alphabet, *padding, budget)
        }
        Operation::Base64Encode { alphabet, padding } => {
            codec::base64_encode(input, *alphabet, *padding, budget)
        }
        Operation::XorRepeat { key, offset } => bytes::xor_repeat(input, key, *offset, budget),
        Operation::Sha256CounterXor {
            seed,
            initial_counter,
            counter_width,
            counter_byte_order,
            seed_order,
        } => crypto::sha256_counter_xor(
            input,
            literal_operand(seed)?,
            *initial_counter,
            *counter_width,
            *counter_byte_order,
            *seed_order,
            budget,
        ),
        Operation::AesGcmDecrypt {
            key,
            nonce,
            associated_data,
            tag_layout,
        } => crypto::aes_gcm_decrypt(
            input,
            literal_operand(key)?,
            literal_operand(nonce)?,
            literal_operand(associated_data)?,
            *tag_layout,
            budget,
        ),
        Operation::ScryptDerive {
            salt,
            log_n,
            r,
            p,
            output_length,
        } => crypto::scrypt_derive(
            input,
            literal_operand(salt)?,
            *log_n,
            *r,
            *p,
            *output_length,
            budget,
        ),
        Operation::ByteAdd { value } => bytes::byte_add(input, *value, budget),
        Operation::RotateBits { count } => bytes::rotate_bits(input, *count, budget),
        Operation::Slice { start, length } => bytes::slice(input, *start, *length, budget),
        Operation::Select { indices } => bytes::select(input, indices, budget),
        Operation::SelectBits {
            indices,
            bits_per_byte,
        } => bits::select_bits(input, indices, *bits_per_byte, budget),
        Operation::SelectBitRange {
            start_bit,
            bit_count,
            stride_bits,
            phase,
            bits_per_byte,
            remainder,
        } => bits::select_bit_range(
            input,
            bits::BitWindow::new(*start_bit, *bit_count, *stride_bits, *phase),
            *bits_per_byte,
            *remainder,
            budget,
        ),
        Operation::Reverse {} => bytes::reverse(input, budget),
        Operation::Permute { indices } => bytes::permute(input, indices, budget),
        Operation::GzipDecompress {} => compression::gzip(input, budget),
        Operation::ZlibDecompress {} => compression::zlib(input, budget),
    }
}

fn literal_operand(operand: &OperandRef) -> Result<&[u8], StepFailure> {
    operand
        .as_literal_bytes()
        .ok_or(StepFailure::OperandRequiresCase)
}

pub(super) const fn check_output_size(
    length: usize,
    budget: OutputBudget,
) -> Result<(), StepFailure> {
    if length > budget.max_output {
        return Err(StepFailure::OutputLimitExceeded {
            limit: budget.max_output,
        });
    }
    if length > budget.remaining_intermediate {
        return Err(StepFailure::IntermediateBudgetExceeded {
            limit: budget.max_intermediate,
        });
    }
    Ok(())
}
