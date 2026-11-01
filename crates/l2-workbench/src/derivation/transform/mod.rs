mod bits;
mod bytes;
mod codec;
mod compression;
mod crypto;

use super::memory::{Admission, Buffer, BufferError};
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

pub(super) enum TransformError<E> {
    Step(StepFailure),
    Admission(E),
}

impl<E> From<StepFailure> for TransformError<E> {
    fn from(error: StepFailure) -> Self {
        Self::Step(error)
    }
}

impl<E> From<BufferError<E>> for TransformError<E> {
    fn from(error: BufferError<E>) -> Self {
        match error {
            BufferError::Allocation => Self::Step(StepFailure::AllocationFailed),
            BufferError::Admission(error) => Self::Admission(error),
        }
    }
}

pub(super) fn apply<A: Admission>(
    input: &[u8],
    operation: &Operation,
    budget: OutputBudget,
    admission: &A,
) -> Result<Buffer<A>, TransformError<A::Error>> {
    let output = dispatch(input, operation, budget, admission)?;
    check_output_size(output.bytes.len(), budget)?;
    Ok(output)
}

fn dispatch<A: Admission>(
    input: &[u8],
    operation: &Operation,
    budget: OutputBudget,
    admission: &A,
) -> Result<Buffer<A>, TransformError<A::Error>> {
    match operation {
        Operation::HexDecode {} => codec::hex_decode(input, budget, admission),
        Operation::HexEncode { case } => {
            untracked(admission, || codec::hex_encode(input, *case, budget))
        }
        Operation::Base64Decode { alphabet, padding } => {
            codec::base64_decode(input, *alphabet, *padding, budget, admission)
        }
        Operation::Base64Encode { alphabet, padding } => untracked(admission, || {
            codec::base64_encode(input, *alphabet, *padding, budget)
        }),
        Operation::XorRepeat { key, offset } => {
            untracked(admission, || bytes::xor_repeat(input, key, *offset, budget))
        }
        Operation::Sha256CounterXor {
            seed,
            initial_counter,
            counter_width,
            counter_byte_order,
            seed_order,
        } => untracked(admission, || {
            crypto::sha256_counter_xor(
                input,
                literal_operand(seed)?,
                *initial_counter,
                *counter_width,
                *counter_byte_order,
                *seed_order,
                budget,
            )
        }),
        Operation::AesGcmDecrypt {
            key,
            nonce,
            associated_data,
            tag_layout,
        } => untracked(admission, || {
            crypto::aes_gcm_decrypt(
                input,
                literal_operand(key)?,
                literal_operand(nonce)?,
                literal_operand(associated_data)?,
                *tag_layout,
                budget,
            )
        }),
        Operation::ScryptDerive {
            salt,
            log_n,
            r,
            p,
            output_length,
        } => untracked(admission, || {
            crypto::scrypt_derive(
                input,
                literal_operand(salt)?,
                *log_n,
                *r,
                *p,
                *output_length,
                budget,
            )
        }),
        Operation::ByteAdd { value } => {
            untracked(admission, || bytes::byte_add(input, *value, budget))
        }
        Operation::RotateBits { count } => {
            untracked(admission, || bytes::rotate_bits(input, *count, budget))
        }
        Operation::Slice { start, length } => {
            bytes::slice(input, *start, *length, budget, admission)
        }
        Operation::Select { indices } => {
            untracked(admission, || bytes::select(input, indices, budget))
        }
        Operation::SelectBits {
            indices,
            bits_per_byte,
        } => untracked(admission, || {
            bits::select_bits(input, indices, *bits_per_byte, budget)
        }),
        Operation::SelectBitRange {
            start_bit,
            bit_count,
            stride_bits,
            phase,
            bits_per_byte,
            remainder,
        } => untracked(admission, || {
            bits::select_bit_range(
                input,
                bits::BitWindow::new(*start_bit, *bit_count, *stride_bits, *phase),
                *bits_per_byte,
                *remainder,
                budget,
            )
        }),
        Operation::Reverse {} => untracked(admission, || bytes::reverse(input, budget)),
        Operation::Permute { indices } => {
            untracked(admission, || bytes::permute(input, indices, budget))
        }
        Operation::GzipDecompress {} => compression::gzip(input, budget, admission),
        Operation::ZlibDecompress {} => compression::zlib(input, budget, admission),
    }
}

fn untracked<A: Admission>(
    admission: &A,
    operation: impl FnOnce() -> Result<Vec<u8>, StepFailure>,
) -> Result<Buffer<A>, TransformError<A::Error>> {
    // Refuse operations whose temporary allocations have no admission model
    admission
        .reject_untracked_operation()
        .map_err(TransformError::Admission)?;
    let lease = admission.reserve(0).map_err(TransformError::Admission)?;
    Ok(Buffer::from_untracked(operation()?, lease))
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
