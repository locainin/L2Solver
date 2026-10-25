use super::{Family, KeyTestStatus, SearchLimit, SearchReport, keys};
use crate::derivation::{Base64Alphabet, Base64Padding, Operation};

pub(super) fn generate(input: &[u8], parent: usize, report: &mut SearchReport) -> Vec<Operation> {
    let mut operations = Vec::new();
    for family in &report.plan.families {
        match family {
            Family::Hex => operations.push(Operation::HexDecode {}),
            Family::Base64 => {
                for alphabet in [Base64Alphabet::Standard, Base64Alphabet::UrlSafe] {
                    for padding in [Base64Padding::Required, Base64Padding::Forbidden] {
                        operations.push(Operation::Base64Decode { alphabet, padding });
                    }
                }
            }
            Family::Gzip => operations.push(Operation::GzipDecompress {}),
            Family::Zlib => operations.push(Operation::ZlibDecompress {}),
            Family::Reverse => operations.push(Operation::Reverse {}),
            Family::SingleByteXor => {
                operations.extend((0..=u8::MAX).map(|byte| Operation::XorRepeat {
                    key: vec![byte],
                    offset: 0,
                }));
            }
            Family::ByteAdd => {
                operations.extend((0..=u8::MAX).map(|value| Operation::ByteAdd { value }));
            }
            Family::RotateBits => {
                operations.extend((0_u8..8).map(|count| Operation::RotateBits { count }));
            }
            Family::KnownPlaintextXor {
                offset,
                bytes,
                key_lengths,
            } => {
                for length in key_lengths {
                    if report.key_tests.len() == report.resources.max_key_tests {
                        super::engine::limit(
                            &mut report.limits,
                            &mut report.search_exhaustive_within_plan,
                            SearchLimit::KeyTests,
                        );
                        break;
                    }
                    let test = keys::test(input, parent, *offset, bytes, usize::from(*length));
                    if test.status == KeyTestStatus::Consistent {
                        operations.push(Operation::XorRepeat {
                            key: test.inferred_key.clone(),
                            offset: 0,
                        });
                    } else if test.status == KeyTestStatus::Untestable {
                        // Missing selected bytes leave this configured hypothesis unresolved
                        super::engine::limit(
                            &mut report.limits,
                            &mut report.search_exhaustive_within_plan,
                            SearchLimit::KnownPlaintextUnavailable,
                        );
                    }
                    report.key_tests.push(test);
                }
            }
        }
    }
    operations
}
