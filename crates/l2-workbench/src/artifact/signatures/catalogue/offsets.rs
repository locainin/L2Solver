//! Signatures defined at nonzero format offsets

use super::{Pattern, SignatureOffsets, SignatureRule, exact_rule};

const START: &[usize] = &[0];
const OFFSET_128: &[usize] = &[128];

pub(super) static RULES: &[SignatureRule] = &[
    // Formats with nonzero identifiers are evaluated only at format-defined offsets
    exact_rule!(
        "dicom",
        "DICOM file marker",
        &["dicom"],
        &["dcm"],
        &["application/dicom"],
        OFFSET_128,
        b"DICM",
        false
    ),
    SignatureRule {
        id: "iso-9660",
        description: "ISO 9660 volume descriptor identifier in a 2048-byte logical-sector image",
        formats: &["iso_9660"],
        extensions: &["iso"],
        media_types: &["application/x-iso9660-image"],
        reference: "https://ecma-international.org/wp-content/uploads/ECMA-119_6th_edition_december_2025.pdf",
        offsets: SignatureOffsets::Iso9660VolumeDescriptors,
        pattern: Pattern::Exact(b"CD001"),
        ambiguous: false,
    },
    SignatureRule {
        id: "hdf5",
        description: "Hierarchical Data Format version 5",
        formats: &["hdf5"],
        extensions: &["h5", "hdf5"],
        media_types: &["application/x-hdf5"],
        reference: "https://portal.hdfgroup.org/documentation/hdf5/latest/_f_m_t1.html",
        offsets: SignatureOffsets::Hdf5Superblocks,
        pattern: Pattern::Exact(b"\x89HDF\r\n\x1a\n"),
        ambiguous: false,
    },
    exact_rule!(
        "rpm",
        "RPM package",
        &["rpm"],
        &["rpm"],
        &["application/x-rpm"],
        START,
        b"\xed\xab\xee\xdb",
        false
    ),
];
