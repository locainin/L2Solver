use l2_workbench::artifact::{ArtifactBoundaryEvidence, ArtifactValidationFormat};

pub(super) fn is_recovery_byte_child_kind(kind: &str) -> bool {
    matches!(
        kind,
        "archive_member" | "png_chunk_payload" | "png_trailing_data" | "der_value"
    )
}

pub(super) const fn validation_format(format: ArtifactValidationFormat) -> &'static str {
    match format {
        ArtifactValidationFormat::Der => "der",
        ArtifactValidationFormat::Elf => "elf",
        ArtifactValidationFormat::PortableExecutable => "portable_executable",
        ArtifactValidationFormat::Png => "png",
        ArtifactValidationFormat::Zip => "zip",
    }
}

pub(super) const fn validation_boundary(boundary: ArtifactBoundaryEvidence) -> &'static str {
    match boundary {
        ArtifactBoundaryEvidence::PngIend => "png_iend",
        ArtifactBoundaryEvidence::DerEncodedLength => "der_encoded_length",
        ArtifactBoundaryEvidence::ZipEndRecord => "zip_end_record",
    }
}
