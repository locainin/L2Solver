use super::{ArtifactError, ArtifactFormat, ArtifactReport, MAX_ARTIFACT_BYTES, signatures};

const STATIC_LIMITATION: &str = "Header, section, symbol, and import facts are static file observations and do not establish runtime behavior";

/// Inspect a bounded PE or ELF image without executing it
///
/// # Errors
/// Returns an error for unsupported formats, malformed ranges, or resource-limit violations
pub fn inspect(bytes: &[u8]) -> Result<ArtifactReport, ArtifactError> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err(ArtifactError::ArtifactTooLarge {
            length: bytes.len(),
            maximum: MAX_ARTIFACT_BYTES,
        });
    }
    let mut report = match candidate_executable_format(bytes) {
        Some(ArtifactFormat::Elf) => super::elf::parse(bytes)?,
        Some(ArtifactFormat::PortableExecutable) => super::pe::parse(bytes)?,
        None => return Err(ArtifactError::UnsupportedFormat),
    };
    report.sha256 = crate::sha256(bytes);
    report.limitations.push(STATIC_LIMITATION);
    Ok(report)
}

/// Select the executable parser indicated by a literal leading signature
#[must_use]
pub fn candidate_executable_format(bytes: &[u8]) -> Option<ArtifactFormat> {
    if bytes.starts_with(signatures::ELF_MAGIC) {
        Some(ArtifactFormat::Elf)
    } else if bytes.starts_with(signatures::MZ_MAGIC) {
        Some(ArtifactFormat::PortableExecutable)
    } else {
        None
    }
}
