use l2_workbench::artifact::{self, ArtifactFormat, ArtifactReferenceKind};
use std::error::Error;

use super::support::{minimal_elf, minimal_pe};

#[test]
fn elf_sections_exact_file_ranges() -> Result<(), Box<dyn Error>> {
    let bytes = minimal_elf()?;
    let report = artifact::inspect(&bytes)?;

    assert_eq!(report.format, ArtifactFormat::Elf);
    assert_eq!(report.sha256, l2_workbench::sha256(&bytes));
    assert_eq!(report.bitness, 64);
    let entry = report.entrypoint.as_ref().ok_or("ELF entry is missing")?;
    assert_eq!(entry.address, 0x0040_0004);
    assert_eq!(entry.file_offset, Some(0x104));
    let text = report
        .sections
        .iter()
        .find(|section| section.name == ".text")
        .ok_or("ELF text section is missing")?;
    assert_eq!(text.file_offset, Some(0x100));
    assert_eq!(text.file_size, 16);
    let symbol = report
        .references
        .iter()
        .find(|reference| reference.name == "network_send")
        .ok_or("undefined ELF symbol is missing")?;
    assert_eq!(symbol.kind, ArtifactReferenceKind::Import);
    assert_eq!(symbol.record_range.offset, 0x160 + 48);
    assert!(symbol.name_range.is_some());
    Ok(())
}

#[test]
fn pe_imports_through_declared_sections() -> Result<(), Box<dyn Error>> {
    let bytes = minimal_pe()?;
    let report = artifact::inspect(&bytes)?;

    assert_eq!(report.format, ArtifactFormat::PortableExecutable);
    assert_eq!(report.bitness, 32);
    let entry = report.entrypoint.as_ref().ok_or("PE entry is missing")?;
    assert_eq!(entry.address, 0x0040_1000);
    assert_eq!(entry.file_offset, Some(0x200));
    let import = report
        .references
        .iter()
        .find(|reference| reference.kind == ArtifactReferenceKind::Import)
        .ok_or("PE import is missing")?;
    assert_eq!(import.name, "send_packet");
    assert_eq!(import.library.as_deref(), Some("sample.dll"));
    assert_eq!(import.record_range.offset, 0x2b0);
    assert_eq!(
        import
            .library_range
            .as_ref()
            .map(|range| (range.offset, range.length)),
        Some((0x280, 10))
    );
    assert_eq!(
        import
            .name_range
            .as_ref()
            .map(|range| (range.offset, range.length)),
        Some((0x2c2, 11))
    );
    Ok(())
}

#[test]
fn malformed_section_oversized_images_rejected() -> Result<(), Box<dyn Error>> {
    let mut elf = minimal_elf()?;
    super::support::put_u64(&mut elf, 40, 0x1_0000)?;
    assert!(matches!(
        artifact::inspect(&elf),
        Err(artifact::ArtifactError::InvalidRange { .. })
    ));

    let oversized = vec![0; artifact::MAX_ARTIFACT_BYTES + 1];
    assert!(matches!(
        artifact::inspect(&oversized),
        Err(artifact::ArtifactError::ArtifactTooLarge { .. })
    ));
    Ok(())
}

#[test]
fn non_elf_not_memory_size() -> Result<(), Box<dyn Error>> {
    let mut bytes = minimal_elf()?;
    super::support::put_u32(&mut bytes, 64, 4)?;
    super::support::put_u64(&mut bytes, 24, 0)?;
    super::support::put_u64(&mut bytes, 104, 0)?;

    let report = artifact::inspect(&bytes)?;

    assert!(report.entrypoint.is_none());
    assert!(
        report
            .sections
            .iter()
            .all(|section| !section.name.starts_with("LOAD["))
    );
    Ok(())
}
