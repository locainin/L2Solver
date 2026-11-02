use l2_workbench::artifact::{FileSignatureMatchKind, scan_file_signatures};
use std::error::Error;

const ISO_9660_LOGICAL_SECTOR_SIZE: usize = 2_048;

fn write_iso_9660_descriptor(
    bytes: &mut [u8],
    sector_number: usize,
    descriptor_type: u8,
) -> Result<(), Box<dyn Error>> {
    let start = sector_number * ISO_9660_LOGICAL_SECTOR_SIZE;
    let descriptor = bytes
        .get_mut(start..start + ISO_9660_LOGICAL_SECTOR_SIZE)
        .ok_or("ISO-9660 descriptor is outside the test fixture")?;
    *descriptor
        .first_mut()
        .ok_or("missing ISO-9660 descriptor type field")? = descriptor_type;
    descriptor
        .get_mut(1..6)
        .ok_or("missing ISO-9660 standard identifier field")?
        .copy_from_slice(b"CD001");
    *descriptor
        .get_mut(6)
        .ok_or("missing ISO-9660 descriptor version field")? = 1;
    Ok(())
}

#[test]
fn common_fixed_exact_byte_evidence() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![0_u8; 300];
    bytes
        .get_mut(..8)
        .ok_or("missing PNG prefix")?
        .copy_from_slice(b"\x89PNG\r\n\x1a\n");
    bytes
        .get_mut(257..265)
        .ok_or("missing tar signature range")?
        .copy_from_slice(b"ustar\x0000");

    let report = scan_file_signatures(&bytes);
    let png = report
        .matches
        .iter()
        .find(|candidate| candidate.rule_id == "png")
        .ok_or("PNG signature was not reported")?;
    assert_eq!((png.range.offset, png.range.length), (0, 8));
    assert_eq!(png.pattern_hex, "89 50 4e 47 0d 0a 1a 0a");
    assert_eq!(png.observed_hex, png.pattern_hex);
    assert_eq!(png.match_kind, FileSignatureMatchKind::Exact);
    assert_eq!(png.possible_formats, ["png"]);

    let tar = report
        .matches
        .iter()
        .find(|candidate| candidate.rule_id == "tar-ustar")
        .ok_or("tar signature was not reported")?;
    assert_eq!((tar.range.offset, tar.range.length), (257, 8));
    assert_eq!(tar.possible_formats, ["tar"]);
    let serialized = serde_json::to_value(tar)?;
    assert!(serialized.get("expected_offset").is_none());
    assert_eq!(report.source_sha256, l2_workbench::sha256(&bytes));
    assert_eq!(report.source_length, bytes.len());
    assert_eq!(report.catalogue.version, 2);
    assert_eq!(report.catalogue.rules_evaluated, 81);
    Ok(())
}

#[test]
fn tar_signatures_complete_published_variant() -> Result<(), Box<dyn Error>> {
    let variants: &[(&[u8], &str)] = &[
        (b"ustar\x0000", "tar-ustar"),
        (b"ustar  \0", "tar-ustar-gnu"),
    ];
    for (signature, expected_rule) in variants {
        let mut bytes = vec![0_u8; 265];
        bytes
            .get_mut(257..265)
            .ok_or("missing complete tar signature range")?
            .copy_from_slice(signature);
        let report = scan_file_signatures(&bytes);
        assert!(
            report
                .matches
                .iter()
                .any(|candidate| candidate.rule_id == *expected_rule),
            "complete {expected_rule} signature must be retained"
        );
    }

    let mut incomplete = vec![0_u8; 265];
    incomplete
        .get_mut(257..262)
        .ok_or("missing incomplete tar signature range")?
        .copy_from_slice(b"ustar");
    assert!(
        scan_file_signatures(&incomplete)
            .matches
            .iter()
            .all(|candidate| !candidate.rule_id.starts_with("tar-ustar")),
        "an incomplete tar prefix must not become a format candidate"
    );
    Ok(())
}

#[test]
fn masked_signature_observed_variable_bytes() -> Result<(), Box<dyn Error>> {
    let bytes = b"RIFF\x11\x22\x33\x44WAVEfmt ";
    let report = scan_file_signatures(bytes);
    let wave = report
        .matches
        .iter()
        .find(|candidate| candidate.rule_id == "riff-wave")
        .ok_or("RIFF/WAVE signature was not reported")?;

    assert_eq!(wave.match_kind, FileSignatureMatchKind::Masked);
    assert_eq!(wave.pattern_hex, "52 49 46 46 ?? ?? ?? ?? 57 41 56 45");
    assert_eq!(wave.observed_hex, "52 49 46 46 11 22 33 44 57 41 56 45");
    assert_eq!((wave.range.offset, wave.range.length), (0, 12));
    assert_eq!(wave.possible_formats, ["wave"]);

    let changed_fixed_byte = scan_file_signatures(b"RIFX\x11\x22\x33\x44WAVEfmt ");
    assert!(
        changed_fixed_byte
            .matches
            .iter()
            .all(|candidate| candidate.rule_id != "riff-wave")
    );
    Ok(())
}

#[test]
fn jpeg_subtypes_require_application_identifiers() -> Result<(), Box<dyn Error>> {
    let cases: &[(&[u8], &str, usize)] = &[
        (b"\xff\xd8\xff\xe0\x00\x10JFIF\x00", "jpeg-jfif", 11),
        (b"\xff\xd8\xff\xe1\x00\x16Exif\x00\x00", "jpeg-exif", 12),
    ];
    for (bytes, rule_id, expected_length) in cases {
        let report = scan_file_signatures(bytes);
        let candidate = report
            .matches
            .iter()
            .find(|candidate| candidate.rule_id == *rule_id)
            .ok_or_else(|| format!("{rule_id} signature was not reported"))?;
        assert_eq!(candidate.match_kind, FileSignatureMatchKind::Masked);
        assert_eq!(candidate.range.length, *expected_length);
    }

    for marker_without_identifier in [
        b"\xff\xd8\xff\xe0\x00\x10OTHER".as_slice(),
        b"\xff\xd8\xff\xe1\x00\x16OTHER\x00".as_slice(),
    ] {
        let report = scan_file_signatures(marker_without_identifier);
        assert!(
            report
                .matches
                .iter()
                .all(|candidate| !matches!(candidate.rule_id, "jpeg-jfif" | "jpeg-exif"))
        );
    }
    Ok(())
}

#[test]
fn current_mach_dex_magics_recognized() -> Result<(), Box<dyn Error>> {
    let cases: &[(&[u8], &str, &str)] = &[
        (b"\xca\xfe\xba\xbf", "mach-o-fat-64", "mach_o_fat_64"),
        (b"dex\n037\0", "dex-037", "dalvik_executable"),
        (b"dex\n038\0", "dex-038", "dalvik_executable"),
        (b"dex\n040\0", "dex-040", "dalvik_executable"),
        (b"dex\n041\0", "dex-041", "dalvik_executable_container"),
    ];

    for (bytes, rule_id, format) in cases {
        let report = scan_file_signatures(bytes);
        let candidate = report
            .matches
            .iter()
            .find(|candidate| candidate.rule_id == *rule_id)
            .ok_or_else(|| format!("{rule_id} signature was not reported"))?;
        assert!(candidate.possible_formats.contains(format));
        let expected_source = if *rule_id == "mach-o-fat-64" {
            "https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h"
        } else {
            "https://source.android.com/docs/core/runtime/dex-format"
        };
        assert_eq!(candidate.reference, expected_source);
    }
    Ok(())
}

#[test]
fn supported_nonzero_offset_declared_range() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![0_u8; 40_000];
    let cases: &[(usize, &[u8], &str)] = &[
        (4, b"ftypisom", "mp4-isom"),
        (128, b"DICM", "dicom"),
        (512, b"\x89HDF\r\n\x1a\n", "hdf5"),
        (32_769, b"CD001", "iso-9660"),
    ];
    for (offset, pattern, _) in cases {
        bytes
            .get_mut(*offset..offset + pattern.len())
            .ok_or("test signature range is outside the fixture")?
            .copy_from_slice(pattern);
    }

    let report = scan_file_signatures(&bytes);
    for (offset, pattern, rule_id) in cases {
        let candidate = report
            .matches
            .iter()
            .find(|candidate| candidate.rule_id == *rule_id)
            .ok_or_else(|| format!("{rule_id} signature was not reported"))?;
        assert_eq!(
            (candidate.range.offset, candidate.range.length),
            (*offset, pattern.len())
        );
    }
    Ok(())
}

#[test]
fn iso_9660_through_input_boundary() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![0_u8; 20 * ISO_9660_LOGICAL_SECTOR_SIZE];
    for sector_number in 16..=19 {
        let descriptor_type = if sector_number == 16 { 1 } else { 2 };
        write_iso_9660_descriptor(&mut bytes, sector_number, descriptor_type)?;
    }

    let report = scan_file_signatures(&bytes);
    let matches: Vec<_> = report
        .matches
        .iter()
        .filter(|candidate| candidate.rule_id == "iso-9660")
        .collect();
    let offsets: Vec<_> = matches
        .iter()
        .map(|candidate| candidate.range.offset)
        .collect();

    assert_eq!(
        offsets,
        [
            16 * ISO_9660_LOGICAL_SECTOR_SIZE + 1,
            17 * ISO_9660_LOGICAL_SECTOR_SIZE + 1,
            18 * ISO_9660_LOGICAL_SECTOR_SIZE + 1,
            19 * ISO_9660_LOGICAL_SECTOR_SIZE + 1,
        ]
    );
    assert!(matches.iter().all(|candidate| candidate.range.length == 5));
    assert!(
        matches
            .iter()
            .all(|candidate| candidate.description.contains("2048-byte"))
    );
    assert_eq!(
        matches
            .get(3)
            .ok_or("missing final ISO-9660 descriptor match")?
            .reference,
        "https://ecma-international.org/wp-content/uploads/ECMA-119_6th_edition_december_2025.pdf"
    );
    Ok(())
}

#[test]
fn iso_9660_proper_descriptor_terminator() -> Result<(), Box<dyn Error>> {
    let mut bytes = vec![0_u8; 22 * ISO_9660_LOGICAL_SECTOR_SIZE];
    for sector_number in 16..=19 {
        let descriptor_type = if sector_number == 16 { 1 } else { 2 };
        write_iso_9660_descriptor(&mut bytes, sector_number, descriptor_type)?;
    }
    write_iso_9660_descriptor(&mut bytes, 20, u8::MAX)?;
    write_iso_9660_descriptor(&mut bytes, 21, 2)?;

    let report = scan_file_signatures(&bytes);
    let offsets: Vec<_> = report
        .matches
        .iter()
        .filter(|candidate| candidate.rule_id == "iso-9660")
        .map(|candidate| candidate.range.offset)
        .collect();

    assert_eq!(
        offsets,
        [
            16 * ISO_9660_LOGICAL_SECTOR_SIZE + 1,
            17 * ISO_9660_LOGICAL_SECTOR_SIZE + 1,
            18 * ISO_9660_LOGICAL_SECTOR_SIZE + 1,
            19 * ISO_9660_LOGICAL_SECTOR_SIZE + 1,
            20 * ISO_9660_LOGICAL_SECTOR_SIZE + 1,
        ]
    );
    Ok(())
}

#[test]
fn hdf5_signature_offsets() -> Result<(), Box<dyn Error>> {
    const OFFSET: usize = 16_777_216;
    const SIGNATURE: &[u8] = b"\x89HDF\r\n\x1a\n";
    let mut bytes = vec![0_u8; OFFSET + SIGNATURE.len()];
    bytes
        .get_mut(OFFSET..)
        .ok_or("missing HDF5 signature range")?
        .copy_from_slice(SIGNATURE);

    let report = scan_file_signatures(&bytes);
    let candidate = report
        .matches
        .iter()
        .find(|candidate| candidate.rule_id == "hdf5")
        .ok_or("HDF5 signature at the next power-of-two offset was not reported")?;
    assert_eq!(
        (candidate.range.offset, candidate.range.length),
        (OFFSET, 8)
    );
    Ok(())
}

#[test]
fn nonzero_offset_rules_truncated_boundaries() -> Result<(), Box<dyn Error>> {
    let cases: &[(usize, &[u8], &str)] = &[
        (4, b"ftypisom", "mp4-isom"),
        (128, b"DICM", "dicom"),
        (512, b"\x89HDF\r\n\x1a\n", "hdf5"),
        (32_769, b"CD001", "iso-9660"),
    ];

    for (offset, pattern, rule_id) in cases {
        let mut bytes = vec![0_u8; offset + pattern.len() - 1];
        let available = pattern.len() - 1;
        let destination = bytes
            .get_mut(*offset..)
            .ok_or("fixture offset must be inside its allocation")?;
        let prefix = pattern
            .get(..available)
            .ok_or("available length must be inside the signature")?;
        destination.copy_from_slice(prefix);
        let report = scan_file_signatures(&bytes);
        assert!(
            report
                .matches
                .iter()
                .all(|candidate| candidate.rule_id != *rule_id),
            "{rule_id} matched a truncated signature"
        );
    }
    Ok(())
}

#[test]
fn shared_signature_every_supported_interpretation() -> Result<(), Box<dyn Error>> {
    let report = scan_file_signatures(b"\xca\xfe\xba\xbe\x00\x00\x00\x34");
    let shared = report
        .matches
        .iter()
        .find(|candidate| candidate.rule_id == "cafebabe")
        .ok_or("shared signature was not reported")?;

    assert!(shared.ambiguous);
    assert_eq!(shared.possible_formats, ["java_class", "mach_o_fat"]);
    assert!(shared.interpretation.contains("candidate"));
    Ok(())
}

#[test]
fn signatures_declared_offsets_complete_patterns() -> Result<(), Box<dyn Error>> {
    let misplaced = scan_file_signatures(b"x\x89PNG\r\n\x1a\n");
    assert!(
        misplaced
            .matches
            .iter()
            .all(|candidate| candidate.rule_id != "png")
    );

    let truncated = scan_file_signatures(b"\x89PNG\r\n\x1a");
    assert_eq!(truncated.matches.len(), 0);

    let mut misplaced_tar = vec![0_u8; 300];
    misplaced_tar
        .get_mut(258..263)
        .ok_or("test range is outside the allocated fixture")?
        .copy_from_slice(b"ustar");
    let report = scan_file_signatures(&misplaced_tar);
    assert!(
        report
            .matches
            .iter()
            .all(|candidate| candidate.rule_id != "tar-ustar")
    );
    Ok(())
}

#[test]
fn container_signatures_not_unparsed_subtype() -> Result<(), Box<dyn Error>> {
    let zip = scan_file_signatures(b"PK\x03\x04ordinary container bytes");
    let candidate = zip
        .matches
        .iter()
        .find(|candidate| candidate.rule_id == "zip-local-file")
        .ok_or("ZIP container signature was not reported")?;

    assert_eq!(candidate.possible_formats, ["zip_container"]);
    assert!(!candidate.possible_formats.contains(&"docx"));
    assert!(!candidate.possible_formats.contains(&"apk"));
    assert!(candidate.interpretation.contains("does not prove"));
    Ok(())
}
