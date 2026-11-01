use crate::artifact::signatures::{count_file_signature_matches, matches_zip_signature};

#[test]
fn zip_selection_accepts_catalogue_prefixes_and_rejects_interior_or_partial_markers() {
    for prefix in [b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"] {
        assert!(
            matches_zip_signature(prefix),
            "expected ZIP prefix {prefix:?}"
        );
    }
    for source in [b"PK\x03".as_slice(), b"xPK\x03\x04", b"ordinary"] {
        assert!(
            !matches_zip_signature(source),
            "unexpected ZIP prefix in {source:?}"
        );
    }
}

#[test]
fn match_count_includes_catalogue_matches_and_ignores_unrelated_bytes() {
    assert_eq!(count_file_signature_matches(b"PK\x03\x04"), 1);
    assert_eq!(count_file_signature_matches(b"ordinary bytes"), 0);
    assert_eq!(count_file_signature_matches(b"xPK\x03\x04"), 0);
}

#[test]
fn match_count_follows_hdf5_offsets_and_iso_descriptor_terminators()
-> Result<(), Box<dyn std::error::Error>> {
    let mut hdf = vec![0; 1_032];
    for offset in [512, 1_024] {
        hdf.get_mut(offset..offset + 8)
            .ok_or("missing HDF5 fixture range")?
            .copy_from_slice(b"\x89HDF\r\n\x1a\n");
    }
    assert_eq!(count_file_signature_matches(&hdf), 2);

    let mut iso = vec![0; 19 * 2_048];
    for sector in [16, 17, 18] {
        let offset = sector * 2_048;
        iso.get_mut(offset + 1..offset + 6)
            .ok_or("missing ISO fixture range")?
            .copy_from_slice(b"CD001");
    }
    *iso.get_mut(17 * 2_048).ok_or("missing ISO terminator")? = u8::MAX;
    assert_eq!(count_file_signature_matches(&iso), 2);
    Ok(())
}
