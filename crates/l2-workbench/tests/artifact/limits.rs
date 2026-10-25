use l2_workbench::artifact::{self, ArtifactError, MAX_REFERENCES};
use std::error::Error;

use super::support::{minimal_pe, put_u32};

#[test]
fn pe_import_descriptor_exact_quota() -> Result<(), Box<dyn Error>> {
    let mut bytes = minimal_pe()?;
    bytes.resize(0x10_300, 0);
    let section = 0x98 + 224;
    put_u32(&mut bytes, section + 16, 0x10_100)?;
    put_u32(&mut bytes, 0x98 + 96 + 12, 60)?;

    for index in 0..MAX_REFERENCES {
        let offset = index
            .checked_mul(4)
            .and_then(|displacement| 0x2b0_usize.checked_add(displacement))
            .ok_or("fixture thunk offset overflow")?;
        put_u32(&mut bytes, offset, 0x10c0)?;
    }
    put_u32(&mut bytes, 0x254 + 12, 0x1080)?;
    let references = u32::try_from(MAX_REFERENCES)?;
    let empty_thunk_rva = references
        .checked_mul(4)
        .and_then(|displacement| 0x10b0_u32.checked_add(displacement))
        .ok_or("fixture thunk address overflow")?;
    put_u32(&mut bytes, 0x254 + 16, empty_thunk_rva)?;

    let report = artifact::inspect(&bytes)?;

    assert_eq!(report.references.len(), MAX_REFERENCES);
    Ok(())
}

#[test]
fn repeated_long_cannot_text_budget() -> Result<(), Box<dyn Error>> {
    let mut bytes = minimal_pe()?;
    bytes.resize(0x3_000, 0);
    let section = 0x98 + 224;
    put_u32(&mut bytes, section + 16, 0x2_e00)?;
    put_u32(&mut bytes, 0x240, 0x1300)?;
    put_u32(&mut bytes, 0x24c, 0x1600)?;
    put_u32(&mut bytes, 0x250, 0x1300)?;

    let mut long_name = vec![b'N'; 4_095];
    long_name.push(0);
    bytes
        .get_mut(0x800..0x800 + long_name.len())
        .ok_or("fixture library name range is outside the image")?
        .copy_from_slice(&long_name);
    bytes
        .get_mut(0x1802..0x1802 + long_name.len())
        .ok_or("fixture symbol name range is outside the image")?
        .copy_from_slice(&long_name);
    for index in 0..129_usize {
        let offset = index
            .checked_mul(4)
            .and_then(|displacement| 0x500_usize.checked_add(displacement))
            .ok_or("fixture thunk offset overflow")?;
        put_u32(&mut bytes, offset, 0x2600)?;
    }

    let result = artifact::inspect(&bytes);
    assert!(
        matches!(
            &result,
            Err(ArtifactError::LimitExceeded {
                field: "artifact reference text",
                maximum: 1_048_576,
            })
        ),
        "unexpected result: {result:?}"
    );
    Ok(())
}
