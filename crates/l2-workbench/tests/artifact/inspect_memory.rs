use std::{error::Error, mem::size_of};

use crate::{
    artifact::{
        ArtifactError, ArtifactReference, ArtifactReport, ArtifactSection, FileMapping,
        elf::SectionHeader,
        inspect::{InspectMemoryError, inspect, inspect_with_memory, legacy_error},
        test_support as support,
    },
    job::{MemoryBudget, MemoryClass, MemoryError},
};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn legacy_inspection_maps_allocator_failure_to_an_explicit_artifact_error() {
    assert_eq!(
        legacy_error(InspectMemoryError::Allocation),
        ArtifactError::AllocationFailure
    );
}

fn retained_report_bytes(report: &ArtifactReport) -> usize {
    report.sha256.capacity()
        + report.architecture.capacity()
        + report.sections.capacity() * size_of::<ArtifactSection>()
        + report.mappings.capacity() * size_of::<FileMapping>()
        + report.references.capacity() * size_of::<ArtifactReference>()
        + report.limitations.capacity() * size_of::<&'static str>()
        + report
            .sections
            .iter()
            .map(|section| section.name.capacity())
            .sum::<usize>()
        + report
            .references
            .iter()
            .map(|reference| {
                reference.name.capacity() + reference.library.as_ref().map_or(0, String::capacity)
            })
            .sum::<usize>()
}

#[test]
fn tiny_pe_and_elf_reports_fit_small_budgets_and_keep_their_charges() -> TestResult {
    for image in [support::minimal_pe()?, support::minimal_elf()?] {
        let expected = inspect(&image)?;
        let budget = MemoryBudget::new(16_384);
        let mut lease = budget.try_reserve(MemoryClass::Executor, 37)?;
        let report = inspect_with_memory(&image, &mut lease)?;

        assert_eq!(report, expected);
        assert_eq!(
            lease.bytes(),
            37 + u64::try_from(retained_report_bytes(&report))?
        );
        assert_eq!(budget.snapshot()?.used_bytes, lease.bytes());
        assert!(budget.snapshot()?.peak_bytes < 16_384);

        drop(report);
        drop(lease);
        assert_eq!(budget.snapshot()?.used_bytes, 0);
    }
    Ok(())
}

#[test]
fn missing_signature_is_rejected_without_admission() -> TestResult {
    let budget = MemoryBudget::new(0);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    for bytes in [b"".as_slice(), b"not an executable".as_slice()] {
        assert!(matches!(
            inspect_with_memory(bytes, &mut lease),
            Err(InspectMemoryError::Format(ArtifactError::UnsupportedFormat))
        ));
        assert_eq!(lease.bytes(), 0);
        assert_eq!(budget.snapshot()?.rejected, 0);
    }
    Ok(())
}

#[test]
fn empty_elf_tables_do_not_reserve_section_or_symbol_ceilings() -> TestResult {
    let mut image = support::minimal_elf()?;
    support::put_u64(&mut image, 24, 0)?;
    support::put_u64(&mut image, 40, 0)?;
    support::put_u16(&mut image, 56, 0)?;
    support::put_u16(&mut image, 60, 0)?;
    support::put_u16(&mut image, 62, 0)?;
    let budget = MemoryBudget::new(512);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut lease)?;
    assert!(report.sections.is_empty());
    assert!(report.mappings.is_empty());
    assert!(report.references.is_empty());
    assert_eq!(report, inspect(&image)?);
    assert!(budget.snapshot()?.peak_bytes < 512);
    Ok(())
}

#[test]
fn denied_growth_restores_the_existing_charge_for_each_format() -> TestResult {
    for image in [support::minimal_pe()?, support::minimal_elf()?] {
        let budget = MemoryBudget::new(32);
        let mut lease = budget.try_reserve(MemoryClass::Executor, 17)?;
        let result = inspect_with_memory(&image, &mut lease);

        assert!(matches!(
            result,
            Err(InspectMemoryError::Memory(MemoryError::Limit { .. }))
        ));
        assert_eq!(lease.bytes(), 17);
        assert_eq!(budget.snapshot()?.used_bytes, 17);
    }
    Ok(())
}

#[test]
fn malformed_elf_releases_partial_sections_and_preserves_the_format_error() -> TestResult {
    let mut image = support::minimal_elf()?;
    support::put_u32(&mut image, 0x200 + 4 * 64, 999)?;
    let expected = inspect(&image)
        .err()
        .ok_or("fixture must have an invalid section name")?;
    let budget = MemoryBudget::new(16_384);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 23)?;

    let result = inspect_with_memory(&image, &mut lease);
    assert!(matches!(result, Err(InspectMemoryError::Format(error)) if error == expected));
    assert_eq!(lease.bytes(), 23);
    assert_eq!(budget.snapshot()?.used_bytes, 23);
    assert!(budget.snapshot()?.peak_bytes > 23);
    Ok(())
}

#[test]
fn malformed_pe_releases_partial_imports_and_preserves_the_format_error() -> TestResult {
    let mut image = support::minimal_pe()?;
    support::put_u32(&mut image, 0x254 + 12, 0x1080)?;
    let expected = inspect(&image)
        .err()
        .ok_or("fixture must have an invalid import descriptor")?;
    let budget = MemoryBudget::new(16_384);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 23)?;

    let result = inspect_with_memory(&image, &mut lease);
    assert!(matches!(result, Err(InspectMemoryError::Format(error)) if error == expected));
    assert_eq!(lease.bytes(), 23);
    assert_eq!(budget.snapshot()?.used_bytes, 23);
    assert!(budget.snapshot()?.peak_bytes > 23);
    Ok(())
}

#[test]
fn long_import_name_needs_more_memory_than_the_same_short_import() -> TestResult {
    let short = support::minimal_pe()?;
    let probe = MemoryBudget::new(32_768);
    let mut probe_lease = probe.try_reserve(MemoryClass::Executor, 0)?;
    let short_report = inspect_with_memory(&short, &mut probe_lease)?;
    let short_peak = probe.snapshot()?.peak_bytes;
    drop(short_report);
    drop(probe_lease);

    let mut long = short;
    let start = 0x2c2;
    long.resize(start + 4_096, 0);
    long.get_mut(start..start + 4_095)
        .ok_or("long import name is outside fixture")?
        .fill(b'N');

    let budget = MemoryBudget::new(short_peak);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let result = inspect_with_memory(&long, &mut lease);
    assert!(matches!(
        result,
        Err(InspectMemoryError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(lease.bytes(), 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn invalid_utf8_names_match_standard_lossy_decoding() -> TestResult {
    let mut image = support::minimal_pe()?;
    let section_name = [b'x', 0xff, 0xfe, 0xf0, 0x9f];
    let import_name = [b'Q', 0xc2, 0x80, 0xff, 0xfe, 0xf0, 0x9f, b'Y'];
    let section = 0x98 + 224;
    image
        .get_mut(section..section + 8)
        .ok_or("PE section name is outside fixture")?
        .fill(0);
    image
        .get_mut(section..section + section_name.len())
        .ok_or("PE section name is outside fixture")?
        .copy_from_slice(&section_name);
    image
        .get_mut(0x2c2..0x2c2 + import_name.len() + 1)
        .ok_or("PE import name is outside fixture")?
        .fill(0);
    image
        .get_mut(0x2c2..0x2c2 + import_name.len())
        .ok_or("PE import name is outside fixture")?
        .copy_from_slice(&import_name);

    let budget = MemoryBudget::new(16_384);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut lease)?;
    let section = report.sections.first().ok_or("expected a PE section")?;
    let import = report.references.first().ok_or("expected a PE import")?;
    assert_eq!(section.name, String::from_utf8_lossy(&section_name));
    assert_eq!(import.name, String::from_utf8_lossy(&import_name));
    Ok(())
}

#[test]
fn zero_ordinal_and_unknown_machine_names_remain_well_formed() -> TestResult {
    let mut image = support::minimal_pe()?;
    support::put_u16(&mut image, 0x84, 0)?;
    support::put_u32(&mut image, 0x2b0, 0x8000_0000)?;
    let budget = MemoryBudget::new(16_384);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut lease)?;
    assert_eq!(report.architecture, "pe_machine_0");
    assert_eq!(
        report.references.first().map(|record| record.name.as_str()),
        Some("#0")
    );
    assert_eq!(report, inspect(&image)?);
    Ok(())
}

#[test]
fn additional_elf_section_headers_are_admitted_before_their_storage_grows() -> TestResult {
    let small = support::minimal_elf()?;
    let probe = MemoryBudget::new(32_768);
    let mut probe_lease = probe.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&small, &mut probe_lease)?;
    let small_peak = probe.snapshot()?.peak_bytes;
    drop(report);
    drop(probe_lease);

    let mut larger = small;
    larger.resize(0x200 + 50 * 64, 0);
    support::put_u16(&mut larger, 60, 50)?;
    let budget = MemoryBudget::new(small_peak);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let result = inspect_with_memory(&larger, &mut lease);
    assert!(matches!(
        result,
        Err(InspectMemoryError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(lease.bytes(), 0);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn elf_map_and_output_vector_overlap_in_the_peak_charge() -> TestResult {
    let image = support::minimal_elf()?;
    let budget = MemoryBudget::new(32_768);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut lease)?;
    let map_node =
        crate::allocation::btree_node_bytes::<(u8, String, Option<u64>), ArtifactReference>()
            .ok_or("ELF symbol index charge overflow")?;
    let overlapping = map_node
        + 5 * size_of::<SectionHeader>()
        + 5 * size_of::<ArtifactSection>()
        + 2 * size_of::<ArtifactReference>();
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(overlapping)?);
    assert_eq!(report.references.len(), 2);
    assert_eq!(budget.snapshot()?.used_bytes, lease.bytes());
    Ok(())
}

#[test]
fn pe_import_vector_replacement_requires_both_buffers_to_fit() -> TestResult {
    let mut image = support::minimal_pe()?;
    support::put_u32(&mut image, 0x240, 0x1100)?;
    for index in 0..6 {
        support::put_u32(&mut image, 0x300 + index * 4, 0x10c0)?;
    }
    let budget = MemoryBudget::new(32_768);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut lease)?;
    assert_eq!(report.references.len(), 6);
    let minimum_overlap = 12 * size_of::<ArtifactReference>() + 5 * (11 + 10);
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(minimum_overlap)?);
    let retained = lease.bytes();
    drop(report);
    drop(lease);

    let tight = MemoryBudget::new(retained);
    let mut lease = tight.try_reserve(MemoryClass::Executor, 0)?;
    let result = inspect_with_memory(&image, &mut lease);
    assert!(matches!(
        result,
        Err(InspectMemoryError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(lease.bytes(), 0);
    assert_eq!(tight.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn pe_export_and_import_vectors_overlap_and_keep_source_order() -> TestResult {
    let image = pe_with_export_and_import()?;
    let budget = MemoryBudget::new(16_384);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut lease)?;
    let names = report
        .references
        .iter()
        .map(|reference| reference.name.as_str())
        .collect::<Vec<_>>();
    assert_eq!(names, ["exported", "send_packet"]);
    let overlapping = 9 * size_of::<ArtifactReference>() + 8 + 11 + 10;
    assert!(budget.snapshot()?.peak_bytes >= u64::try_from(overlapping)?);
    assert_eq!(report, inspect(&image)?);
    Ok(())
}

#[test]
fn pe_invalid_export_ordinal_releases_the_partial_report() -> TestResult {
    let mut image = pe_with_export_and_import()?;
    support::put_u16(&mut image, 0x338, 1)?;
    let budget = MemoryBudget::new(16_384);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 13)?;
    assert!(matches!(
        inspect_with_memory(&image, &mut lease),
        Err(InspectMemoryError::Format(ArtifactError::InvalidHeader {
            field: "PE export ordinal"
        }))
    ));
    assert_eq!(lease.bytes(), 13);
    assert_eq!(budget.snapshot()?.used_bytes, 13);
    Ok(())
}

fn pe_with_export_and_import() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut image = support::minimal_pe()?;
    support::put_u32(&mut image, 0x98 + 96, 0x1100)?;
    support::put_u32(&mut image, 0x98 + 96 + 4, 40)?;
    support::put_u32(&mut image, 0x300 + 20, 1)?;
    support::put_u32(&mut image, 0x300 + 24, 1)?;
    support::put_u32(&mut image, 0x300 + 28, 0x1130)?;
    support::put_u32(&mut image, 0x300 + 32, 0x1134)?;
    support::put_u32(&mut image, 0x300 + 36, 0x1138)?;
    support::put_u32(&mut image, 0x330, 0x1000)?;
    support::put_u32(&mut image, 0x334, 0x1140)?;
    image
        .get_mut(0x340..0x349)
        .ok_or("PE export name is outside fixture")?
        .copy_from_slice(b"exported\0");
    Ok(image)
}

#[test]
fn retained_input_and_report_are_charged_at_the_same_time() -> TestResult {
    let image = support::minimal_pe()?;
    let budget = MemoryBudget::new(16_384);
    let input_bytes = u64::try_from(image.capacity())?;
    let input = budget.try_reserve(MemoryClass::Base, input_bytes)?;
    let mut output = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut output)?;

    assert!(output.bytes() >= u64::try_from(retained_report_bytes(&report))?);
    assert_eq!(budget.snapshot()?.used_bytes, input_bytes + output.bytes());
    assert!(budget.snapshot()?.peak_bytes >= input_bytes + output.bytes());
    drop(report);
    drop(output);
    assert_eq!(budget.snapshot()?.used_bytes, input_bytes);
    drop(input);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn existing_report_survives_a_second_inspection_denied_by_shared_pressure() -> TestResult {
    let image = support::minimal_pe()?;
    let budget = MemoryBudget::new(16_384);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 11)?;
    let report = inspect_with_memory(&image, &mut lease)?;
    let before = lease.bytes();
    let blocker = budget.try_reserve(MemoryClass::Base, 16_384 - before)?;

    let result = inspect_with_memory(&image, &mut lease);
    assert!(matches!(
        result,
        Err(InspectMemoryError::Memory(MemoryError::Limit { .. }))
    ));
    assert_eq!(lease.bytes(), before);
    assert_eq!(budget.snapshot()?.used_bytes, 16_384);
    assert_eq!(report, inspect(&image)?);
    drop(report);
    drop(blocker);
    Ok(())
}

#[test]
fn reserved_worker_credit_allows_inspection_when_the_root_budget_is_full() -> TestResult {
    let image = support::minimal_elf()?;
    let budget = MemoryBudget::new(65_536);
    let work = budget.try_working_set(16_384)?;
    let snapshot = budget.snapshot()?;
    let blocker = budget.try_reserve(
        MemoryClass::Base,
        snapshot.limit_bytes - snapshot.used_bytes - snapshot.working_sets.reserved_bytes,
    )?;
    let mut lease = work.budget().try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut lease)?;

    assert_eq!(report, inspect(&image)?);
    let snapshot = budget.snapshot()?;
    assert_eq!(
        snapshot.used_bytes + snapshot.working_sets.reserved_bytes,
        65_536
    );
    assert_eq!(snapshot.rejected, 0);
    drop(report);
    drop(lease);
    drop(blocker);
    drop(work);
    assert_eq!(budget.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn duplicate_elf_symbols_keep_the_first_record_and_count_unique_text_once() -> TestResult {
    let (image, symbol_start) = repeated_long_elf_symbols(false)?;

    let expected = inspect(&image)?;
    assert_eq!(expected.references.len(), 1);
    let first = expected
        .references
        .first()
        .ok_or("expected an ELF symbol")?;
    assert_eq!(first.record_range.offset, symbol_start + 24);
    assert_eq!(first.name.len(), 4_095);
    let budget = MemoryBudget::new(32_768);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut lease)?;
    assert_eq!(report, expected);
    assert!(budget.snapshot()?.peak_bytes < 32_768);
    Ok(())
}

#[test]
fn distinct_elf_symbols_still_enforce_the_reference_text_limit() -> TestResult {
    let (image, _) = repeated_long_elf_symbols(true)?;
    let expected = ArtifactError::LimitExceeded {
        field: "artifact reference text",
        maximum: 1_048_576,
    };
    assert_eq!(inspect(&image).err(), Some(expected.clone()));
    let budget = MemoryBudget::new(8 * 1024 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 29)?;
    assert!(matches!(
        inspect_with_memory(&image, &mut lease),
        Err(InspectMemoryError::Format(error)) if error == expected
    ));
    assert_eq!(lease.bytes(), 29);
    assert_eq!(budget.snapshot()?.used_bytes, 29);
    Ok(())
}

fn repeated_long_elf_symbols(distinct_addresses: bool) -> Result<(Vec<u8>, usize), Box<dyn Error>> {
    let mut image = support::minimal_elf()?;
    let symbol_start = 0x400_usize;
    let duplicate_count = 257_usize;
    let symbol_bytes = (duplicate_count + 1) * 24;
    let string_start = symbol_start + symbol_bytes;
    image.resize(string_start + 4_097, 0);
    support::put_u64(
        &mut image,
        0x200 + 3 * 64 + 24,
        u64::try_from(symbol_start)?,
    )?;
    support::put_u64(
        &mut image,
        0x200 + 3 * 64 + 32,
        u64::try_from(symbol_bytes)?,
    )?;
    support::put_u64(
        &mut image,
        0x200 + 4 * 64 + 24,
        u64::try_from(string_start)?,
    )?;
    support::put_u64(&mut image, 0x200 + 4 * 64 + 32, 4_097)?;
    image
        .get_mut(string_start + 1..string_start + 4_096)
        .ok_or("symbol string table is outside fixture")?
        .fill(b'S');
    for index in 1..=duplicate_count {
        let offset = symbol_start + index * 24;
        support::put_u32(&mut image, offset, 1)?;
        support::put_u16(&mut image, offset + 6, 1)?;
        let address = if distinct_addresses {
            0x0040_0004 + u64::try_from(index)?
        } else {
            0x0040_0004
        };
        support::put_u64(&mut image, offset + 8, address)?;
    }
    Ok((image, symbol_start))
}

#[test]
fn maximum_elf_symbols_remain_sorted_with_admitted_index_growth() -> TestResult {
    let mut image = support::minimal_elf()?;
    let symbol_start = 0x400_usize;
    let symbol_count = crate::artifact::MAX_REFERENCES;
    let symbol_bytes = symbol_count * 24;
    let string_start = symbol_start + symbol_bytes;
    image.resize(string_start, 0);
    let mut strings = vec![0];
    for index in 1..symbol_count {
        let name = format!("sym{index:05}");
        let offset = symbol_start + index * 24;
        support::put_u32(&mut image, offset, u32::try_from(strings.len())?)?;
        support::put_u16(&mut image, offset + 6, 1)?;
        support::put_u64(&mut image, offset + 8, 0x0040_0004)?;
        strings.extend_from_slice(name.as_bytes());
        strings.push(0);
    }
    support::put_u64(
        &mut image,
        0x200 + 3 * 64 + 24,
        u64::try_from(symbol_start)?,
    )?;
    support::put_u64(
        &mut image,
        0x200 + 3 * 64 + 32,
        u64::try_from(symbol_bytes)?,
    )?;
    support::put_u64(
        &mut image,
        0x200 + 4 * 64 + 24,
        u64::try_from(string_start)?,
    )?;
    support::put_u64(
        &mut image,
        0x200 + 4 * 64 + 32,
        u64::try_from(strings.len())?,
    )?;
    image.extend_from_slice(&strings);

    let budget = MemoryBudget::new(16 * 1024 * 1024);
    let mut lease = budget.try_reserve(MemoryClass::Executor, 0)?;
    let report = inspect_with_memory(&image, &mut lease)?;
    assert_eq!(report.references.len(), symbol_count - 1);
    assert_eq!(
        report.references.first().map(|symbol| symbol.name.as_str()),
        Some("sym00001")
    );
    assert_eq!(
        report.references.last().map(|symbol| symbol.name.as_str()),
        Some("sym16383")
    );
    assert!(report.references.windows(2).all(|pair| {
        pair.first()
            .zip(pair.last())
            .is_some_and(|(first, second)| first.name < second.name)
    }));
    assert_eq!(
        lease.bytes(),
        u64::try_from(retained_report_bytes(&report))?
    );
    Ok(())
}
