use crate::evidence::{Case, EvidenceError, MAX_SOURCE_ALIASES, MAX_SOURCES};

fn populated_case() -> Result<Case, EvidenceError> {
    let mut case = Case::new();
    for source_number in 0..MAX_SOURCES {
        let digest = format!("{number:064x}", number = source_number + 1);
        let label = format!("source-{source_number}.pcap");
        case.add_source(&label, "file", 1, &digest, None)?;
        for alias_number in 0..32 {
            let alias = format!("source-{source_number}-alias-{alias_number}.pcap");
            case.add_source(&alias, "file", 1, &digest, None)?;
        }
    }
    Ok(case)
}

fn case_with_two_sources() -> Result<(Case, String, String), EvidenceError> {
    let mut case = Case::new();
    let first = format!("{:064x}", 10);
    let second = format!("{:064x}", 11);
    case.add_source("first.pcap", "file", 1, &first, None)?;
    case.add_source("second.pcap", "file", 1, &second, None)?;
    Ok((case, first, second))
}

#[test]
fn transaction_without_source_changes_does_not_snapshot_source_records() -> Result<(), EvidenceError>
{
    let mut case = populated_case()?;
    let source_count = case.sources().len();

    case.transaction(|case| {
        assert!(
            case.transaction_checkpoints
                .last()
                .is_some_and(|checkpoint| checkpoint.source_snapshots.is_empty())
        );
        case.add_limitation("A bounded transaction without source changes")?;
        assert_eq!(*case, case.try_clone()?);
        let encoded = case.to_json()?;
        assert_eq!(Case::from_json(&encoded)?, *case);
        Ok(())
    })?;

    assert_eq!(case.sources().len(), source_count);
    case.validate()?;
    Ok(())
}

#[test]
fn transaction_snapshots_each_changed_source_once_and_restores_it() -> Result<(), EvidenceError> {
    let mut case = populated_case()?;
    let original = case
        .sources()
        .first()
        .ok_or(EvidenceError::MissingReference { kind: "source" })?
        .clone();
    let digest = format!("{:064x}", 1);

    let result = case.transaction(|case| {
        for alias_number in 32..MAX_SOURCE_ALIASES {
            let alias = format!("source-0-alias-{alias_number}.pcap");
            case.add_source(&alias, "file", 1, &digest, None)?;
        }
        let checkpoint = case
            .transaction_checkpoints
            .last()
            .ok_or(EvidenceError::HashMismatch)?;
        assert_eq!(checkpoint.source_snapshots.len(), 1);
        assert_eq!(
            checkpoint
                .source_snapshots
                .get(&0)
                .map(|source| source.aliases.len()),
            Some(32)
        );
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });

    assert_eq!(result, Err(EvidenceError::InvalidSourceRange));
    assert_eq!(case.sources().first(), Some(&original));
    case.validate()?;
    Ok(())
}

#[test]
fn outer_rollback_restores_source_changes_from_a_successful_inner_transaction()
-> Result<(), EvidenceError> {
    let (mut case, first, second) = case_with_two_sources()?;
    let original = case.sources().to_vec();

    let result = case.transaction(|case| {
        case.add_source("first-outer.pcap", "file", 1, &first, None)?;
        case.transaction(|case| {
            case.add_source("first-inner.pcap", "file", 1, &first, None)?;
            case.add_source("second-inner.pcap", "file", 1, &second, None)?;
            Ok(())
        })?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });

    assert_eq!(result, Err(EvidenceError::InvalidSourceRange));
    assert_eq!(case.sources(), original);
    case.validate()?;
    Ok(())
}

#[test]
fn failed_inner_transaction_restores_only_its_source_changes() -> Result<(), EvidenceError> {
    let (mut case, first, second) = case_with_two_sources()?;

    case.transaction(|case| {
        case.add_source("first-outer.pcap", "file", 1, &first, None)?;
        let inner = case.transaction(|case| {
            case.add_source("first-inner.pcap", "file", 1, &first, None)?;
            case.add_source("second-inner.pcap", "file", 1, &second, None)?;
            Err::<(), _>(EvidenceError::InvalidSourceRange)
        });
        assert_eq!(inner, Err(EvidenceError::InvalidSourceRange));
        Ok(())
    })?;

    let first_source = case
        .sources()
        .first()
        .ok_or(EvidenceError::MissingReference { kind: "source" })?;
    let second_source = case
        .sources()
        .get(1)
        .ok_or(EvidenceError::MissingReference { kind: "source" })?;
    assert_eq!(first_source.aliases, ["first-outer.pcap"]);
    assert_eq!(second_source.aliases.len(), 0);
    case.validate()?;
    Ok(())
}

#[test]
fn nested_appended_sources_restore_their_indexes_at_each_rollback_level()
-> Result<(), EvidenceError> {
    let mut case = Case::new();
    let first = format!("{:064x}", 20);
    let outer_source = format!("{:064x}", 21);
    let inner_source = format!("{:064x}", 22);
    let outer_id = format!("sha256:{outer_source}");
    let inner_id = format!("sha256:{inner_source}");
    case.add_source("first.pcap", "file", 1, &first, None)?;

    let outer_result = case.transaction(|case| {
        assert_eq!(
            case.add_source("outer.pcap", "file", 1, &outer_source, None)?,
            outer_id
        );
        let inner = case.transaction(|case| {
            case.add_source("inner.pcap", "file", 1, &inner_source, None)?;
            Err::<(), _>(EvidenceError::InvalidSourceRange)
        });
        assert_eq!(inner, Err(EvidenceError::InvalidSourceRange));
        assert_eq!(case.sources().len(), 2);
        assert_eq!(case.source_index.get(&outer_id), Some(&1));
        assert!(!case.source_index.contains_key(&inner_id));
        case.validate()?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });

    assert_eq!(outer_result, Err(EvidenceError::InvalidSourceRange));
    assert_eq!(case.sources().len(), 1);
    assert!(!case.source_index.contains_key(&outer_id));
    assert!(!case.source_index.contains_key(&inner_id));
    case.validate()?;

    assert_eq!(
        case.add_source("outer.pcap", "file", 1, &outer_source, None)?,
        outer_id
    );
    let inner_id = case.add_source("inner.pcap", "file", 1, &inner_source, None)?;
    assert_eq!(case.source_index.get(&outer_id), Some(&1));
    assert_eq!(case.source_index.get(&inner_id), Some(&2));
    case.validate()?;
    Ok(())
}

#[test]
fn rollback_restores_source_blob_attachment_and_deduplication() -> Result<(), EvidenceError> {
    let mut case = Case::new();
    let bytes = b"source retained during the failed transaction";
    let digest = crate::sha256(bytes);
    let source_length =
        u64::try_from(bytes.len()).map_err(|_| EvidenceError::InvalidSourceRange)?;
    case.add_source("source.pcap", "file", source_length, &digest, None)?;

    let result = case.transaction(|case| {
        let blob = case.add_blob(bytes)?;
        case.add_source("source.pcap", "file", source_length, &digest, Some(&blob))?;
        assert_eq!(
            case.transaction_checkpoints
                .last()
                .map(|checkpoint| checkpoint.source_snapshots.len()),
            Some(1)
        );
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });

    assert_eq!(result, Err(EvidenceError::InvalidSourceRange));
    assert!(
        case.sources()
            .first()
            .is_some_and(|source| source.blob.is_none())
    );
    assert_eq!(case.blobs().len(), 0);
    case.validate()?;
    Ok(())
}

#[test]
fn panic_unwind_clears_transaction_scope_without_changing_panic_rollback_contract() {
    let mut case = Case::new();
    let unwind_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _: Result<(), EvidenceError> = case.transaction(|case| {
            case.add_limitation("Retained partial change")?;
            std::panic::resume_unwind(Box::new(()))
        });
    }));

    assert!(unwind_result.is_err());
    assert!(case.transaction_checkpoints.is_empty());
    assert_eq!(case.limitations(), ["Retained partial change"]);
}
