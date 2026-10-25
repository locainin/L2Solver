use l2_workbench::{
    evidence::{Case, CaseResourceUsage, EvidenceError, SourceRange},
    sha256,
};
use serde_json::json;

#[test]
fn resource_usage_tracks_unique_blobs_details_and_source_ranges() -> Result<(), EvidenceError> {
    let mut case = Case::new();
    assert_eq!(
        case.resource_usage(),
        CaseResourceUsage {
            blob_bytes: 0,
            details_bytes: 0,
            source_ranges: 0,
        }
    );

    let source_bytes = b"payload";
    let blob = case.add_blob(source_bytes)?;
    assert_eq!(case.add_blob(source_bytes)?, blob);
    let other_blob = case.add_blob(b"other")?;
    let source = case.add_source(
        "sample.bin",
        "file",
        source_bytes.len() as u64,
        &sha256(source_bytes),
        Some(&blob),
    )?;
    case.add_node(
        "sample",
        Some(&blob),
        vec![
            SourceRange {
                source: source.clone(),
                packet: None,
                offset: 0,
                length: 1,
            },
            SourceRange {
                source,
                packet: None,
                offset: 1,
                length: 2,
            },
        ],
        json!({"a": 1}),
    )?;
    case.add_node("other", Some(&other_blob), Vec::new(), json!({"b": 2}))?;

    assert_eq!(
        case.resource_usage(),
        CaseResourceUsage {
            blob_bytes: source_bytes.len() + b"other".len(),
            details_bytes: 14,
            source_ranges: 2,
        }
    );
    case.validate()
}

#[test]
fn resource_usage_tracks_commits_and_restores_failed_nested_transactions()
-> Result<(), EvidenceError> {
    let mut case = Case::new();
    case.add_bytes_node("base", b"base", Vec::new(), json!({"a": 1}))?;
    let initial = CaseResourceUsage {
        blob_bytes: 4,
        details_bytes: 7,
        source_ranges: 0,
    };
    assert_eq!(case.resource_usage(), initial);

    case.transaction(|case| {
        case.add_bytes_node("committed", b"add", Vec::new(), json!({"b": 2}))?;
        Ok::<_, EvidenceError>(())
    })?;
    let committed = CaseResourceUsage {
        blob_bytes: 7,
        details_bytes: 14,
        source_ranges: 0,
    };
    assert_eq!(case.resource_usage(), committed);

    let rolled_back = case.transaction(|case| {
        case.add_bytes_node("outer", b"outer", Vec::new(), json!({"c": 3}))?;
        case.transaction(|case| {
            case.add_bytes_node("inner", b"inner", Vec::new(), json!({"d": 4}))?;
            Ok::<_, EvidenceError>(())
        })?;
        Err::<(), _>(EvidenceError::InvalidSourceRange)
    });
    assert_eq!(rolled_back, Err(EvidenceError::InvalidSourceRange));
    assert_eq!(case.resource_usage(), committed);

    case.transaction(|case| {
        case.add_bytes_node("outer", b"outer", Vec::new(), json!({"c": 3}))?;
        let inner = case.transaction(|case| {
            case.add_bytes_node("inner", b"inner", Vec::new(), json!({"d": 4}))?;
            Err::<(), _>(EvidenceError::InvalidSourceRange)
        });
        assert_eq!(inner, Err(EvidenceError::InvalidSourceRange));
        Ok::<_, EvidenceError>(())
    })?;
    assert_eq!(
        case.resource_usage(),
        CaseResourceUsage {
            blob_bytes: 7 + b"outer".len(),
            details_bytes: 21,
            source_ranges: 0,
        }
    );
    case.validate()
}

#[test]
fn repeated_resource_usage_reads_are_exact_and_do_not_mutate_the_case() -> Result<(), EvidenceError>
{
    let mut case = Case::new();
    let source_bytes = b"source";
    let blob = case.add_blob(source_bytes)?;
    let source = case.add_source(
        "source.bin",
        "file",
        source_bytes.len() as u64,
        &sha256(source_bytes),
        Some(&blob),
    )?;
    case.add_node(
        "observation",
        Some(&blob),
        vec![SourceRange {
            source,
            packet: None,
            offset: 0,
            length: 1,
        }],
        json!({"a": 1}),
    )?;
    let expected = CaseResourceUsage {
        blob_bytes: source_bytes.len(),
        details_bytes: 7,
        source_ranges: 1,
    };
    let before = case.clone();

    for _ in 0..32 {
        assert_eq!(case.resource_usage(), expected);
    }

    assert_eq!(case, before);
    case.validate()
}
