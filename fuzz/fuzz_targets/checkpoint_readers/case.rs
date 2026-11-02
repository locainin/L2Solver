use l2_workbench::{
    evidence::{Case, CaseSnapshotLimits, EvidenceError},
    job::MemoryBudget,
};

pub fn read(graph: &[u8], pack: &[u8]) -> Result<Case, EvidenceError> {
    // Expanded data and live Case allocations have independent fixed ceilings
    let memory = MemoryBudget::new(16 * 1024 * 1024);
    let (case, usage) = Case::from_snapshot_with_memory(
        graph,
        pack,
        CaseSnapshotLimits::new(65_536, 65_536),
        &memory,
    )?;
    assert!(usage.graph_bytes + usage.blob_pack_bytes <= 65_536);
    assert!(usage.graph_decoded_bytes + usage.blob_pack_bytes <= 65_536);
    assert!(case.validate().is_ok());
    Ok(case)
}
