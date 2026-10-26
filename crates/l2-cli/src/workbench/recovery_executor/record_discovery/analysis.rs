use l2_workbench::protocol::{
    RecordSchemaAnalysisReport, RecordSchemaMultiStrategyAnalysisReport,
    RecordSchemaProposalLimits, analyze_record_schemas,
    analyze_record_schemas_with_repeated_boundaries,
};

pub(super) fn analyze_strategies(
    training: &[&[u8]],
    held_out: &[&[u8]],
    limits: RecordSchemaProposalLimits,
    include_repeated_boundaries: bool,
) -> Result<RecordSchemaMultiStrategyAnalysisReport, l2_workbench::protocol::RecordDiscoveryError> {
    if include_repeated_boundaries {
        return analyze_record_schemas_with_repeated_boundaries(training, held_out, limits);
    }
    Ok(RecordSchemaMultiStrategyAnalysisReport {
        fixed_layout: analyze_record_schemas(training, held_out, limits)?,
        fixed_layout_limits: limits,
        repeated_boundaries: None,
        repeated_boundary_limits: None,
    })
}

pub(super) fn reports(
    analysis: &RecordSchemaMultiStrategyAnalysisReport,
) -> impl Iterator<Item = &RecordSchemaAnalysisReport> {
    std::iter::once(&analysis.fixed_layout).chain(analysis.repeated_boundaries.iter())
}

pub(super) fn has_survivors(analysis: &RecordSchemaMultiStrategyAnalysisReport) -> bool {
    reports(analysis).any(|report| {
        report
            .discovery
            .as_ref()
            .is_some_and(|discovery| !discovery.surviving.is_empty())
    })
}
