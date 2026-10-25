use super::{
    builder::Builder,
    model::{CarrierError, MAX_RULES, Report, Rule, Sample},
    projection::{extract_dns_labels, extract_samples},
    relationships::add_relationships,
    resolve::resolve_samples,
    source::SourceReader,
    timing::extract_timing,
};
use std::collections::HashSet;

/// Build bounded carrier observations only from exact, verified source ranges
///
/// Caller rules select every projection and preserve their offsets, widths, and bit order
///
/// # Errors
/// Rejects invalid source identities, mappings, duplicate samples, or request limits
pub fn extract(
    sources: &mut [SourceReader],
    samples: &[Sample<'_>],
    rules: &[Rule],
) -> Result<Report, CarrierError> {
    validate_rules(rules)?;
    let resolved = resolve_samples(sources, samples)?;
    let mut builder = Builder::new(rules);
    for rule in rules {
        match rule {
            Rule::Timing => extract_timing(&mut builder, samples, &resolved)?,
            Rule::DnsLabels {
                offset,
                ascii_case_fold,
            } => extract_dns_labels(
                &mut builder,
                rule,
                *offset,
                *ascii_case_fold,
                samples,
                &resolved,
            )?,
            _ => extract_samples(&mut builder, rule, samples, &resolved)?,
        }
    }
    add_relationships(&mut builder.report, &mut builder.retained_ranges)?;
    Ok(builder.report)
}

fn validate_rules(rules: &[Rule]) -> Result<(), CarrierError> {
    if rules.is_empty() || rules.len() > MAX_RULES {
        return Err(CarrierError::InvalidRules);
    }
    let mut unique = HashSet::with_capacity(rules.len());
    if rules.iter().any(|rule| !unique.insert(rule)) {
        return Err(CarrierError::InvalidRules);
    }
    Ok(())
}
