use super::{clean_quality, interface};
use l2_audit::{BridgeIdentity, MAX_FINDINGS, Policy, SourceLabelMap, StpObservation};
use serde_json::json;
use std::error::Error;

#[test]
fn finding_limit_omissions() -> Result<(), Box<dyn Error>> {
    for (count, omitted) in [
        (MAX_FINDINGS - 1, false),
        (MAX_FINDINGS, false),
        (MAX_FINDINGS + 1, true),
    ] {
        let mut observed = interface();
        // The untagged finding uses the first slot before distinct root observations
        observed.stp = (1..count)
            .map(|packet| {
                Ok(StpObservation {
                    root: BridgeIdentity {
                        priority: 32_768,
                        system_id_extension: 0,
                        mac: "02:00:00:00:00:01".into(),
                    },
                    version: "Stp".into(),
                    packet: u64::try_from(packet)?,
                    frames: 1,
                })
            })
            .collect::<Result<_, Box<dyn Error>>>()?;
        let policy = Policy {
            allow_untagged: Some(false),
            expected_stp_root: Some("02:00:00:00:00:02".into()),
            ..Policy::default()
        };
        let labels = SourceLabelMap::default();
        let interfaces = [observed];
        for assessment in [
            l2_audit::assess(&interfaces, &policy, &clean_quality())?,
            l2_audit::assess_with_source_labels(&interfaces, &policy, &clean_quality(), &labels)?,
        ] {
            assert_eq!(assessment.findings.len(), count.min(MAX_FINDINGS));
            let value = serde_json::to_value(&assessment)?;
            let expected = if omitted {
                json!(["findings"])
            } else {
                json!([])
            };
            assert_eq!(
                value.pointer("/resource_limits/reached"),
                Some(&expected),
                "finding count {count} must distinguish a full report from an omitted result"
            );
        }
    }
    Ok(())
}
