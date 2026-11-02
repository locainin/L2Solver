#[path = "../src/baseline_model.rs"]
mod baseline_model;

use baseline_model::{
    Baseline, BaselineFact, Change, ChangeKind, MAX_BASELINE_FACT_BYTES, MAX_FACT_BYTES, MAX_FACTS,
    SCHEMA_VERSION, StableSource, single_capture_source,
};
use std::collections::BTreeSet;

fn source() -> Result<StableSource, l2_audit::SourceLabelMapError> {
    single_capture_source()
}

fn fact(value: impl Into<String>) -> Result<BaselineFact, l2_audit::SourceLabelMapError> {
    Ok(BaselineFact::SourceMac {
        source: source()?,
        mac: value.into(),
    })
}

fn facts(values: &[&str]) -> Result<BTreeSet<BaselineFact>, l2_audit::SourceLabelMapError> {
    values.iter().map(|value| fact(*value)).collect()
}

mod comparison {
    use super::*;

    #[test]
    fn sorts_typed_changes() -> Result<(), Box<dyn std::error::Error>> {
        let baseline = Baseline::new(facts(&["vlan:20", "stp:root:old"])?)?;
        let current = Baseline::new(facts(&["lldp:core-01", "vlan:20"])?)?;

        assert_eq!(
            baseline.compare(&current)?,
            vec![
                Change {
                    kind: ChangeKind::Added,
                    observation: fact("lldp:core-01")?,
                },
                Change {
                    kind: ChangeKind::NotObserved,
                    observation: fact("stp:root:old")?,
                },
            ]
        );
        Ok(())
    }

    #[test]
    fn equal_facts_no_security_verdict() -> Result<(), Box<dyn std::error::Error>> {
        let baseline = Baseline::new(facts(&["lldp:core-01"])?)?;
        assert_eq!(baseline.compare(&baseline)?.len(), 0);
        Ok(())
    }
}

mod serialization {
    use super::*;

    #[test]
    fn facts_are_structured_objects() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(baseline_model::MAX_BASELINE_JSON_BYTES, 32 * 1024 * 1024);
        let baseline = Baseline::new(BTreeSet::from([BaselineFact::StpRoot {
            source: source()?,
            priority: 32_768,
            system_id_extension: 20,
            mac: String::from("00:11:22:33:44:55"),
            version: String::from("rstp"),
        }]))?;
        let value = serde_json::to_value(&baseline)?;
        let fact = value
            .get("facts")
            .and_then(serde_json::Value::as_array)
            .and_then(|facts| facts.first())
            .ok_or("missing fact")?;
        assert_eq!(fact.get("kind"), Some(&serde_json::json!("stp_root")));
        assert_eq!(fact.get("source"), Some(&serde_json::json!("capture")));
        assert_eq!(fact.get("priority"), Some(&serde_json::json!(32_768)));
        assert!(
            baseline
                .facts
                .first()
                .is_some_and(|fact| fact.describe().contains("priority=32768"))
        );
        Ok(())
    }

    #[test]
    fn change_kinds_keep_stable_names() -> Result<(), Box<dyn std::error::Error>> {
        let encoded = serde_json::to_value(Change {
            kind: ChangeKind::NotObserved,
            observation: fact("vlan:20")?,
        })?;
        assert_eq!(
            encoded.get("kind"),
            Some(&serde_json::json!("not_observed"))
        );
        assert!(
            encoded
                .get("observation")
                .is_some_and(serde_json::Value::is_object)
        );
        Ok(())
    }
}

mod limits {
    use super::*;

    #[test]
    fn enforces_fact_count() -> Result<(), Box<dyn std::error::Error>> {
        const { assert!(MAX_FACTS == 65_536) };
        let at_limit = (0..MAX_FACTS)
            .map(|index| fact(format!("{index:012}")))
            .collect::<Result<_, _>>()?;
        assert!(Baseline::new(at_limit).is_ok());

        let over_limit = (0..=MAX_FACTS)
            .map(|index| fact(format!("{index:012}")))
            .collect::<Result<_, _>>()?;
        assert!(matches!(
            Baseline::new(over_limit),
            Err(baseline_model::BaselineError::TooManyFacts { count, max })
                if count == MAX_FACTS + 1 && max == MAX_FACTS
        ));
        Ok(())
    }

    #[test]
    fn measures_payload_in_utf8_bytes() -> Result<(), Box<dyn std::error::Error>> {
        let fixed = source()?.as_str().len();
        let at_limit = format!("{}x", "é".repeat((MAX_FACT_BYTES - fixed - 1) / "é".len()));
        assert_eq!(at_limit.len() + fixed, MAX_FACT_BYTES);
        assert!(Baseline::new(BTreeSet::from([fact(&at_limit)?])).is_ok());

        let over_limit = format!("{at_limit}é");
        assert!(matches!(
            Baseline::new(BTreeSet::from([fact(over_limit)?])),
            Err(baseline_model::BaselineError::FactTooLong { length, max })
                if length > MAX_FACT_BYTES && max == MAX_FACT_BYTES
        ));
        Ok(())
    }

    #[test]
    fn enforces_aggregate_fact_bytes() -> Result<(), Box<dyn std::error::Error>> {
        assert_eq!(MAX_BASELINE_FACT_BYTES, 32 * 1024 * 1024);
        let payload = "x".repeat(MAX_FACT_BYTES - source()?.as_str().len() - 8);
        let count = MAX_BASELINE_FACT_BYTES / MAX_FACT_BYTES;
        let facts = (0..count)
            .map(|index| fact(format!("{index:08}{payload}")))
            .collect::<Result<_, _>>()?;
        let at_limit = Baseline::new(facts)?;
        assert_eq!(at_limit.facts.len(), count);

        let mut over_limit = at_limit.facts;
        over_limit.insert(fact(format!("{count:08}{payload}"))?);
        assert!(matches!(
            Baseline::new(over_limit),
            Err(baseline_model::BaselineError::TotalBytesExceeded { total, max })
                if total > MAX_BASELINE_FACT_BYTES && max == MAX_BASELINE_FACT_BYTES
        ));
        Ok(())
    }
}

mod validation {
    use super::*;

    #[test]
    fn rejects_future_schema() {
        let future = Baseline {
            schema_version: SCHEMA_VERSION + 1,
            facts: BTreeSet::new(),
        };
        assert!(matches!(
            future.validate(),
            Err(baseline_model::BaselineError::UnsupportedSchema { found, expected })
                if found == SCHEMA_VERSION + 1 && expected == SCHEMA_VERSION
        ));
    }

    #[test]
    fn rejects_unsafe_source_labels() {
        for label in ["", "../port", "port name", "\u{1b}switch"] {
            assert!(
                StableSource::new(label.to_owned()).is_err(),
                "accepted {label:?}"
            );
        }
    }

    #[test]
    fn schema_and_facts_are_required() {
        for json in [r#"{"facts":[]}"#, r#"{"schema_version":2}"#] {
            assert!(serde_json::from_str::<Baseline>(json).is_err());
        }
    }

    #[test]
    fn nested_fact_unknown_fields_rejected() {
        let json = r#"{
            "schema_version": 2,
            "facts": [{
                "kind": "source_mac",
                "source": "capture",
                "mac": "02:00:00:00:00:01",
                "unexpected": true
            }]
        }"#;

        assert!(serde_json::from_str::<Baseline>(json).is_err());
    }
}
