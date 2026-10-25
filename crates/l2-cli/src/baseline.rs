//! Baselines compare observations and never assert that missing traffic proves removal

use crate::baseline_model::MAX_BASELINE_JSON_BYTES;
use crate::{
    arguments::SourceMapping,
    baseline_model::{
        Baseline, BaselineFact, Change, ChangeKind, StableSource, single_capture_source,
    },
    bounded_json, input, output as output_limits, publish, survey,
};
use l2_audit::{Policy, Report, SourceLabelMap};
use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    io::{self, Write},
    path::Path,
};

/// Whether a baseline comparison retained all authoritative observations
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BaselineCollectionStatus {
    Complete,
    Incomplete,
}

/// Printed baseline differences together with the collection outcome
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BaselineCompareResult {
    pub changes: Vec<Change>,
    pub status: BaselineCollectionStatus,
}

fn snapshot(report: &Report, mappings: &[SourceMapping]) -> Result<Baseline, Box<dyn Error>> {
    let sources = stable_sources(report, mappings)?;
    let mut facts = BTreeSet::new();
    for interface in &report.interfaces {
        let source = sources
            .get(&(interface.section, interface.index))
            .ok_or("capture source has no stable baseline label")?;
        for mac in &interface.macs {
            facts.insert(BaselineFact::SourceMac {
                source: source.clone(),
                mac: mac.clone(),
            });
        }
        for vlan in &interface.vlans {
            facts.insert(BaselineFact::VlanStack {
                source: source.clone(),
                tags: vlan.tags.clone(),
            });
        }
        if interface.untagged_packet.is_some() {
            facts.insert(BaselineFact::UntaggedTraffic {
                source: source.clone(),
            });
        }
        for neighbor in &interface.neighbors {
            facts.insert(BaselineFact::LldpNeighbor {
                source: source.clone(),
                chassis_id: neighbor.chassis_id.clone(),
                port_id: neighbor.port_id.clone(),
                system_name: neighbor.system_name.clone(),
            });
        }
        for protocol in &interface.protocols {
            facts.insert(BaselineFact::Protocol {
                source: source.clone(),
                protocol: protocol.protocol.to_string(),
                status: protocol.status.to_string(),
            });
        }
        for identity in &interface.identities {
            facts.insert(BaselineFact::ProtocolIdentity {
                source: source.clone(),
                protocol: identity.protocol.to_string(),
                role: identity.role.to_string(),
                outer_source_mac: identity.source_mac.clone(),
                claimed_mac: identity.claimed_mac.clone(),
                address: identity.address.as_ref().map(ToString::to_string),
                vlan_tags: identity.vlan_tags.clone(),
            });
        }
        for stp in &interface.stp {
            facts.insert(BaselineFact::StpRoot {
                source: source.clone(),
                priority: stp.root.priority,
                system_id_extension: stp.root.system_id_extension,
                mac: stp.root.mac.clone(),
                version: stp.version.clone(),
            });
        }
    }
    Baseline::new(facts).map_err(Into::into)
}

fn stable_sources(
    report: &Report,
    mappings: &[SourceMapping],
) -> Result<BTreeMap<(u32, u32), StableSource>, Box<dyn Error>> {
    if mappings.is_empty() {
        return match report.interfaces.as_slice() {
            [] => Ok(BTreeMap::new()),
            [interface] => Ok(BTreeMap::from([(
                (interface.section, interface.index),
                single_capture_source()?,
            )])),
            _ => Err(
                "multi-interface baselines require --source SECTION:INDEX=LABEL for every source"
                    .into(),
            ),
        };
    }

    // Keep baseline configuration on the same exact source contract as policy evaluation
    let configured = SourceLabelMap::new(mappings.iter().map(|mapping| {
        (
            l2_capture::InterfaceId {
                section: mapping.section,
                index: mapping.index,
            },
            mapping.label.clone(),
        )
    }))?;
    let observed: Vec<_> = report
        .interfaces
        .iter()
        .map(|interface| l2_capture::InterfaceId {
            section: interface.section,
            index: interface.index,
        })
        .collect();
    configured.validate_for(&observed)?;

    report
        .interfaces
        .iter()
        .map(|interface| {
            let source_id = l2_capture::InterfaceId {
                section: interface.section,
                index: interface.index,
            };
            let label = configured
                .label_for(source_id)
                .ok_or("capture source has no stable baseline label")?;
            Ok((
                (interface.section, interface.index),
                StableSource::new(label.to_owned())?,
            ))
        })
        .collect()
}

pub fn create(
    capture: &Path,
    path: &Path,
    sources: &[SourceMapping],
    output: &mut impl Write,
) -> Result<bool, Box<dyn Error>> {
    let report = survey::from_file(capture, &Policy::default())?;
    if !report.collection_complete() {
        return Err("incomplete capture cannot establish a baseline".into());
    }
    let baseline = snapshot(&report, sources)?;
    // Serialize before creating the file so model failures cannot leave a baseline behind
    let mut bytes = Vec::new();
    {
        let mut bounded = output_limits::BoundedWriter::named(
            &mut bytes,
            MAX_BASELINE_JSON_BYTES,
            "baseline JSON",
        );
        serde_json::to_writer(&mut bounded, &baseline)?;
        bounded.write_all(b"\n")?;
    }
    publish::create(path, |file| file.write_all(&bytes))?;
    writeln!(
        output,
        "Baseline created: {} observations at {}",
        baseline.facts.len(),
        path.display().to_string().escape_debug()
    )?;
    Ok(true)
}

pub fn compare(
    path: &Path,
    capture: &Path,
    sources: &[SourceMapping],
) -> Result<BaselineCompareResult, Box<dyn Error>> {
    let baseline: Baseline = bounded_json::read(
        input::regular(path)?,
        u64::try_from(MAX_BASELINE_JSON_BYTES)?,
    )?;
    baseline.validate()?;
    let report = survey::from_file(capture, &Policy::default())?;
    let changes = baseline.compare(&snapshot(&report, sources)?)?;
    let status = if report.collection_complete() {
        BaselineCollectionStatus::Complete
    } else {
        BaselineCollectionStatus::Incomplete
    };
    Ok(BaselineCompareResult { changes, status })
}

pub fn render_comparison(
    comparison: &BaselineCompareResult,
    output: &mut impl Write,
) -> io::Result<()> {
    if comparison.changes.is_empty() {
        writeln!(output, "No differences among retained observations")?;
    }
    for change in &comparison.changes {
        let label = match change.kind {
            ChangeKind::Added => "NEW",
            ChangeKind::NotObserved => "NOT OBSERVED",
        };
        writeln!(
            output,
            "{label} {}",
            change.observation.describe().escape_debug()
        )?;
    }
    writeln!(
        output,
        "Not observed means absent from this sample, not proof of removal or protection."
    )?;
    if comparison.status == BaselineCollectionStatus::Incomplete {
        writeln!(
            output,
            "Collection is incomplete; comparison cannot establish an unchanged environment."
        )?;
    }
    Ok(())
}
