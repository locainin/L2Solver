//! Mechanical enforcement for the workspace dependency direction

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fmt,
    path::{Path, PathBuf},
};

use serde_json::Value;

use crate::process::{self, CommandSpec};

// These are the wire-facing crates that must stay independent of upper layers
const FOUNDATION_CRATES: &[&str] = &[
    "l2-helper-protocol",
    "l2-core",
    "l2-codecs",
    "wifi-core",
    "wifi-codecs",
    "wifi-radiotap",
];
// These crates own I/O, discovery, planning, authority, or presentation
const HIGH_LAYER_CRATES: &[&str] = &[
    "l2-workbench",
    "l2-pcap",
    "l2-io",
    "l2-live",
    "l2-cli",
    "l2-helper",
    "l2-audit",
    "l2-onpath",
    "l2-segmentation",
    "l2-engine",
    "l2-discovery",
    "wifi-linux",
    "wifi-audit",
    "wifi-discovery",
    "wifi-lab",
];
// These layers evaluate or plan observations and cannot own helper authority
const AUDIT_CRATES: &[&str] = &[
    "l2-audit",
    "l2-onpath",
    "l2-segmentation",
    "wifi-audit",
    "l2-workbench",
];
// The helper implementation stays below all protocol and audit stacks
const HELPER_FORBIDDEN_CRATES: &[&str] = &[
    "l2-workbench",
    "l2-core",
    "l2-codecs",
    "l2-discovery",
    "l2-audit",
    "l2-onpath",
    "l2-segmentation",
    "wifi-core",
    "wifi-codecs",
    "wifi-radiotap",
    "wifi-discovery",
    "wifi-audit",
];

/// Failure while reading or validating the workspace dependency graph
#[derive(Debug)]
pub enum DependencyPolicyError {
    /// Cargo metadata could not be produced
    MetadataCommand(String),
    /// Cargo emitted bytes that were not UTF-8
    MetadataEncoding,
    /// Cargo emitted malformed JSON
    MetadataJson(String),
    /// Cargo metadata did not contain a required field
    MetadataShape(&'static str),
    /// A workspace package crossed a forbidden layer boundary
    Forbidden {
        /// Package that declared or reached the forbidden dependency
        from: String,
        /// Forbidden package reached from `from`
        to: String,
        /// Workspace path proving the dependency direction violation
        path: Vec<String>,
    },
}

impl fmt::Display for DependencyPolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MetadataCommand(error) => {
                write!(
                    formatter,
                    "could not read Cargo workspace metadata: {error}"
                )
            }
            Self::MetadataEncoding => {
                formatter.write_str("Cargo workspace metadata was not valid UTF-8")
            }
            Self::MetadataJson(error) => {
                write!(
                    formatter,
                    "Cargo workspace metadata was not valid JSON: {error}"
                )
            }
            Self::MetadataShape(field) => {
                write!(formatter, "Cargo workspace metadata is missing {field}")
            }
            Self::Forbidden { from, to, path } => write!(
                formatter,
                "workspace dependency policy forbids {from} from reaching {to}: {}",
                path.join(" -> ")
            ),
        }
    }
}

impl std::error::Error for DependencyPolicyError {}

/// Check the workspace graph reported by Cargo metadata
///
/// All dependency declarations are considered, including optional, target,
/// build, and development dependencies. This keeps feature selection and
/// platform-specific manifests from bypassing the layer boundary.
///
/// # Errors
///
/// Returns an error when Cargo metadata cannot be read or a forbidden path is
/// present in the workspace graph
pub fn check(root: &Path) -> Result<(), DependencyPolicyError> {
    let specification = CommandSpec::new("cargo").args([
        "metadata",
        "--format-version",
        "1",
        "--no-deps",
        "--offline",
    ]);
    let output = process::output(root, &specification)
        .map_err(|error| DependencyPolicyError::MetadataCommand(error.to_string()))?;
    let metadata =
        String::from_utf8(output.stdout).map_err(|_| DependencyPolicyError::MetadataEncoding)?;
    validate_metadata(&metadata)
}

/// Validate a Cargo metadata JSON document
///
/// This smaller entry point keeps graph validation deterministic and makes
/// malformed, optional, and target-specific dependency cases testable without
/// changing a repository manifest.
///
/// # Errors
///
/// Returns an error when the JSON shape is invalid or a forbidden path exists
pub fn validate_metadata(metadata: &str) -> Result<(), DependencyPolicyError> {
    let document = serde_json::from_str::<Value>(metadata)
        .map_err(|error| DependencyPolicyError::MetadataJson(error.to_string()))?;
    let graph = parse_graph(&document)?;
    validate_graph(&graph)
}

type DependencyGraph = BTreeMap<String, Vec<String>>;

fn parse_graph(document: &Value) -> Result<DependencyGraph, DependencyPolicyError> {
    let packages = document
        .get("packages")
        .and_then(Value::as_array)
        .ok_or(DependencyPolicyError::MetadataShape("packages"))?;
    let workspace_members = document
        .get("workspace_members")
        .and_then(Value::as_array)
        .ok_or(DependencyPolicyError::MetadataShape("workspace_members"))?;
    let workspace_members = workspace_members
        .iter()
        .map(|member| {
            member.as_str().ok_or(DependencyPolicyError::MetadataShape(
                "workspace_members entry",
            ))
        })
        .collect::<Result<BTreeSet<_>, _>>()?;

    let mut package_by_id = BTreeMap::new();
    let mut package_by_path = BTreeMap::<PathBuf, String>::new();
    let mut package_names = BTreeSet::new();
    for package in packages {
        let id = package
            .get("id")
            .and_then(Value::as_str)
            .ok_or(DependencyPolicyError::MetadataShape("package id"))?;
        if !workspace_members.contains(id) {
            continue;
        }
        let name = package
            .get("name")
            .and_then(Value::as_str)
            .ok_or(DependencyPolicyError::MetadataShape("package name"))?
            .to_owned();
        let manifest_path = package
            .get("manifest_path")
            .and_then(Value::as_str)
            .ok_or(DependencyPolicyError::MetadataShape("manifest_path"))?;
        let manifest_path = Path::new(manifest_path)
            .parent()
            .ok_or(DependencyPolicyError::MetadataShape("manifest parent"))?
            .to_owned();
        package_by_path.insert(manifest_path, name.clone());
        package_names.insert(name.clone());
        package_by_id.insert(id.to_owned(), (name, package));
    }

    let mut graph = BTreeMap::new();
    for (_id, (name, package)) in package_by_id {
        let dependencies = package
            .get("dependencies")
            .and_then(Value::as_array)
            .ok_or(DependencyPolicyError::MetadataShape("dependencies"))?;
        let mut edges = BTreeSet::new();
        for dependency in dependencies {
            // No kind, optional, or target filter is applied here. Every
            // declared edge is part of the policy, even when a feature or
            // target normally keeps it out of the default build.
            let dependency_name = dependency
                .get("name")
                .and_then(Value::as_str)
                .ok_or(DependencyPolicyError::MetadataShape("dependency name"))?;
            let target = dependency
                .get("path")
                .and_then(Value::as_str)
                .map(Path::new)
                .and_then(|path| package_by_path.get(path))
                .cloned()
                .or_else(|| {
                    // Cargo supplies `source: null` for path dependencies.
                    // The name fallback also keeps synthetic metadata and
                    // renamed workspace entries understandable to reviewers.
                    dependency
                        .get("source")
                        .filter(|source| source.is_null())
                        .and_then(|_| package_names.get(dependency_name).cloned())
                });
            if let Some(target) = target {
                edges.insert(target);
            }
        }
        graph.insert(name, edges.into_iter().collect());
    }
    Ok(graph)
}

fn validate_graph(graph: &DependencyGraph) -> Result<(), DependencyPolicyError> {
    for from in graph.keys() {
        let forbidden = forbidden_targets(from);
        if forbidden.is_empty() {
            continue;
        }
        if let Some((to, path)) = find_forbidden_path(graph, from, forbidden) {
            return Err(DependencyPolicyError::Forbidden {
                from: from.clone(),
                to,
                path,
            });
        }
    }
    Ok(())
}

fn forbidden_targets(from: &str) -> &'static [&'static str] {
    if FOUNDATION_CRATES.contains(&from) {
        HIGH_LAYER_CRATES
    } else if AUDIT_CRATES.contains(&from) {
        &["l2-helper"]
    } else if from == "l2-helper" {
        HELPER_FORBIDDEN_CRATES
    } else {
        &[]
    }
}

fn find_forbidden_path(
    graph: &DependencyGraph,
    from: &str,
    forbidden: &[&str],
) -> Option<(String, Vec<String>)> {
    let mut queue = VecDeque::new();
    let mut visited = BTreeSet::new();
    for target in graph.get(from)? {
        queue.push_back((target.clone(), vec![from.to_owned(), target.clone()]));
    }
    while let Some((current, path)) = queue.pop_front() {
        if forbidden.contains(&current.as_str()) {
            return Some((current, path));
        }
        if !visited.insert(current.clone()) {
            continue;
        }
        if let Some(children) = graph.get(&current) {
            for child in children {
                let mut child_path = path.clone();
                child_path.push(child.clone());
                queue.push_back((child.clone(), child_path));
            }
        }
    }
    None
}
