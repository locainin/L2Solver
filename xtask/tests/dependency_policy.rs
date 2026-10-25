use std::{error::Error, path::Path};

use serde_json::Value;
use xtask::dependency_policy::{DependencyPolicyError, validate_metadata};

fn metadata(packages: &[String]) -> Result<String, Box<dyn Error>> {
    let packages = packages
        .iter()
        .map(|package| serde_json::from_str::<Value>(package))
        .collect::<Result<Vec<_>, _>>()?;
    let workspace_members = packages
        .iter()
        .map(|package| {
            package
                .get("id")
                .cloned()
                .ok_or_else(|| std::io::Error::other("fixture package has no id"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    serde_json::to_string(&serde_json::json!({
        "packages": packages,
        "workspace_members": workspace_members,
    }))
    .map_err(Into::into)
}

fn package(name: &str, dependencies: &str) -> String {
    format!(
        r#"{{
            "name": "{name}",
            "id": "path+file:///workspace/{name}#0.1.0",
            "manifest_path": "/workspace/{name}/Cargo.toml",
            "dependencies": [{dependencies}]
        }}"#
    )
}

fn empty_package(name: &str) -> String {
    package(name, "")
}

fn dependency(name: &str, optional: bool, target: Option<&str>, kind: Option<&str>) -> String {
    let target = target.map_or_else(|| "null".to_owned(), |value| format!(r#""{value}""#));
    let kind = kind.map_or_else(|| "null".to_owned(), |value| format!(r#""{value}""#));
    format!(
        r#"{{
            "name": "{name}",
            "source": null,
            "path": "/workspace/{name}",
            "optional": {optional},
            "target": {target},
            "kind": {kind}
        }}"#
    )
}

fn forbidden(error: DependencyPolicyError, from: &str, to: &str) -> Result<(), Box<dyn Error>> {
    match error {
        DependencyPolicyError::Forbidden {
            from: actual_from,
            to: actual_to,
            path,
        } => {
            assert_eq!(actual_from, from);
            assert_eq!(actual_to, to);
            assert_eq!(path.first().map(String::as_str), Some(from));
            assert_eq!(path.last().map(String::as_str), Some(to));
            Ok(())
        }
        other => Err(std::io::Error::other(format!(
            "unexpected dependency policy error: {other:?}"
        ))
        .into()),
    }
}

#[test]
fn rejects_optional_target_io_dependency() -> Result<(), Box<dyn Error>> {
    let json = metadata(&[
        package(
            "l2-core",
            &dependency("l2-live", true, Some("cfg(unix)"), Some("build")),
        ),
        empty_package("l2-live"),
    ])?;
    let error = validate_metadata(&json)
        .err()
        .ok_or_else(|| std::io::Error::other("optional target dependency must be checked"))?;
    forbidden(error, "l2-core", "l2-live")
}

#[test]
fn foundation_rejects_indirect_io_dependency() -> Result<(), Box<dyn Error>> {
    let json = metadata(&[
        package("l2-core", &dependency("l2-capture", false, None, None)),
        package("l2-capture", &dependency("l2-live", false, None, None)),
        empty_package("l2-live"),
    ])?;
    let error = validate_metadata(&json)
        .err()
        .ok_or_else(|| std::io::Error::other("indirect I/O dependency must be checked"))?;
    forbidden(error, "l2-core", "l2-live")?;
    Ok(())
}

#[test]
fn onpath_helper_dependency_rejected() -> Result<(), Box<dyn Error>> {
    let json = metadata(&[
        package(
            "l2-audit",
            &dependency("l2-helper-protocol", false, None, None),
        ),
        package("l2-onpath", &dependency("l2-helper", false, None, None)),
        empty_package("l2-helper-protocol"),
        empty_package("l2-helper"),
    ])?;
    let error = validate_metadata(&json)
        .err()
        .ok_or_else(|| std::io::Error::other("onpath must not reach helper"))?;
    forbidden(error, "l2-onpath", "l2-helper")
}

#[test]
fn helper_rejects_protocol_decoder_stack() -> Result<(), Box<dyn Error>> {
    let json = metadata(&[
        package(
            "l2-helper",
            &dependency("l2-codecs", false, None, Some("dev")),
        ),
        empty_package("l2-codecs"),
    ])?;
    let error = validate_metadata(&json)
        .err()
        .ok_or_else(|| std::io::Error::other("helper must stay below decoder layers"))?;
    forbidden(error, "l2-helper", "l2-codecs")
}

#[test]
fn cli_composition_reaches_live_layer() -> Result<(), Box<dyn Error>> {
    let json = metadata(&[
        package(
            "l2-cli",
            &dependency("l2-live", true, Some("cfg(unix)"), None),
        ),
        empty_package("l2-live"),
    ])?;
    validate_metadata(&json)?;
    Ok(())
}

#[test]
fn foundations_reject_upper_layer_dependencies() -> Result<(), Box<dyn Error>> {
    for (from, to) in [
        ("wifi-core", "wifi-linux"),
        ("wifi-codecs", "wifi-audit"),
        ("wifi-radiotap", "wifi-lab"),
        ("l2-helper-protocol", "l2-segmentation"),
        ("l2-core", "l2-engine"),
        ("l2-codecs", "l2-discovery"),
    ] {
        let json = metadata(&[
            package(
                from,
                &dependency(to, true, Some("cfg(test)"), Some("build")),
            ),
            empty_package(to),
        ])?;
        let error = validate_metadata(&json)
            .err()
            .ok_or_else(|| std::io::Error::other("foundation dependency must be checked"))?;
        forbidden(error, from, to)?;
    }
    Ok(())
}

#[test]
fn audit_layers_reject_helper_implementation() -> Result<(), Box<dyn Error>> {
    for from in ["wifi-audit", "l2-segmentation"] {
        let json = metadata(&[
            package(from, &dependency("l2-helper", false, None, None)),
            empty_package("l2-helper"),
        ])?;
        let error = validate_metadata(&json)
            .err()
            .ok_or_else(|| std::io::Error::other("audit layer must not reach helper"))?;
        forbidden(error, from, "l2-helper")?;
    }
    Ok(())
}

#[test]
fn helper_rejects_decoder_layer_dependencies() -> Result<(), Box<dyn Error>> {
    for to in [
        "wifi-core",
        "wifi-codecs",
        "wifi-radiotap",
        "wifi-discovery",
        "wifi-audit",
    ] {
        let json = metadata(&[
            package("l2-helper", &dependency(to, false, None, Some("dev"))),
            empty_package(to),
        ])?;
        let error = validate_metadata(&json)
            .err()
            .ok_or_else(|| std::io::Error::other("helper must not reach wireless layers"))?;
        forbidden(error, "l2-helper", to)?;
    }
    Ok(())
}

#[test]
fn current_workspace_graph_obeys_policy() -> Result<(), Box<dyn Error>> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or_else(|| std::io::Error::other("xtask has a workspace parent"))?;
    xtask::dependency_policy::check(root)?;
    Ok(())
}

#[test]
fn workbench_decoder_authority_boundary() -> Result<(), Box<dyn Error>> {
    for (from, to) in [
        ("l2-core", "l2-workbench"),
        ("l2-workbench", "l2-helper"),
        ("l2-helper", "l2-workbench"),
    ] {
        let json = metadata(&[
            package(from, &dependency(to, false, None, None)),
            empty_package(to),
        ])?;
        let error = validate_metadata(&json)
            .err()
            .ok_or("workbench dependency direction must be checked")?;
        forbidden(error, from, to)?;
    }
    Ok(())
}
