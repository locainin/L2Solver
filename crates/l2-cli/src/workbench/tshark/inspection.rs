use super::{
    model::PluginRecord,
    phase::{require_success, run_phase},
    preparation::PreparedCapture,
    process,
    profile::{PROFILE, verify_effective_preferences},
    version,
};
use std::{collections::BTreeMap, error::Error, ffi::OsString};

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/inspection.rs"]
mod tests;

pub(super) struct ToolInspection {
    pub(super) version: String,
    pub(super) version_output: process::Output,
    pub(super) plugin_args: Vec<OsString>,
    pub(super) plugin_output: process::Output,
    pub(super) preferences_args: Vec<OsString>,
    pub(super) preferences_output: process::Output,
    pub(super) plugins: Vec<PluginRecord>,
    pub(super) verified_profile_preferences: BTreeMap<String, String>,
    pub(super) effective_preferences_count: usize,
}

pub(super) fn inspect_tool(prepared: &PreparedCapture) -> Result<ToolInspection, Box<dyn Error>> {
    let (version, version_output) = inspect_version(prepared)?;

    let profile_args = [
        OsString::from("-n"),
        OsString::from("-C"),
        OsString::from(PROFILE),
    ];
    // Glossary requests keep -G first across supported release lines
    let mut plugin_args = vec![OsString::from("-G"), OsString::from("plugins")];
    plugin_args.extend_from_slice(&profile_args);
    let plugin_output = run_phase(prepared, &plugin_args, prepared.metadata_maximum)?;
    require_success(
        "plugin inventory",
        plugin_output.status,
        &plugin_output.stderr,
    )?;
    let plugins = parse_plugins(&plugin_output.stdout)?;

    let (preferences_args, preferences_output, verified_profile_preferences) =
        inspect_preferences(prepared)?;
    let effective_preferences_count = preference_count(&preferences_output.stdout)?;
    Ok(ToolInspection {
        version,
        version_output,
        plugin_args,
        plugin_output,
        preferences_args,
        preferences_output,
        plugins,
        verified_profile_preferences,
        effective_preferences_count,
    })
}

type PreferenceInspection = (Vec<OsString>, process::Output, BTreeMap<String, String>);

pub(super) fn inspect_preferences(
    prepared: &PreparedCapture,
) -> Result<PreferenceInspection, Box<dyn Error>> {
    let preferences_args = ["-G", "currentprefs", "-n", "-C", PROFILE]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
    let preferences_output = run_phase(prepared, &preferences_args, prepared.metadata_maximum)?;
    require_success(
        "effective preferences",
        preferences_output.status,
        &preferences_output.stderr,
    )?;
    let verified = verify_effective_preferences(&preferences_output.stdout, &prepared.profile)?;
    Ok((preferences_args, preferences_output, verified))
}

pub(super) fn inspect_version(
    prepared: &PreparedCapture,
) -> Result<(String, process::Output), Box<dyn Error>> {
    let version_args = [OsString::from("-n"), OsString::from("-v")];
    let version_output = run_phase(prepared, &version_args, prepared.metadata_maximum)?;
    require_success("version", version_output.status, &version_output.stderr)?;
    let version = String::from_utf8(version_output.stdout.clone())?
        .lines()
        .next()
        .ok_or("TShark did not report its version")?
        .trim()
        .to_owned();
    version::validate(&version)?;
    Ok((version, version_output))
}

fn parse_plugins(bytes: &[u8]) -> Result<Vec<PluginRecord>, Box<dyn Error>> {
    let text = std::str::from_utf8(bytes)?;
    text.lines()
        .filter(|line| !line.is_empty())
        .map(|line| {
            let mut columns = line.split('\t');
            let name = columns.next().ok_or("TShark plugin name is missing")?;
            let version = columns.next().ok_or("TShark plugin version is missing")?;
            let kind = columns.next().ok_or("TShark plugin type is missing")?;
            let path = columns.next().ok_or("TShark plugin path is missing")?;
            if columns.next().is_some()
                || [name, version, kind, path]
                    .iter()
                    .any(|value| value.is_empty())
            {
                return Err("TShark returned a malformed plugin record".into());
            }
            Ok(PluginRecord {
                name: name.to_owned(),
                version: version.to_owned(),
                kind: kind.to_owned(),
                path: path.to_owned(),
            })
        })
        .collect()
}

fn preference_count(bytes: &[u8]) -> Result<usize, Box<dyn Error>> {
    Ok(std::str::from_utf8(bytes)?
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .count())
}
