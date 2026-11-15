use l2_workbench::sha256;
use std::{
    collections::BTreeMap,
    error::Error,
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};

pub(super) const PROFILE: &str = "l2solver-offline";
pub(super) const PREFERENCES: &str = "# L2Solver isolated offline profile\n\
gui.packet_list_show_related: FALSE\n\
ip.defragment: TRUE\n\
ipv6.defragment: TRUE\n\
tcp.desegment_tcp_streams: TRUE\n\
http.desegment_headers: TRUE\n\
http.desegment_body: TRUE\n\
tls.desegment_ssl_records: TRUE\n\
tls.desegment_ssl_application_data: TRUE\n";
pub(super) const REASSEMBLY_PREFERENCES: &[&str] = &[
    "ip.defragment=TRUE",
    "ipv6.defragment=TRUE",
    "tcp.desegment_tcp_streams=TRUE",
    "http.desegment_headers=TRUE",
    "http.desegment_body=TRUE",
    "tls.desegment_ssl_records=TRUE",
    "tls.desegment_ssl_application_data=TRUE",
];

pub(super) struct Profile {
    config_directory: PathBuf,
    extcap_directory: PathBuf,
    home_directory: PathBuf,
    xdg_config_directory: PathBuf,
    xdg_data_directory: PathBuf,
    temporary_directory: PathBuf,
    preferences: String,
    pub(super) preferences_sha256: String,
}

pub(super) fn create_profile(directory: &Path, object_files: Option<u64>) -> io::Result<Profile> {
    let mut preferences = PREFERENCES.to_owned();
    if let Some(object_files) = object_files {
        // A guard filename makes suffix exhaustion exceed the monitored file budget
        let collision_limit = object_files
            .checked_add(1)
            .and_then(|limit| i32::try_from(limit).ok())
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "TShark object count exceeds the supported collision limit",
                )
            })?;
        preferences.push_str("gui.max_export_objects: ");
        preferences.push_str(&collision_limit.to_string());
        preferences.push('\n');
    }
    let config_directory = directory.join("config");
    let extcap_directory = directory.join("extcap");
    let home_directory = directory.join("home");
    let xdg_config_directory = home_directory.join(".config");
    let xdg_data_directory = home_directory.join(".local").join("share");
    let profile_directory = config_directory.join("profiles").join(PROFILE);
    fs::create_dir_all(&profile_directory)?;
    fs::create_dir_all(&xdg_config_directory)?;
    fs::create_dir_all(&xdg_data_directory)?;
    // Offline reads need no external capture helpers, including helpers probed at startup
    fs::create_dir(&extcap_directory)?;
    fs::write(profile_directory.join("preferences"), &preferences)?;
    let preferences_sha256 = sha256(preferences.as_bytes());
    Ok(Profile {
        config_directory,
        extcap_directory,
        home_directory,
        xdg_config_directory,
        xdg_data_directory,
        temporary_directory: directory.to_owned(),
        preferences,
        preferences_sha256,
    })
}

pub(super) fn profile_environment(profile: &Profile) -> Vec<(OsString, OsString)> {
    let mut environment = [
        ("WIRESHARK_CONFIG_DIR", &profile.config_directory),
        ("WIRESHARK_EXTCAP_DIR", &profile.extcap_directory),
        ("HOME", &profile.home_directory),
        ("XDG_CONFIG_HOME", &profile.xdg_config_directory),
        ("XDG_DATA_HOME", &profile.xdg_data_directory),
        ("USERPROFILE", &profile.home_directory),
        ("APPDATA", &profile.config_directory),
        ("TMPDIR", &profile.temporary_directory),
        ("TMP", &profile.temporary_directory),
        ("TEMP", &profile.temporary_directory),
    ]
    .into_iter()
    .map(|(name, path)| (OsString::from(name), path.as_os_str().to_os_string()))
    .collect::<Vec<_>>();
    environment.extend(
        [("LC_ALL", "C"), ("LANG", "C"), ("TZ", "UTC")]
            .into_iter()
            .map(|(name, value)| (OsString::from(name), OsString::from(value))),
    );
    environment
}

pub(super) fn verify_effective_preferences(
    bytes: &[u8],
    profile: &Profile,
) -> Result<BTreeMap<String, String>, Box<dyn Error>> {
    let expected = profile
        .preferences
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(|line| {
            let (name, value) = line
                .split_once(':')
                .ok_or("invalid setting in the built-in TShark profile")?;
            Ok((name.trim().to_owned(), value.trim().to_owned()))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn Error>>>()?;
    let text = std::str::from_utf8(bytes)?;
    let mut observed = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        // Wireshark comments out settings that still equal their defaults
        let line = line.strip_prefix('#').unwrap_or(line).trim();
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if expected.contains_key(name) {
            observed.insert(name.to_owned(), value.trim().to_owned());
        }
    }
    for (name, value) in &expected {
        if observed.get(name) != Some(value) {
            return Err(
                format!("TShark profile setting {name} did not take effect as configured").into(),
            );
        }
    }
    Ok(observed)
}
