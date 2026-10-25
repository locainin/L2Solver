//! Generate bounded artifact names from validated formats and member paths

const MAX_BASENAME_BYTES: usize = 96;
const SAFE_FILE_EXTENSIONS: &[&str] = &[
    "aif", "aiff", "avi", "bin", "bmp", "bz2", "cer", "conf", "crt", "csv", "der", "doc", "docx",
    "eml", "gif", "gz", "h5", "hdf5", "htm", "html", "ini", "jpeg", "jpg", "json", "log", "md",
    "mov", "mp3", "mp4", "ods", "odt", "pdf", "png", "ppt", "pptx", "rtf", "svg", "tar", "tif",
    "tiff", "txt", "wav", "webp", "xls", "xlsx", "xml", "yaml", "yml", "zip",
];
pub(super) fn archive_member_name(node_id: u64, archive_path: Option<&str>) -> String {
    let basename = archive_path
        .and_then(|path| path.rsplit(['/', '\\']).find(|part| !part.is_empty()))
        .unwrap_or("archive-member");
    let basename = safe_basename(basename);
    let has_extension = basename
        .rsplit_once('.')
        .is_some_and(|(stem, extension)| !stem.is_empty() && safe_extension(extension).is_some());
    let basename = if has_extension {
        basename
    } else {
        format!("{basename}.bin")
    };
    format!("artifact-{node_id}-{basename}")
}

fn safe_basename(value: &str) -> String {
    let mut result = String::new();
    for character in value.chars() {
        let safe = if character.is_alphanumeric() || matches!(character, ' ' | '-' | '_' | '.') {
            character
        } else {
            '_'
        };
        if result.len().saturating_add(safe.len_utf8()) > MAX_BASENAME_BYTES {
            break;
        }
        result.push(safe);
    }
    let result = result.trim_matches([' ', '.']);
    if result.is_empty() || result == ".." {
        String::from("archive-member")
    } else {
        result.to_owned()
    }
}

pub(super) fn safe_extension(extension: &str) -> Option<String> {
    if !extension.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
        return None;
    }
    let extension = extension.to_ascii_lowercase();
    SAFE_FILE_EXTENSIONS
        .contains(&extension.as_str())
        .then_some(extension)
}
