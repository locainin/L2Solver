use super::snapshot::{HashControl, hash_file};
use std::{
    fs::{self, File},
    io,
    path::{Path, PathBuf},
};

pub(super) fn resolve_executable(program: &Path) -> io::Result<PathBuf> {
    let has_path_component = program.is_absolute()
        || program.components().count() > 1
        || program
            .parent()
            .is_some_and(|parent| !parent.as_os_str().is_empty());
    if has_path_component {
        return executable_file(program)?.ok_or_else(|| executable_not_found(program));
    }
    let search_path = std::env::var_os("PATH").unwrap_or_default();
    resolve_executable_in_search_path(program, &search_path)
}

pub(super) fn resolve_executable_in_search_path(
    program: &Path,
    search_path: &std::ffi::OsStr,
) -> io::Result<PathBuf> {
    for directory in std::env::split_paths(search_path) {
        let candidate = directory.join(program);
        if let Some(resolved) = executable_file(&candidate)? {
            return Ok(resolved);
        }
        #[cfg(windows)]
        if candidate.extension().is_none()
            && let Some(resolved) = executable_file(&candidate.with_extension("exe"))?
        {
            return Ok(resolved);
        }
    }
    Err(executable_not_found(program))
}

fn executable_file(path: &Path) -> io::Result<Option<PathBuf>> {
    let resolved = match path.canonicalize() {
        Ok(path) => path,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let metadata = fs::metadata(&resolved)?;
    if !metadata.is_file() {
        return Ok(None);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Ok(None);
        }
    }
    Ok(Some(resolved))
}

fn executable_not_found(program: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::NotFound,
        format!("TShark executable not found: {}", program.display()),
    )
}

pub(super) fn verify_executable_unchanged(
    file: &mut File,
    length: u64,
    digest: &str,
    control: HashControl<'_>,
) -> io::Result<()> {
    let (current_length, current_digest) = hash_file(file, length, control)?;
    if current_length != length || current_digest != digest {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "TShark executable changed while enrichment was running",
        ));
    }
    Ok(())
}
