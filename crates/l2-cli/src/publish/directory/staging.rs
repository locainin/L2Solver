//! Keep staging writes and cleanup bound to a verified directory

use super::inspection::{
    DirectoryIdentity, open_directory_at, trusted_directory_identity, verify_named_directory,
};
use rustix::fd::OwnedFd;
use std::{
    ffi::{OsStr, OsString},
    fs::Permissions,
    io,
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    path::PathBuf,
};

#[cfg(test)]
#[path = "../../../tests/publish/staging.rs"]
mod tests;

pub(super) struct StagedDirectory<'a> {
    temporary: tempfile::TempDir,
    parent: &'a OwnedFd,
    pub(super) name: OsString,
    pub(super) fd: OwnedFd,
    pub(super) identity: DirectoryIdentity,
    retained: bool,
}

impl<'a> StagedDirectory<'a> {
    pub(super) fn create(parent: &'a OwnedFd, destination: &OsStr) -> io::Result<Self> {
        let trust = super::super::recheck_output_parent(parent)?;
        let proc_fd = super::super::open_proc_fd_directory()?;
        let parent_number = parent.as_raw_fd().to_string();
        super::super::verify_proc_fd_entry(&proc_fd, parent, &parent_number)?;
        let stable_parent = PathBuf::from(format!("/proc/thread-self/fd/{parent_number}"));
        // Distinct prefixes keep an unpublished stage from taking the destination name
        let prefix = if destination
            .as_encoded_bytes()
            .starts_with(b".l2solver-stage-")
        {
            ".l2solver-tmp-"
        } else {
            ".l2solver-stage-"
        };
        // Leave the stage alone if its identity cannot be established
        let temporary = tempfile::Builder::new()
            .prefix(prefix)
            .permissions(Permissions::from_mode(0o700))
            .disable_cleanup(true)
            .tempdir_in(stable_parent)?;
        let name = temporary
            .path()
            .file_name()
            .ok_or_else(|| io::Error::other("temporary directory has no name"))?
            .to_owned();
        let fd = open_directory_at(parent, &name, None)?;
        super::super::verify_proc_fd_entry(&proc_fd, &fd, &fd.as_raw_fd().to_string())?;
        let parent_mount = super::super::trust_policy::mount_id(parent)?;
        let identity =
            trusted_directory_identity(&trust, &fd, "staging directory", Some(parent_mount))?;
        Ok(Self {
            temporary,
            parent,
            name,
            fd,
            identity,
            retained: false,
        })
    }

    pub(super) fn writer_path(&self) -> PathBuf {
        // The writer addresses the inode even if the stage name changes
        PathBuf::from(format!("/proc/thread-self/fd/{}/.", self.fd.as_raw_fd()))
    }

    pub(super) fn check(&self) -> io::Result<()> {
        let trust = super::super::recheck_output_parent(self.parent)?;
        let parent_mount = super::super::trust_policy::mount_id(self.parent)?;
        let identity =
            trusted_directory_identity(&trust, &self.fd, "staging directory", Some(parent_mount))?;
        if identity != self.identity {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "held staging identity changed before publication",
            ));
        }
        verify_named_directory(self.parent, &self.name, self.identity)
    }

    pub(super) const fn retain(&mut self) {
        self.retained = true;
    }
}

impl Drop for StagedDirectory<'_> {
    fn drop(&mut self) {
        // Cleanup may remove the name only while it still identifies this stage in a trusted parent
        if !self.retained && self.check().is_ok() {
            self.temporary.disable_cleanup(false);
        }
    }
}
