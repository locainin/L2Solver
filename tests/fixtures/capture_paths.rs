use super::captures;

use std::{io, path::PathBuf};

pub struct CapturePaths {
    directory: tempfile::TempDir,
}

impl CapturePaths {
    pub fn new() -> io::Result<Self> {
        let directory = tempfile::tempdir()?;
        // Keep every generated capture inside the directory that owns its lifetime
        for (name, bytes) in [
            ("lldp.pcap", captures::LLDP),
            ("linux-stp.pcap", captures::LINUX_STP),
            ("short.pcap", captures::SHORT),
            ("unsupported.pcapng", captures::UNSUPPORTED),
            ("wifi-drift-radiotap.pcap", captures::WIFI_DRIFT),
        ] {
            std::fs::write(directory.path().join(name), bytes)?;
        }
        Ok(Self { directory })
    }

    pub fn path(&self, name: &str) -> PathBuf {
        self.directory.path().join(name)
    }
}
