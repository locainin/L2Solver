//! Offline path operands resolve to bounded streams without blocking on special files

use std::{
    error::Error,
    fs::{File, OpenOptions},
    io::{self, BufReader, Read, Seek, SeekFrom},
    path::{Path, PathBuf},
};

pub type CaptureReader = BufReader<Box<dyn Read>>;

/// Add source context to capture-format errors while preserving path-aware I/O errors
pub fn capture_error(path: &Path, error: l2_pcap::Error) -> Box<dyn Error> {
    if matches!(&error, l2_pcap::Error::Io(_)) {
        return Box::new(error);
    }
    Box::new(CapturePathError {
        path: path.to_owned(),
        source: error,
    })
}

/// Add source context only when a boxed capture parser error reaches a text boundary
pub fn boxed_capture_error(path: &Path, error: Box<dyn Error>) -> Box<dyn Error> {
    match error.downcast::<l2_pcap::Error>() {
        Ok(error) => capture_error(path, *error),
        Err(error) => error,
    }
}

#[derive(Debug)]
struct CapturePathError {
    path: PathBuf,
    source: l2_pcap::Error,
}

impl std::fmt::Display for CapturePathError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "capture '{}': {}",
            self.path.display(),
            self.source
        )
    }
}

impl Error for CapturePathError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.source)
    }
}

/// A regular input file that keeps filesystem failures attached to its path
pub struct InputFile<R = File> {
    inner: R,
    path: PathBuf,
}

impl<R> InputFile<R> {
    const fn new(inner: R, path: PathBuf) -> Self {
        Self { inner, path }
    }

    pub(crate) fn into_inner(self) -> R {
        self.inner
    }
}

impl<R: Read> Read for InputFile<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        with_path(&self.path, "read", self.inner.read(buffer))
    }
}

impl<R: Seek> Seek for InputFile<R> {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        with_path(&self.path, "seek", self.inner.seek(position))
    }
}

impl InputFile<File> {
    pub fn metadata(&self) -> io::Result<std::fs::Metadata> {
        with_path(&self.path, "inspect", self.inner.metadata())
    }
}

#[cfg(target_os = "linux")]
impl<R: std::os::fd::AsFd> std::os::fd::AsFd for InputFile<R> {
    fn as_fd(&self) -> std::os::fd::BorrowedFd<'_> {
        self.inner.as_fd()
    }
}

/// Open `-` as standard input or require a regular filesystem object
///
/// # Errors
/// Returns an I/O error when the path cannot be opened or is not a regular file
pub fn capture(path: &Path) -> io::Result<CaptureReader> {
    if path == Path::new("-") {
        return Ok(BufReader::new(Box::new(InputFile::new(
            io::stdin(),
            path.to_owned(),
        ))));
    }
    Ok(BufReader::new(Box::new(regular(path)?)))
}

/// Open one regular file while rejecting FIFOs, devices, sockets, and directories
///
/// # Errors
/// Returns an I/O error when opening or file-type validation fails
pub fn regular(path: &Path) -> io::Result<InputFile> {
    open_regular(path, false)
}

/// Open one regular file while rejecting a symbolic link in the final path component
///
/// Unix applies the check atomically to the final component; parent components may resolve
/// through symbolic links. Other platforms perform a pre-open check and validate the opened
/// target, but cannot provide the same race-free guarantee through `std::fs`
///
/// # Errors
/// Returns an I/O error when opening or file-type validation fails
pub fn regular_no_follow(path: &Path) -> io::Result<InputFile> {
    open_regular(path, true)
}

/// Allocate a reusable read buffer while reporting allocation failure as an I/O error
///
/// # Errors
/// Returns an I/O error when the fixed buffer cannot be allocated
pub fn io_buffer() -> io::Result<Vec<u8>> {
    const IO_BUFFER_BYTES: usize = 64 * 1024;

    let mut buffer = Vec::new();
    buffer
        .try_reserve_exact(IO_BUFFER_BYTES)
        .map_err(io::Error::other)?;
    buffer.resize(IO_BUFFER_BYTES, 0);
    Ok(buffer)
}

fn open_regular(path: &Path, no_follow: bool) -> io::Result<InputFile> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        // A FIFO with no writer must not trap an offline worker during open
        let mut flags = libc::O_NONBLOCK;
        if no_follow {
            flags |= libc::O_NOFOLLOW;
        }
        options.custom_flags(flags);
    }
    #[cfg(not(unix))]
    {
        // Check special files before open on platforms without a nonblocking flag
        let metadata = if no_follow {
            with_path(path, "inspect", std::fs::symlink_metadata(path))?
        } else {
            with_path(path, "inspect", std::fs::metadata(path))?
        };
        if no_follow && metadata.file_type().is_symlink() {
            return Err(context_error(path, "open", invalid_regular_input()));
        }
        with_path(path, "open", require_regular(&metadata))?;
    }
    let file = with_path(path, "open", options.open(path))?;
    // Validate the exact opened object so a path swap cannot bypass the check
    let metadata = with_path(path, "inspect", file.metadata())?;
    with_path(path, "open", require_regular(&metadata))?;
    Ok(InputFile::new(file, path.to_owned()))
}

fn with_path<T>(path: &Path, operation: &'static str, result: io::Result<T>) -> io::Result<T> {
    result.map_err(|source| context_error(path, operation, source))
}

fn context_error(path: &Path, operation: &'static str, source: io::Error) -> io::Error {
    io::Error::new(
        source.kind(),
        InputError {
            path: path.to_owned(),
            operation,
            source,
        },
    )
}

#[derive(Debug)]
struct InputError {
    path: PathBuf,
    operation: &'static str,
    source: io::Error,
}

impl std::fmt::Display for InputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "failed to {} '{}': {}",
            self.operation,
            self.path.display(),
            self.source
        )
    }
}

impl std::error::Error for InputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

fn invalid_regular_input() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        "offline input must be a regular file; use - for standard input",
    )
}

fn require_regular(metadata: &std::fs::Metadata) -> io::Result<()> {
    if metadata.is_file() {
        return Ok(());
    }
    Err(invalid_regular_input())
}
