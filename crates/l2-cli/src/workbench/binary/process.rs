use std::{
    error::Error,
    ffi::OsStr,
    io::{self, Read},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

pub(super) struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

struct Guard(Child);
impl Drop for Guard {
    fn drop(&mut self) {
        // Failed reads and deadlines also reap the analyzer process
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(target_os = "linux")]
pub(super) fn run(arguments: &[&OsStr], maximum: usize) -> Result<Output, Box<dyn Error>> {
    use rustix::fs::{OFlags, fcntl_getfl, fcntl_setfl};
    let mut child = Guard(
        Command::new("r2")
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?,
    );
    let mut stdout = child
        .0
        .stdout
        .take()
        .ok_or("radare2 output pipe unavailable")?;
    let mut stderr = child
        .0
        .stderr
        .take()
        .ok_or("radare2 diagnostic pipe unavailable")?;
    fcntl_setfl(&stdout, fcntl_getfl(&stdout)? | OFlags::NONBLOCK)?;
    fcntl_setfl(&stderr, fcntl_getfl(&stderr)? | OFlags::NONBLOCK)?;
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut output = Output {
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    loop {
        let stdout_closed = drain(&mut stdout, &mut output.stdout, maximum)?;
        let stderr_closed = drain(&mut stderr, &mut output.stderr, 256 * 1024)?;
        if let Some(status) = child.0.try_wait()? {
            if !status.success() {
                return Err(format!("radare2 static analysis failed with {status}").into());
            }
            if stdout_closed && stderr_closed {
                return Ok(output);
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "radare2 analysis exceeded 30 seconds",
            )
            .into());
        }
        thread::sleep(Duration::from_millis(2));
    }
}

#[cfg(not(target_os = "linux"))]
pub(super) fn run(_arguments: &[&OsStr], _maximum: usize) -> Result<Output, Box<dyn Error>> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "bounded radare2 process capture requires Linux",
    )
    .into())
}

fn drain(reader: &mut impl Read, output: &mut Vec<u8>, maximum: usize) -> io::Result<bool> {
    let mut buffer = [0_u8; 8192];
    // Return regularly even if the analyzer continuously writes output
    for _ in 0..32 {
        match reader.read(&mut buffer) {
            Ok(0) => return Ok(true),
            Ok(length) => {
                if output.len() + length > maximum {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "radare2 output exceeded its byte budget",
                    ));
                }
                output.extend_from_slice(
                    buffer
                        .get(..length)
                        .ok_or_else(|| io::Error::other("analyzer read exceeded its buffer"))?,
                );
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(false),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(false)
}
