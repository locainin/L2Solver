use super::*;
use std::{
    os::unix::process::ExitStatusExt,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const CHILD_ROOT: &str = "L2_TEST_EXECUTOR_UPDATE_CRASH_ROOT";
const CHILD_TEST: &str = "cache::execution_update::crash::executor_update_crash_child";

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
#[ignore = "runs only as a controlled child of killed_executor_update_preserves_the_last_committed_cursor"]
fn executor_update_crash_child() -> Result<(), Box<dyn Error>> {
    let root = std::env::var_os(CHILD_ROOT).ok_or("missing controlled child directory")?;
    let root = Path::new(&root);
    let cache = cache_at(root, 64 * 1024)?;
    let mut lease = cache.lease(&stage_key("executor-update")?)?;
    let active = lease
        .load_active(limits())?
        .ok_or("missing child checkpoint")?;
    let mut generation = active.generation().clone();
    let snapshot = active.snapshot().clone();
    drop(active);
    lease.update_active_executor(&mut generation, &snapshot, limits(), |writer| {
        writer.write_all(b"uncommitted cursor bytes")?;
        writer.flush()?;
        fs::write(root.join("ready"), b"cursor write started")?;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        Err::<Value, _>(io::Error::other("parent did not kill the child").into())
    })?;
    Err("child unexpectedly published its cursor".into())
}

#[test]
fn killed_executor_update_preserves_the_last_committed_cursor() -> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::new(None)?;
    let snapshot = fixture.initial_snapshot.clone();
    let usage = fixture.cache.stats()?.entry_bytes;
    drop(fixture.lease);
    let log = fs::File::create(fixture.temporary.path().join("child.log"))?;
    let child = Command::new(std::env::current_exe()?)
        .args(["--ignored", "--exact", CHILD_TEST, "--nocapture"])
        .env(CHILD_ROOT, fixture.temporary.path())
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    let mut child = OwnedChild(child);
    let deadline = Instant::now() + Duration::from_secs(30);
    let ready = fixture.temporary.path().join("ready");
    while !ready.exists() && Instant::now() < deadline {
        if child.0.try_wait()?.is_some() {
            return Err(format!(
                "child exited before writing its cursor: {}",
                fs::read_to_string(fixture.temporary.path().join("child.log"))?
            )
            .into());
        }
        thread::sleep(Duration::from_millis(10));
    }
    assert!(
        ready.exists(),
        "child never reached the partial cursor write"
    );
    assert!(
        fixture.cache.stats()?.entry_bytes > usage,
        "pending cursor bytes were not accounted"
    );
    child.0.kill()?;
    let status = child.0.wait()?;
    assert!(
        status.signal().is_some(),
        "the controlled child was not killed by a signal"
    );
    fixture.lease = fixture.cache.lease(&stage_key("executor-update")?)?;
    fixture.assert_current(b"cursor-zero", &json!({"cursor":0}), &snapshot)?;
    assert_eq!(fixture.cache.stats()?.entry_bytes, usage);
    assert_eq!(fs::read_dir(fixture.directory()?)?.count(), 3);
    Ok(())
}
