#[path = "../src/publish.rs"]
mod publish;

#[cfg(target_os = "linux")]
#[path = "publish/directory.rs"]
mod directory;

#[cfg(target_os = "linux")]
mod linux {
    use super::publish::{
        self,
        test_hooks::{self, TestFault},
    };
    use std::{
        cell::Cell,
        ffi::OsString,
        fs,
        io::{self, Write},
        path::{Path, PathBuf},
        process::Command,
        sync::{
            Arc, Barrier,
            atomic::{AtomicU64, Ordering},
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };

    static NEXT_TEST_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    fn set_fault(fault: TestFault) {
        test_hooks::TEST_FAULT.with(|slot| slot.set(Some(fault)));
    }

    #[test]
    fn streamed_publication_callback_result_complete() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("streamed-result")?;
        let destination = root.join("result.bin");
        let result = publish::create(&destination, |file| {
            file.write_all(b"first")?;
            file.write_all(b"second")?;
            Ok(11_u64)
        })?;
        assert_eq!(result, 11);
        assert_eq!(fs::read(&destination)?, b"firstsecond");
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn parent_directory_components_opening_callback() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("parent-component")?;
        let real = root.join("real");
        fs::create_dir(&real)?;
        let destination = real.join("..").join("real").join("output.json");
        let callback_called = Cell::new(false);

        let error = require_failure(
            publish::create(&destination, |_| {
                callback_called.set(true);
                Ok(())
            }),
            "parent-directory component must be rejected",
        )?;

        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!callback_called.get());
        assert_eq!(fs::read_dir(&real)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn directory_style_destinations_opening_callback() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("directory-style-destination")?;
        let redirected = root.join("redirected");

        for destination in [root.join("redirected/."), root.join("redirected/")] {
            let callback_called = Cell::new(false);
            let error = require_failure(
                publish::create(&destination, |_| {
                    callback_called.set(true);
                    Ok(())
                }),
                "directory-style destination must be rejected",
            )?;

            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
            assert!(!callback_called.get());
            assert!(!redirected.exists());
        }

        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn unicode_destination_accepts_dot_components() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("unicode")?;
        let real = root.join("real");
        fs::create_dir(&real)?;
        let destination = root
            .join(".")
            .join("real")
            .join(".")
            .join("résumé-报告.json");

        publish::create(&destination, |file| file.write_all(b"complete"))?;

        assert_eq!(fs::read(real.join("résumé-报告.json"))?, b"complete");
        assert_eq!(fs::read_dir(&real)?.count(), 1);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn relative_destination_directory_without_replacement() -> Result<(), Box<dyn std::error::Error>>
    {
        let destination = Path::new("Cargo.toml");
        let error = require_failure(
            publish::create(destination, |file| file.write_all(b"replacement")),
            "relative destination collision must be rejected",
        )?;

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        Ok(())
    }

    #[test]
    fn refuses_existing_destination_without_replacement() -> Result<(), Box<dyn std::error::Error>>
    {
        let root = test_directory("existing")?;
        let destination = root.join("output.json");
        fs::write(&destination, b"existing")?;

        let error = require_failure(
            publish::create(&destination, |file| file.write_all(b"replacement")),
            "existing destination must be rejected",
        )?;

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert!(error.to_string().contains("destination already exists"));
        assert_eq!(fs::read(&destination)?, b"existing");
        assert_eq!(fs::read_dir(&root)?.count(), 1);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn failed_leaves_no_staging_entry() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("write-failure")?;
        let destination = root.join("output.json");

        let error = require_failure(
            publish::create(&destination, |file| {
                file.write_all(b"partial")?;
                Err(io::Error::other("simulated write failure"))
            }),
            "callback failure must be returned",
        )?;

        assert!(error.to_string().contains("write temporary output"));
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&root)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn injected_file_no_published_name() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("file-sync-failure")?;
        let destination = root.join("output.json");
        set_fault(TestFault::FileSync);

        let error = require_failure(
            publish::create(&destination, |file| file.write_all(b"complete")),
            "file sync failure must be returned",
        )?;

        assert!(error.to_string().contains("sync temporary output"));
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&root)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn injected_failure_no_published_name() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("link-failure")?;
        let destination = root.join("output.json");
        set_fault(TestFault::Link);

        let error = require_failure(
            publish::create(&destination, |file| file.write_all(b"complete")),
            "link failure must be returned",
        )?;

        assert!(error.to_string().contains("link temporary output"));
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&root)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn injected_directory_complete_published_file() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("directory-sync-failure")?;
        let destination = root.join("output.json");
        let sentinel = root.join("keep.txt");
        fs::write(&sentinel, b"keep")?;
        set_fault(TestFault::DirectorySync);

        let error = require_failure(
            publish::create(&destination, |file| file.write_all(b"complete")),
            "directory sync failure must be returned",
        )?;

        assert!(error.to_string().contains("sync output directory"));
        assert_eq!(fs::read(&destination)?, b"complete");
        assert_eq!(fs::read(&sentinel)?, b"keep");
        assert_eq!(fs::read_dir(&root)?.count(), 2);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn unsupported_tmpfile_without_named_fallback() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("unsupported-filesystem")?;
        let destination = root.join("output.json");
        set_fault(TestFault::UnsupportedFilesystem);

        let error = require_failure(
            publish::create(&destination, |file| file.write_all(b"complete")),
            "unsupported O_TMPFILE must be returned",
        )?;

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("unnamed temporary files"));
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&root)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn unavailable_proc_without_named_fallback() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("proc-unavailable")?;
        let destination = root.join("output.json");
        set_fault(TestFault::SecurePublication);

        let error = require_failure(
            publish::create(&destination, |file| file.write_all(b"complete")),
            "secure publication failure must be returned",
        )?;

        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(error.to_string().contains("/proc/self/fd"));
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&root)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn rejects_symlinked_parent_components() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("symlink-parent")?;
        let real = root.join("real");
        let linked = root.join("linked");
        fs::create_dir(&real)?;
        std::os::unix::fs::symlink(&real, &linked)?;
        let destination = linked.join("output.json");

        let error = require_failure(
            publish::create(&destination, |file| file.write_all(b"complete")),
            "symlinked parent components must be rejected",
        )?;

        assert_eq!(error.kind(), io::ErrorKind::NotADirectory);
        assert!(!real.join("output.json").exists());
        assert_eq!(fs::read_dir(&real)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn symlink_destination_without_following_replacing() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("symlink-destination")?;
        let outside = root.join("outside.txt");
        let destination = root.join("output.json");
        fs::write(&outside, b"outside")?;
        std::os::unix::fs::symlink(&outside, &destination)?;

        let error = require_failure(
            publish::create(&destination, |file| file.write_all(b"replacement")),
            "symlink destination must be treated as existing",
        )?;

        assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read(&outside)?, b"outside");
        assert_eq!(fs::read_link(&destination)?, outside);
        assert_eq!(fs::read_dir(&root)?.count(), 2);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn unlinked_parent_without_publishing_elsewhere() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("unlinked-parent")?;
        let parent = root.join("parent");
        let destination = parent.join("output.json");
        fs::create_dir(&parent)?;

        let error = require_failure(
            publish::create(&destination, |file| {
                file.write_all(b"complete")?;
                fs::remove_dir(&parent)?;
                Ok(())
            }),
            "an unlinked pinned directory must not accept publication",
        )?;

        assert!(error.to_string().contains("link temporary output"));
        assert!(!destination.exists());
        assert!(!parent.exists());
        assert_eq!(fs::read_dir(&root)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn parent_replacement_cannot_publication_cleanup() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("parent-replacement")?;
        let original = root.join("workspace");
        let renamed = root.join("renamed");
        let replacement = root.join("replacement");
        let destination = original.join("output.json");
        fs::create_dir(&original)?;
        fs::create_dir(&replacement)?;
        let replacement_sentinel = replacement.join("output.json");

        publish::create(&destination, |file| {
            file.write_all(b"complete")?;
            fs::rename(&original, &renamed)?;
            std::os::unix::fs::symlink(&replacement, &original)?;
            fs::write(&replacement_sentinel, b"outside")?;
            Ok(())
        })?;

        assert_eq!(fs::read(renamed.join("output.json"))?, b"complete");
        assert_eq!(fs::read(&replacement_sentinel)?, b"outside");
        assert_eq!(fs::read_dir(&renamed)?.count(), 1);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn name_longer_without_staging() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("name-too-long")?;
        let long_name = OsString::from("n".repeat(usize::try_from(libc::NAME_MAX)? + 1));
        let destination = root.join(long_name);

        let error = require_failure(
            publish::create(&destination, |file| file.write_all(b"complete")),
            "NAME_MAX violation must be reported",
        )?;

        assert_eq!(error.kind(), io::ErrorKind::InvalidFilename);
        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&root)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn concurrent_publishers_no_replace_winner() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("concurrent")?;
        let destination = root.join("output.json");
        let workers = 8;
        let barrier = Arc::new(Barrier::new(workers));
        let mut handles = Vec::with_capacity(workers);

        for index in 0..workers {
            let barrier = Arc::clone(&barrier);
            let destination = destination.clone();
            handles.push(thread::spawn(move || {
                publish::create(&destination, |file| {
                    barrier.wait();
                    file.write_all(format!("worker-{index}").as_bytes())
                })
            }));
        }

        let mut successes = 0;
        for handle in handles {
            let result = handle.join().map_err(|_| "publisher thread panicked")?;
            if let Err(error) = result {
                assert_eq!(error.kind(), io::ErrorKind::AlreadyExists);
            } else {
                successes += 1;
            }
        }

        assert_eq!(successes, 1);
        assert!(fs::read(&destination)?.starts_with(b"worker-"));
        assert_eq!(fs::read_dir(&root)?.count(), 1);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn child_publish_process() -> Result<(), Box<dyn std::error::Error>> {
        let Ok(stage) = std::env::var("L2SOLVER_PUBLISH_PAUSE_STAGE") else {
            return Ok(());
        };
        let destination = PathBuf::from(
            std::env::var_os("L2SOLVER_PUBLISH_CHILD_DESTINATION")
                .ok_or("missing child destination")?,
        );
        let ready = PathBuf::from(
            std::env::var_os("L2SOLVER_PUBLISH_READY").ok_or("missing child ready marker")?,
        );
        let release = PathBuf::from(
            std::env::var_os("L2SOLVER_PUBLISH_RELEASE").ok_or("missing child release marker")?,
        );
        assert!(matches!(stage.as_str(), "before-link" | "after-link"));
        publish::create(&destination, |file| file.write_all(b"complete"))?;
        assert!(ready.exists());
        assert!(release.exists());
        Ok(())
    }

    fn require_failure(
        result: io::Result<()>,
        message: &str,
    ) -> Result<io::Error, Box<dyn std::error::Error>> {
        match result {
            Ok(()) => Err(io::Error::other(message).into()),
            Err(error) => Ok(error),
        }
    }

    #[test]
    fn killing_child_no_staging_name() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("kill-before-link")?;
        let destination = root.join("output.json");
        kill_child_at_stage(&root, &destination, "before-link")?;

        assert!(!destination.exists());
        assert_eq!(fs::read_dir(&root)?.count(), 0);
        remove_test_directory(&root)?;
        Ok(())
    }

    #[test]
    fn killing_child_without_staging_name() -> Result<(), Box<dyn std::error::Error>> {
        let root = test_directory("kill-after-link")?;
        let destination = root.join("output.json");
        kill_child_at_stage(&root, &destination, "after-link")?;

        assert_eq!(fs::read(&destination)?, b"complete");
        assert_eq!(fs::read_dir(&root)?.count(), 1);
        remove_test_directory(&root)?;
        Ok(())
    }

    fn kill_child_at_stage(
        root: &Path,
        destination: &Path,
        stage: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let marker_root = root.join(format!("markers-{stage}"));
        fs::create_dir(&marker_root)?;
        let ready = marker_root.join("ready");
        let release = marker_root.join("release");
        let mut child = Command::new(std::env::current_exe()?)
            .args(["--exact", "linux::child_publish_process"])
            .env("L2SOLVER_PUBLISH_PAUSE_STAGE", stage)
            .env("L2SOLVER_PUBLISH_CHILD_DESTINATION", destination)
            .env("L2SOLVER_PUBLISH_READY", &ready)
            .env("L2SOLVER_PUBLISH_RELEASE", &release)
            .spawn()?;

        wait_for_path(&ready, Duration::from_secs(5))?;
        let _ = child.kill();
        let status = child.wait()?;
        assert!(!status.success(), "killed child unexpectedly succeeded");
        fs::remove_dir_all(marker_root)?;
        Ok(())
    }

    fn wait_for_path(path: &Path, timeout: Duration) -> io::Result<()> {
        let started = Instant::now();
        while !path.exists() {
            if started.elapsed() >= timeout {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("timed out waiting for {}", path.display()),
                ));
            }
            thread::sleep(Duration::from_millis(10));
        }
        Ok(())
    }

    fn test_directory(name: &str) -> io::Result<PathBuf> {
        let sequence = NEXT_TEST_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(io::Error::other)?
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("l2solver-publish-{name}-{timestamp}-{sequence}"));
        fs::create_dir(&root)?;
        Ok(root)
    }

    fn remove_test_directory(path: &Path) -> io::Result<()> {
        fs::remove_dir_all(path)
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn secure_publication_requires_linux() -> Result<(), Box<dyn std::error::Error>> {
    let destination = std::env::temp_dir().join("l2solver-publish-unsupported-output");
    let error = match publish::create(&destination, |_| Ok(())) {
        Ok(()) => return Err(std::io::Error::other("non-Linux must fail closed").into()),
        Err(error) => error,
    };
    assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    Ok(())
}
