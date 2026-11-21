use super::*;

const KIB: u64 = 1024;

#[test]
fn process_reservation() -> TestResult {
    let memory = MemoryBudget::new(64 * KIB);
    let case = memory.try_working_set(8 * KIB)?;
    let before = memory.snapshot()?;
    let process = memory.try_process_working_set(16 * KIB)?;
    let during = memory.snapshot()?;

    assert_eq!(during.working_sets.active_cases, 1);
    assert_eq!(during.working_sets.admitted_cases, 1);
    assert_eq!(during.working_sets.active_processes, 1);
    assert_eq!(during.working_sets.peak_active_processes, 1);
    assert_eq!(during.working_sets.admitted_processes, 1);
    assert_eq!(during.working_sets.reserved_bytes, 24 * KIB);
    // Only the ledger's metadata is an owned allocation
    assert!(during.used_bytes - before.used_bytes < 16 * KIB);

    drop(process);
    let after = memory.snapshot()?;
    assert_eq!(after.used_bytes, before.used_bytes);
    assert_eq!(after.working_sets.reserved_bytes, 8 * KIB);
    assert_eq!(after.working_sets.active_processes, 0);
    assert_eq!(after.working_sets.peak_active_processes, 1);
    assert_eq!(after.working_sets.admitted_processes, 1);
    assert_eq!(after.working_sets.active_cases, 1);
    drop(case);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn process_and_case_share_limit() -> TestResult {
    let memory = MemoryBudget::new(64 * KIB);
    let process = memory.try_process_working_set(40 * KIB)?;
    let before = memory.snapshot()?;
    assert!(memory.try_working_set(30 * KIB).is_err());
    let denied = memory.snapshot()?;
    assert_eq!(denied.working_sets.active_cases, 0);
    assert_eq!(denied.working_sets.active_processes, 1);
    assert_eq!(denied.working_sets.reserved_bytes, 40 * KIB);
    assert_eq!(
        denied.working_sets.admission_denials,
        before.working_sets.admission_denials + 1
    );
    drop(process);
    let case = memory.try_working_set(30 * KIB)?;
    assert_eq!(memory.snapshot()?.working_sets.active_cases, 1);
    drop(case);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}

#[test]
fn concurrent_process_admission() -> TestResult {
    let memory = MemoryBudget::new(32 * KIB);
    let start = Arc::new(Barrier::new(3));
    let finish = Arc::new(Barrier::new(3));
    let (sender, receiver) = mpsc::channel();
    let mut threads = Vec::new();
    for _ in 0..2 {
        let memory = memory.clone();
        let start = Arc::clone(&start);
        let finish = Arc::clone(&finish);
        let sender = sender.clone();
        threads.push(thread::spawn(move || {
            start.wait();
            let reservation = memory.try_process_working_set(20 * KIB);
            let _ = sender.send(reservation.is_ok());
            finish.wait();
            drop(reservation);
        }));
    }
    start.wait();
    let admitted = [
        receiver.recv_timeout(Duration::from_secs(2))?,
        receiver.recv_timeout(Duration::from_secs(2))?,
    ];
    let snapshot = memory.snapshot()?;
    finish.wait();
    for thread in threads {
        thread.join().map_err(|_| "reservation worker panicked")?;
    }
    assert_eq!(admitted.into_iter().filter(|success| *success).count(), 1);
    assert_eq!(snapshot.working_sets.active_processes, 1);
    assert_eq!(snapshot.working_sets.reserved_bytes, 20 * KIB);
    assert_eq!(memory.snapshot()?.working_sets.reserved_bytes, 0);
    assert_eq!(memory.snapshot()?.used_bytes, 0);
    Ok(())
}
