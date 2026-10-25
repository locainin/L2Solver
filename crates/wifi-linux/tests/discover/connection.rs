use super::discover::finish_connection;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

#[derive(Debug)]
struct DropSignal(Arc<AtomicBool>);

impl Drop for DropSignal {
    fn drop(&mut self) {
        self.0.store(true, Ordering::Release);
    }
}

fn spawn_pending_worker(dropped: &Arc<AtomicBool>) -> tokio::task::JoinHandle<()> {
    let signal = DropSignal(Arc::clone(dropped));
    tokio::spawn(async move {
        let _signal = signal;
        std::future::pending::<()>().await;
    })
}

#[test]
fn expected_connection_abort_is_successful() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime
        .block_on(async { finish_connection(tokio::spawn(std::future::pending::<()>())).await })?;
    Ok(())
}

#[test]
fn completed_connection_is_successful() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        let task = tokio::spawn(async {});
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
        finish_connection(task).await
    })?;
    Ok(())
}

#[test]
fn failed_connection_preserves_worker_error() {
    let result = super::discover::connection_result(super::discover::ConnectionOutcome::Failed(
        String::from("simulated connection failure"),
    ));

    assert_eq!(
        result,
        Err(crate::DiscoveryError::Netlink(String::from(
            "connection worker failed: simulated connection failure",
        ))),
    );
}

#[test]
fn external_deadline_collection_aborts_worker() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    let result = runtime.block_on(async {
        let dropped = Arc::new(AtomicBool::new(false));
        let connection = spawn_pending_worker(&dropped);
        let deadline_result = tokio::time::timeout(
            Duration::from_millis(10),
            super::discover::collect_with_connection(
                connection,
                std::future::pending::<Result<(), crate::DiscoveryError>>(),
            ),
        )
        .await;
        let worker_drop_result = tokio::time::timeout(Duration::from_millis(100), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await;
        (deadline_result, worker_drop_result)
    });

    assert!(result.0.is_err(), "deadline did not cancel the collection");
    assert!(
        result.1.is_ok(),
        "connection worker remained detached after deadline cancellation"
    );
    Ok(())
}

#[test]
fn dropping_collection_aborts_connection_worker() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()?;
    runtime.block_on(async {
        let dropped = Arc::new(AtomicBool::new(false));
        let connection = spawn_pending_worker(&dropped);
        let started = Arc::new(AtomicBool::new(false));
        let collection_started = Arc::clone(&started);
        let pending_collection = async move {
            collection_started.store(true, Ordering::Release);
            std::future::pending::<Result<(), crate::DiscoveryError>>().await
        };
        let collection = tokio::spawn(super::discover::collect_with_connection(
            connection,
            pending_collection,
        ));
        tokio::time::timeout(Duration::from_millis(100), async {
            while !started.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "collection did not start before cancellation")?;
        collection.abort();
        let _ = collection.await;

        tokio::time::timeout(Duration::from_millis(100), async {
            while !dropped.load(Ordering::Acquire) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .map_err(|_| "connection worker remained detached after collection was dropped")
    })?;
    Ok(())
}

#[test]
fn successful_collection_value_stopping_worker() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        let dropped = Arc::new(AtomicBool::new(false));
        let connection = spawn_pending_worker(&dropped);

        let result = super::discover::collect_with_connection(connection, async {
            Ok::<_, crate::DiscoveryError>(42)
        })
        .await?;

        assert_eq!(result, 42);
        assert!(dropped.load(Ordering::Acquire));
        Ok::<_, crate::DiscoveryError>(())
    })?;
    Ok(())
}

#[test]
fn failed_collection_worker_error() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread().build()?;
    runtime.block_on(async {
        let dropped = Arc::new(AtomicBool::new(false));
        let connection = spawn_pending_worker(&dropped);

        let result = super::discover::collect_with_connection(connection, async {
            Err::<(), _>(crate::DiscoveryError::Netlink(String::from(
                "simulated collection failure",
            )))
        })
        .await;

        assert!(matches!(
            result,
            Err(crate::DiscoveryError::Netlink(reason))
                if reason == "simulated collection failure"
        ));
        assert!(dropped.load(Ordering::Acquire));
        Ok::<_, Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}
