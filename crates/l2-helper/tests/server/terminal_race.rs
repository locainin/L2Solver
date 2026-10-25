use std::error::Error;
use std::sync::{Arc, Barrier};
use std::thread;
use std::time::Duration;

use l2_helper::{FrontendClient, HelperReplyKind, HelperServer, QueueReceiveSocket, SessionStop};

use super::{binding, server_config, session, support};

#[test]
fn concurrent_close_winning_terminal_operation() -> Result<(), Box<dyn Error>> {
    let session = session(91)?;
    let Some((frontend, transport)) = support::pair()? else {
        return Ok(());
    };
    let client = FrontendClient::with_reply_timeout(frontend, session, Duration::from_secs(1))?;
    let receiver = QueueReceiveSocket::new(binding(91)?, vec![])?;
    let server = HelperServer::new(server_config(session)?, transport, receiver)?;
    let server = thread::spawn(move || server.run());
    client.hello()?;
    let barrier = Arc::new(Barrier::new(2));
    let workload_client = client.try_clone()?;
    let close_barrier = Arc::clone(&barrier);
    let close = thread::spawn(move || {
        close_barrier.wait();
        workload_client.close()
    });
    let cancel = thread::spawn(move || {
        barrier.wait();
        client.cancel()
    });
    let close = close.join().map_err(|_| "close worker panicked")?;
    let cancel = cancel.join().map_err(|_| "cancel worker panicked")?;
    let report = server.join().map_err(|_| "helper worker panicked")??;
    // The peer-state lock chooses one terminal transition, never both
    match report.stop() {
        SessionStop::Closed => {
            assert_eq!(close?, HelperReplyKind::Closed);
            assert!(cancel.is_err());
        }
        SessionStop::Cancelled => {
            assert_eq!(cancel?, HelperReplyKind::Cancelled);
            assert!(close.is_err());
        }
    }
    Ok(())
}
