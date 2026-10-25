use super::TransportReceipt;
use crate::sha256;
use std::{
    io::{self, Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    thread,
    time::{Duration, Instant},
};

const TRANSFER_DEADLINE: Duration = Duration::from_secs(2);
const POLL_INTERVAL: Duration = Duration::from_millis(1);
const RECEIVE_CHUNK_BYTES: usize = 8 * 1024;

pub(super) struct TransferResult {
    pub received: Vec<u8>,
    pub receipt: TransportReceipt,
}

pub(super) fn transfer(bytes: &[u8]) -> io::Result<TransferResult> {
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let deadline = Instant::now()
        .checked_add(TRANSFER_DEADLINE)
        .ok_or_else(|| timeout_error("loopback deadline overflow"))?;
    let mut client = TcpStream::connect_timeout(&address, remaining(deadline)?)?;
    client.set_nonblocking(true)?;
    let mut server = accept_client(&listener, &client, deadline)?;
    server.set_nonblocking(true)?;
    let received = pump_bytes(&mut client, &mut server, bytes, deadline)?;
    let receipt = TransportReceipt {
        address: String::from("127.0.0.1"),
        port: address.port(),
        sent_length: bytes.len(),
        received_length: received.len(),
        received_sha256: sha256(&received),
        matches_sent: received == bytes,
    };
    Ok(TransferResult { received, receipt })
}

fn accept_client(
    listener: &TcpListener,
    client: &TcpStream,
    deadline: Instant,
) -> io::Result<TcpStream> {
    let client_address = client.local_addr()?;
    loop {
        remaining(deadline)?;
        match listener.accept() {
            Ok((server, _)) if server.peer_addr()? == client_address => return Ok(server),
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(POLL_INTERVAL);
            }
            Err(error) => return Err(error),
        }
    }
}

fn pump_bytes(
    client: &mut TcpStream,
    server: &mut TcpStream,
    bytes: &[u8],
    deadline: Instant,
) -> io::Result<Vec<u8>> {
    let mut received = Vec::new();
    received
        .try_reserve_exact(bytes.len())
        .map_err(|_| io::Error::other("loopback receive allocation failed"))?;
    let mut sent = 0;
    let mut write_closed = false;
    let mut server_closed = false;
    while !server_closed {
        remaining(deadline)?;
        let mut progressed = false;
        if sent < bytes.len() {
            let pending = bytes
                .get(sent..)
                .ok_or_else(|| io::Error::other("loopback send cursor exceeds input"))?;
            match client.write(pending) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "loopback write ended",
                    ));
                }
                Ok(length) => {
                    sent = sent
                        .checked_add(length)
                        .ok_or_else(|| io::Error::other("loopback send length overflow"))?;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        } else if !write_closed {
            client.shutdown(Shutdown::Write)?;
            write_closed = true;
            progressed = true;
        }

        let mut chunk = [0_u8; RECEIVE_CHUNK_BYTES];
        match server.read(&mut chunk) {
            Ok(0) => server_closed = true,
            Ok(length) => {
                received.extend_from_slice(
                    chunk.get(..length).ok_or_else(|| {
                        io::Error::other("loopback read length exceeds its buffer")
                    })?,
                );
                progressed = true;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(error) => return Err(error),
        }
        if !progressed {
            thread::sleep(POLL_INTERVAL);
        }
    }
    Ok(received)
}

fn remaining(deadline: Instant) -> io::Result<Duration> {
    let duration = deadline.saturating_duration_since(Instant::now());
    if duration.is_zero() {
        return Err(timeout_error("loopback transfer exceeded two seconds"));
    }
    Ok(duration)
}

fn timeout_error(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, message)
}
