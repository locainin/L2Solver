//! Fixed-workload parser benchmark with capture setup outside the timed region

use std::{
    env,
    error::Error,
    hint::black_box,
    io::{self, Write},
    time::Instant,
};

const BENCH_ITERATIONS: u32 = 50_000_000;

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = env::args_os().skip(1).collect::<Vec<_>>();
    // Test discovery must not execute the fixed workload or emit timing output
    if arguments.iter().any(|argument| argument == "--list") {
        if !arguments.iter().any(|argument| argument == "--ignored") {
            writeln!(io::stdout().lock(), "ethernet_lldp: benchmark")?;
        }
        return Ok(());
    }
    let bytes = include_bytes!("../../../tests/pcaps/lldp.pcap");
    let mut capture = l2_pcap::CaptureReader::new(bytes.as_slice())?;
    let packet = capture
        .next_packet()?
        .ok_or("benchmark fixture has no packet")?;
    let start = Instant::now();
    for _ in 0..BENCH_ITERATIONS {
        // Keep both input and parsed fields visible to the optimizer
        let frame = l2_core::decode(black_box(packet.bytes()))?;
        black_box(l2_codecs::decode_lldp(frame.payload)?);
    }
    writeln!(
        io::stdout().lock(),
        "ethernet_lldp iterations={BENCH_ITERATIONS} elapsed_ns={}",
        start.elapsed().as_nanos()
    )?;
    Ok(())
}
