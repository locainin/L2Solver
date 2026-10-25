#![no_main]
use l2_engine::{EngineConfig, Event, EventEngine, FakeClock};
use libfuzzer_sys::fuzz_target;

// Input length bounds the workload even when cancellation or queue pressure occurs
fuzz_target!(|data: &[u8]| {
    let Ok(mut engine) = EventEngine::new(FakeClock::default(), EngineConfig::default()) else {
        return;
    };
    let mut previous = 0;
    for byte in data.iter().take(4096) {
        match byte % 5 {
            0 => {
                let _ = engine.enqueue(Event::CaptureGap {
                    dropped: u64::from(*byte),
                });
            }
            1 => {
                let _ = engine.set_timer(std::time::Duration::from_nanos(u64::from(*byte)));
            }
            2 => {
                let _ = engine.clock_mut().advance_nanos(u64::from(*byte));
            }
            3 => {
                let _ = engine.request_cancel();
            }
            _ => {
                let _ = engine.cleanup();
            }
        }
        if let Ok(Some(event)) = engine.next_ready() {
            assert!(event.sequence().get() > previous);
            previous = event.sequence().get();
        }
    }
});
