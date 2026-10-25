#![no_main]

use l2_canary::{
    AgentId, AgentKey, Canary, CanaryIdentity, ReplayGuard, RunId, SessionKey, UnverifiedCanary,
    WIRE_LEN,
};
use libfuzzer_sys::fuzz_target;

// Exercise hostile bytes and a valid structure on every iteration
fuzz_target!(|data: &[u8]| {
    let Some(canary) = structured_canary(data) else {
        return;
    };
    let Ok(agent_key) = AgentKey::new(canary.source_agent_id(), &[0x42; 32]) else {
        return;
    };
    let Ok(key) = SessionKey::derive(&agent_key, &canary.identity()) else {
        return;
    };
    let _ = l2_canary::verify(UnverifiedCanary::new(data), &key);

    let Ok(encoded) = l2_canary::encode(&canary, &key) else {
        return;
    };
    assert_eq!(encoded.len(), WIRE_LEN);
    let Ok(verified) = l2_canary::verify(UnverifiedCanary::new(&encoded), &key) else {
        return;
    };
    assert_eq!(verified.as_canary(), &canary);

    let mut replay = ReplayGuard::new();
    assert!(replay.accept(&verified).is_ok());
    assert!(replay.accept(&verified).is_err());
});

fn structured_canary(data: &[u8]) -> Option<Canary> {
    let mut run_id = [0_u8; 16];
    let mut source_agent_id = [0_u8; 16];
    let mut destination_agent_id = [0_u8; 16];
    let mut nonce = [0_u8; 16];
    copy_available(data, 0, &mut run_id);
    copy_available(data, 16, &mut source_agent_id);
    copy_available(data, 32, &mut destination_agent_id);
    copy_available(data, 56, &mut nonce);
    if run_id.iter().all(|byte| *byte == 0) {
        run_id[0] = 1;
    }
    if source_agent_id.iter().all(|byte| *byte == 0) {
        source_agent_id[0] = 2;
    }
    if destination_agent_id.iter().all(|byte| *byte == 0) || destination_agent_id == source_agent_id
    {
        destination_agent_id[0] = source_agent_id[0].wrapping_add(1).max(1);
    }
    let sequence = data
        .get(48..56)
        .and_then(|bytes| <[u8; 8]>::try_from(bytes).ok())
        .map_or(1, u64::from_be_bytes);
    let identity = CanaryIdentity::new(
        RunId::from_recorded(run_id).ok()?,
        AgentId::new(source_agent_id).ok()?,
        AgentId::new(destination_agent_id).ok()?,
    )
    .ok()?;
    Canary::new(identity, sequence.max(1), nonce).ok()
}

fn copy_available(data: &[u8], offset: usize, output: &mut [u8; 16]) {
    let Some(available) = data.get(offset..) else {
        return;
    };
    let count = available.len().min(output.len());
    let Some(source) = available.get(..count) else {
        return;
    };
    let Some(destination) = output.get_mut(..count) else {
        return;
    };
    destination.copy_from_slice(source);
}
