use super::{Check, CheckBindingOrigin, RecordedCheck, Result, invalid};
use sha2::{Digest, Sha256};

const IDENTITY_DOMAIN: &[u8] = b"L2Solver journal check v2\0";

/// Bind the selected model, exact stored check bytes and evidence reference
pub(super) fn identity(hypothesis: &str, value: &[u8], evidence: &str) -> Result<String> {
    let mut digest = Sha256::new();
    digest.update(IDENTITY_DOMAIN);
    for part in [hypothesis.as_bytes(), value, evidence.as_bytes()] {
        digest.update(u64::try_from(part.len())?.to_be_bytes());
        digest.update(part);
    }
    Ok(format!("{:x}", digest.finalize()))
}

/// Check the digest before decoding the value that can affect a conclusion
pub(super) fn decode(
    id: u64,
    hypothesis: &str,
    recorded_identity: String,
    value: String,
    evidence_sha256: String,
    binding_origin: &str,
) -> Result<RecordedCheck> {
    if id == 0 {
        return Err(invalid("journal check identity must use a positive row ID"));
    }
    if !crate::hashing::is_sha256_digest(hypothesis)
        || !crate::hashing::is_sha256_digest(&recorded_identity)
    {
        return Err(invalid(
            "journal check identity must be a 64-character SHA-256 hash",
        ));
    }
    if !crate::hashing::is_sha256_digest(&evidence_sha256) {
        return Err(invalid(
            "journal check evidence must be a 64-character SHA-256 hash",
        ));
    }
    let value = value.into_bytes();
    if identity(hypothesis, &value, &evidence_sha256)? != recorded_identity {
        return Err(invalid("journal check identity mismatch"));
    }
    let check: Check = serde_json::from_slice(&value)?;
    if check.explanation.trim().is_empty() {
        return Err(invalid(
            "a check requires an explanation and supporting evidence",
        ));
    }
    let binding_origin = match binding_origin {
        "recorded" => CheckBindingOrigin::Recorded,
        "legacy_unverified" => CheckBindingOrigin::LegacyUnverified,
        _ => return Err(invalid("journal check binding origin is invalid")),
    };
    Ok(RecordedCheck {
        id,
        identity: recorded_identity,
        binding_origin,
        check,
        evidence_sha256,
    })
}
