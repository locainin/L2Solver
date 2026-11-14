//! Supported upstream release lines for offline dissection

use std::io;

/// Reject affected, development and unrecognized builds before capture access
pub(super) fn validate(banner: &str) -> io::Result<()> {
    // Wireshark appends one period when it prints the complete banner
    let banner = banner.strip_suffix('.').unwrap_or(banner);
    let tail = banner
        .strip_prefix("TShark (Wireshark) ")
        .or_else(|| banner.strip_prefix("TShark "));
    let version = tail
        .filter(|tail| !has_development_metadata(tail))
        .and_then(|tail| tail.split_ascii_whitespace().next())
        .and_then(parse);
    // Older distro versions need independently verified backport evidence
    if matches!(version, Some((4, 4, patch)) if patch >= 19)
        || matches!(version, Some((4, 6, patch)) if patch >= 9)
    {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "TShark requires a supported patched upstream release: 4.4.19+ or 4.6.9+; development, prerelease and older backported builds are unqualified",
    ))
}

fn has_development_metadata(tail: &str) -> bool {
    // The first word is checked separately as the numeric release version
    tail.split_ascii_whitespace().skip(1).any(|word| {
        untagged_git_description(word)
            || word
                .split(|character: char| !character.is_ascii_alphanumeric())
                .any(development_fragment)
    })
}

fn untagged_git_description(word: &str) -> bool {
    let word = word.trim_matches(|character: char| matches!(character, '(' | ')' | '.' | ','));
    let mut parts = word.rsplitn(3, '-');
    let (Some(hash), Some(count), Some(tag)) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let Some(hash) = hash.strip_prefix('g') else {
        return false;
    };
    // Upstream uses v<release>-<commits>-g<hash> for Git descriptions
    !hash.is_empty()
        && hash.bytes().all(|byte| byte.is_ascii_hexdigit())
        && !count.is_empty()
        && count.bytes().all(|byte| byte.is_ascii_digit())
        && count.bytes().any(|byte| byte != b'0')
        && tag.starts_with('v')
}

fn development_fragment(fragment: &str) -> bool {
    let fragment = fragment.to_ascii_lowercase();
    if matches!(
        fragment.as_str(),
        "candidate" | "devel" | "development" | "dirty" | "prerelease"
    ) {
        return true;
    }
    [
        "rc", "dev", "alpha", "beta", "pre", "preview", "snapshot", "nightly",
    ]
    .into_iter()
    .any(|marker| {
        fragment.split_once(marker).is_some_and(|(prefix, suffix)| {
            prefix
                .bytes()
                .last()
                .is_some_and(|byte| byte.is_ascii_digit())
                || (prefix.is_empty()
                    && (suffix.is_empty()
                        || suffix
                            .bytes()
                            .next()
                            .is_some_and(|byte| byte.is_ascii_digit())))
        })
    })
}

fn parse(text: &str) -> Option<(u32, u32, u32)> {
    let mut parts = text.split('.');
    let major = component(parts.next()?)?;
    let minor = component(parts.next()?)?;
    let patch = component(parts.next()?)?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn component(text: &str) -> Option<u32> {
    if text.is_empty()
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || (text.len() > 1 && text.starts_with('0'))
    {
        return None;
    }
    text.parse().ok()
}

#[cfg(test)]
#[path = "../../../tests/workbench/tshark/version.rs"]
mod tests;
