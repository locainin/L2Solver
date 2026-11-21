use super::{stat_identity_at, verify_exchange_identities};
use std::{ffi::OsStr, fs, io};

#[test]
fn exchange_requires_both_expected_directories() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    for name in ["previous", "staged", "other"] {
        fs::create_dir(root.path().join(name))?;
    }
    let parent = fs::File::open(root.path())?.into();
    let previous = stat_identity_at(&parent, OsStr::new("previous"))?;
    let staged = stat_identity_at(&parent, OsStr::new("staged"))?;
    let other = stat_identity_at(&parent, OsStr::new("other"))?;
    let expected = (previous, staged);

    verify_exchange_identities(expected, expected)?;
    // A mismatch at either name alone must make the exchange uncertain
    for actual in [(other, staged), (previous, other), (staged, previous)] {
        assert!(verify_exchange_identities(actual, expected).is_err());
    }
    Ok(())
}
