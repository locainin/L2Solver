#[cfg(unix)]
use std::ffi::OsString;
use xtask::args::{Command, MAX_REVIEW_NUMBER, ParseError, parse, usage};

#[test]
fn parses_each_maintenance_command() {
    let cases = [
        (vec!["check"], Command::Check),
        (vec!["fuzz-smoke"], Command::FuzzSmoke),
        (vec!["fuzz-release"], Command::FuzzRelease),
        (vec!["mutate"], Command::Mutate),
        (vec!["profile"], Command::Profile),
        (vec!["corpus-minimize"], Command::CorpusMinimize),
        (
            vec!["package-review", "5"],
            Command::PackageReview { number: 5 },
        ),
    ];

    for (arguments, expected) in cases {
        assert_eq!(parse(arguments), Ok(expected));
    }
}

#[test]
fn package_requires_bounded_positive_number() {
    for arguments in [
        vec!["package-review"],
        vec!["package-review", "+1"],
        vec!["package-review", "0"],
        vec!["package-review", "10001"],
        vec!["package-review", "5", "extra"],
    ] {
        assert!(matches!(parse(arguments), Err(ParseError::Usage(_))));
    }
    assert_eq!(
        parse(["package-review", &MAX_REVIEW_NUMBER.to_string()]),
        Ok(Command::PackageReview {
            number: MAX_REVIEW_NUMBER,
        })
    );
}

#[cfg(unix)]
#[test]
fn unknown_nonunicode_args_panic_free() {
    assert!(matches!(parse(["unknown"]), Err(ParseError::Usage(_))));
    let invalid = OsString::from_vec(vec![0xff]);
    assert!(matches!(parse([invalid]), Err(ParseError::NonUnicode)));
}

#[test]
fn usage_describes_the_public_commands() {
    let text = usage();
    assert!(text.contains("cargo xtask check"));
    assert!(text.contains("cargo xtask package-review <N>"));
}

#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
