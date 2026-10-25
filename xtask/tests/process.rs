use std::ffi::OsString;
use xtask::process::CommandSpec;

#[test]
fn command_args_avoid_shell_parsing() {
    let spec = CommandSpec::new("cargo")
        .arg("check")
        .arg("$(touch should-not-run)")
        .arg("a; b");

    assert_eq!(spec.program(), OsString::from("cargo"));
    assert_eq!(
        spec.arguments(),
        [
            OsString::from("check"),
            OsString::from("$(touch should-not-run)"),
            OsString::from("a; b")
        ]
    );
}

#[test]
fn command_builder_preserves_argument_order() {
    let spec = CommandSpec::new("cargo").args(["one", "two"]).arg("three");

    assert_eq!(
        spec.arguments(),
        [
            OsString::from("one"),
            OsString::from("two"),
            OsString::from("three")
        ]
    );
}
