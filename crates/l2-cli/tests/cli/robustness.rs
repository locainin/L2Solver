use l2_cli::arguments::{Command, SurveyInput, parse};
use std::ffi::OsString;

#[test]
fn unicode_duration_rejected_without_panicking() {
    for duration in ["é", "1é", "💣", "60秒"] {
        let arguments = [
            OsString::from("assess"),
            OsString::from("--interface"),
            OsString::from("enp4s0"),
            OsString::from("--duration"),
            OsString::from(duration),
        ];
        assert!(parse(&arguments).is_err(), "accepted {duration:?}");
    }
}

#[cfg(unix)]
#[test]
fn non_utf8_rejected_without_panicking() {
    use std::os::unix::ffi::OsStringExt;

    let arguments = [
        OsString::from("assess"),
        OsString::from("--interface"),
        OsString::from_vec(vec![0xff, 0xfe]),
        OsString::from("--duration"),
        OsString::from("60s"),
    ];
    assert!(parse(&arguments).is_err());
}

#[cfg(unix)]
#[test]
fn legacy_wifi_keeps_path() -> Result<(), Box<dyn std::error::Error>> {
    use std::os::unix::ffi::OsStringExt;

    let capture = OsString::from_vec(vec![b'c', b'a', b'p', 0xff]);
    let arguments = [OsString::from("wifi"), capture.clone()];

    let Command::Wifi(options) = parse(&arguments)? else {
        return Err("legacy Wi-Fi command did not produce a Wi-Fi assessment".into());
    };
    assert_eq!(options.input, SurveyInput::File(capture.into()));
    Ok(())
}
