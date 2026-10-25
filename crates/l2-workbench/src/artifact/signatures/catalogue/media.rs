//! Audio, video, and shared media-container signatures

use super::{Pattern, SignatureOffsets, SignatureRule, exact_rule};

const START: &[usize] = &[0];
const OFFSET_4: &[usize] = &[4];

// RIFF and IFF reserve the size field, so those four positions are deliberate wildcards
const RIFF_WAVE: &[Option<u8>] = &[
    Some(b'R'),
    Some(b'I'),
    Some(b'F'),
    Some(b'F'),
    None,
    None,
    None,
    None,
    Some(b'W'),
    Some(b'A'),
    Some(b'V'),
    Some(b'E'),
];
const RIFF_AVI: &[Option<u8>] = &[
    Some(b'R'),
    Some(b'I'),
    Some(b'F'),
    Some(b'F'),
    None,
    None,
    None,
    None,
    Some(b'A'),
    Some(b'V'),
    Some(b'I'),
    Some(b' '),
];
const RIFF_WEBP: &[Option<u8>] = &[
    Some(b'R'),
    Some(b'I'),
    Some(b'F'),
    Some(b'F'),
    None,
    None,
    None,
    None,
    Some(b'W'),
    Some(b'E'),
    Some(b'B'),
    Some(b'P'),
];
const FORM_AIFF: &[Option<u8>] = &[
    Some(b'F'),
    Some(b'O'),
    Some(b'R'),
    Some(b'M'),
    None,
    None,
    None,
    None,
    Some(b'A'),
    Some(b'I'),
    Some(b'F'),
    Some(b'F'),
];

pub(super) static RULES: &[SignatureRule] = &[
    // Audio/video containers include subtype bytes where the outer prefix is shared
    SignatureRule {
        id: "riff-wave",
        description: "RIFF WAVE audio container",
        formats: &["wave"],
        extensions: &["wav"],
        media_types: &["audio/wav"],
        reference: super::CATALOGUE_SOURCE,
        offsets: SignatureOffsets::Declared(START),
        pattern: Pattern::Masked(RIFF_WAVE),
        ambiguous: false,
    },
    SignatureRule {
        id: "riff-avi",
        description: "RIFF AVI video container",
        formats: &["avi"],
        extensions: &["avi"],
        media_types: &["video/x-msvideo"],
        reference: super::CATALOGUE_SOURCE,
        offsets: SignatureOffsets::Declared(START),
        pattern: Pattern::Masked(RIFF_AVI),
        ambiguous: false,
    },
    SignatureRule {
        id: "riff-webp",
        description: "RIFF WebP image container",
        formats: &["webp"],
        extensions: &["webp"],
        media_types: &["image/webp"],
        reference: super::CATALOGUE_SOURCE,
        offsets: SignatureOffsets::Declared(START),
        pattern: Pattern::Masked(RIFF_WEBP),
        ambiguous: false,
    },
    SignatureRule {
        id: "form-aiff",
        description: "IFF AIFF audio container",
        formats: &["aiff"],
        extensions: &["aiff", "aif"],
        media_types: &["audio/aiff"],
        reference: super::CATALOGUE_SOURCE,
        offsets: SignatureOffsets::Declared(START),
        pattern: Pattern::Masked(FORM_AIFF),
        ambiguous: false,
    },
    exact_rule!(
        "flac",
        "Free Lossless Audio Codec stream",
        &["flac"],
        &["flac"],
        &["audio/flac"],
        START,
        b"fLaC",
        false
    ),
    exact_rule!(
        "ogg",
        "Ogg container",
        &["ogg_container"],
        &["ogg", "oga", "ogv"],
        &["application/ogg"],
        START,
        b"OggS",
        true
    ),
    exact_rule!(
        "midi",
        "Standard MIDI file",
        &["midi"],
        &["mid", "midi"],
        &["audio/midi"],
        START,
        b"MThd",
        false
    ),
    exact_rule!(
        "id3",
        "ID3-tagged audio stream",
        &["id3_tagged_audio"],
        &["mp3"],
        &["audio/mpeg"],
        START,
        b"ID3",
        true
    ),
    exact_rule!(
        "ebml",
        "Extensible Binary Meta Language container",
        &["matroska_or_webm"],
        &["mkv", "mka", "webm"],
        &["application/ebml"],
        START,
        b"\x1a\x45\xdf\xa3",
        true
    ),
    exact_rule!(
        "asf",
        "Advanced Systems Format container",
        &["asf"],
        &["asf", "wma", "wmv"],
        &["application/vnd.ms-asf"],
        START,
        b"\x30\x26\xb2\x75\x8e\x66\xcf\x11\xa6\xd9\x00\xaa\x00\x62\xce\x6c",
        true
    ),
    exact_rule!(
        "mp4-isom",
        "ISO Base Media file with isom brand",
        &["iso_base_media"],
        &["mp4"],
        &["video/mp4"],
        OFFSET_4,
        b"ftypisom",
        true
    ),
    exact_rule!(
        "mp4-mp42",
        "ISO Base Media file with mp42 brand",
        &["iso_base_media"],
        &["mp4"],
        &["video/mp4"],
        OFFSET_4,
        b"ftypmp42",
        true
    ),
    exact_rule!(
        "quicktime",
        "QuickTime file type box",
        &["quicktime"],
        &["mov"],
        &["video/quicktime"],
        OFFSET_4,
        b"ftypqt  ",
        false
    ),
    exact_rule!(
        "heic",
        "High Efficiency Image Container brand",
        &["heic"],
        &["heic"],
        &["image/heic"],
        OFFSET_4,
        b"ftypheic",
        true
    ),
    exact_rule!(
        "avif",
        "AV1 Image File Format brand",
        &["avif"],
        &["avif"],
        &["image/avif"],
        OFFSET_4,
        b"ftypavif",
        true
    ),
];
