//! Raster and still-image signatures

use super::{Pattern, SignatureOffsets, SignatureRule, exact_rule};

const START: &[usize] = &[0];

// JPEG segment lengths vary, but these identifiers distinguish JFIF and Exif payloads
const JPEG_JFIF: &[Option<u8>] = &[
    Some(0xff),
    Some(0xd8),
    Some(0xff),
    Some(0xe0),
    None,
    None,
    Some(b'J'),
    Some(b'F'),
    Some(b'I'),
    Some(b'F'),
    Some(0),
];
const JPEG_EXIF: &[Option<u8>] = &[
    Some(0xff),
    Some(0xd8),
    Some(0xff),
    Some(0xe1),
    None,
    None,
    Some(b'E'),
    Some(b'x'),
    Some(b'i'),
    Some(b'f'),
    Some(0),
    Some(0),
];

pub(super) static RULES: &[SignatureRule] = &[
    // Raster and still-image signatures use only the bytes stated by their formats
    exact_rule!(
        "png",
        "Portable Network Graphics image",
        &["png"],
        &["png"],
        &["image/png"],
        START,
        b"\x89PNG\r\n\x1a\n",
        false
    ),
    exact_rule!(
        "gif87a",
        "Graphics Interchange Format 87a image",
        &["gif"],
        &["gif"],
        &["image/gif"],
        START,
        b"GIF87a",
        false
    ),
    exact_rule!(
        "gif89a",
        "Graphics Interchange Format 89a image",
        &["gif"],
        &["gif"],
        &["image/gif"],
        START,
        b"GIF89a",
        false
    ),
    SignatureRule {
        id: "jpeg-jfif",
        description: "JPEG image with a JFIF application identifier",
        formats: &["jpeg_jfif"],
        extensions: &["jpg", "jpeg"],
        media_types: &["image/jpeg"],
        reference: "https://www.w3.org/Graphics/JPEG/jfif.pdf",
        offsets: SignatureOffsets::Declared(START),
        pattern: Pattern::Masked(JPEG_JFIF),
        ambiguous: false,
    },
    SignatureRule {
        id: "jpeg-exif",
        description: "JPEG image with an Exif application identifier",
        formats: &["jpeg_exif"],
        extensions: &["jpg", "jpeg"],
        media_types: &["image/jpeg"],
        reference: "https://www.cipa.jp/e/std/std-sec.html",
        offsets: SignatureOffsets::Declared(START),
        pattern: Pattern::Masked(JPEG_EXIF),
        ambiguous: false,
    },
    exact_rule!(
        "jpeg-dqt",
        "JPEG image beginning with a quantization table",
        &["jpeg"],
        &["jpg", "jpeg"],
        &["image/jpeg"],
        START,
        b"\xff\xd8\xff\xdb",
        false
    ),
    exact_rule!(
        "jpeg-app14",
        "JPEG image with an APP14 marker",
        &["jpeg"],
        &["jpg", "jpeg"],
        &["image/jpeg"],
        START,
        b"\xff\xd8\xff\xee",
        false
    ),
    exact_rule!(
        "jpeg-2000",
        "JPEG 2000 signature box",
        &["jpeg_2000"],
        &["jp2", "jpx"],
        &["image/jp2"],
        START,
        b"\x00\x00\x00\x0cjP  \r\n\x87\n",
        false
    ),
    exact_rule!(
        "tiff-le",
        "TIFF image, little-endian",
        &["tiff"],
        &["tif", "tiff"],
        &["image/tiff"],
        START,
        b"II*\x00",
        false
    ),
    exact_rule!(
        "tiff-be",
        "TIFF image, big-endian",
        &["tiff"],
        &["tif", "tiff"],
        &["image/tiff"],
        START,
        b"MM\x00*",
        false
    ),
    exact_rule!(
        "big-tiff-le",
        "BigTIFF image, little-endian",
        &["big_tiff"],
        &["tif", "tiff"],
        &["image/tiff"],
        START,
        b"II+\x00",
        false
    ),
    exact_rule!(
        "big-tiff-be",
        "BigTIFF image, big-endian",
        &["big_tiff"],
        &["tif", "tiff"],
        &["image/tiff"],
        START,
        b"MM\x00+",
        false
    ),
    exact_rule!(
        "bmp",
        "Windows bitmap image",
        &["bmp"],
        &["bmp"],
        &["image/bmp"],
        START,
        b"BM",
        false
    ),
    exact_rule!(
        "ico",
        "Windows icon image",
        &["ico"],
        &["ico"],
        &["image/vnd.microsoft.icon"],
        START,
        b"\x00\x00\x01\x00",
        false
    ),
    exact_rule!(
        "cursor",
        "Windows cursor image",
        &["cur"],
        &["cur"],
        &["image/x-win-bitmap"],
        START,
        b"\x00\x00\x02\x00",
        false
    ),
    exact_rule!(
        "photoshop",
        "Adobe Photoshop document",
        &["photoshop"],
        &["psd"],
        &["image/vnd.adobe.photoshop"],
        START,
        b"8BPS",
        false
    ),
    exact_rule!(
        "openexr",
        "OpenEXR image",
        &["openexr"],
        &["exr"],
        &["image/x-exr"],
        START,
        b"v/1\x01",
        false
    ),
    exact_rule!(
        "qoi",
        "Quite OK Image",
        &["qoi"],
        &["qoi"],
        &["image/qoi"],
        START,
        b"qoif",
        false
    ),
];
