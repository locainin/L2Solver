//! Archive and compressed-stream signatures

use super::{SignatureRule, exact_rule, exact_rule_from};

const START: &[usize] = &[0];
const OFFSET_257: &[usize] = &[257];
const GNU_TAR_FORMAT_SOURCE: &str = "https://www.gnu.org/software/tar/manual/tar.html";

pub(super) static RULES: &[SignatureRule] = &[
    // Archives and compressed streams report the container, never an application subtype
    exact_rule!(
        "zip-local-file",
        "ZIP local-file header",
        &["zip_container"],
        &["zip"],
        &["application/zip"],
        START,
        b"PK\x03\x04",
        true
    ),
    exact_rule!(
        "zip-empty",
        "ZIP empty-archive end record",
        &["zip_container"],
        &["zip"],
        &["application/zip"],
        START,
        b"PK\x05\x06",
        true
    ),
    exact_rule!(
        "zip-spanned",
        "ZIP spanned-archive data descriptor",
        &["zip_container"],
        &["zip"],
        &["application/zip"],
        START,
        b"PK\x07\x08",
        true
    ),
    exact_rule!(
        "rar-4",
        "RAR archive version 1.5 through 4",
        &["rar"],
        &["rar"],
        &["application/vnd.rar"],
        START,
        b"Rar!\x1a\x07\x00",
        false
    ),
    exact_rule!(
        "rar-5",
        "RAR archive version 5",
        &["rar"],
        &["rar"],
        &["application/vnd.rar"],
        START,
        b"Rar!\x1a\x07\x01\x00",
        false
    ),
    exact_rule!(
        "seven-zip",
        "7-Zip archive",
        &["seven_zip"],
        &["7z"],
        &["application/x-7z-compressed"],
        START,
        b"7z\xbc\xaf\x27\x1c",
        false
    ),
    exact_rule!(
        "gzip",
        "gzip compressed stream",
        &["gzip"],
        &["gz", "tgz"],
        &["application/gzip"],
        START,
        b"\x1f\x8b\x08",
        false
    ),
    exact_rule!(
        "bzip2",
        "bzip2 compressed stream",
        &["bzip2"],
        &["bz2"],
        &["application/x-bzip2"],
        START,
        b"BZh",
        false
    ),
    exact_rule!(
        "xz",
        "XZ compressed stream",
        &["xz"],
        &["xz"],
        &["application/x-xz"],
        START,
        b"\xfd7zXZ\x00",
        false
    ),
    exact_rule!(
        "zstandard",
        "Zstandard frame",
        &["zstandard"],
        &["zst"],
        &["application/zstd"],
        START,
        b"\x28\xb5\x2f\xfd",
        false
    ),
    exact_rule!(
        "lz4-frame",
        "LZ4 frame",
        &["lz4"],
        &["lz4"],
        &["application/x-lz4"],
        START,
        b"\x04\x22\x4d\x18",
        false
    ),
    exact_rule!(
        "cabinet",
        "Microsoft Cabinet archive",
        &["cabinet"],
        &["cab"],
        &["application/vnd.ms-cab-compressed"],
        START,
        b"MSCF",
        false
    ),
    exact_rule!(
        "ar-archive",
        "Unix ar archive container",
        &["ar_archive"],
        &["a", "ar", "deb"],
        &["application/x-archive"],
        START,
        b"!<arch>\n",
        true
    ),
    exact_rule!(
        "cpio-newc",
        "cpio new ASCII archive",
        &["cpio"],
        &["cpio"],
        &["application/x-cpio"],
        START,
        b"070701",
        false
    ),
    exact_rule!(
        "cpio-crc",
        "cpio new ASCII archive with CRC",
        &["cpio"],
        &["cpio"],
        &["application/x-cpio"],
        START,
        b"070702",
        false
    ),
    exact_rule_from!(
        "tar-ustar",
        "POSIX tar ustar magic and version",
        &["tar"],
        &["tar"],
        &["application/x-tar"],
        OFFSET_257,
        b"ustar\x0000",
        false,
        GNU_TAR_FORMAT_SOURCE
    ),
    exact_rule_from!(
        "tar-ustar-gnu",
        "Old GNU tar magic across the contiguous magic and version fields",
        &["tar_oldgnu"],
        &["tar"],
        &["application/x-tar"],
        OFFSET_257,
        b"ustar  \0",
        false,
        GNU_TAR_FORMAT_SOURCE
    ),
];
