//! Capture, forensic-store, executable, and bytecode signatures

use super::{ELF_MAGIC, MZ_MAGIC, SignatureRule, exact_rule, exact_rule_from};

const START: &[usize] = &[0];
const APPLE_FAT_SOURCE: &str =
    "https://github.com/apple-oss-distributions/cctools/blob/main/include/mach-o/fat.h";
const ANDROID_DEX_SOURCE: &str = "https://source.android.com/docs/core/runtime/dex-format";

pub(super) static RULES: &[SignatureRule] = &[
    // Capture and forensic stores are first-class inputs for recursive investigations
    exact_rule!(
        "pcap-le",
        "libpcap, little-endian microsecond timestamps",
        &["pcap"],
        &["pcap"],
        &["application/vnd.tcpdump.pcap"],
        START,
        b"\xd4\xc3\xb2\xa1",
        false
    ),
    exact_rule!(
        "pcap-be",
        "libpcap, big-endian microsecond timestamps",
        &["pcap"],
        &["pcap"],
        &["application/vnd.tcpdump.pcap"],
        START,
        b"\xa1\xb2\xc3\xd4",
        false
    ),
    exact_rule!(
        "pcap-ns-le",
        "libpcap, little-endian nanosecond timestamps",
        &["pcap"],
        &["pcap"],
        &["application/vnd.tcpdump.pcap"],
        START,
        b"\x4d\x3c\xb2\xa1",
        false
    ),
    exact_rule!(
        "pcap-ns-be",
        "libpcap, big-endian nanosecond timestamps",
        &["pcap"],
        &["pcap"],
        &["application/vnd.tcpdump.pcap"],
        START,
        b"\xa1\xb2\x3c\x4d",
        false
    ),
    exact_rule!(
        "pcapng",
        "PCAP Next Generation section header",
        &["pcapng"],
        &["pcapng"],
        &["application/x-pcapng"],
        START,
        b"\x0a\x0d\x0d\x0a",
        false
    ),
    exact_rule!(
        "sqlite3",
        "SQLite format 3 database",
        &["sqlite3"],
        &["sqlite", "sqlite3", "db"],
        &["application/vnd.sqlite3"],
        START,
        b"SQLite format 3\0",
        false
    ),
    exact_rule!(
        "windows-evtx",
        "Windows event log file",
        &["windows_evtx"],
        &["evtx"],
        &["application/x-evtx"],
        START,
        b"ElfFile\0",
        false
    ),
    exact_rule!(
        "windows-registry-hive",
        "Windows registry hive",
        &["windows_registry_hive"],
        &["dat", "hiv"],
        &["application/x-windows-registry-hive"],
        START,
        b"regf",
        false
    ),
    // Executable and code containers remain candidates until their structure is parsed
    exact_rule!(
        "elf",
        "Executable and Linkable Format",
        &["elf"],
        &["elf", "so", "o"],
        &["application/x-elf"],
        START,
        ELF_MAGIC,
        false
    ),
    exact_rule!(
        "dos-mz",
        "DOS MZ executable family prefix",
        &["dos_mz_or_descendant"],
        &["exe", "dll", "sys"],
        &["application/vnd.microsoft.portable-executable"],
        START,
        MZ_MAGIC,
        true
    ),
    exact_rule!(
        "mach-o-32-be",
        "Mach-O 32-bit image",
        &["mach_o_32"],
        &[],
        &["application/x-mach-binary"],
        START,
        b"\xfe\xed\xfa\xce",
        false
    ),
    exact_rule!(
        "mach-o-64-be",
        "Mach-O 64-bit image",
        &["mach_o_64"],
        &[],
        &["application/x-mach-binary"],
        START,
        b"\xfe\xed\xfa\xcf",
        false
    ),
    exact_rule!(
        "mach-o-32-le",
        "Mach-O 32-bit image with reversed byte order",
        &["mach_o_32"],
        &[],
        &["application/x-mach-binary"],
        START,
        b"\xce\xfa\xed\xfe",
        false
    ),
    exact_rule!(
        "mach-o-64-le",
        "Mach-O 64-bit image with reversed byte order",
        &["mach_o_64"],
        &[],
        &["application/x-mach-binary"],
        START,
        b"\xcf\xfa\xed\xfe",
        false
    ),
    exact_rule!(
        "cafebabe",
        "Shared Java class and Mach-O fat-binary signature",
        &["java_class", "mach_o_fat"],
        &["class"],
        &["application/java-vm", "application/x-mach-binary"],
        START,
        b"\xca\xfe\xba\xbe",
        true
    ),
    exact_rule_from!(
        "mach-o-fat-64",
        "Mach-O 64-bit fat-binary wrapper",
        &["mach_o_fat_64"],
        &[],
        &["application/x-mach-binary"],
        START,
        b"\xca\xfe\xba\xbf",
        false,
        APPLE_FAT_SOURCE
    ),
    exact_rule!(
        "wasm",
        "WebAssembly binary module",
        &["webassembly"],
        &["wasm"],
        &["application/wasm"],
        START,
        b"\0asm",
        false
    ),
    exact_rule_from!(
        "dex-035",
        "Android Dalvik executable version 035",
        &["dalvik_executable"],
        &["dex"],
        &["application/vnd.android.dex"],
        START,
        b"dex\n035\0",
        false,
        ANDROID_DEX_SOURCE
    ),
    exact_rule_from!(
        "dex-037",
        "Android Dalvik executable version 037",
        &["dalvik_executable"],
        &["dex"],
        &["application/vnd.android.dex"],
        START,
        b"dex\n037\0",
        false,
        ANDROID_DEX_SOURCE
    ),
    exact_rule_from!(
        "dex-038",
        "Android Dalvik executable version 038",
        &["dalvik_executable"],
        &["dex"],
        &["application/vnd.android.dex"],
        START,
        b"dex\n038\0",
        false,
        ANDROID_DEX_SOURCE
    ),
    exact_rule_from!(
        "dex-039",
        "Android Dalvik executable version 039",
        &["dalvik_executable"],
        &["dex"],
        &["application/vnd.android.dex"],
        START,
        b"dex\n039\0",
        false,
        ANDROID_DEX_SOURCE
    ),
    exact_rule_from!(
        "dex-040",
        "Android Dalvik executable version 040",
        &["dalvik_executable"],
        &["dex"],
        &["application/vnd.android.dex"],
        START,
        b"dex\n040\0",
        false,
        ANDROID_DEX_SOURCE
    ),
    exact_rule_from!(
        "dex-041",
        "Experimental Android Dalvik executable container version 041",
        &["dalvik_executable_container"],
        &["dex"],
        &["application/vnd.android.dex"],
        START,
        b"dex\n041\0",
        true,
        ANDROID_DEX_SOURCE
    ),
];
