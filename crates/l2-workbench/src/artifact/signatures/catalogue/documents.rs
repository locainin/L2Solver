//! Document and shared compound-container signatures

use super::{SignatureRule, exact_rule};

const START: &[usize] = &[0];

pub(super) static RULES: &[SignatureRule] = &[
    // Documents and shared compound containers need later structural checks for subtypes
    exact_rule!(
        "pdf",
        "Portable Document Format",
        &["pdf"],
        &["pdf"],
        &["application/pdf"],
        START,
        b"%PDF-",
        false
    ),
    exact_rule!(
        "postscript",
        "PostScript document",
        &["postscript"],
        &["ps", "eps"],
        &["application/postscript"],
        START,
        b"%!PS",
        true
    ),
    exact_rule!(
        "rtf",
        "Rich Text Format document",
        &["rtf"],
        &["rtf"],
        &["application/rtf"],
        START,
        b"{\\rtf",
        false
    ),
    exact_rule!(
        "ole-cfb",
        "OLE Compound File Binary container",
        &["ole_compound_file"],
        &["doc", "xls", "ppt", "msi"],
        &["application/x-ole-storage"],
        START,
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        true
    ),
];
