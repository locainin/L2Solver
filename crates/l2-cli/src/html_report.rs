//! Static report pages escape all report text before adding it to HTML

use std::io::{self, Write};

// The CSP hash covers STYLE exactly, so both values change together
const DOCUMENT_PREFIX: &[u8] = b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'sha256-nEs63+zSVYcJ0I0tlXhG/nHIiqkuJ3435paiurz9wxg='; base-uri 'none'; form-action 'none'\"><title>";
const STYLE: &[u8] = b"body{max-width:76rem;margin:3rem auto;padding:0 1.5rem;background:#10171c;color:#e2e9ed;font:16px/1.6 system-ui}h1,a,summary{color:#85d5ce}pre{white-space:pre-wrap;overflow-wrap:anywhere;font:14px/1.6 ui-monospace,monospace;border-top:1px solid #34464e;padding-top:1.5rem}summary{cursor:pointer}nav ul{columns:18rem}li{break-inside:avoid}details{margin:1rem 0}section{scroll-margin-top:1rem}";

pub fn write(output: &mut impl Write, report: &str) -> io::Result<()> {
    begin(output, "L2Solver passive survey")?;
    output.write_all(b"<pre>")?;
    escaped(output, report)?;
    output.write_all(b"</pre>")?;
    end(output)
}

pub fn begin(output: &mut impl Write, title: &str) -> io::Result<()> {
    output.write_all(DOCUMENT_PREFIX)?;
    escaped(output, title)?;
    output.write_all(b"</title><style>")?;
    output.write_all(STYLE)?;
    output.write_all(b"</style></head><body><h1>")?;
    escaped(output, title)?;
    output.write_all(b"</h1>")
}

pub fn escaped(output: &mut impl Write, text: &str) -> io::Result<()> {
    for character in text.chars() {
        match character {
            '&' => output.write_all(b"&amp;")?,
            '<' => output.write_all(b"&lt;")?,
            '>' => output.write_all(b"&gt;")?,
            '"' => output.write_all(b"&quot;")?,
            '\'' => output.write_all(b"&#39;")?,
            _ => write!(output, "{character}")?,
        }
    }
    Ok(())
}

pub fn end(output: &mut impl Write) -> io::Result<()> {
    output.write_all(b"</body></html>\n")
}
