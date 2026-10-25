#[path = "../src/html_report.rs"]
mod html_report;

use base64::{Engine, engine::general_purpose::STANDARD};
use sha2::{Digest, Sha256};

#[test]
fn text_cannot_html_markup() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    html_report::write(&mut output, "</pre><script>alert('x')</script> & \"name\"")?;
    let html = String::from_utf8(output)?;
    assert!(!html.contains("<script>"));
    assert!(html.contains("&lt;/pre&gt;&lt;script&gt;"));
    assert!(html.contains("&amp; &quot;name&quot;"));
    assert!(html.contains("&#39;x&#39;"));
    assert!(html.contains("Content-Security-Policy"));
    assert!(!html.contains("unsafe-inline"));
    let stylesheet = html
        .split_once("<style>")
        .and_then(|(_, rest)| rest.split_once("</style>"))
        .map(|(style, _)| style)
        .ok_or("missing stylesheet")?;
    let digest = STANDARD.encode(Sha256::digest(stylesheet.as_bytes()));
    assert!(html.contains(&format!("style-src 'sha256-{digest}'")));
    Ok(())
}

#[test]
fn document_title_escaped_head_body() -> Result<(), Box<dyn std::error::Error>> {
    let mut output = Vec::new();
    html_report::begin(&mut output, "<script>title</script>")?;
    html_report::end(&mut output)?;
    let html = String::from_utf8(output)?;
    assert!(html.contains("<title>&lt;script&gt;title&lt;/script&gt;</title>"));
    assert!(html.contains("<h1>&lt;script&gt;title&lt;/script&gt;</h1>"));
    assert!(!html.contains("<script>"));
    Ok(())
}

#[test]
fn output_failure_is_propagated() {
    assert!(html_report::write(&mut [].as_mut_slice(), "report").is_err());
}
