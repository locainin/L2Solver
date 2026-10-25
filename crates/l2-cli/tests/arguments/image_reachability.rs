use super::common::{NumericDefault, TestResult, help_defaults, reject_zero, workbench};
use l2_cli::arguments::WorkbenchCommand;
use l2_workbench::artifact::{
    MAX_PIXEL_REACHABILITY_REPORT_BYTES, MAX_PNG_PIXELS, PixelReachabilityLimits, PngPixelLimits,
    ReachableRgbLimits,
};

const COMMAND: &[&str] = &["image-reachability", "case.json", "--node", "1"];

fn expected_defaults() -> [NumericDefault; 14] {
    let png = PngPixelLimits::default();
    let enumeration = ReachableRgbLimits::default();
    let analysis = PixelReachabilityLimits::default();
    [
        ("--minimum-blank-column-gap", "1".to_owned()),
        ("--max-input-bytes", png.max_input_bytes.to_string()),
        ("--max-width", png.max_width.to_string()),
        ("--max-height", png.max_height.to_string()),
        ("--max-pixels", png.max_pixels.to_string()),
        ("--max-pixel-bytes", png.max_pixel_bytes.to_string()),
        (
            "--max-decode-work-bytes",
            png.max_work_buffer_bytes.to_string(),
        ),
        (
            "--max-decoder-memory-bytes",
            png.max_decoder_memory_bytes.to_string(),
        ),
        (
            "--max-conversion-samples",
            enumeration.max_conversion_samples.to_string(),
        ),
        (
            "--max-reachable-set-bytes",
            enumeration.max_set_bytes.to_string(),
        ),
        (
            "--max-analysis-work-bytes",
            analysis.max_work_bytes.to_string(),
        ),
        ("--max-report-bytes", analysis.max_report_bytes.to_string()),
        (
            "--max-receipt-bytes",
            MAX_PIXEL_REACHABILITY_REPORT_BYTES.to_string(),
        ),
        // PBM output allows one byte per pixel plus its bounded header
        ("--max-mask-bytes", (MAX_PNG_PIXELS + 64).to_string()),
    ]
}

#[test]
fn preserves_numeric_defaults() -> TestResult {
    let WorkbenchCommand::ImageReachability(options) = workbench(COMMAND)? else {
        return Err("image reachability command was not selected".into());
    };
    assert_eq!(
        [
            (
                "--minimum-blank-column-gap",
                options.minimum_blank_column_gap.to_string()
            ),
            ("--max-input-bytes", options.max_input_bytes.to_string()),
            ("--max-width", options.max_width.to_string()),
            ("--max-height", options.max_height.to_string()),
            ("--max-pixels", options.max_pixels.to_string()),
            ("--max-pixel-bytes", options.max_pixel_bytes.to_string()),
            (
                "--max-decode-work-bytes",
                options.max_decode_work_bytes.to_string()
            ),
            (
                "--max-decoder-memory-bytes",
                options.max_decoder_memory_bytes.to_string()
            ),
            (
                "--max-conversion-samples",
                options.max_conversion_samples.to_string()
            ),
            (
                "--max-reachable-set-bytes",
                options.max_reachable_set_bytes.to_string()
            ),
            (
                "--max-analysis-work-bytes",
                options.max_analysis_work_bytes.to_string()
            ),
            ("--max-report-bytes", options.max_report_bytes.to_string()),
            ("--max-receipt-bytes", options.max_receipt_bytes.to_string()),
            ("--max-mask-bytes", options.max_mask_bytes.to_string()),
        ],
        expected_defaults()
    );
    Ok(())
}

#[test]
fn rejects_zero_budgets() {
    reject_zero(COMMAND, &expected_defaults());
}

#[test]
fn help_shows_numeric_defaults() -> TestResult {
    help_defaults(COMMAND, &expected_defaults())
}
