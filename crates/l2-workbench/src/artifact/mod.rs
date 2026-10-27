//! Bounded PE/ELF inspection and source-bound static analysis receipts

mod analyzer;
mod bytes;
mod code_links;
mod color_reachability;
mod der;
mod elf;
mod embedded;
mod inspect;
mod model;
mod pe;
mod png;
mod png_pixels;
mod png_stream;
mod r2;
mod range_analyzer;
mod signatures;
mod validator;
pub mod zip;

pub use analyzer::{
    AnalysisBoundary, AnalysisFormat, AnalysisOmission, AnalysisStage, AnalysisStatus,
    AnalyzedArtifact, AnalyzerError, AnalyzerLimits, ArtifactAnalysis, ArtifactAnalysisOptions,
    ArtifactOrigin, ArtifactRegionTransformReport, ArtifactValidationState, RecoveryMode,
    ValidationSummary, analyze_artifacts, analyze_artifacts_with_source_sha256,
    archive_member_origin,
};
pub use code_links::{
    CodeLink, CodeLinkError, CodeLinkLimits, CodeLinkReport, CodeLinkSourceChecks,
    CodeLinkSourceVerification, CodeLinkStatus, MAX_CODE_LINKS, MAX_RUNTIME_MODULE_MAPPINGS,
    RuntimeModuleMap, RuntimeModuleMapping, link_code_to_trace,
};
pub use color_reachability::{
    DEFAULT_RGB_CONVERSION_BUDGET, FixedPointYcbcrCoefficients, FixedPointYcbcrModel,
    FixedPointYcbcrModelError, MAX_PIXEL_REACHABILITY_REPORT_BYTES,
    MAX_PIXEL_REACHABILITY_WORK_BYTES, PixelBounds, PixelComponent, PixelConnectivity,
    PixelCoordinate, PixelReachabilityLimits, REACHABLE_RGB_SET_BYTES, ReachableRgbLimits,
    ReachableRgbSet, RgbColor, RgbReachabilityError, RgbReachabilityReport, TOTAL_RGB_COLORS,
    TOTAL_YCBCR_INPUTS, analyze_rgb_reachability,
};
pub use der::{
    DerError, DerIntegerMetadata, DerLimits, DerNode, DerOctetStringMetadata, DerReport, DerTag,
    DerTagClass, MAX_DER_DEPTH, MAX_DER_NODES, MAX_DER_OBJECT_BYTES, MAX_DER_VALUE_PREVIEW_BYTES,
    parse_der,
};
pub use embedded::{
    EmbeddedCandidate, EmbeddedDiscoveryError, EmbeddedDiscoveryLimits, EmbeddedDiscoveryOmissions,
    EmbeddedDiscoveryReport, EmbeddedFormat, EmbeddedValidationEvidence, EmbeddedValidationFailure,
    discover_embedded_objects, discover_embedded_objects_with_work,
};
pub use inspect::candidate_executable_format;
pub use inspect::inspect;
pub use model::{
    AnalysisFunction, AnalysisImport, AnalysisReceipt, AnalysisTool, ArtifactError, ArtifactFormat,
    ArtifactReference, ArtifactReferenceKind, ArtifactReport, ArtifactSection, EntryPoint,
    ExternalObservation, FileMapping, FileRange, FunctionRejectionReason, RejectedFunction,
};
pub use png::{PNG_SIGNATURE, PngChunk, PngError, PngLimits, PngReport, parse_png};
pub use png_pixels::{
    CanonicalPixelLayout, MAX_PNG_DECODER_BYTES, MAX_PNG_PIXEL_BYTES, MAX_PNG_PIXEL_INPUT_BYTES,
    MAX_PNG_PIXEL_WORK_BYTES, MAX_PNG_PIXELS, PngPixel, PngPixelDecodeError, PngPixelImage,
    PngPixelLimits, decode_png_pixels,
};
pub use png_stream::{PngRangeChunk, PngRangeReport, PngReadError, parse_png_from_reader};
pub use r2::import_r2_json;
pub use range_analyzer::analyze_artifacts_from_reader;
pub use signatures::{
    FILE_SIGNATURE_RELATION_REASON, FileSignatureCatalogue, FileSignatureEvidence,
    FileSignatureMatch, FileSignatureMatchKind, FileSignatureReport, scan_file_signatures,
};
pub use validator::{
    ArtifactBoundaryEvidence, ArtifactResourceOmissionReason, ArtifactStructure,
    ArtifactValidationFailure, ArtifactValidationFormat, ArtifactValidationOutcome,
    ArtifactValidationPolicy, ArtifactValidationPolicyError, ArtifactValidator,
};

/// Maximum PE or ELF image size inspected in memory
pub const MAX_ARTIFACT_BYTES: usize = 16 * 1024 * 1024;
const MAX_REFERENCE_TEXT_BYTES: usize = 1024 * 1024;
/// Maximum combined size of r2 JSON command outputs
pub const MAX_R2_JSON_BYTES: usize = 8 * 1024 * 1024;
/// Maximum section count retained from one image
pub const MAX_SECTIONS: usize = 1_024;
/// Maximum imports and symbols retained from one image
pub const MAX_REFERENCES: usize = 16_384;
/// Maximum functions retained from one r2 report
pub const MAX_R2_FUNCTIONS: usize = 4_096;
/// Maximum individual function byte range copied into a receipt
pub const MAX_R2_FUNCTION_BYTES: usize = 1_048_576;
/// Maximum aggregate function bytes copied into one receipt
pub const MAX_R2_CODE_BYTES: usize = 8 * 1024 * 1024;
