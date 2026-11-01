//! Discover and process bounded transformations of file-backed objects

mod archive;
mod budget;
mod observation;
mod png;
mod ranges;
mod readers;

use super::{
    analysis::AnalyzedSources,
    file_artifact::{DerivedFile, STREAM_METADATA_BYTES},
    input::{InputSet, LoadedSource},
    policy::STREAM_EXPANSION_RATIO,
};
use archive::inspect_archive;
pub(super) use budget::StreamingBudget;
use budget::{Reservation, observation_work};
use l2_workbench::{
    artifact::{AnalysisOmission, ArtifactAnalysis, ArtifactAnalysisOptions},
    derivation::{
        Operation, StreamInput, StreamLimits, StreamReceipt, StreamTransformError, stream_transform,
    },
    job::{Counter, Job, MemoryBudget, MemoryClass, MemoryError, MemoryLease},
};

pub(in crate::refine) fn reserve_stream_object(
    memory: &MemoryBudget,
) -> Result<MemoryLease, MemoryError> {
    memory.try_reserve(MemoryClass::Executor, STREAM_METADATA_BYTES)
}
use observation::ObservingWriter;
pub(super) use observation::{Observation, ObservingReader};
use readers::JobReader;
use std::{
    collections::VecDeque,
    error::Error,
    fmt,
    fs::File,
    io::{Seek, SeekFrom},
};

struct StreamObject {
    observation: Observation,
    derived: DerivedFile,
}

pub(super) struct StreamContext<'a> {
    pub(super) analysis: &'a mut AnalyzedSources,
    pub(super) input: &'a InputSet,
    pub(super) source_index: usize,
    pub(super) source: &'a LoadedSource,
    pub(super) observation: Observation,
    pub(super) report: &'a mut ArtifactAnalysis,
    pub(super) options: ArtifactAnalysisOptions,
    pub(super) job: &'a Job,
    pub(super) memory: &'a MemoryBudget,
    pub(super) report_memory: &'a mut MemoryLease,
    pub(super) omission_memory: &'a mut MemoryLease,
    pub(super) budget: &'a mut StreamingBudget,
    pub(super) profile: crate::arguments::RecoveryProfile,
}

pub(super) fn append_streams(mut context: StreamContext<'_>) -> Result<(), Box<dyn Error>> {
    let mut queue = VecDeque::new();
    let operations = context.observation.operations()?;
    let observation_limited = context
        .observation
        .gzip_header_observation_limited(&operations);
    if observation_limited {
        omit(
            &mut context,
            None,
            "gzip header may exceed the 4096-byte streaming observation limit",
        )?;
    }
    if operations.is_empty() {
        if !observation_limited {
            omit(
                &mut context,
                None,
                "no supported whole-source streaming transformation was identified",
            )?;
        }
        return Ok(());
    }
    if context.options.limits.max_depth == 0 {
        omit(&mut context, None, "stream recursion depth is exhausted")?;
        return Ok(());
    }
    for operation in operations {
        if let Some(object) = transform_source(&mut context, &operation)? {
            queue.try_reserve(1)?;
            queue.push_back(object);
        }
    }
    while let Some(object) = queue.pop_front() {
        context.job.check_cancelled()?;
        let files_before = context.analysis.file_artifacts.len();
        let Some(object) = png::inspect_png(&mut context, object)? else {
            continue;
        };
        let Some(object) = inspect_archive(&mut context, object)? else {
            continue;
        };
        let retained_prefix = context.analysis.file_artifacts.len() > files_before;
        let found_ranges = ranges::inspect_ranges(&mut context, &object)?;
        let operations = object.observation.operations()?;
        let observation_limited = object
            .observation
            .gzip_header_observation_limited(&operations);
        if observation_limited {
            omit(
                &mut context,
                None,
                "gzip header may exceed the 4096-byte streaming observation limit",
            )?;
        }
        if operations.is_empty() {
            if !found_ranges && !retained_prefix && !observation_limited {
                omit(
                    &mut context,
                    None,
                    "derived stream has no supported whole-source transformation or retained validated format",
                )?;
            }
            continue;
        }
        if object.derived.steps.len() >= context.options.limits.max_depth {
            omit(&mut context, None, "stream recursion depth is exhausted")?;
            continue;
        }
        for operation in operations {
            if let Some(child) = transform_object(&mut context, &object, &operation)? {
                queue.try_reserve(1)?;
                queue.push_back(child);
            }
        }
    }
    Ok(())
}

fn transform_source(
    context: &mut StreamContext<'_>,
    operation: &Operation,
) -> Result<Option<StreamObject>, Box<dyn Error>> {
    let length = context.source.length();
    let required_reads = u64::try_from(length)?
        .checked_add(1)
        .ok_or("source transform read length overflows")?;
    if required_reads > context.input.extra_read_bytes() {
        omit(
            context,
            Some(operation.clone()),
            "source read limit prevented streaming transformation",
        )?;
        return Ok(None);
    }
    let Some(reservation) = context.budget.reserve(length, operation) else {
        omit(
            context,
            Some(operation.clone()),
            "stream output or work budget is exhausted",
        )?;
        return Ok(None);
    };
    // The queued observation and receipts must fit before the decoder can produce them
    let memory = reserve_stream_object(context.memory)?;
    let mut spool = tempfile::tempfile()?;
    let mut writer = ObservingWriter::new(&mut spool, context.job);
    let limits = operation_limits(length, reservation);
    let input = StreamInput {
        length,
        sha256: &context.report.source_sha256,
    };
    let result = context.source.with_range_reader(
        context.input,
        context.source_index,
        context.job,
        |reader| {
            stream_transform(
                reader,
                &mut writer,
                operation,
                input,
                limits,
                context.memory,
            )
        },
    )?;
    let observation = writer.finish();
    let Some(result) = result else {
        context.budget.refund(reservation, None)?;
        omit(
            context,
            Some(operation.clone()),
            "source read limit prevented streaming transformation",
        )?;
        return Ok(None);
    };
    finish_attempt(
        context,
        operation,
        result,
        spool,
        observation,
        Vec::new(),
        reservation,
        memory,
    )
}

fn transform_object(
    context: &mut StreamContext<'_>,
    object: &StreamObject,
    operation: &Operation,
) -> Result<Option<StreamObject>, Box<dyn Error>> {
    let receipt = object
        .derived
        .steps
        .last()
        .ok_or("stream receipt is missing")?;
    let length = receipt.output_length;
    let Some(reservation) = context.budget.reserve(length, operation) else {
        omit(
            context,
            Some(operation.clone()),
            "stream output or work budget is exhausted",
        )?;
        return Ok(None);
    };
    let memory = reserve_stream_object(context.memory)?;
    let mut file = object.derived.spool.file.try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut reader = JobReader {
        inner: &mut file,
        job: context.job,
    };
    let mut spool = tempfile::tempfile()?;
    let mut writer = ObservingWriter::new(&mut spool, context.job);
    let result = stream_transform(
        &mut reader,
        &mut writer,
        operation,
        StreamInput {
            length,
            sha256: &receipt.output_sha256,
        },
        operation_limits(length, reservation),
        context.memory,
    );
    let observation = writer.finish();
    finish_attempt(
        context,
        operation,
        result,
        spool,
        observation,
        object.derived.steps.as_ref().clone(),
        reservation,
        memory,
    )
}

const fn operation_limits(length: usize, reservation: Reservation) -> StreamLimits {
    StreamLimits {
        max_input_bytes: length,
        max_output_bytes: reservation.output,
        max_work_bytes: reservation.base + reservation.output,
        max_expansion_ratio: STREAM_EXPANSION_RATIO,
    }
}

#[expect(
    clippy::too_many_arguments,
    reason = "the bounded spool and its immutable receipt form one attempt"
)]
fn finish_attempt(
    context: &mut StreamContext<'_>,
    operation: &Operation,
    result: Result<StreamReceipt, StreamTransformError>,
    file: File,
    observation: Observation,
    mut steps: Vec<StreamReceipt>,
    reservation: Reservation,
    memory: MemoryLease,
) -> Result<Option<StreamObject>, Box<dyn Error>> {
    match result {
        Ok(receipt) => {
            context.budget.refund(reservation, Some(&receipt))?;
            context.report.work_bytes = context
                .report
                .work_bytes
                .checked_add(receipt.work_bytes)
                .and_then(|work| work.checked_add(observation_work(receipt.output_length)?))
                .and_then(|work| work.checked_add(receipt.output_length))
                .ok_or("stream work overflows")?;
            steps.try_reserve(1)?;
            steps.push(receipt);
            context.job.increment(Counter::Transforms, 1)?;
            Ok(Some(StreamObject {
                observation,
                derived: DerivedFile::new(file, memory, steps),
            }))
        }
        Err(error @ (StreamTransformError::InputChanged | StreamTransformError::Io(_))) => {
            Err(error.into())
        }
        Err(StreamTransformError::Memory(error)) => Err(error.into()),
        Err(error) => {
            // A failed decoder may have processed output that was never written
            context.report.work_bytes = context
                .report
                .work_bytes
                .checked_add(reservation.work)
                .ok_or("stream work overflows")?;
            omit_formatted(context, Some(operation.clone()), format_args!("{error}"))?;
            Ok(None)
        }
    }
}

fn omit(
    context: &mut StreamContext<'_>,
    operation: Option<Operation>,
    reason: &str,
) -> Result<(), Box<dyn Error>> {
    omit_formatted(context, operation, format_args!("{reason}"))
}

fn omit_formatted(
    context: &mut StreamContext<'_>,
    operation: Option<Operation>,
    reason: fmt::Arguments<'_>,
) -> Result<(), Box<dyn Error>> {
    super::analysis_memory::reserve_omission(
        &mut context.report.omissions,
        context.omission_memory,
    )?;
    let message = super::analysis_memory::format_message(reason, context.omission_memory)?;
    context
        .report
        .omissions
        .push(AnalysisOmission::SourceStreamTransform {
            operation,
            reason: message,
        });
    Ok(())
}
