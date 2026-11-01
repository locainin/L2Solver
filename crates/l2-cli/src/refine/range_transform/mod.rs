//! Discover and process bounded transformations of file-backed objects

mod archive;
mod budget;
mod observation;
mod png;
mod readers;

use super::{
    analysis::AnalyzedSources,
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

const STREAM_OBJECT_MEMORY_BYTES: u64 = 16 * 1024;

pub(in crate::refine) fn reserve_stream_object(
    memory: &MemoryBudget,
) -> Result<MemoryLease, MemoryError> {
    memory.try_reserve(MemoryClass::Executor, STREAM_OBJECT_MEMORY_BYTES)
}
use observation::ObservingWriter;
pub(super) use observation::{Observation, ObservingReader};
use readers::JobReader;
use std::{
    collections::VecDeque,
    error::Error,
    fs::File,
    io::{Seek, SeekFrom},
};

struct StreamObject {
    file: File,
    receipt: StreamReceipt,
    steps: Vec<StreamReceipt>,
    observation: Observation,
    depth: usize,
    memory: MemoryLease,
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
    pub(super) budget: &'a mut StreamingBudget,
}

pub(super) fn append_streams(mut context: StreamContext<'_>) -> Result<(), Box<dyn Error>> {
    let mut queue = VecDeque::new();
    let operations = context.observation.operations()?;
    if operations.is_empty() {
        omit(
            &mut context,
            None,
            "no supported whole-source streaming transformation was identified",
        )?;
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
        let Some(object) = png::inspect_png(&mut context, object)? else {
            continue;
        };
        let Some(mut object) = inspect_archive(&mut context, object)? else {
            continue;
        };
        let operations = object.observation.operations()?;
        if operations.is_empty() {
            omit(
                &mut context,
                None,
                "derived stream has no supported whole-source transformation or validated format",
            )?;
            continue;
        }
        if object.depth >= context.options.limits.max_depth {
            omit(&mut context, None, "stream recursion depth is exhausted")?;
            continue;
        }
        for operation in operations {
            if let Some(child) = transform_object(&mut context, &mut object, &operation)? {
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
        1,
        reservation,
        memory,
    )
}

fn transform_object(
    context: &mut StreamContext<'_>,
    object: &mut StreamObject,
    operation: &Operation,
) -> Result<Option<StreamObject>, Box<dyn Error>> {
    let length = object.receipt.output_length;
    let Some(reservation) = context.budget.reserve(length, operation) else {
        omit(
            context,
            Some(operation.clone()),
            "stream output or work budget is exhausted",
        )?;
        return Ok(None);
    };
    let memory = reserve_stream_object(context.memory)?;
    object.file.seek(SeekFrom::Start(0))?;
    let mut reader = JobReader {
        inner: &mut object.file,
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
            sha256: &object.receipt.output_sha256,
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
        object.steps.clone(),
        object.depth + 1,
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
    depth: usize,
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
            steps.push(receipt.clone());
            context.job.increment(Counter::Transforms, 1)?;
            Ok(Some(StreamObject {
                file,
                receipt,
                steps,
                observation,
                depth,
                memory,
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
            omit(context, Some(operation.clone()), &error.to_string())?;
            Ok(None)
        }
    }
}

fn omit(
    context: &mut StreamContext<'_>,
    operation: Option<Operation>,
    reason: &str,
) -> Result<(), Box<dyn Error>> {
    context.report.omissions.try_reserve(1)?;
    let mut message = String::new();
    message.try_reserve_exact(reason.len())?;
    message.push_str(reason);
    context
        .report
        .omissions
        .push(AnalysisOmission::SourceStreamTransform {
            operation,
            reason: message,
        });
    Ok(())
}
