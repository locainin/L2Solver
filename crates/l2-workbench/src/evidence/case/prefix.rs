//! Bind checkpoint state to the immutable prefix of its original evidence Case

use super::{Blob, Case, CaseResourceLimits, Edge, EvidenceError, Node, Source};
use serde::{Serialize, Serializer, ser::SerializeSeq};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io::{self, Write},
};

const PREFIX_VERSION: u32 = 1;

/// Compact binding to the original records that later recovery may extend
#[derive(Debug)]
pub struct CasePrefixBinding {
    nodes: usize,
    blobs: usize,
    edges: usize,
    limitations: usize,
    complete: bool,
    sources: Vec<SourceBinding>,
    graph_digest: [u8; 32],
}

#[derive(Debug)]
struct SourceBinding {
    core_digest: [u8; 32],
    aliases: Vec<[u8; 32]>,
    had_blob: bool,
}

#[derive(Serialize)]
struct SourceCore<'a> {
    id: &'a str,
    label: &'a str,
    kind: &'a str,
    length: u64,
}

#[derive(Serialize)]
struct GraphPrefix<'a> {
    version: u32,
    schema_version: u32,
    resource_limits: CaseResourceLimits,
    nodes: &'a [Node],
    blobs: BlobDescriptors<'a>,
    edges: &'a [Edge],
    limitations: &'a [String],
}

struct BlobDescriptors<'a>(&'a [Blob]);

impl Serialize for BlobDescriptors<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for blob in self.0 {
            // Blob contents are immutable and snapshot loading checks their content IDs
            sequence.serialize_element(&(&blob.id, blob.bytes.len()))?;
        }
        sequence.end()
    }
}

impl Case {
    /// Capture the ordered original graph prefix without copying retained blob bytes
    ///
    /// # Errors
    /// Returns an error if bounded metadata cannot be allocated or hashed
    pub fn checkpoint_prefix(&self) -> Result<CasePrefixBinding, EvidenceError> {
        let mut sources = Vec::new();
        sources.try_reserve_exact(self.sources.len()).map_err(|_| {
            EvidenceError::AllocationFailed {
                field: "checkpoint source bindings",
            }
        })?;
        for source in &self.sources {
            let mut aliases = Vec::new();
            aliases
                .try_reserve_exact(source.aliases.len())
                .map_err(|_| EvidenceError::AllocationFailed {
                    field: "checkpoint source aliases",
                })?;
            aliases.extend(
                source
                    .aliases
                    .iter()
                    .map(|alias| <[u8; 32]>::from(Sha256::digest(alias.as_bytes()))),
            );
            sources.push(SourceBinding {
                core_digest: source_digest(source)?,
                aliases,
                had_blob: source.blob.is_some(),
            });
        }
        let mut binding = CasePrefixBinding {
            nodes: self.nodes.len(),
            blobs: self.blobs.len(),
            edges: self.edges.len(),
            limitations: self.limitations.len(),
            complete: self.collection_complete,
            sources,
            graph_digest: [0; 32],
        };
        binding.graph_digest = binding
            .graph_digest_for(self)?
            .ok_or(EvidenceError::InvalidJson)?;
        Ok(binding)
    }
}

impl CasePrefixBinding {
    /// Check the original graph, source identities, and monotonic additions before rebinding
    ///
    /// # Errors
    /// Returns an error if bounded metadata cannot be allocated or hashed
    pub fn matches(&self, case: &Case) -> Result<bool, EvidenceError> {
        if !self.complete && case.collection_complete {
            return Ok(false);
        }
        if case.sources.len() < self.sources.len() {
            return Ok(false);
        }
        for (saved, source) in self.sources.iter().zip(&case.sources) {
            if saved.core_digest != source_digest(source)?
                || (saved.had_blob && source.blob.is_none())
            {
                return Ok(false);
            }
            let mut aliases = HashSet::new();
            aliases.try_reserve(source.aliases.len()).map_err(|_| {
                EvidenceError::AllocationFailed {
                    field: "checkpoint source aliases",
                }
            })?;
            aliases.extend(
                source
                    .aliases
                    .iter()
                    .map(|alias| <[u8; 32]>::from(Sha256::digest(alias.as_bytes()))),
            );
            if saved.aliases.iter().any(|alias| !aliases.contains(alias)) {
                return Ok(false);
            }
        }
        Ok(self.graph_digest_for(case)? == Some(self.graph_digest))
    }

    fn graph_digest_for(&self, case: &Case) -> Result<Option<[u8; 32]>, EvidenceError> {
        let (Some(nodes), Some(blobs), Some(edges), Some(limitations)) = (
            case.nodes.get(..self.nodes),
            case.blobs.get(..self.blobs),
            case.edges.get(..self.edges),
            case.limitations.get(..self.limitations),
        ) else {
            return Ok(None);
        };
        hash_json(&GraphPrefix {
            version: PREFIX_VERSION,
            schema_version: case.schema_version,
            resource_limits: case.resource_limits,
            nodes,
            blobs: BlobDescriptors(blobs),
            edges,
            limitations,
        })
        .map(Some)
    }
}

fn source_digest(source: &Source) -> Result<[u8; 32], EvidenceError> {
    hash_json(&SourceCore {
        id: &source.id,
        label: &source.label,
        kind: &source.kind,
        length: source.length,
    })
}

fn hash_json(value: &impl Serialize) -> Result<[u8; 32], EvidenceError> {
    struct HashWriter(Sha256);
    impl Write for HashWriter {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.update(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    let mut output = HashWriter(Sha256::new());
    serde_json::to_writer(&mut output, value).map_err(|_| EvidenceError::InvalidJson)?;
    Ok(output.0.finalize().into())
}
