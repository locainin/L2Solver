use super::{IngestReceipt, Result, Store, invalid, packets};
use std::fs::File;

impl Store {
    /// Open the retained file identified by a validated ingest receipt
    ///
    /// The descriptor pins the opened file but does not prevent other writers from changing it
    /// Consumers must compare the bytes they use with the receipt's hash and length
    ///
    /// # Errors
    /// Rejects mismatched receipts, missing files, and files with the wrong length
    pub fn open_retained_source(&self, receipt: &IngestReceipt) -> Result<File> {
        self.validate_ingest_receipt(receipt)?;
        let file = packets::source_file(&self.sources.path(), &receipt.source_id)?;
        if file.metadata()?.len() != receipt.bytes {
            return Err(invalid("retained source length changed"));
        }
        Ok(file)
    }
}
