// Keep short inputs exhaustive and bound repeated snapshots for longer inputs
pub(super) const MAX_CHECKPOINTS: usize = 8;
pub(super) const CHUNK_BYTES: usize = 13;

pub(super) fn should_checkpoint(index: usize, count: usize, selector: u8) -> bool {
    if index >= count {
        return false;
    }
    if count <= MAX_CHECKPOINTS || index == 0 || index == count - 1 {
        return true;
    }
    // The input selects interior boundaries while first and last remain covered
    let stride = count.div_ceil(MAX_CHECKPOINTS - 2);
    index % stride == usize::from(selector) % stride
}
