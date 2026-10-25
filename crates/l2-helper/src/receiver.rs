use std::collections::VecDeque;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

use l2_helper_protocol::InterfaceBindingRequest;

use crate::{BindingError, HelperError, MAX_FRAME_BYTES};

/// Cooperative cancellation signal passed to the receive backend
#[derive(Clone, Debug)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    /// Create a token in the running state
    #[must_use]
    pub fn new() -> Self {
        Self {
            cancelled: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Request cancellation; repeated requests are harmless
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    /// Return whether cancellation was requested
    #[must_use]
    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

impl Default for CancellationToken {
    fn default() -> Self {
        Self::new()
    }
}

/// A receive backend already bound to one immutable namespace/ifindex identity
pub trait ReceiveSocket: Send + 'static {
    /// Return the binding recorded when the backend was opened
    fn binding(&self) -> InterfaceBindingRequest;

    /// Revalidate the retained descriptor and kernel identity
    ///
    /// This check runs before opening a session and before each receive. A
    /// real Linux backend must fail closed when the namespace object, ifindex,
    /// datalink, or descriptor association cannot be proven unchanged.
    ///
    /// # Errors
    /// Returns a binding error when the retained identity cannot be proven
    fn revalidate(&self) -> Result<(), BindingError>;

    /// Receive one bounded frame, or return `None` when no frame is ready
    ///
    /// Implementations must check the token while waiting. The helper can
    /// acknowledge cancellation immediately on its control channel, but an
    /// arbitrary blocking backend cannot be forcibly interrupted safely.
    ///
    /// # Errors
    /// Returns a backend or binding error when capture fails
    fn receive(&mut self, cancellation: &CancellationToken)
    -> Result<Option<Vec<u8>>, HelperError>;
}

/// An in-memory receive source for deterministic integration tests and fixtures
#[derive(Debug)]
pub struct QueueReceiveSocket {
    original_binding: InterfaceBindingRequest,
    binding: InterfaceBindingRequest,
    frames: VecDeque<Vec<u8>>,
}

impl QueueReceiveSocket {
    /// Create a receive source with a fixed binding and bounded queued frames
    ///
    /// # Errors
    /// Returns [`HelperError::Reply`] when a frame exceeds the IPC frame limit
    pub fn new(
        binding: InterfaceBindingRequest,
        frames: Vec<Vec<u8>>,
    ) -> Result<Self, HelperError> {
        if frames.iter().any(|frame| frame.len() > MAX_FRAME_BYTES) {
            return Err(HelperError::Reply(crate::ReplyError::MessageTooLarge {
                length: frames.iter().map(Vec::len).max().unwrap_or_default(),
                maximum: MAX_FRAME_BYTES,
            }));
        }
        Ok(Self {
            original_binding: binding,
            binding,
            frames: frames.into_iter().collect(),
        })
    }

    /// Change the source's reported binding for link-replacement tests
    pub const fn replace_binding(&mut self, binding: InterfaceBindingRequest) {
        self.binding = binding;
    }
}

impl ReceiveSocket for QueueReceiveSocket {
    fn binding(&self) -> InterfaceBindingRequest {
        self.binding
    }

    fn revalidate(&self) -> Result<(), BindingError> {
        if self.binding == self.original_binding {
            Ok(())
        } else {
            Err(BindingError::IdentityLost)
        }
    }

    fn receive(
        &mut self,
        cancellation: &CancellationToken,
    ) -> Result<Option<Vec<u8>>, HelperError> {
        if cancellation.is_cancelled() {
            return Ok(None);
        }
        Ok(self.frames.pop_front())
    }
}
