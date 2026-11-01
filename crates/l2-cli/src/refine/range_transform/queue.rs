//! Admit queue storage while the old and replacement buffers coexist

use super::StreamObject;
use l2_workbench::job::{MemoryBudget, MemoryClass, MemoryLease};
use std::{collections::VecDeque, error::Error, mem::size_of};

pub(super) struct StreamQueue {
    pub(super) values: VecDeque<StreamObject>,
    memory: MemoryLease,
}

impl StreamQueue {
    pub(super) fn new(memory: &MemoryBudget) -> Result<Self, Box<dyn Error>> {
        Ok(Self {
            values: VecDeque::new(),
            memory: memory.try_reserve(MemoryClass::Executor, 0)?,
        })
    }

    pub(super) fn push(&mut self, object: StreamObject) -> Result<(), Box<dyn Error>> {
        if self.values.len() == self.values.capacity() {
            self.grow()?;
        }
        self.values.push_back(object);
        Ok(())
    }

    pub(super) fn pop_front(&mut self) -> Option<StreamObject> {
        self.values.pop_front()
    }

    fn grow(&mut self) -> Result<(), Box<dyn Error>> {
        let old = self
            .values
            .capacity()
            .checked_mul(size_of::<StreamObject>())
            .ok_or("stream queue capacity overflows")?;
        let wanted = self
            .values
            .capacity()
            .checked_mul(2)
            .ok_or("stream queue size overflows")?
            .max(4);
        let requested = wanted
            .checked_mul(size_of::<StreamObject>())
            .ok_or("stream queue capacity overflows")?;
        let before = self.memory.bytes();
        super::super::analysis_memory::charge(&mut self.memory, requested)?;
        let mut next = VecDeque::new();
        if let Err(error) = next.try_reserve_exact(wanted) {
            drop(next);
            self.memory.try_resize(before)?;
            return Err(Box::new(error));
        }
        let admitted = next
            .capacity()
            .checked_mul(size_of::<StreamObject>())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .and_then(|bytes| before.checked_add(bytes));
        let Some(admitted) = admitted else {
            drop(next);
            self.memory.try_resize(before)?;
            return Err("stream queue memory overflows".into());
        };
        if let Err(error) = self.memory.try_resize(admitted) {
            drop(next);
            self.memory.try_resize(before)?;
            return Err(Box::new(error));
        }
        next.append(&mut self.values);
        let previous = std::mem::replace(&mut self.values, next);
        drop(previous);
        self.memory.try_resize(
            admitted
                .checked_sub(u64::try_from(old)?)
                .ok_or("stream queue charge is inconsistent")?,
        )?;
        Ok(())
    }
}
