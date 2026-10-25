use super::BuildInput;
use crate::reconstruction::InputSelection;
use serde::Serialize;
use std::error::Error;

/// Inclusive original capture record bounds for a deliberately scoped analysis
#[derive(Clone, Copy, Debug, Serialize)]
pub struct RecordWindow {
    pub first: u32,
    pub last: u32,
}

#[derive(Clone, Copy)]
pub(super) struct Scope {
    pub first: u32,
    pub selected: u64,
    pub window: Option<RecordWindow>,
    pub mode: InputSelection,
}

impl Scope {
    pub const fn capture(selected: u64) -> Self {
        Self {
            first: 1,
            selected,
            window: None,
            mode: InputSelection::ConsecutiveRecords,
        }
    }

    pub fn window(input: BuildInput<'_>, window: RecordWindow) -> Result<Self, Box<dyn Error>> {
        if window.first == 0
            || window.last < window.first
            || u64::from(window.last) > input.frames_seen
        {
            return Err("record window is outside the source capture".into());
        }
        let selected = u64::from(window.last) - u64::from(window.first) + 1;
        if u64::try_from(input.records.len())? != selected
            || input.records.iter().enumerate().any(|(offset, record)| {
                u64::try_from(offset).ok().is_none_or(|offset| {
                    u64::from(record.number) != u64::from(window.first) + offset
                })
            })
        {
            return Err("record window must supply every selected consecutive record".into());
        }
        Ok(Self {
            first: window.first,
            selected,
            window: Some(window),
            mode: InputSelection::ConsecutiveRecords,
        })
    }

    pub fn selection(input: BuildInput<'_>, selected: u64) -> Result<Self, Box<dyn Error>> {
        if selected > input.frames_seen || u64::try_from(input.records.len())? > selected {
            return Err("record selection count is outside the source capture".into());
        }
        let mut previous = 0;
        for record in input.records {
            if record.number <= previous || u64::from(record.number) > input.frames_seen {
                return Err("selected records must have increasing original source numbers".into());
            }
            previous = record.number;
        }
        Ok(Self {
            first: input.records.first().map_or(1, |record| record.number),
            selected,
            window: None,
            mode: InputSelection::SelectedRecords,
        })
    }
}
