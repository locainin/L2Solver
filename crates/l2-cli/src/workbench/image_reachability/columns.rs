//! One-dimensional grouping of columns containing classified pixels

use l2_workbench::artifact::PixelCoordinate;
use serde::Serialize;
use std::{error::Error, mem::size_of};

#[derive(Clone, Copy, Debug, Default)]
struct ColumnStats {
    pixel_count: usize,
    min_y: u32,
    max_y: u32,
}

/// One horizontal range separated by the caller-selected blank-column gap
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub(super) struct ColumnGroup {
    pub(super) start_x: u32,
    pub(super) end_x_exclusive: u32,
    pub(super) occupied_column_count: usize,
    pub(super) unreachable_pixel_count: usize,
    pub(super) min_y: u32,
    pub(super) max_y: u32,
}

pub(super) fn group(
    width: u32,
    coordinates: &[PixelCoordinate],
    minimum_blank_gap: u32,
    maximum_work_bytes: usize,
    maximum_report_bytes: usize,
) -> Result<Vec<ColumnGroup>, Box<dyn Error>> {
    if coordinates.is_empty() {
        return Ok(Vec::new());
    }
    let width = usize::try_from(width)?;
    let required_work = width
        .checked_mul(size_of::<ColumnStats>())
        .ok_or("column-group work size overflow")?;
    if required_work > maximum_work_bytes {
        return Err(format!(
            "column grouping requires {required_work} work bytes; maximum is {maximum_work_bytes}"
        )
        .into());
    }

    let mut columns = Vec::new();
    columns.try_reserve_exact(width)?;
    let allocated_work = columns.capacity().saturating_mul(size_of::<ColumnStats>());
    if allocated_work > maximum_work_bytes {
        return Err(format!(
            "column grouping allocated {allocated_work} work bytes; maximum is {maximum_work_bytes}"
        )
        .into());
    }
    columns.resize(width, ColumnStats::default());

    // Count each marked pixel once while retaining only per-column bounds
    for coordinate in coordinates {
        let x = usize::try_from(coordinate.x)?;
        let column = columns
            .get_mut(x)
            .ok_or("unreachable pixel lies outside the decoded image width")?;
        if column.pixel_count == 0 {
            column.min_y = coordinate.y;
            column.max_y = coordinate.y;
        } else {
            column.min_y = column.min_y.min(coordinate.y);
            column.max_y = column.max_y.max(coordinate.y);
        }
        column.pixel_count = column
            .pixel_count
            .checked_add(1)
            .ok_or("column pixel count overflow")?;
    }

    let group_count = count_groups(&columns, minimum_blank_gap)?;
    let required_report = group_count
        .checked_mul(size_of::<ColumnGroup>())
        .ok_or("column-group report size overflow")?;
    if required_report > maximum_report_bytes {
        return Err(format!(
            "column groups require {required_report} report bytes; maximum is {maximum_report_bytes}"
        )
        .into());
    }
    build_groups(
        &columns,
        minimum_blank_gap,
        group_count,
        maximum_report_bytes,
    )
}

fn count_groups(columns: &[ColumnStats], minimum_blank_gap: u32) -> Result<usize, Box<dyn Error>> {
    let gap = usize::try_from(minimum_blank_gap)?;
    let mut count = 0_usize;
    let mut previous = None;
    for (index, column) in columns.iter().enumerate() {
        if column.pixel_count == 0 {
            continue;
        }
        if previous.is_none_or(|last: usize| index.saturating_sub(last + 1) >= gap) {
            count = count.checked_add(1).ok_or("column-group count overflow")?;
        }
        previous = Some(index);
    }
    Ok(count)
}

fn build_groups(
    columns: &[ColumnStats],
    minimum_blank_gap: u32,
    group_count: usize,
    maximum_report_bytes: usize,
) -> Result<Vec<ColumnGroup>, Box<dyn Error>> {
    let gap = usize::try_from(minimum_blank_gap)?;
    let mut groups = Vec::new();
    groups.try_reserve_exact(group_count)?;
    let allocated = groups.capacity().saturating_mul(size_of::<ColumnGroup>());
    if allocated > maximum_report_bytes {
        return Err(format!(
            "column groups allocated {allocated} report bytes; maximum is {maximum_report_bytes}"
        )
        .into());
    }

    let mut current = None;
    let mut previous_x = None;
    for (x, column) in columns.iter().enumerate() {
        if column.pixel_count == 0 {
            continue;
        }
        if previous_x.is_some_and(|last: usize| x.saturating_sub(last + 1) >= gap)
            && let Some(group) = current.take()
        {
            groups.push(group);
        }
        update_group(&mut current, x, *column)?;
        previous_x = Some(x);
    }
    if let Some(group) = current {
        groups.push(group);
    }
    if groups.len() != group_count {
        return Err("column-group count changed between validation passes".into());
    }
    Ok(groups)
}

fn update_group(
    current: &mut Option<ColumnGroup>,
    x: usize,
    column: ColumnStats,
) -> Result<(), Box<dyn Error>> {
    let x = u32::try_from(x)?;
    if let Some(group) = current {
        group.end_x_exclusive = x.checked_add(1).ok_or("column range overflow")?;
        group.occupied_column_count = group
            .occupied_column_count
            .checked_add(1)
            .ok_or("occupied-column count overflow")?;
        group.unreachable_pixel_count = group
            .unreachable_pixel_count
            .checked_add(column.pixel_count)
            .ok_or("column-group pixel count overflow")?;
        group.min_y = group.min_y.min(column.min_y);
        group.max_y = group.max_y.max(column.max_y);
        return Ok(());
    }
    *current = Some(ColumnGroup {
        start_x: x,
        end_x_exclusive: x.checked_add(1).ok_or("column range overflow")?,
        occupied_column_count: 1,
        unreachable_pixel_count: column.pixel_count,
        min_y: column.min_y,
        max_y: column.max_y,
    });
    Ok(())
}
