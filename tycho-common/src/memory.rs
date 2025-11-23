use std::alloc::System;

use deepsize::DeepSizeOf;
use stats_alloc::{Region, StatsAlloc, INSTRUMENTED_SYSTEM};

// TODO - use the `static GLOBAL: Jemalloc = Jemalloc;` pattern if we switch to jemalloc
#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

pub fn get_allocated_bytes() -> usize {
    GLOBAL.stats().bytes_allocated
}

pub fn get_deallocated_bytes() -> usize {
    GLOBAL.stats().bytes_deallocated
}

pub fn get_net_allocated_bytes() -> usize {
    get_allocated_bytes() - get_deallocated_bytes()
}

/// Formats byte size into human-readable format and logs it via debug!
///
/// # Arguments
/// * `bytes` - The size in bytes to format
/// * `label` - The identifier for this metric (e.g., "reorg_buffer_size", "memory_allocated")
///
/// # Returns
/// The formatted string (e.g., "45.32 MB", "1.23 GB")
pub fn format_bytes(bytes: usize, label: &str) -> String {
    let formatted = format_bytes_inline(bytes);

    tracing::info!("{} = {}", label, formatted);
    formatted
}

/// Reports comprehensive memory metrics including cache sizes, gateway stats, and total system
/// memory
///
/// Shows:
/// - Individual cache sizes (reorg buffer, protocol cache, DCI cache)
/// - Gateway internals (LRU cache, DB pool)
/// - Total tracked memory
/// - System-wide memory (allocated, deallocated, net)
/// - Percentage of total memory accounted for by tracked components
pub fn report_extractor_memory_metrics(
    reorg_buffer_size: usize,
    protocol_cache_size: usize,
    dci_cache_size: Option<usize>,
) {
    let total_tracked = reorg_buffer_size + protocol_cache_size + dci_cache_size.unwrap_or(0);
    let net_allocated = get_net_allocated_bytes();
    let percentage =
        if net_allocated > 0 { (total_tracked as f64 / net_allocated as f64) * 100.0 } else { 0.0 };

    format_bytes(reorg_buffer_size, "reorg_buffer");
    format_bytes(protocol_cache_size, "protocol_cache");
    if let Some(dci_size) = dci_cache_size {
        format_bytes(dci_size, "dci_cache");
    }

    tracing::info!(
        "Memory: tracked={} ({:.1}% of total), system_net={} (allocated_total={}, deallocated_total={}), unaccounted={}",
        format_bytes_inline(total_tracked),
        percentage,
        format_bytes_inline(net_allocated),
        format_bytes_inline(get_allocated_bytes()),
        format_bytes_inline(get_deallocated_bytes()),
        format_bytes_inline(net_allocated.saturating_sub(total_tracked))
    );
}

pub fn report_tracked_memory_metrics(label: &str, tracked_size: usize) {
    let net_allocated = get_net_allocated_bytes();
    let percentage =
        if net_allocated > 0 { (tracked_size as f64 / net_allocated as f64) * 100.0 } else { 0.0 };

    tracing::info!(
        "{}: tracked={} ({:.1}% of total), system_net={}",
        label,
        format_bytes_inline(tracked_size),
        percentage,
        format_bytes_inline(net_allocated)
    );
}

pub fn report_used_memory_metrics_with_label(label: &str) {
    let net_allocated = get_net_allocated_bytes();
    tracing::info!("{}: system_net={}", label, format_bytes_inline(net_allocated));
}

pub fn report_used_memory_metrics() {
    let net_allocated = get_net_allocated_bytes();
    tracing::info!("system_net={}", format_bytes_inline(net_allocated));
}

pub fn report_deepsize_of_memory_metrics<T: DeepSizeOf>(label: &str, object: &T) {
    tracing::info!("{}: deepsize={}", label, format_bytes_inline(object.deep_size_of()));
}

pub fn report_memory_metrics(label: &str, object_size: usize) {
    tracing::info!("{}: self reported size={}", label, format_bytes_inline(object_size));
}

/// Reports memory metrics for the deltas buffer
pub fn report_deltas_buffer_memory(buffer_size: usize) {
    let net_allocated = get_net_allocated_bytes();
    let percentage =
        if net_allocated > 0 { (buffer_size as f64 / net_allocated as f64) * 100.0 } else { 0.0 };

    tracing::info!(
        "PendingDeltas: buffer={} ({:.1}% of total), system_net={}",
        format_bytes_inline(buffer_size),
        percentage,
        format_bytes_inline(net_allocated)
    );
}

/// Internal helper to format bytes without logging (for inline use in log messages)
pub fn format_bytes_inline(bytes: usize) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    let bytes_f64 = bytes as f64;

    if bytes_f64 >= GB {
        format!("{:.2} GB", bytes_f64 / GB)
    } else if bytes_f64 >= MB {
        format!("{:.2} MB", bytes_f64 / MB)
    } else if bytes_f64 >= KB {
        format!("{:.2} KB", bytes_f64 / KB)
    } else {
        format!("{} B", bytes)
    }
}

/// Measure and report heap allocations for a synchronous function
///
/// This function is transparent - it returns the value produced by the provided function
/// while measuring and reporting the net heap allocations that occurred during execution.
///
/// # Arguments
/// * `label` - Identifier for the allocation being measured (e.g., "cache_initialization")
/// * `f` - The function to measure
///
/// # Returns
/// The value produced by function `f`
pub fn measure_allocation<T, F>(label: &str, f: F) -> T
where
    F: FnOnce() -> T,
{
    let reg = Region::new(GLOBAL);
    let value = f();
    let stats = reg.change();

    // Use net allocations (allocated - deallocated) to account for growth/reallocation
    let actual_heap: i32 = stats.bytes_allocated as i32 - stats.bytes_deallocated as i32;
    tracing::info!(
        "{}: change {}{} (allocated {}, deallocated {})",
        label,
        if actual_heap >= 0 { "" } else { "-" },
        format_bytes_inline(actual_heap.unsigned_abs() as usize),
        format_bytes_inline(stats.bytes_allocated),
        format_bytes_inline(stats.bytes_deallocated)
    );

    value
}

/// Measure and report heap allocations for an async function
///
/// This function is transparent - it returns the value produced by the provided async function
/// while measuring and reporting the net heap allocations that occurred during execution.
///
/// # Arguments
/// * `label` - Identifier for the allocation being measured (e.g., "async_cache_load")
/// * `f` - The async function to measure
///
/// # Returns
/// The value produced by async function `f`
pub async fn measure_allocation_async<T, F, Fut>(label: &str, f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let reg = Region::new(GLOBAL);
    let value = f().await;
    let stats = reg.change();

    // Use net allocations (allocated - deallocated) to account for growth/reallocation
    let actual_heap: i32 = stats.bytes_allocated as i32 - stats.bytes_deallocated as i32;
    tracing::info!(
        "{}: change {}{} (allocated {}, deallocated {})",
        label,
        if actual_heap >= 0 { "" } else { "-" },
        format_bytes_inline(actual_heap.unsigned_abs() as usize),
        format_bytes_inline(stats.bytes_allocated),
        format_bytes_inline(stats.bytes_deallocated)
    );

    value
}
