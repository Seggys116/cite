pub(crate) const MINUTE_MS: i64 = 60_000;
pub(crate) const HOUR_MS: i64 = 3_600_000;
pub(crate) const DAY_MS: i64 = 86_400_000;

// Longest window any query honours; longer requests are clamped to it.
pub(crate) const MAX_WINDOW_SECS: u64 = 400 * 86_400;
// Windows up to this length chart per minute, matching the in-memory analytics.
pub(crate) const MINUTE_STEP_MAX_WINDOW_SECS: u64 = 48 * 3600;
// Windows longer than this read the hourly rollups instead of raw rows.
pub(crate) const ROLLUP_MIN_WINDOW_SECS: u64 = 6 * 3600;
// Minute rollups older than this are removed; it exceeds the longest window they serve.
pub(crate) const MINUTE_KEEP_MS: i64 = 7 * HOUR_MS;

/// Most rows a single request query returns, whatever limit the caller passes.
pub const MAX_REQUEST_LIMIT: usize = 100_000;
/// Most items a single top query returns.
pub const MAX_TOP_LIMIT: usize = 10_000;
/// Rows an export writes when the filter carries no explicit limit.
pub const DEFAULT_EXPORT_LIMIT: u64 = 1_000_000;

pub(crate) const TOP_N: usize = 20;
pub(crate) const METHOD_CAP: usize = 16;
// Per-request byte counts are clamped so SQLite's integer SUM cannot overflow on hostile input.
pub(crate) const BYTES_CLAMP: u64 = 1 << 36;
// A batch whose events span more than this is a backfill or import rather than live traffic, so it skips the minute rollups.
pub(crate) const BACKFILL_SPAN_MS: i64 = 10 * MINUTE_MS;
