// Histogram layouts shared with the in-memory analytics so percentiles and size buckets agree exactly.

pub(crate) const LAT_LEN: usize = 128;
pub(crate) const SIZE_LES: [u64; 9] = [
    1 << 10,
    1 << 12,
    1 << 14,
    1 << 16,
    1 << 18,
    1 << 20,
    1 << 22,
    1 << 24,
    1 << 26,
];
pub(crate) const SIZE_LEN: usize = SIZE_LES.len() + 1;

// Log-scale histogram: exact below 4 ms, then four sub-buckets per power of two.
pub(crate) fn lat_index(ms: u32) -> usize {
    if ms < 4 {
        return ms as usize;
    }
    let bits = (32 - ms.leading_zeros()) as usize;
    let sub = ((ms >> (bits - 3)) & 3) as usize;
    4 + (bits - 3) * 4 + sub
}

fn lat_lower(idx: usize) -> u64 {
    if idx < 4 {
        return idx as u64;
    }
    let k = idx - 4;
    let bits = k / 4 + 3;
    (4 + (k % 4) as u64) << (bits - 3)
}

fn lat_mid(idx: usize) -> u64 {
    if idx < 4 {
        return idx as u64;
    }
    let lo = lat_lower(idx);
    let hi = lat_lower(idx + 1) - 1;
    (lo + hi) / 2
}

pub(crate) fn size_index(bytes: u64) -> usize {
    SIZE_LES
        .iter()
        .position(|&l| bytes <= l)
        .unwrap_or(SIZE_LES.len())
}

// Index into the per-class counters: 0 is anything outside 1xx..5xx.
pub(crate) fn class_index(status: u16) -> usize {
    match status / 100 {
        c @ 1..=5 => c as usize,
        _ => 0,
    }
}

// Nearest-rank percentile over the merged histogram, reported as the bucket midpoint.
pub(crate) fn percentile(hist: &[u64], total: u64, pct: u64) -> u64 {
    if total == 0 {
        return 0;
    }
    let target = total.saturating_mul(pct).div_ceil(100).max(1);
    let mut acc = 0u64;
    for (i, c) in hist.iter().enumerate() {
        acc += c;
        if acc >= target {
            return lat_mid(i);
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_buckets_contain_their_values() {
        for ms in (0..100_000u32).chain([u32::MAX - 1, u32::MAX]) {
            let idx = lat_index(ms);
            assert!(idx < LAT_LEN);
            let lo = lat_lower(idx);
            let hi = if idx + 1 < LAT_LEN {
                lat_lower(idx + 1) - 1
            } else {
                u64::MAX
            };
            assert!(lo <= u64::from(ms) && u64::from(ms) <= hi, "ms {ms}");
        }
    }

    #[test]
    fn size_and_class_indexes() {
        assert_eq!(size_index(0), 0);
        assert_eq!(size_index(1024), 0);
        assert_eq!(size_index(1025), 1);
        assert_eq!(size_index(u64::MAX), 9);
        assert_eq!(class_index(204), 2);
        assert_eq!(class_index(0), 0);
        assert_eq!(class_index(700), 0);
    }

    #[test]
    fn percentile_of_empty_is_zero() {
        assert_eq!(percentile(&[0; LAT_LEN], 0, 99), 0);
    }
}
