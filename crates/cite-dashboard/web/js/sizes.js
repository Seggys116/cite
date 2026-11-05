// The API reports response sizes cumulatively; charts need per-bucket counts, so each bucket keeps only what the previous bound missed.
export function perBucketSizes(sizes) {
  let previous = 0;
  return (sizes || []).map((b) => {
    const count = Math.max(0, (Number(b.count) || 0) - previous);
    previous = Math.max(previous, Number(b.count) || 0);
    return { le: b.le, count };
  });
}
