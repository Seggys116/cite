// Step movement shared by the site wizard and the rule builder: forward only past a clean step, back at any time
export function advance(current, count, problem) {
  if (problem) return current;
  return Math.min(current + 1, count - 1);
}

export function back(current) {
  return Math.max(current - 1, 0);
}

export function isLast(current, count) {
  return current === count - 1;
}

// A step can be opened from the progress list when every step before it is clean
export function canOpen(target, current, problems) {
  if (target <= current) return target >= 0;
  for (let i = current; i < target; i += 1) {
    if (problems[i]) return false;
  }
  return true;
}

export function stepStates(count, current) {
  return Array.from({ length: count }, (_, i) => ({ index: i, state: i < current ? 'done' : i === current ? 'current' : 'todo' }));
}

export function progressText(current, count, title) {
  return `Step ${current + 1} of ${count}: ${title}`;
}
