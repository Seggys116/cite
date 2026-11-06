const SUCCESS = new Set(['promote', 'switch', 'rollback']);
const SHA_RE = /\b[0-9a-f]{7,40}\b/;

export const isFailure = (entry) => Boolean(entry) && /fail/i.test(String(entry.action || ''));
export const isSuccess = (entry) => Boolean(entry) && SUCCESS.has(String(entry.action || ''));

export function commitOf(entry) {
  if (!entry) return '';
  const own = entry.sha || entry.commit || entry.git_sha;
  if (typeof own === 'string' && /^[0-9a-f]{7,64}$/i.test(own)) return own.toLowerCase();
  const found = String(entry.note || '').match(SHA_RE);
  return found && /\d/.test(found[0]) ? found[0] : '';
}

export function refOf(entry) {
  if (!entry) return '';
  const own = entry.git_ref || entry.ref;
  return typeof own === 'string' ? own : '';
}

// Newest first. The row that put the active slot live is the current one; a failed attempt is never current.
export function historyRows(history, active) {
  const list = Array.isArray(history) ? history : [];
  const newest = [...list].reverse();
  const current = newest.find((d) => isSuccess(d) && d.slot === active);
  const successes = list.filter(isSuccess);
  return newest.map((d) => {
    const commit = commitOf(d);
    const failed = isFailure(d);
    return {
      id: d.id,
      at: d.at,
      slot: d.slot,
      action: d.action,
      note: d.note || '',
      failed,
      commit,
      ref: refOf(d),
      current: d === current,
      canRollback: false,
      canRedeploy: failed || d === current,
      canDeployCommit: Boolean(commit) && d !== current,
      successes: successes.length,
    };
  });
}

// Rolling back needs an earlier successful release on the other slot to return to
export function canRollback(history, active) {
  const list = (Array.isArray(history) ? history : []).filter(isSuccess);
  if (list.length < 2) return false;
  return list.some((d) => d.slot && d.slot !== active);
}

export function deployRefFor(row, source) {
  if (row && row.commit) return row.commit;
  if (row && row.ref) return row.ref;
  return (source && source.branch) || 'main';
}

// Failures at the top of the history count until a later success replaces them
export function latestFailure(history) {
  const list = Array.isArray(history) ? history : [];
  for (let i = list.length - 1; i >= 0; i -= 1) {
    if (isSuccess(list[i])) return null;
    if (isFailure(list[i])) return list[i];
  }
  return null;
}

export function unhealthyTargets(site) {
  const live = (site && site.live && site.live[site.active]) || [];
  return live.filter((t) => t && t.status && !/^(up|ok|healthy|pass)/i.test(String(t.status)));
}

export function failureNote(site) {
  const failed = latestFailure(site && site.history);
  const bad = unhealthyTargets(site);
  if (failed && failed.note) return `Last deploy failed: ${failed.note}`;
  if (failed) return 'Last deploy failed.';
  if (bad.length) return `${bad.length === 1 ? 'A target is' : `${bad.length} targets are`} not passing the health check: ${bad.map((t) => t.addr).join(', ')}`;
  return '';
}

export function deployFailureText(error, fallback = 'The deploy failed.') {
  const message = error && typeof error.message === 'string' ? error.message.trim() : '';
  return message ? `Deploy failed: ${message}` : fallback;
}
