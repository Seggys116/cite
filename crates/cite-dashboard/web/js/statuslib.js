// Turns the node's GET /sites/{id}/status answer into what the Status panel shows; the answer is read tolerantly because nodes of different versions fill different fields
export const PHASES = {
  fetching: { label: 'Fetching', kind: 'info', busy: true },
  building: { label: 'Building', kind: 'info', busy: true },
  packing: { label: 'Packing', kind: 'info', busy: true },
  promoting: { label: 'Promoting', kind: 'info', busy: true },
  idle: { label: 'Idle', kind: 'ok', busy: false },
  failed: { label: 'Failed', kind: 'bad', busy: false },
  unhealthy: { label: 'Unhealthy', kind: 'warn', busy: false },
};

export const BUSY_POLL_MS = 2000;
export const IDLE_POLL_MS = 10000;

const BAD_HEALTH = /unhealthy|down|dead|exited|restarting|crash|fail/i;
const OK_HEALTH = /^(healthy|up|running|ok|pass|passing)$/i;

export function healthTone(text) {
  const t = String(text ?? '');
  if (!t) return 'muted';
  if (BAD_HEALTH.test(t) && !/^healthy$/i.test(t)) return 'bad';
  if (OK_HEALTH.test(t)) return 'ok';
  return 'muted';
}

export function shortSha(sha) {
  const s = String(sha ?? '');
  return s ? s.slice(0, 7) : '';
}

const slotsOf = (status) => (status && Array.isArray(status.slots) ? status.slots : []);
const activeSlot = (status) => slotsOf(status).find((s) => s.slot === status.active) || null;

function activeUnhealthy(status) {
  const slot = activeSlot(status);
  if (!slot) return false;
  return healthTone(slot.health) === 'bad' || /down|fail/i.test(String(slot.haproxy_check ?? ''));
}

// The phase chip: what the manager reports, or unhealthy when it is idle but the live slot is not serving well
export function phaseOf(status) {
  const raw = String((status && status.phase) || '').toLowerCase();
  const known = Object.hasOwn(PHASES, raw) ? raw : '';
  if (known === 'idle' && activeUnhealthy(status)) return 'unhealthy';
  if (known) return known;
  if (status && status.error) return 'failed';
  return activeUnhealthy(status) ? 'unhealthy' : 'idle';
}

export function phaseView(status) {
  const phase = phaseOf(status);
  const meta = PHASES[phase];
  const op = status && status.operation;
  let detail = '';
  if (op && meta.busy) {
    detail = [op.kind, op.slot ? `slot ${op.slot}` : '', op.step].filter(Boolean).join(', ');
  }
  return { phase, label: meta.label, kind: meta.kind, busy: meta.busy, detail };
}

// The reason to show in the red banner: the most specific message the node gave
export function errorText(status) {
  if (!status) return '';
  const phase = phaseOf(status);
  const slot = activeSlot(status);
  const report = slot && slot.report;
  const deploy = report && report.deploy;
  const parts = [
    status.error,
    status.last_failure && status.last_failure.note,
    report && report.last_error,
    deploy && deploy.result === 'failed' ? deploy.reason : '',
  ].filter((p) => typeof p === 'string' && p.trim());
  if (parts.length) return parts[0].trim();
  if (phase === 'unhealthy') return `The ${status.active || 'live'} slot is not passing its health check.`;
  if (phase === 'failed') return 'The last attempt failed and the node gave no reason. Open the manager logs.';
  return '';
}

export function showsBanner(status) {
  const phase = phaseOf(status);
  return phase === 'failed' || phase === 'unhealthy' || Boolean(status && status.error);
}

export function pendingChanges(status) {
  return Boolean(status) && status.settings_current === false;
}

export function pendingLabel(status) {
  return pendingChanges(status) ? 'Changes not built yet' : '';
}

function duration(secs) {
  if (secs === null || secs === undefined) return '';
  if (secs < 60) return `${secs}s`;
  return `${Math.floor(secs / 60)}m ${secs % 60}s`;
}

export function slotRows(status) {
  return slotsOf(status).map((s) => {
    const report = s.report || {};
    const tone = healthTone(s.health);
    return {
      slot: s.slot,
      active: s.slot === (status && status.active),
      container: s.container || '',
      health: s.health || 'unknown',
      tone,
      restarts: s.restart_count || 0,
      exitCode: s.exit_code ?? null,
      oom: Boolean(s.oom_killed),
      phase: report.phase || '',
      head: shortSha(report.head_sha),
      live: shortSha(report.live_sha),
      lastBuild: duration(report.last_build_secs),
      failedSha: shortSha(report.last_failed_sha),
      error: report.last_error || '',
      haproxy: s.haproxy || '',
    };
  });
}

// What the manager worked out on its own; the active slot is preferred because it is what is serving
export function detectedOf(status) {
  const slots = slotsOf(status);
  const ordered = [...slots.filter((s) => s.slot === (status && status.active)), ...slots.filter((s) => s.slot !== (status && status.active))];
  for (const s of ordered) {
    const d = s.report && s.report.detected;
    if (d && typeof d === 'object') return d;
  }
  return null;
}

export function pollDelay(status) {
  return PHASES[phaseOf(status)].busy ? BUSY_POLL_MS : IDLE_POLL_MS;
}

export function unsupported(error) {
  return Boolean(error) && (error.status === 404 || error.status === 501);
}
