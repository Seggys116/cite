// Dev aid: mock site routes; a handler returns undefined for routes it does not own. The sites are chosen so every state can be seen.
const ESC = String.fromCharCode(27);
const stateOf = new WeakMap();
const FULL = ['site-status', 'site-logs', 'source-build', 'site-github-token', 'site-build-env', 'site-runtime-env', 'deploy-async', 'cert-generate', 'cert-origin-ca', 'cert-acme', 'alerts', 'forges'];
// The second node is older, so gated controls can be checked by switching nodes
const LIMITED = ['site-status', 'source-build', 'site-github-token', 'site-build-env', 'deploy-async', 'cert-generate'];

export const capabilitiesFor = (node) => (node.idx === 1 ? LIMITED : FULL);
export const forgeHostFor = () => 'api.github.com';

const colour = (code, text) => `${ESC}[${code}m${text}${ESC}[0m`;
const SHA = 'f3a9c1e07b2d4856a0c9e1d3b7f54a6c8e2d1b90';

function seedManager(site, failed) {
  const t = (s) => new Date(Date.now() - s * 1000).toISOString();
  const lines = [
    { ts: t(240), stream: 'stdout', phase: 'fetching', text: `Fetching ${site.source.repo}@${site.source.branch || 'main'}` },
    { ts: t(236), stream: 'stdout', phase: 'fetching', text: `Resolved ${SHA.slice(0, 7)} (${site.source.branch || 'main'})` },
    { ts: t(230), stream: 'stdout', phase: 'building', text: `${colour('36', 'install')} ${site.source.package_manager || 'npm'} ci` },
    { ts: t(212), stream: 'stdout', phase: 'building', text: 'added 412 packages in 14s' },
    { ts: t(210), stream: 'stderr', phase: 'building', text: `${colour('33', 'warn')} deprecated inflight@1.0.6: this module is not supported` },
    { ts: t(208), stream: 'stdout', phase: 'building', text: `${colour('36', 'build')} ${site.source.build_command || 'npm run build'}` },
  ];
  if (failed) {
    lines.push(
      { ts: t(190), stream: 'stderr', phase: 'building', text: `${colour('31', 'error')} during build:` },
      { ts: t(190), stream: 'stderr', phase: 'building', text: 'Error: Cannot find module \'@docs/theme\' imported from /work/src/main.ts' },
      { ts: t(189), stream: 'stderr', phase: 'building', text: 'npm ERR! code ELIFECYCLE' },
      { ts: t(189), stream: 'stderr', phase: 'building', text: 'Build failed: the build command exited with status 1' },
    );
  } else {
    lines.push(
      { ts: t(180), stream: 'stdout', phase: 'building', text: 'vite v5.4.2 building for production... transformed 204 modules.' },
      { ts: t(170), stream: 'stdout', phase: 'packing', text: 'Packed dist (3.1 MiB, 188 files)' },
      { ts: t(165), stream: 'stdout', phase: 'promoting', text: 'Promoted release to the blue slot' },
    );
  }
  return lines;
}

function seedExecutor(site) {
  const t = (s) => new Date(Date.now() - s * 1000).toISOString();
  return [
    { ts: t(120), stream: 'stdout', phase: '', text: `Serving ${site.id} on port 8080` },
    { ts: t(60), stream: 'stdout', phase: '', text: 'GET /healthz 200 1ms' },
    { ts: t(30), stream: 'stderr', phase: '', level: 'warn', text: 'slow response for /search (1840ms)' },
  ];
}

function seedFor(node, site) {
  const failed = node.idx === 0 && site.id === 'docs';
  const unhealthy = node.idx === 1 && site.id === 'shop';
  return {
    phase: failed ? 'failed' : 'idle',
    error: failed ? 'The build command exited with status 1: Cannot find module \'@docs/theme\' imported from /work/src/main.ts' : null,
    unhealthy,
    operation: null,
    lastFailure: failed ? { at: new Date(Date.now() - 189000).toISOString(), slot: site.active === 'blue' ? 'green' : 'blue', note: 'The build command exited with status 1' } : null,
    settingsCurrent: !(node.idx === 1 && site.id === 'docs'),
    manager: seedManager(site, failed),
    executor: seedExecutor(site),
    token: unhealthy
      ? { source: 'site', site_token_set: true, node_token_configured: node.idx === 0, status: 'invalid token: the git host answered 401', verified: false, expires_at: null }
      : { source: node.idx === 0 ? 'node' : 'none', site_token_set: false, node_token_configured: node.idx === 0, status: null, verified: node.idx === 0 ? true : null, expires_at: null },
    buildEnv: new Map([['VITE_API_URL', 'https://api.example.com']]),
    runtimeEnv: new Map(),
    timers: [],
  };
}

function siteState(node, site) {
  let byNode = stateOf.get(node);
  if (!byNode) {
    byNode = new Map();
    stateOf.set(node, byNode);
  }
  if (!byNode.has(site.id)) byNode.set(site.id, seedFor(node, site));
  return byNode.get(site.id);
}

export function install(register, h) {
  const { ApiError, iso } = h;
  const gate = (node, name) => {
    if (!capabilitiesFor(node).includes(name)) throw new ApiError(404, 'Not Found');
  };
  const need = (site) => {
    if (!site.source) throw new ApiError(404, `site ${site.id} is not built from a repository`);
  };

  function slotsFor(node, site, st) {
    return ['blue', 'green'].map((slot) => {
      const active = site.active === slot;
      const bad = st.unhealthy && active;
      return {
        slot,
        container: `${site.id}-${slot}`,
        health: bad ? 'unhealthy' : (active || site[slot].targets.length ? 'healthy' : 'none'),
        restart_count: bad ? 7 : 0,
        exit_code: bad ? 1 : null,
        oom_killed: false,
        haproxy: bad ? 'DOWN' : 'UP',
        haproxy_check: bad ? 'L7STS' : 'L7OK',
        report: {
          v: 1,
          phase: active ? st.phase : 'idle',
          head_sha: SHA,
          live_sha: active ? SHA : null,
          last_build_secs: 74,
          last_error: active ? st.error : null,
          last_failed_sha: active && st.error ? SHA : null,
          deploy: st.error && active ? { id: 'dep-1', result: 'failed', reason: st.error, sha: SHA } : null,
          detected: { package_manager: 'pnpm', build_command: 'pnpm build', output_dir: 'dist', rendering: 'static', install_command: 'pnpm install --frozen-lockfile', node_major: 22, framework: 'vite', spa_fallback: 'index.html' },
        },
      };
    });
  }

  function statusOf(node, site) {
    const st = siteState(node, site);
    return {
      phase: st.phase,
      error: st.error,
      active: site.active,
      operation: st.operation,
      last_failure: st.lastFailure,
      slots: slotsFor(node, site, st),
      settings_current: st.settingsCurrent && !(node.pendingBuild && node.pendingBuild.has(site.id)),
      checked_at: iso(Date.now()),
    };
  }

  function logsOf(node, site, q) {
    gate(node, 'site-logs');
    const st = siteState(node, site);
    const source = q.get('source');
    if (source !== 'manager' && source !== 'executor') throw new ApiError(400, 'source must be manager or executor');
    const slot = q.get('slot');
    if (slot && slot !== 'blue' && slot !== 'green') throw new ApiError(400, 'slot must be blue or green');
    const list = source === 'manager' ? st.manager : st.executor;
    const since = q.get('since');
    let from = 0;
    if (since) {
      const m = /^c-(\d+)$/.exec(since);
      if (!m) throw new ApiError(400, 'since is not a valid cursor');
      from = Number(m[1]);
    } else {
      const tail = Number(q.get('tail') || 200);
      if (!Number.isInteger(tail) || tail < 1 || tail > 1000) throw new ApiError(400, 'tail must be between 1 and 1000');
      from = Math.max(0, list.length - tail);
    }
    // A running executor keeps printing, so following it shows new lines
    if (source === 'executor' && Date.now() - (st.lastTick || 0) > 2000) {
      st.lastTick = Date.now();
      list.push({ ts: iso(Date.now()), stream: 'stdout', phase: '', text: `GET /healthz 200 ${1 + (list.length % 4)}ms` });
    }
    return { lines: list.slice(from), cursor: `c-${list.length}`, truncated: false };
  }

  function tokenRoute(node, site, method, body) {
    gate(node, 'site-github-token');
    need(site);
    const st = siteState(node, site);
    if (method === 'GET') return st.token;
    if (method === 'PUT') {
      const t = body && typeof body.token === 'string' ? body.token.trim() : '';
      if (!t) throw new ApiError(400, 'token is required');
      if (/bad|invalid/i.test(t)) throw new ApiError(400, 'the git host rejected the token (401 Bad credentials); the previous token is kept');
      st.token = { source: 'site', site_token_set: true, node_token_configured: node.idx === 0, status: null, verified: true, expires_at: iso(Date.now() + 90 * 86400000) };
      st.settingsCurrent = false;
      return st.token;
    }
    if (method === 'DELETE') {
      if (!st.token.site_token_set) throw new ApiError(409, 'the site has no token of its own');
      if (node.idx !== 0) throw new ApiError(409, 'this node has no token of its own, so the site would be left without one');
      st.token = { source: 'node', site_token_set: false, node_token_configured: true, status: null, verified: true, expires_at: null };
      return st.token;
    }
    throw new ApiError(405, 'method not allowed');
  }

  function envRoute(node, site, which, method, body) {
    gate(node, which === 'build-env' ? 'site-build-env' : 'site-runtime-env');
    need(site);
    const st = siteState(node, site);
    const map = which === 'build-env' ? st.buildEnv : st.runtimeEnv;
    if (method === 'GET') return { names: [...map.keys()].sort() };
    if (method !== 'PATCH') throw new ApiError(405, 'method not allowed');
    const set = (body && body.set) || {};
    const unset = (body && body.unset) || [];
    const nameOk = (n) => /^[A-Z_][A-Z0-9_]{0,63}$/.test(n) && !/^(PATH|HOME|NODE_OPTIONS|LD_PRELOAD|GIT_|NPM_CONFIG_|CITE_|XDG_)/.test(n);
    for (const [name, value] of Object.entries(set)) {
      if (!nameOk(name)) throw new ApiError(400, `build env: ${JSON.stringify(name)} is not allowed`);
      if (typeof value !== 'string' || value.length > 4096) throw new ApiError(400, `build env: the value of ${name} is not valid`);
    }
    for (const name of unset) {
      if (!nameOk(name)) throw new ApiError(400, `build env: ${JSON.stringify(name)} is not allowed`);
    }
    for (const [name, value] of Object.entries(set)) map.set(name, value);
    for (const name of unset) map.delete(name);
    st.settingsCurrent = false;
    return { names: [...map.keys()].sort() };
  }

  // Walks the phases the manager reports, then promotes or fails; a ref or a variable can force the failure
  function startDeploy(node, site, body) {
    gate(node, 'deploy-async');
    need(site);
    const st = siteState(node, site);
    if (st.operation) throw new ApiError(409, 'a deploy is already running for this site');
    const ref = (body && body.git_ref) || site.source.branch || 'main';
    const slot = site.active === 'blue' ? 'green' : 'blue';
    const id = `dep-${Math.random().toString(36).slice(2, 8)}`;
    const push = (phase, text, stream = 'stdout') => st.manager.push({ ts: iso(Date.now()), stream, phase, text });
    const step = (ms, fn) => st.timers.push(setTimeout(fn, ms));
    const begin = (phase, stepText) => {
      st.phase = phase;
      st.operation = { kind: 'deploy', slot, deploy_id: id, step: stepText, started_at: iso(Date.now()) };
    };
    st.error = null;
    begin('fetching', `fetching ${ref}`);
    push('fetching', `Fetching ${site.source.repo}@${ref}`);
    step(1500, () => { begin('building', 'install and build'); push('building', `${site.source.package_manager || 'npm'} ci`); });
    step(3000, () => { push('building', site.source.build_command || 'npm run build'); begin('packing', 'packing the output'); });
    step(4500, () => begin('promoting', `switching to ${slot}`));
    step(6000, () => {
      const forced = /bad|down/i.test(ref) || st.buildEnv.has('FAIL_BUILD');
      st.operation = null;
      if (forced) {
        const reason = st.buildEnv.has('FAIL_BUILD') ? 'The build command exited with status 1: FAIL_BUILD is set' : `Build failed: ref ${ref} does not build`;
        st.phase = 'failed';
        st.error = reason;
        st.lastFailure = { at: iso(Date.now()), slot, note: reason };
        push('building', reason, 'stderr');
        const entry = { id, at: iso(Date.now()), slot, action: 'failed', note: `${body.note || `Deploy ${ref}`}: ${reason}` };
        site.history.push(entry);
        return;
      }
      st.phase = 'idle';
      st.settingsCurrent = true;
      if (node.pendingBuild) node.pendingBuild.delete(site.id);
      site.active = slot;
      push('promoting', `Promoted release to the ${slot} slot`);
      site.history.push({ id, at: iso(Date.now()), slot, action: 'promote', note: body.note || `Deploy ${ref} ${SHA.slice(0, 7)}` });
    });
    return { deployment_id: id };
  }

  register(({ node, method, seg, q, body }) => {
    if (seg[0] !== 'sites' || !seg[1] || !seg[2]) return undefined;
    const [, id, action] = seg;
    const site = node.sites.find((s) => s.id === id);
    if (!site) return undefined;
    if (action === 'status') {
      gate(node, 'site-status');
      need(site);
      if (method !== 'GET') throw new ApiError(405, 'method not allowed');
      return statusOf(node, site);
    }
    if (action === 'logs') {
      need(site);
      return logsOf(node, site, q);
    }
    if (action === 'github-token') return tokenRoute(node, site, method, body);
    if (action === 'build-env' || action === 'runtime-env') return envRoute(node, site, action, method, body);
    if (action === 'deploy' && method === 'POST' && body && body.wait === false) return startDeploy(node, site, body);
    return undefined;
  });
}
