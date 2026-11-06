// A node lists the features it can serve; the console shows only controls for features the node lists
export const FEATURES = {
  status: 'site-status',
  logs: 'site-logs',
  build: 'source-build',
  token: 'site-github-token',
  buildEnv: 'site-build-env',
  runtimeEnv: 'site-runtime-env',
  deployAsync: 'deploy-async',
  certGenerate: 'cert-generate',
  certOriginCa: 'cert-origin-ca',
  certAcme: 'cert-acme',
  alerts: 'alerts',
  forges: 'forges',
};

export function capabilitiesOf(info) {
  const list = info && Array.isArray(info.capabilities) ? info.capabilities : [];
  return new Set(list.filter((c) => typeof c === 'string'));
}

export function hasFeature(info, feature) {
  const name = FEATURES[feature];
  return Boolean(name) && capabilitiesOf(info).has(name);
}

export function siteFeatures(info) {
  const out = {};
  for (const key of Object.keys(FEATURES)) out[key] = hasFeature(info, key);
  return out;
}

export function showsBuildSettings(info, site) {
  return Boolean(site && site.source) && hasFeature(info, 'build');
}

const TTL_MS = 60000;
const cache = new Map();

// One GET /node per node per minute, shared by every panel that asks while it is in flight
export function nodeInfoCached(node, load, now = Date.now()) {
  const hit = cache.get(node);
  if (hit && (hit.pending || now - hit.at < TTL_MS)) return hit.promise;
  const entry = { at: now, pending: true, promise: null };
  entry.promise = Promise.resolve()
    .then(load)
    .then((info) => {
      entry.pending = false;
      return info;
    }, (error) => {
      cache.delete(node);
      throw error;
    });
  cache.set(node, entry);
  return entry.promise;
}

export function forgetNodeInfo(node) {
  if (node === undefined) cache.clear();
  else cache.delete(node);
}
