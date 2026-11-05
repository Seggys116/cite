const BASE = '/api/v1';

export const apiEvents = new EventTarget();

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

const mockParam = new URLSearchParams(location.search).get('mock');
export const isMock = Boolean(mockParam) && mockParam !== '0';

let csrfToken = '';

function rememberCsrf(path, data) {
  if (path === '/session' && data && typeof data === 'object') csrfToken = typeof data.csrf === 'string' ? data.csrf : '';
}

async function send(method, path, body) {
  const init = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
  if (method !== 'GET' && csrfToken) init.headers['X-Cite-Csrf'] = csrfToken;
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(BASE + path, init);
  } catch (err) {
    throw new ApiError(0, 'Cannot reach the dashboard server');
  }
  const type = res.headers.get('content-type') || '';
  let data = null;
  if (type.includes('json')) data = await res.json().catch(() => null);
  else data = await res.text().catch(() => '');
  return { res, data };
}

function failure({ res, data }) {
  if (res.status === 401) apiEvents.dispatchEvent(new Event('unauthorized'));
  const message = (data && typeof data === 'object' && data.error) || res.statusText || 'Request failed';
  return new ApiError(res.status, message);
}

const isCsrfFailure = ({ res, data }) => res.status === 403 && data && typeof data === 'object' && /csrf/i.test(String(data.error || ''));

async function realRequest(method, path, body) {
  let out = await send(method, path, body);
  if (method !== 'GET' && isCsrfFailure(out)) {
    const fresh = await send('GET', '/session');
    if (fresh.res.ok) {
      rememberCsrf('/session', fresh.data);
      out = await send(method, path, body);
    }
  }
  if (!out.res.ok) throw failure(out);
  if (method === 'DELETE' && path === '/session') csrfToken = '';
  else rememberCsrf(path, out.data);
  return out.data;
}

let transport = realRequest;

// Swaps in the in-memory fake when the page is opened with ?mock=1
export async function initApi() {
  if (!isMock) return;
  const mod = await import('/mock.js');
  transport = mod.mockRequest;
}

export function qs(params) {
  const out = new URLSearchParams();
  for (const [key, val] of Object.entries(params || {})) {
    if (val !== undefined && val !== null && val !== '') out.set(key, String(val));
  }
  const text = out.toString();
  return text ? '?' + text : '';
}

export const api = {
  get: (path) => transport('GET', path),
  post: (path, body) => transport('POST', path, body),
  put: (path, body) => transport('PUT', path, body),
  del: (path) => transport('DELETE', path),
};

export function nodeApi(name) {
  const base = '/nodes/' + encodeURIComponent(name);
  return {
    get: (path) => api.get(base + path),
    post: (path, body) => api.post(base + path, body),
    put: (path, body) => api.put(base + path, body),
    del: (path) => api.del(base + path),
  };
}
