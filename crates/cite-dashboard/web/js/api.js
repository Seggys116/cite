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

async function realRequest(method, path, body) {
  const init = { method, credentials: 'same-origin', headers: { Accept: 'application/json' } };
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
  if (!res.ok) {
    if (res.status === 401) apiEvents.dispatchEvent(new Event('unauthorized'));
    const message = (data && typeof data === 'object' && data.error) || res.statusText || 'Request failed';
    throw new ApiError(res.status, message);
  }
  return data;
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
