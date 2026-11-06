const PART_RE = /^[A-Za-z0-9._-]{1,100}$/;
const SCP_RE = /^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):([^/@\s][^\s]*)$/;
const HOSTLESS_RE = /^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/;

export const GITHUB_HOSTS = ['github.com'];

const partOk = (p) => PART_RE.test(p) && p !== '.' && p !== '..';

function stripGit(name) {
  return name.length > 4 && name.toLowerCase().endsWith('.git') ? name.slice(0, -4) : name;
}

const fail = (error) => ({ ok: false, repo: '', host: null, branch: null, nonGithub: false, error });

function decode(segment) {
  try {
    return decodeURIComponent(segment);
  } catch (err) {
    return segment;
  }
}

function fromPath(path, host) {
  const parts = path.split(/[?#]/)[0].split('/').filter(Boolean);
  if (parts.length < 2) return fail('The repository must look like owner/name.');
  const owner = parts[0];
  const name = stripGit(parts[1]);
  if (!partOk(owner) || !partOk(name)) return fail('The repository must look like owner/name.');
  let branch = null;
  if (parts[2] === 'tree' && parts.length > 3) branch = parts.slice(3).map(decode).join('/');
  const bare = host ? host.toLowerCase().replace(/^www\./, '') : null;
  return {
    ok: true, repo: `${owner}/${name}`, host: bare, branch, nonGithub: Boolean(bare) && !GITHUB_HOSTS.includes(bare), error: null,
  };
}

// Credentials in a pasted URL are refused and never repeated back, since the message is shown on screen
export function parseRepo(input) {
  const text = String(input ?? '').trim();
  if (!text) return { ...fail(''), empty: true };
  if (/\s/.test(text)) return fail('The repository cannot contain spaces.');
  const scheme = text.match(/^([a-z][a-z0-9+.-]*):\/\/(.*)$/i);
  if (scheme) {
    const proto = scheme[1].toLowerCase();
    if (!['http', 'https', 'ssh', 'git'].includes(proto)) return fail('Use an https address, an ssh address or owner/name.');
    const rest = scheme[2];
    const slash = rest.indexOf('/');
    const authority = slash < 0 ? rest : rest.slice(0, slash);
    if (slash < 0) return fail('The repository must look like owner/name.');
    if (authority.includes('@')) {
      const user = authority.slice(0, authority.lastIndexOf('@'));
      if (proto !== 'ssh' || user.includes(':')) return fail('Remove the user name and password from the address; the token is set separately.');
    }
    const host = authority.slice(authority.lastIndexOf('@') + 1).replace(/:\d+$/, '');
    if (!host) return fail('The address has no host name.');
    return fromPath(rest.slice(slash + 1), host);
  }
  const scp = text.match(SCP_RE);
  if (scp && !HOSTLESS_RE.test(text) && scp[1].includes('.')) return fromPath(scp[2], scp[1]);
  if (HOSTLESS_RE.test(text)) return fromPath(text, null);
  const bare = text.match(/^([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\/(.+)$/);
  if (bare) return fromPath(bare[2], bare[1]);
  return fail('The repository must look like owner/name.');
}

// What to say when the address names a host other than GitHub; info is the node's GET /node answer
export function forgeHint(parsed, info) {
  if (!parsed || !parsed.ok || !parsed.nonGithub) return '';
  const caps = (info && info.capabilities) || [];
  const apiHost = info && info.github && info.github.api_host;
  if (caps.includes('forges')) {
    return apiHost
      ? `The node fetches from its configured forge API (${apiHost}), not from ${parsed.host}. Use this only if they are the same server.`
      : `The node fetches from its configured forge API, not from ${parsed.host}. Use this only if they are the same server.`;
  }
  return `This node only fetches from GitHub, so ${parsed.host} will not be reached. Only the owner/name part is kept.`;
}

// The branch of a /tree/<branch> address is offered as a suggestion, never applied silently
export function branchSuggestion(parsed, currentBranch) {
  if (!parsed || !parsed.ok || !parsed.branch) return null;
  return parsed.branch === currentBranch ? null : parsed.branch;
}

export function repoSummary(parsed) {
  if (!parsed || parsed.empty || !parsed.ok) return '';
  return `Using ${parsed.repo}`;
}
