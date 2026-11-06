import { pollProblem as nodePollProblem } from './buildlib.js';
import { parseRepo } from './repolib.js';

const ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;
const BRANCH_RE = /^[A-Za-z0-9._/-]+$/;
const REF_RE = /^[A-Za-z0-9._/-]{1,100}$/;

export const RUNTIMES = ['node', 'bun', 'static', 'rust'];
export const NODE_MAJORS = [22, 24];

// A pasted address is accepted too (see repolib); a leading dot in a part is refused as before
export function repoProblem(repo) {
  const parsed = parseRepo(repo);
  const dotted = parsed.ok && parsed.repo.split('/').some((p) => p.startsWith('.'));
  return parsed.ok && !dotted ? null : 'The repository must look like owner/name.';
}

export function branchProblem(branch) {
  const b = String(branch || '').trim();
  const ok = b && b.length <= 256 && BRANCH_RE.test(b) && !b.startsWith('/') && !b.endsWith('/') && !b.includes('..');
  return ok ? null : 'The branch contains characters git refs do not allow here.';
}

export function runtimeProblem(runtime) {
  return RUNTIMES.includes(runtime) ? null : 'Pick node, bun, static or rust.';
}

export function pollProblem(poll) {
  return nodePollProblem(poll);
}

export function gitRefProblem(ref) {
  const r = String(ref || '').trim();
  if (!r) return 'Enter a branch, tag or commit to deploy.';
  const ok = REF_RE.test(r) && !r.startsWith('-') && !r.includes('..');
  return ok ? null : 'The ref may use letters, digits, dot, underscore, dash and slash, up to 100 characters, and cannot start with a dash or contain "..".';
}

export function cleanToken(token) {
  const t = String(token || '').trim();
  return t || undefined;
}

export const TOKEN_HELP_HAVE = 'This node already has a GitHub token (CITE_GITHUB_TOKEN). Leave this empty to use it.';
export const TOKEN_HELP_HAVE_MANY = 'Every selected node already has a GitHub token (CITE_GITHUB_TOKEN). Leave this empty to use it.';
export const TOKEN_HELP_NONE = 'Fine-grained token with Contents: read for this repository. Better: set CITE_GITHUB_TOKEN on the node once (see docs). Stored only on the node.';
export const TOKEN_TOGGLE = 'Use a different token for this site';

// A node reports whether it holds a token of its own; an older connector says nothing, which counts as unknown
export function tokenState(info) {
  if (!info || !info.github) return 'unknown';
  return info.github.token_configured ? 'yes' : 'no';
}

// What the token field should do for the nodes picked: hidden when all have one, required when any has none
export function tokenPlan(states) {
  const list = Array.isArray(states) ? states : [];
  const missing = list.filter((s) => s === 'no').length;
  if (missing > 0) return { show: true, required: true, help: TOKEN_HELP_NONE };
  if (list.length > 0 && list.every((s) => s === 'yes')) return { show: false, required: false, help: list.length === 1 ? TOKEN_HELP_HAVE : TOKEN_HELP_HAVE_MANY };
  return { show: true, required: false, help: TOKEN_HELP_NONE };
}

export function tokenProblem(plan, token) {
  if (plan.required && !cleanToken(token)) return 'Enter a GitHub token: a selected node has none configured.';
  return null;
}

// Returns the first problem with the source fields, or null.
export function sourceProblem(src) {
  return repoProblem(src.repo) || branchProblem(src.branch) || runtimeProblem(src.runtime) || pollProblem(src.poll);
}

// Returns the first problem with the new-site form as a message, or null when the form can be submitted.
export function siteProblem(v) {
  const fromGithub = v.mode === 'github';
  if (!v.name.trim()) return 'Give the site a name.';
  if (!ID_RE.test(v.id)) return 'The site id must be lowercase letters, digits and dashes.';
  if (!v.hostCount) return 'Add at least one host name.';
  if (v.pathError) return 'The path regex is not valid.';
  if (fromGithub) {
    const problem = sourceProblem(v.source || {});
    if (problem) return problem;
  } else {
    if (v.targetProblem) return v.targetProblem;
    if (!v.blueCount) return 'Add at least one blue target.';
  }
  if (!v.healthPath.startsWith('/')) return 'The health check path must start with /.';
  if (v.pickNodes && !v.nodePicked) return 'Pick at least one node.';
  return null;
}
