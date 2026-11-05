const ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;
const REPO_PART_RE = /^[A-Za-z0-9._-]+$/;
const BRANCH_RE = /^[A-Za-z0-9._/-]+$/;
const POLL_RE = /^[0-9]+(s|m|h)$/;
const REF_RE = /^[A-Za-z0-9._/-]{1,100}$/;

export const RUNTIMES = ['node', 'bun', 'static', 'rust'];
export const NODE_MAJORS = [22, 24];

// Mirrors cite_core's owner/name rule: two non-empty tokens of letters, digits, dot, underscore and dash, none starting with a dot.
export function repoProblem(repo) {
  const parts = String(repo || '').trim().split('/');
  const ok = parts.length === 2 && parts.every((p) => p && !p.startsWith('.') && REPO_PART_RE.test(p));
  return ok ? null : 'The repository must look like owner/name.';
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
  return POLL_RE.test(String(poll || '').trim()) ? null : 'The poll interval must be a number with s, m or h, such as 5m.';
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
