const ID_RE = /^[a-z0-9][a-z0-9-]{0,62}$/;

// Returns the first problem with the new-site form as a message, or null when the form can be submitted.
export function siteProblem(v) {
  if (!v.name.trim()) return 'Give the site a name.';
  if (!ID_RE.test(v.id)) return 'The site id must be lowercase letters, digits and dashes.';
  if (!v.hostCount) return 'Add at least one host name.';
  if (v.pathError) return 'The path regex is not valid.';
  if (v.targetProblem) return v.targetProblem;
  if (!v.blueCount) return 'Add at least one blue target.';
  if (!v.healthPath.startsWith('/')) return 'The health check path must start with /.';
  if (v.pickNodes && !v.nodePicked) return 'Pick at least one node.';
  return null;
}
