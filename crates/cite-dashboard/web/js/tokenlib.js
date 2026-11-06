export const MAX_TOKEN = 512;

export function tokenInputProblem(text) {
  const t = String(text ?? '').trim();
  if (!t) return 'Enter the token.';
  if (t.length > MAX_TOKEN) return `A token is at most ${MAX_TOKEN} characters.`;
  if (![...t].every((ch) => ch.charCodeAt(0) > 0x20 && ch.charCodeAt(0) < 0x7f)) return 'A token has no spaces or special characters.';
  return null;
}

// Where the token in use comes from, in words; the token itself is never reported
export function tokenSourceText(status) {
  const s = status || {};
  if (s.source === 'site' || (!s.source && s.site_token_set)) return 'This site uses its own token.';
  if (s.source === 'node' || (!s.source && s.node_token_configured)) return 'This site uses the node token (CITE_GITHUB_TOKEN).';
  return 'No token is set. Private repositories cannot be fetched, and public ones may be rate limited.';
}

export function tokenHealth(status) {
  const s = status || {};
  if (s.verified === false || /invalid|revoked|expired|bad|reject/i.test(String(s.status || ''))) {
    return { kind: 'bad', text: s.status ? `The git host rejected the token: ${s.status}` : 'The git host rejected the token.' };
  }
  if (s.verified === true) return { kind: 'ok', text: s.expires_at ? `Verified with the git host. Expires ${s.expires_at}.` : 'Verified with the git host.' };
  if (s.status) return { kind: 'muted', text: s.status };
  return { kind: 'muted', text: '' };
}

export function canUseNodeToken(status) {
  return Boolean(status) && status.site_token_set === true;
}

export function nodeTokenNote(status) {
  if (!status) return '';
  return status.node_token_configured ? '' : 'This node has no token of its own, so removing the site token would leave the site without one.';
}
