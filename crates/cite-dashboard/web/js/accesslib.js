export const TLS_MODES = ['full', 'flexible'];

export const CLOUDFLARE_ONLY_LABEL = 'Only allow traffic through the Cloudflare proxy';
export const CLOUDFLARE_ONLY_HELP = 'When on, requests that do not arrive from Cloudflare\'s network are refused. Turn it on only for sites that are proxied by Cloudflare (orange cloud).';
export const TLS_FULL_LABEL = 'Full (the node serves its own certificate)';
export const TLS_FLEXIBLE_LABEL = 'Flexible SSL (Cloudflare serves HTTPS to visitors and talks to your server over plain http)';
export const FULL_HELP = 'Visitors, or Cloudflare, connect over HTTPS and the node answers with its own certificate. Create or upload one under Settings, Certificates.';
export const FLEXIBLE_HELP = 'Cloudflare serves HTTPS to visitors and talks to your server over plain http, so no certificate is needed on the node. Traffic between Cloudflare and your server is not encrypted.';
export const FLEXIBLE_WARNING = 'Without Only allow traffic through the Cloudflare proxy, anyone can reach your server directly over plain http with no encryption. Flexible SSL still works, but turn that option on if the site is proxied by Cloudflare.';
export const ZONE_LOCK_LABEL = 'Also require that requests come from MY Cloudflare account (advanced)';
export const ZONE_LOCK_TOGGLE = 'Show the advanced account check';

export const ZONE_HEADER = 'X-Cite-Origin-Secret';
export const BOT_POLICIES = [
  { value: 'allow', label: 'Allow all bots' },
  { value: 'block_bad', label: 'Block scraper and tool bots' },
  { value: 'block_all', label: 'Block all bots including search engines' },
];
export const BOT_SPOOF_NOTE = 'Bots are recognised by their user agent, which any client can fake, so this stops honest tools and lazy scripts and not a determined scraper. Blocked requests still appear in analytics.';
export const SEO_WARNING = 'This also blocks search engine crawlers, link preview bots and uptime monitors, so the site can drop out of search results and shares lose their preview cards. Do not use it on a site that depends on search traffic.';
export const ZONE_LOCK_HELP = 'Without this, anyone using Cloudflare could send traffic to your server address. This adds a secret header that you set once in a Cloudflare Transform Rule. Optional.';
export const ZONE_LOCK_NEEDS_CLOUDFLARE = 'Turn on Only allow traffic through the Cloudflare proxy first.';

// The advanced account check stays folded away unless the site already uses it, so the plain option never mentions rules or secrets
export function zoneLockOpenByDefault(access) {
  return Boolean(access && access.zone_lock);
}
export const ZONE_STEPS = [
  'Open your domain in the Cloudflare dashboard and go to Rules, then Transform Rules.',
  'Choose Modify Request Header and create a rule that matches this site\'s hostname.',
  `Under Modify request header, choose Set static, enter ${ZONE_HEADER} as the header name and paste the secret as the value.`,
  'Deploy the rule. Until it is live, requests through Cloudflare are refused with a 403.',
];

// A missing or partial access object means open access with the node's own TLS and no bot blocking
export function accessOf(site) {
  const raw = (site && site.access) || {};
  const cloudflareOnly = raw.cloudflare_only === true;
  return {
    cloudflare_only: cloudflareOnly,
    tls: raw.tls === 'flexible' ? 'flexible' : 'full',
    bots: BOT_POLICIES.some((p) => p.value === raw.bots) ? raw.bots : 'allow',
    zone_lock: cloudflareOnly && raw.zone_lock === true,
  };
}

export function isDefaultAccess(access) {
  return !access.cloudflare_only && access.tls === 'full' && (access.bots || 'allow') === 'allow' && !access.zone_lock;
}

// Defaults are left out of the request unless the site already carries access, so older connectors never see an unknown field
export function accessForSave(access, previous) {
  const normal = accessOf({ access });
  const next = { cloudflare_only: normal.cloudflare_only, tls: normal.tls };
  if (normal.bots !== 'allow') next.bots = normal.bots;
  if (normal.zone_lock) next.zone_lock = true;
  if (isDefaultAccess(normal) && !previous) return undefined;
  return next;
}

// The secret is made when the lock goes on, so it is only worth showing when the lock was off before
export function zoneLockTurnedOn(previous, next) {
  return Boolean(next && next.zone_lock) && !(previous && previous.zone_lock);
}

export const ZONE_UNREADABLE_NOTE = 'The secret store could not be read on this node; the lock state is unknown. Fix the file or rotate after restoring it.';

// One line about the stored secret; formatDate turns the node's timestamp into text
export function zoneStatusLine(status, formatDate) {
  if (status && status.readable === false) return ZONE_UNREADABLE_NOTE;
  if (!status || !status.configured) return 'No secret has been created yet. Rotate the secret to make one.';
  const when = status.created_at ? ` on ${formatDate(status.created_at)}` : '';
  const print = status.fingerprint ? `, fingerprint ${status.fingerprint}` : '';
  return `A secret was created${when}${print}. It cannot be shown again; rotate it to get a new one.`;
}

// What a create with several nodes means for the zone secret: nodes that took the site now hold a lock whose secret nobody has seen,
// so they are rotated and shown even when others failed, and the error says where the secrets went
export function createVerdict({ results, nodes, zoneLock }) {
  const list = Array.isArray(results) ? results : [];
  const failed = list.filter((r) => r && (r.error || r.ok === false)).map((r) => ({ node: r.node || 'node', error: r.error || 'failed' }));
  const created = list.filter((r) => r && r.ok !== false && !r.error).map((r) => r.node).filter(Boolean);
  let rotate = [];
  if (zoneLock) rotate = created.length || failed.length ? created : [...nodes];
  let error = null;
  if (failed.length) {
    error = failed.map((f) => `${f.node}: ${f.error}`).join('; ');
    if (rotate.length) error += `. The zone secret for ${rotate.join(', ')} is shown in the dialog.`;
  }
  return { failed, created, rotate, error, ok: failed.length === 0 };
}

// Lines for nodes where the rotate call itself failed; those sites hold a lock with no secret shown yet
export function rotationFailureLines(failures, describe) {
  return failures.map((f) => `${f.node}: ${describe(f.error)}. Rotate the secret from that site's page.`);
}

export const SECRET_CLOSE_WARNING = 'You have not copied the secret. It cannot be shown again, so you would have to rotate it to get a new one. Close anyway?';

// The secret dialog only closes on a button, and asks first when nothing was copied
export function secretCloseNeedsConfirm(copied) {
  return !copied;
}

export function botWarning(bots) {
  return bots === 'block_all' ? SEO_WARNING : '';
}

export const NO_BOT_BLOCKING = 'No bot blocking is active for this site';

// Allow never reads as protection: it says outright that nothing blocks bots
export function botStatusLine(bots) {
  if (bots === 'block_bad') return 'Scraper and tool bots are blocked for this site.';
  if (bots === 'block_all') return 'All bots are blocked for this site, including search engines.';
  return NO_BOT_BLOCKING;
}

// Firewall rules that look at the user agent and reach this site, global or scoped to it, so the owner sees what could block bots
export function userAgentRulesFor(rules, siteId) {
  return (Array.isArray(rules) ? rules : [])
    .filter((r) => r && (!r.site || r.site === siteId))
    .map((r) => {
      const m = r.matchers || {};
      const patterns = [...(m.user_agent_regexes || []), ...(m.user_agent_regex ? [m.user_agent_regex] : [])];
      return { id: r.id, name: r.name || r.id, enabled: r.enabled !== false, scope: r.site ? 'this site' : 'all sites', action: r.action || '', patterns };
    })
    .filter((r) => r.patterns.length > 0);
}

// The sentence above the list of rules; disabled rules are named as such so they are not counted as protection
export function userAgentRulesLine(list) {
  if (!list.length) return 'No firewall rule looks at user agents for this site.';
  const live = list.filter((r) => r.enabled).length;
  if (!live) return `${list.length} firewall ${list.length === 1 ? 'rule looks' : 'rules look'} at user agents for this site, but ${list.length === 1 ? 'it is' : 'all are'} switched off.`;
  return `${live} firewall ${live === 1 ? 'rule' : 'rules'} may block by user agent for this site:`;
}

export function flexibleWithoutCloudflare(access) {
  return access.tls === 'flexible' && !access.cloudflare_only;
}

export function tlsHelp(tls) {
  return tls === 'flexible' ? FLEXIBLE_HELP : FULL_HELP;
}

// The list the edge trusts, with where it came from and how current it is
export function rangesLine(info) {
  if (!info || !Array.isArray(info.ranges)) return '';
  const count = info.ranges.length;
  const source = info.source === 'custom' ? 'custom list' : 'built-in list';
  const updated = info.updated ? `, updated ${info.updated}` : '';
  return `Cloudflare ranges on this node: ${source}${updated}, ${count} ${count === 1 ? 'range' : 'ranges'}.`;
}
