// The create-site wizard's model: one decision per step, and the site body built from the answers
import { cleanToken, tokenProblem } from './siteCheck.js';
import { firstSourceProblem, formToSource, sourceToForm } from './buildlib.js';
import { parseRepo } from './repolib.js';
import { accessForSave, accessOf } from './accesslib.js';
import { pathFieldsFromRows, pathsProblem } from './conditionlib.js';

export const STEPS = [
  { id: 'source', title: 'Where does the site come from?' },
  { id: 'details', title: 'Details' },
  { id: 'domains', title: 'Name and domains' },
  { id: 'protection', title: 'Protection' },
  { id: 'where', title: 'Where should it run?' },
];

export const SOURCES = [
  { value: 'github', title: 'Build from a GitHub repository', text: 'The node fetches the code, builds it and keeps it up to date.' },
  { value: 'servers', title: 'Serve servers I already run', text: 'Send traffic to servers you operate, with weights and a health check.' },
];

const ID_RE = /^[a-z0-9][a-z0-9-]{0,39}$/;

export function emptySiteForm() {
  return {
    source: '',
    kind: 'site',
    name: '',
    id: '',
    hosts: [],
    paths: [],
    src: sourceToForm({ repo: '' }),
    blue: [],
    green: [],
    targetProblem: null,
    healthPath: '/',
    access: accessOf(null),
    nodes: [],
    replicate: false,
  };
}

// ctx carries what only the page knows: the token plan for the selected nodes and whether a token was typed
export function stepProblem(form, step, ctx = {}) {
  switch (step) {
    case 0:
      return form.source ? null : 'Choose where the site comes from.';
    case 1:
      if (form.source === 'github') {
        const bad = firstSourceProblem(form.src);
        return (bad && bad.message) || (ctx.tokenPlan ? tokenProblem(ctx.tokenPlan, ctx.token) : null);
      }
      if (form.targetProblem) return form.targetProblem;
      if (!form.blue.length) return 'Add at least one server for the live slot.';
      if (!String(form.healthPath).startsWith('/')) return 'The health check path must start with /.';
      return null;
    case 2:
      if (!form.name.trim()) return 'Give the site a name.';
      if (!ID_RE.test(form.id)) return 'The site id must be lowercase letters, digits and dashes.';
      if (!form.hosts.length) return 'Add at least one domain.';
      return pathsProblem(form.paths);
    case 3:
      return null;
    default:
      if (!form.replicate && !form.nodes.length) return 'Pick at least one node.';
      return ctx.tokenPlan && form.source === 'github' ? tokenProblem(ctx.tokenPlan, ctx.token) : null;
  }
}

// The first step with a problem, so Create can send the user back to it
export function firstProblem(form, ctx) {
  for (let step = 0; step < STEPS.length; step += 1) {
    const message = stepProblem(form, step, ctx);
    if (message) return { step, message };
  }
  return null;
}

// A site built from GitHub has empty slots: the node provisions the live one itself
export function buildSite(form) {
  const github = form.source === 'github';
  const site = {
    id: form.id,
    name: form.name.trim(),
    hosts: [...form.hosts],
    ...pathFieldsFromRows(form.paths),
    kind: form.kind,
    blue: { targets: github ? [] : form.blue.map((t) => ({ addr: t.addr, weight: t.weight })), label: null },
    green: { targets: github ? [] : form.green.map((t) => ({ addr: t.addr, weight: t.weight })), label: null },
    active: 'blue',
    maintenance: { enabled: false, page_id: null },
    health: { path: github ? '/' : form.healthPath, interval_ms: 2000, rise: 2, fall: 3, timeout_ms: 1500 },
    source: github ? formToSource(form.src) : null,
  };
  const access = accessForSave(form.access, null);
  if (access) site.access = access;
  return site;
}

export function githubToken(token) {
  return cleanToken(token);
}

// What the last step shows before Create; the token is only ever described, never shown
export function reviewLines(form, { tokenText = '' } = {}) {
  const github = form.source === 'github';
  const lines = [
    ['Source', github ? `GitHub repository ${parseRepo(form.src.repo).repo || form.src.repo.trim()} (${form.src.branch.trim()}, ${form.src.runtime})` :`${form.blue.length} server${form.blue.length === 1 ? '' : 's'} you run`],
    ['Name', `${form.name.trim()} (${form.id})`],
    ['Domains', form.hosts.join(', ')],
  ];
  if (form.paths.some((p) => p.value.trim())) lines.push(['Only for paths', form.paths.filter((p) => p.value.trim()).map((p) => p.value.trim()).join(', ')]);
  const a = form.access;
  const protection = [];
  protection.push(a.cloudflare_only ? 'only through the Cloudflare proxy' : 'open to any visitor');
  if (a.tls === 'flexible') protection.push('Cloudflare handles HTTPS');
  if (a.zone_lock) protection.push('my Cloudflare account only');
  if (a.bots !== 'allow') protection.push(a.bots === 'block_all' ? 'all bots blocked' : 'scraper and tool bots blocked');
  lines.push(['Protection', protection.join(', ')]);
  if (github && tokenText) lines.push(['GitHub token', tokenText]);
  lines.push(['Nodes', form.replicate ? 'every online node' : form.nodes.join(', ')]);
  return lines;
}
