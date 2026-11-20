// Pure helpers for the Firewall screens when rules, presets and sites are read from several nodes at once.
import { matcherSummary } from './conditionlib.js';
import { effectView, resaveBody } from './rulelib.js';

// Key order must not decide whether two rules are the same, so objects are written with sorted keys
function stable(value) {
  if (Array.isArray(value)) return `[${value.map(stable).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).filter((k) => value[k] !== undefined).sort().map((k) => `${JSON.stringify(k)}:${stable(value[k])}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

// Whether a rule is on or off is a per-node state, so it is left out when comparing what the rule does
export function ruleContentKey(rule) {
  const { enabled, ...rest } = rule || {};
  return stable(rest);
}

// perNode is [{ node, rules }]. One row per rule id when every node holds identical content; when the same id has
// different content on two nodes each variant gets its own row, flagged `differs`, and is never merged.
export function mergeRules(perNode) {
  const byId = new Map();
  for (const { node, rules } of perNode) {
    for (const rule of rules || []) {
      if (!byId.has(rule.id)) byId.set(rule.id, new Map());
      const variants = byId.get(rule.id);
      const content = ruleContentKey(rule);
      if (!variants.has(content)) variants.set(content, []);
      variants.get(content).push({ node, enabled: Boolean(rule.enabled), rule });
    }
  }
  const rows = [];
  for (const [id, variants] of byId) {
    const differs = variants.size > 1;
    let n = 0;
    for (const nodes of variants.values()) {
      rows.push({
        key: differs ? `${id}#${n}` : id,
        id,
        rule: nodes[0].rule,
        nodes,
        holders: nodes.map((x) => x.node),
        differs,
      });
      n += 1;
    }
  }
  return rows;
}

// The switch reads on only when every node holding the rule has it on
export function enabledEverywhere(row) {
  return row.nodes.length > 0 && row.nodes.every((x) => x.enabled);
}

// top_blocked keys identify the rule that fired, by id, label or name
export function hitsForRule(rule, summary) {
  const hits = new Map(((summary && summary.top_blocked) || []).map((b) => [b.key, b.count]));
  return hits.get(rule.id) || (rule.label && hits.get(rule.label)) || hits.get(rule.name) || 0;
}

// summaries maps node name to that node's analytics summary; only the nodes holding this row are counted
export function rowHits(row, summaries) {
  return row.nodes.reduce((sum, x) => sum + (Number(hitsForRule(x.rule, summaries[x.node])) || 0), 0);
}

// True when a rule held on several nodes is on at some and off at others. heldByNode is Map(node -> Map(rule id -> rule)).
export function enabledDiffers(id, heldByNode) {
  const states = new Set();
  for (const held of heldByNode.values()) {
    const rule = held.get(id);
    if (rule) states.add(Boolean(rule.enabled));
  }
  return states.size > 1;
}

// The bulk request for one node. The editor works on one merged copy of each rule, so a plain save would stamp that copy's
// on/off state on every node. Here a node keeps its own stored rule and its own `enabled` unless the person toggled that
// row's switch (`touched` holds those rule ids); a rule the node does not hold is created with the value in the edit.
// diff is { replace, delete } from diffRows; deletes are limited to ids this node holds so its whole step cannot fail.
export function bulkBodyFor(node, diff, touched, heldByNode) {
  const held = heldByNode.get(node) || new Map();
  const replace = diff.replace.map((body) => {
    const stored = held.get(body.id);
    if (!stored) return body;
    return { ...resaveBody(stored), ...body, enabled: touched.has(body.id) ? body.enabled : Boolean(stored.enabled) };
  });
  return { replace, delete: diff.delete.filter((id) => held.has(id)) };
}

// Sites from every node as one list, first name wins per id
export function mergeSites(perNode) {
  const seen = new Map();
  for (const { sites } of perNode) {
    for (const site of sites || []) if (!seen.has(site.id)) seen.set(site.id, site);
  }
  return [...seen.values()];
}

// Presets from every node as one list, first copy wins per preset name
export function mergePresets(perNode) {
  const seen = new Map();
  for (const { presets } of perNode) {
    for (const preset of presets || []) if (!seen.has(preset.name)) seen.set(preset.name, preset);
  }
  return [...seen.values()];
}

// Online node names that can take a rule for the given site id ('' or null means any site, so every online node)
export function writableNodes(nodes, sitesByNode, siteId) {
  return (nodes || [])
    .filter((n) => n.online !== false)
    .filter((n) => !siteId || (sitesByNode[n.name] || []).some((s) => s.id === siteId))
    .map((n) => n.name);
}

const ACTION_WORDS = { deny: 'Deny', drop: 'Drop', tarpit: 'Tarpit' };

// What a preset would add, one entry per rule, for the popover and the touch-friendly list
export function presetRulesModel(preset) {
  return (preset.rules || []).map((rule) => {
    const fx = effectView(rule);
    const label = fx.kind === 'redirect' ? 'Redirect' : fx.kind === 'headers' ? fx.label : (ACTION_WORDS[rule.action] || fx.label);
    return {
      name: rule.name,
      action: label,
      pill: fx.pill,
      patterns: matcherSummary(rule.matchers),
      target: rule.redirect ? rule.redirect.to : '',
    };
  });
}

// The first sentence of a preset description; the rules listed beside it carry the detail
export function presetBlurb(preset) {
  const text = String(preset.description || '').trim();
  const end = text.search(/[.!?](\s|$)/);
  return end < 0 ? text : text.slice(0, end + 1);
}

// "edge-nyc is unreachable and is left out." for the one-line note above the page; null when every node answered
export function unreachableNote(names) {
  if (!names.length) return null;
  if (names.length === 1) return `${names[0]} is unreachable and is left out.`;
  return `${names.join(', ')} are unreachable and are left out.`;
}
