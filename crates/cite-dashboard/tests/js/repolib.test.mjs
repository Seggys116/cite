import test from 'node:test';
import assert from 'node:assert/strict';
import {
  branchSuggestion, forgeHint, parseRepo, repoSummary,
} from '../../web/js/repolib.js';

const repoOf = (text) => parseRepo(text).repo;

test('owner/name stays as it is', () => {
  const p = parseRepo('acme/storefront');
  assert.deepEqual([p.ok, p.repo, p.host, p.branch, p.nonGithub], [true, 'acme/storefront', null, null, false]);
  assert.equal(repoOf('  acme/storefront  '), 'acme/storefront');
  assert.equal(repoOf('Acme_Inc/site.v2-beta'), 'Acme_Inc/site.v2-beta');
});

test('browser and clone addresses reduce to owner/name', () => {
  for (const text of [
    'https://github.com/acme/storefront',
    'https://github.com/acme/storefront/',
    'https://github.com/acme/storefront.git',
    'http://github.com/acme/storefront',
    'https://www.github.com/acme/storefront',
    'https://GitHub.com/acme/storefront',
    'git@github.com:acme/storefront.git',
    'git@github.com:acme/storefront',
    'ssh://git@github.com/acme/storefront.git',
    'git://github.com/acme/storefront.git',
    'github.com/acme/storefront',
    'www.github.com/acme/storefront',
    'acme/storefront.git',
    'https://github.com/acme/storefront?tab=readme#install',
    'https://github.com/acme/storefront/issues/4',
    'https://github.com/acme/storefront/tree/main',
  ]) {
    const p = parseRepo(text);
    assert.equal(p.repo, 'acme/storefront', text);
    assert.equal(p.ok, true, text);
    assert.equal(p.nonGithub, false, text);
  }
});

test('a tree address carries its branch', () => {
  assert.equal(parseRepo('https://github.com/acme/storefront/tree/release').branch, 'release');
  assert.equal(parseRepo('https://github.com/acme/storefront/tree/feature/new-nav').branch, 'feature/new-nav');
  assert.equal(parseRepo('https://github.com/acme/storefront/tree/feat%2Fx').branch, 'feat/x');
  assert.equal(parseRepo('https://github.com/acme/storefront/tree').branch, null);
  assert.equal(parseRepo('https://github.com/acme/storefront').branch, null);
  assert.equal(branchSuggestion(parseRepo('https://github.com/a/b/tree/dev'), 'main'), 'dev');
  assert.equal(branchSuggestion(parseRepo('https://github.com/a/b/tree/main'), 'main'), null);
  assert.equal(branchSuggestion(parseRepo('a/b'), 'main'), null);
});

test('other hosts are kept but flagged', () => {
  const p = parseRepo('https://gitlab.example.com/team/app.git');
  assert.deepEqual([p.ok, p.repo, p.host, p.nonGithub], [true, 'team/app', 'gitlab.example.com', true]);
  assert.equal(parseRepo('git@git.example.org:team/app.git').nonGithub, true);
  assert.equal(parseRepo('https://gitea.example.org:3000/team/app').host, 'gitea.example.org');
});

test('addresses with credentials are refused and never repeated', () => {
  const secret = ['ghp', '_', 'abc123'].join('');
  for (const text of [`https://${secret}@github.com/acme/storefront`, `https://user:${secret}@github.com/acme/storefront`, `ssh://user:${secret}@github.com/acme/storefront`]) {
    const p = parseRepo(text);
    assert.equal(p.ok, false, text);
    assert.ok(!p.error.includes(secret), 'error repeats the credential');
    assert.match(p.error, /user name and password/);
  }
  assert.equal(parseRepo('ssh://git@github.com/acme/storefront').ok, true);
});

test('things that are not repositories are explained', () => {
  assert.equal(parseRepo('').empty, true);
  assert.equal(parseRepo('   ').empty, true);
  for (const text of ['storefront', 'acme/', '/storefront', 'acme/a b', 'acme/..', '../storefront', 'https://github.com/acme', 'https://github.com', 'ftp://github.com/acme/storefront', 'file:///etc/passwd', 'acme/store$front', 'a/b/c']) {
    const p = parseRepo(text);
    assert.equal(p.ok, false, text);
    assert.ok(p.error, text);
  }
  assert.equal(parseRepo('acme/' + 'x'.repeat(101)).ok, false);
  assert.equal(parseRepo('acme/' + 'x'.repeat(100)).ok, true);
});

test('the hint depends on what the node reports', () => {
  const gitlab = parseRepo('https://gitlab.example.com/team/app');
  assert.equal(forgeHint(parseRepo('acme/storefront'), {}), '');
  assert.equal(forgeHint(parseRepo('https://github.com/acme/storefront'), {}), '');
  const withForge = forgeHint(gitlab, { capabilities: ['forges'], github: { api_host: 'gitlab.example.com' } });
  assert.match(withForge, /configured forge API \(gitlab\.example\.com\)/);
  assert.match(forgeHint(gitlab, { capabilities: ['forges'] }), /^The node fetches from its configured forge API, not from gitlab\.example\.com/);
  assert.match(forgeHint(gitlab, { capabilities: [] }), /only fetches from GitHub/);
  assert.match(forgeHint(gitlab, null), /only fetches from GitHub/);
  assert.equal(forgeHint(parseRepo('nope'), {}), '');
});

test('the summary says what will be stored', () => {
  assert.equal(repoSummary(parseRepo('https://github.com/acme/storefront.git')), 'Using acme/storefront');
  assert.equal(repoSummary(parseRepo('')), '');
  assert.equal(repoSummary(parseRepo('nope')), '');
});
