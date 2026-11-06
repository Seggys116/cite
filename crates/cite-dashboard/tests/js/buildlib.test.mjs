import test from 'node:test';
import assert from 'node:assert/strict';
import {
  autoHint, changedLabels, commandProblem, firstSourceProblem, formToSource, needsRebuild, pollProblem, pollSeconds, relativePathProblem,
  sourceDiff, sourceProblems, sourceToForm, startCommandProblem,
} from '../../web/js/buildlib.js';

const base = () => sourceToForm({ repo: 'acme/shop', branch: 'main', runtime: 'node', node_major: 22, poll_interval: '5m' });

test('a stored source opens as a form and goes back unchanged', () => {
  const source = {
    repo: 'acme/shop', branch: 'release', runtime: 'bun', node_major: 24, poll_interval: '1h', secret: 'ref-1',
    root_dir: 'web', package_manager: 'pnpm', install_command: 'pnpm i --frozen-lockfile', build_command: 'pnpm build', output_dir: 'dist',
    rendering: 'static', framework: 'vite', spa_fallback: 'index.html', prune: false,
  };
  assert.deepEqual(formToSource(sourceToForm(source), source), source);
});

test('a per-site forge is never part of the form and never sent', () => {
  const stored = { repo: 'acme/shop', branch: 'main', runtime: 'node', node_major: 22, poll_interval: '5m', forge: 'gitea' };
  assert.equal('forge' in sourceToForm(stored), false);
  assert.equal('forge' in formToSource({ ...sourceToForm(stored), forge: 'gitea' }, stored), false);
  assert.equal(sourceProblems({ ...base(), forge: 'x'.repeat(33) }).forge, undefined);
  assert.deepEqual(sourceDiff(stored, { ...stored, forge: 'gitlab' }), []);
});

test('a minimal source gets the defaults the node would use', () => {
  const form = sourceToForm({ repo: 'acme/shop' });
  assert.deepEqual([form.branch, form.runtime, form.node_major, form.poll_interval], ['main', 'node', '22', '5m']);
  assert.deepEqual(formToSource(form), { repo: 'acme/shop', branch: 'main', runtime: 'node', node_major: 22, poll_interval: '5m' });
  const rust = sourceToForm({ repo: 'a/b', runtime: 'rust' });
  assert.equal(rust.node_major, '');
  assert.equal(formToSource(rust).node_major, null);
});

test('empty fields mean auto and are left out', () => {
  const form = { ...base(), build_command: '  ', output_dir: '', package_manager: '', rendering: '', prune: '' };
  const out = formToSource(form);
  for (const key of ['build_command', 'output_dir', 'package_manager', 'rendering', 'prune', 'root_dir', 'framework']) {
    assert.equal(key in out, false, key);
  }
  assert.equal(formToSource({ ...form, prune: 'true' }).prune, true);
  assert.equal(formToSource({ ...form, prune: 'false' }).prune, false);
});

test('a pasted address is stored as owner/name', () => {
  assert.equal(formToSource({ ...base(), repo: 'https://github.com/acme/shop.git' }).repo, 'acme/shop');
});

test('a good form has no problems', () => {
  assert.deepEqual(sourceProblems(base()), {});
  assert.equal(firstSourceProblem(base()), null);
});

test('each field is checked with the node rules', () => {
  const bad = (over) => sourceProblems({ ...base(), ...over });
  assert.ok(bad({ repo: 'nope' }).repo);
  assert.ok(bad({ repo: '' }).repo);
  for (const branch of ['', '-x', 'a..b', 'a b', 'a:b', 'a/', 'x.lock', 'a@{b', 'a//b', 'a~1']) assert.ok(bad({ branch }).branch, branch);
  assert.deepEqual(bad({ branch: 'feature/new-nav' }), {});
  assert.ok(bad({ runtime: 'python' }).runtime);
  assert.ok(bad({ node_major: '20' }).node_major);
  assert.deepEqual(bad({ runtime: 'rust', node_major: '' }), {});
  assert.ok(bad({ poll_interval: '30s' }).poll_interval);
  assert.ok(bad({ package_manager: 'pip' }).package_manager);
  assert.ok(bad({ rendering: 'edge' }).rendering);
  assert.ok(bad({ framework: 'Next JS' }).framework);
  assert.deepEqual(bad({ framework: 'next-js' }), {});
});

test('paths are relative and stay inside the repository', () => {
  for (const ok of ['dist', 'apps/web', 'build/out', '.output', 'a_b-c.d']) assert.equal(relativePathProblem(ok), null, ok);
  for (const bad of ['/etc', '../x', 'a/../b', '-x', 'a b', 'a$b', '', 'x'.repeat(256)]) assert.ok(relativePathProblem(bad), bad);
  assert.ok(sourceProblems({ ...base(), root_dir: '../up' }).root_dir);
  assert.ok(sourceProblems({ ...base(), spa_fallback: '/index.html' }).spa_fallback);
  assert.ok(sourceProblems({ ...base(), output_dir: 'a b' }).output_dir);
});

test('install and build commands may use shell syntax but not several lines', () => {
  assert.equal(commandProblem('npm ci && npm run build'), null);
  assert.ok(commandProblem('npm ci\nrm -rf /'));
  assert.ok(commandProblem('npm ci\u0007'));
  assert.ok(commandProblem('x'.repeat(1025)));
  assert.equal(commandProblem('x'.repeat(1024)), null);
  assert.ok(sourceProblems({ ...base(), build_command: 'a\nb' }).build_command);
});

test('the start command is one program without a shell', () => {
  for (const ok of ['node server.js', 'node .output/server/index.mjs', './bin/server --port 3000', 'bun run start.ts', '"/opt/my app/run" --x', 'node -e \'console.log(1)\'']) {
    assert.equal(startCommandProblem(ok), null, ok);
  }
  for (const bad of ['npm start', 'npx next start', 'pnpm start', 'yarn start', 'cargo run', 'sh -c x', 'bash run.sh', 'env FOO=1 node x', 'FOO=1 node x', 'node a; node b', 'node a | cat', 'node a && b', 'node $HOME', 'node `id`', 'node "$X"', 'node "a', 'node a > out', 'node *.js', '/usr/bin/env node x', '']) {
    assert.ok(startCommandProblem(bad), bad);
  }
  assert.ok(sourceProblems({ ...base(), start_command: 'npm start' }).start_command);
});

test('a start command rules out static rendering', () => {
  const p = sourceProblems({ ...base(), start_command: 'node server.js', rendering: 'static' });
  assert.ok(p.rendering);
  assert.deepEqual(sourceProblems({ ...base(), start_command: 'node server.js', rendering: 'ssr' }), {});
  assert.deepEqual(sourceProblems({ ...base(), rendering: 'static' }), {});
});

test('the poll interval follows the node grammar', () => {
  for (const ok of ['60s', '1m', '5m', '2h', '1d', '366d', 'off', 'OFF', '0', '60000ms', '2min', '3hrs', '1day']) assert.equal(pollProblem(ok), null, ok);
  for (const bad of ['', '5', 'm', '5 m', '59s', '30s', '999ms', '367d', '5w', '-5m', '1.5h']) assert.ok(pollProblem(bad), bad);
  assert.equal(pollSeconds('1h'), 3600);
  assert.equal(pollSeconds('off'), 0);
  assert.equal(pollSeconds('x'), null);
});

test('what changed decides whether a rebuild is offered', () => {
  const prev = { repo: 'acme/shop', branch: 'main', runtime: 'node', node_major: 22, poll_interval: '5m' };
  const next = (over) => formToSource({ ...sourceToForm(prev), ...over }, prev);
  assert.deepEqual(sourceDiff(prev, next({})), []);
  assert.deepEqual(sourceDiff({ repo: 'acme/shop' }, prev), []);
  const poll = sourceDiff(prev, next({ poll_interval: '10m' }));
  assert.deepEqual(poll, ['poll_interval']);
  assert.equal(needsRebuild(poll), false);
  const build = sourceDiff(prev, next({ build_command: 'make', output_dir: 'out' }));
  assert.deepEqual(build.sort(), ['build_command', 'output_dir']);
  assert.equal(needsRebuild(build), true);
  assert.equal(needsRebuild(sourceDiff(prev, next({ branch: 'dev' }))), true);
  assert.equal(needsRebuild(['poll_interval', 'repo']), true);
  assert.equal(needsRebuild([]), false);
  assert.deepEqual(changedLabels(['output_dir', 'poll_interval']), ['Output directory', 'Check for new commits every']);
  assert.deepEqual(sourceDiff(prev, next({ build_command: '' })), []);
});

test('detected values are shown as hints on unset fields', () => {
  const detected = { package_manager: 'pnpm', output_dir: 'dist', node_major: 22, nested: { a: 1 } };
  assert.equal(autoHint('package_manager', detected), 'Auto (detected: pnpm)');
  assert.equal(autoHint('node_major', detected), 'Auto (detected: 22)');
  assert.equal(autoHint('nested', detected), 'Auto (detected: {"a":1})');
  assert.equal(autoHint('build_command', detected), 'Auto');
  assert.equal(autoHint('build_command', null), 'Auto');
  assert.equal(autoHint('output_dir', { output_dir: '' }), 'Auto');
});
