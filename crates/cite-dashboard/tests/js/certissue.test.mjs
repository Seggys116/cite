import test from 'node:test';
import assert from 'node:assert/strict';
import {
  JOB_GIVE_UP_MS, JOB_MAX_POLL_ERRORS, acmeBody, acmeProblem, daysProblem, emailProblem, generateBody, generateProblem, hostChoices, hostProblem,
  isJobDone, jobReduce, jobStart, jobStatusText, nameProblem, originCaBody, originCaProblem, parseHosts, shouldPoll, tokenProblem, MAX_HOSTS,
} from '../../web/js/certissue.js';

const TOKEN = 'abcdEFGH1234_-abcdEFGH1234_-abcdEFGH12';

test('host parsing lowercases, splits on separators and drops duplicates', () => {
  const out = parseHosts('WWW.Example.com, example.com\n*.example.com;www.example.com');
  assert.deepEqual(out.hosts, ['www.example.com', 'example.com', '*.example.com']);
  assert.deepEqual(out.errors, []);
});

test('host parsing reports bad names and empty input', () => {
  assert.match(parseHosts('').errors[0], /at least one/);
  assert.match(parseHosts('localhost').errors[0], /not a valid host name/);
  assert.match(parseHosts('10.0.0.1').errors[0], /not a valid host name|IP address/);
  assert.match(hostProblem('a_b.example.com'), /not a valid/);
  assert.match(hostProblem('-a.example.com'), /not a valid/);
  assert.equal(hostProblem('*.example.com'), '');
  assert.match(hostProblem('*.*.example.com'), /not a valid/);
});

test('host parsing caps the number of names', () => {
  const many = Array.from({ length: MAX_HOSTS + 1 }, (_, i) => `h${i}.example.com`);
  assert.match(parseHosts(many).errors[0], /at most/);
});

test('host choices list uncovered hosts first without duplicates', () => {
  const choices = hostChoices([{ hosts: ['a.example.com', 'B.example.com'] }, { hosts: ['b.example.com', 'c.example.com'] }], ['c.example.com']);
  assert.deepEqual(choices.map((c) => c.host), ['c.example.com', 'a.example.com', 'b.example.com']);
  assert.deepEqual(choices.map((c) => c.uncovered), [true, false, false]);
  assert.deepEqual(hostChoices(null, null), []);
});

test('token shape checks reject blanks, whitespace and odd characters', () => {
  assert.equal(tokenProblem(TOKEN), '');
  assert.match(tokenProblem(''), /Paste/);
  assert.match(tokenProblem(' ' + TOKEN), /spaces/);
  assert.match(tokenProblem('short'), /does not look like/);
  assert.match(tokenProblem(TOKEN.slice(0, 30) + '!!' + TOKEN.slice(32)), /characters/);
});

test('email, name and days checks', () => {
  assert.equal(emailProblem('ops@example.com'), '');
  assert.match(emailProblem('ops@example'), /valid/);
  assert.match(emailProblem(''), /Enter/);
  assert.equal(nameProblem(''), '');
  assert.equal(nameProblem('main-site'), '');
  assert.match(nameProblem('-bad'), /letters/);
  assert.match(nameProblem('bad/name'), /letters/);
  assert.equal(daysProblem('30', 100), '');
  assert.match(daysProblem('0', 100), /1 to 100/);
  assert.match(daysProblem('1.5', 100), /whole/);
  assert.match(daysProblem('101', 100), /1 to 100/);
});

test('generate request builds only what the node reads', () => {
  assert.equal(generateProblem({ hostsText: 'a.example.com', name: '', days: '365' }), '');
  assert.match(generateProblem({ hostsText: 'a.example.com', name: '', days: '99999' }), /days/);
  assert.deepEqual(generateBody({ hostsText: 'a.example.com b.example.com', name: ' site ', days: '90' }), { hosts: ['a.example.com', 'b.example.com'], days: 90, name: 'site' });
  assert.deepEqual(generateBody({ hostsText: 'a.example.com', name: '  ', days: '90' }), { hosts: ['a.example.com'], days: 90 });
});

test('origin CA request validates the token and validity', () => {
  const base = { hostsText: 'a.example.com', name: '', token: TOKEN, days: 365 };
  assert.equal(originCaProblem(base), '');
  assert.match(originCaProblem({ ...base, token: '' }), /Paste/);
  assert.match(originCaProblem({ ...base, days: 12 }), /valid/);
  assert.deepEqual(originCaBody({ ...base, remember: true }), { hosts: ['a.example.com'], cloudflare_token: TOKEN, validity_days: 365, remember_token: true });
  assert.equal(originCaBody({ ...base }).remember_token, false);
});

test('acme request needs the terms to be accepted', () => {
  const base = { hostsText: '*.example.com example.com', name: '', token: TOKEN, email: 'ops@example.com', agree: true, staging: false };
  assert.equal(acmeProblem(base), '');
  assert.match(acmeProblem({ ...base, agree: false }), /Agree/);
  assert.match(acmeProblem({ ...base, email: 'x' }), /valid/);
  assert.match(acmeProblem({ ...base, hostsText: '' }), /at least one/);
  const body = acmeBody({ ...base, staging: true, email: ' ops@example.com ' });
  assert.deepEqual(body, { hosts: ['*.example.com', 'example.com'], email: 'ops@example.com', cloudflare_token: TOKEN, agree_tos: true, staging: true });
});

test('job state machine walks submit, accept, poll and finish', () => {
  let s = jobStart(1000);
  assert.equal(s.phase, 'submitting');
  assert.equal(shouldPoll(s), false);
  s = jobReduce(s, { type: 'accepted', jobId: 'j1' });
  assert.equal(shouldPoll(s), true);
  s = jobReduce(s, { type: 'poll', job: { status: 'pending' } }, 2000);
  assert.equal(s.phase, 'running');
  s = jobReduce(s, { type: 'poll', job: { status: 'issued' } }, 3000);
  assert.equal(s.phase, 'issued');
  assert.equal(isJobDone(s), true);
  assert.equal(shouldPoll(s), false);
  assert.equal(jobReduce(s, { type: 'poll', job: { status: 'failed', error: 'late' } }), s);
});

test('a failed job keeps the reason and a rejection fails at once', () => {
  let s = jobReduce(jobStart(0), { type: 'accepted', jobId: 'j' });
  s = jobReduce(s, { type: 'poll', job: { status: 'failed', error: 'DNS challenge timed out' } });
  assert.equal(s.phase, 'failed');
  assert.equal(s.error, 'DNS challenge timed out');
  const rejected = jobReduce(jobStart(0), { type: 'rejected', message: 'bad token' });
  assert.equal(rejected.phase, 'failed');
  assert.equal(rejected.error, 'bad token');
  assert.equal(jobReduce(jobStart(0), { type: 'accepted', jobId: 'j' }, 0).phase, 'running');
  assert.match(jobReduce(jobReduce(jobStart(0), { type: 'accepted', jobId: 'j' }), { type: 'poll', job: { status: 'failed' } }).error, /without a reason/);
});

test('repeated poll errors end in lost and a good poll resets the count', () => {
  let s = jobReduce(jobStart(0), { type: 'accepted', jobId: 'j' });
  for (let i = 0; i < JOB_MAX_POLL_ERRORS - 1; i += 1) s = jobReduce(s, { type: 'pollError', message: 'offline' });
  assert.equal(s.phase, 'running');
  assert.match(jobStatusText(s), /last status check failed/);
  s = jobReduce(s, { type: 'poll', job: { status: 'pending' } }, 10);
  assert.equal(s.pollErrors, 0);
  for (let i = 0; i < JOB_MAX_POLL_ERRORS; i += 1) s = jobReduce(s, { type: 'pollError', message: 'offline' });
  assert.equal(s.phase, 'lost');
  assert.match(s.error, /offline/);
});

test('a job still pending after the limit stops being polled', () => {
  const s0 = jobReduce(jobStart(0), { type: 'accepted', jobId: 'j' });
  assert.equal(jobReduce(s0, { type: 'poll', job: { status: 'pending' } }, JOB_GIVE_UP_MS - 1).phase, 'running');
  assert.equal(jobReduce(s0, { type: 'poll', job: { status: 'pending' } }, JOB_GIVE_UP_MS + 1).phase, 'lost');
});

test('an unknown status counts as an error instead of looping silently', () => {
  let s = jobReduce(jobStart(0), { type: 'accepted', jobId: 'j' });
  for (let i = 0; i < JOB_MAX_POLL_ERRORS; i += 1) s = jobReduce(s, { type: 'poll', job: { status: 'weird' } });
  assert.equal(s.phase, 'lost');
});
