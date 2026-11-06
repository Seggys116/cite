import test from 'node:test';
import assert from 'node:assert/strict';
import { createPoller } from '../../web/js/poller.js';

// A fake clock: timers run only when the test advances it
function fakeEnv() {
  let now = 0;
  let nextId = 1;
  const timers = new Map();
  const listeners = new Set();
  const env = {
    hiddenNow: false,
    setTimeout(fn, ms) {
      const id = nextId;
      nextId += 1;
      timers.set(id, { at: now + ms, fn });
      return id;
    },
    clearTimeout(id) {
      timers.delete(id);
    },
    hidden: () => env.hiddenNow,
    onVisibility(fn) {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    pending: () => timers.size,
    listeners: () => listeners.size,
    async advance(ms) {
      now += ms;
      for (const [id, t] of [...timers]) {
        if (t.at <= now) {
          timers.delete(id);
          t.fn();
        }
      }
      await new Promise((resolve) => setImmediate(resolve));
    },
    toggle(hidden) {
      env.hiddenNow = hidden;
      listeners.forEach((fn) => fn());
    },
  };
  return env;
}

test('it loads at once, then again after the delay it was given', async () => {
  const env = fakeEnv();
  const seen = [];
  const p = createPoller({ load: async () => { seen.push('load'); return seen.length; }, delay: (r) => (r === 1 ? 2000 : 10000), env });
  p.start();
  await env.advance(0);
  assert.equal(seen.length, 1);
  await env.advance(1999);
  assert.equal(seen.length, 1);
  await env.advance(1);
  assert.equal(seen.length, 2);
  await env.advance(9999);
  assert.equal(seen.length, 2);
  await env.advance(1);
  assert.equal(seen.length, 3);
  p.stop();
});

test('it does not load while the tab is hidden and catches up on return', async () => {
  const env = fakeEnv();
  let loads = 0;
  const p = createPoller({ load: async () => { loads += 1; }, delay: () => 1000, env });
  p.start();
  await env.advance(0);
  assert.equal(loads, 1);
  env.toggle(true);
  await env.advance(1000);
  await env.advance(1000);
  await env.advance(1000);
  assert.equal(loads, 1);
  env.toggle(false);
  await env.advance(0);
  assert.equal(loads, 2);
  p.stop();
});

test('a slow load never overlaps with the next one', async () => {
  const env = fakeEnv();
  let active = 0;
  let peak = 0;
  let release = null;
  const p = createPoller({
    load: () => new Promise((resolve) => {
      active += 1;
      peak = Math.max(peak, active);
      release = () => { active -= 1; resolve(); };
    }),
    delay: () => 100,
    env,
  });
  p.start();
  await env.advance(0);
  p.now();
  await env.advance(500);
  assert.equal(peak, 1);
  release();
  await env.advance(0);
  p.stop();
});

test('a failing load keeps polling', async () => {
  const env = fakeEnv();
  let loads = 0;
  const p = createPoller({ load: async () => { loads += 1; throw new Error('down'); }, delay: () => 500, env });
  p.start();
  await env.advance(0);
  await env.advance(500);
  await env.advance(500);
  assert.equal(loads, 3);
  p.stop();
});

test('stopping clears the timer and the listener', async () => {
  const env = fakeEnv();
  let loads = 0;
  const p = createPoller({ load: async () => { loads += 1; }, delay: () => 100, env });
  p.start();
  await env.advance(0);
  assert.equal(env.pending(), 1);
  assert.equal(env.listeners(), 1);
  p.stop();
  assert.equal(env.pending(), 0);
  assert.equal(env.listeners(), 0);
  await env.advance(1000);
  assert.equal(loads, 1);
  assert.equal(p.isRunning(), false);
  p.start();
  await env.advance(0);
  assert.equal(loads, 1);
});

test('a panel that left the page stops its own polling', async () => {
  const env = fakeEnv();
  let attached = true;
  let loads = 0;
  const p = createPoller({ load: async () => { loads += 1; }, delay: () => 100, alive: () => attached, env });
  p.start();
  await env.advance(0);
  attached = false;
  await env.advance(100);
  await env.advance(100);
  assert.equal(loads, 1);
  assert.equal(p.isRunning(), false);
  assert.equal(env.listeners(), 0);
});

test('an inactive panel skips requests but keeps its schedule', async () => {
  const env = fakeEnv();
  let on = false;
  let loads = 0;
  const p = createPoller({ load: async () => { loads += 1; }, delay: () => 100, active: () => on, env });
  p.start();
  await env.advance(0);
  await env.advance(100);
  assert.equal(loads, 0);
  on = true;
  await env.advance(100);
  assert.equal(loads, 1);
  p.stop();
});
