// Runs a load repeatedly while a panel is on screen: never overlapping, paused while the tab is hidden; env is injectable for tests.
const browserEnv = () => ({
  setTimeout: (fn, ms) => setTimeout(fn, ms),
  clearTimeout: (id) => clearTimeout(id),
  hidden: () => document.hidden,
  onVisibility: (fn) => {
    document.addEventListener('visibilitychange', fn);
    return () => document.removeEventListener('visibilitychange', fn);
  },
});

export function createPoller({
  load, delay, active = () => true, alive = () => true, env = browserEnv(),
}) {
  let timer = null;
  let running = false;
  let stopped = false;
  let inFlight = false;

  const clear = () => {
    if (timer !== null) env.clearTimeout(timer);
    timer = null;
  };

  const schedule = (ms) => {
    clear();
    if (stopped || !running) return;
    timer = env.setTimeout(tick, ms);
  };

  async function tick() {
    timer = null;
    if (stopped) return;
    // A panel that was removed from the page stops itself instead of polling forever
    if (!alive()) {
      stop();
      return;
    }
    if (env.hidden() || !active()) {
      schedule(delay(undefined));
      return;
    }
    if (inFlight) return;
    inFlight = true;
    let result;
    try {
      result = await load();
    } catch (error) {
      result = undefined;
    } finally {
      inFlight = false;
    }
    schedule(delay(result));
  }

  const off = env.onVisibility(() => {
    if (stopped || !running) return;
    // Coming back to the tab refreshes at once; hiding it lets the next tick skip the request
    if (!env.hidden()) {
      clear();
      tick();
    }
  });

  function start({ immediate = true } = {}) {
    if (stopped) return;
    running = true;
    if (immediate) tick();
    else schedule(delay(undefined));
  }

  function stop() {
    stopped = true;
    running = false;
    clear();
    off();
  }

  return {
    start,
    stop,
    // Loads now, for the Refresh button or after an action
    now() {
      if (stopped) return Promise.resolve();
      clear();
      return tick();
    },
    isRunning: () => running && !stopped,
  };
}
