import { bus } from './state.js';

const BAYER = [0, 8, 2, 10, 12, 4, 14, 6, 3, 11, 1, 9, 15, 7, 13, 5];
const THRESHOLD = Float32Array.from(BAYER, (b) => (b + 0.5) / 16);

function readColor() {
  const raw = getComputedStyle(document.documentElement).getPropertyValue('--dither-rgb');
  const parts = raw.split(',').map((p) => parseInt(p, 10));
  return parts.length === 3 && parts.every((p) => !Number.isNaN(p)) ? parts : [206, 66, 43];
}

// Ordered (Bayer 4x4) dither of a slowly drifting sine field, drawn at low resolution and scaled up
export function startDither(canvas, { cell = 4, alpha = 0.22, density = 0.9 } = {}) {
  const ctx = canvas.getContext('2d');
  const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
  let w = 1;
  let hgt = 1;
  let img = null;
  let packed = 0;
  let sinX = new Float32Array(1);
  let cosX = new Float32Array(1);
  let raf = 0;
  let last = 0;
  const origin = performance.now();

  const recolor = () => {
    const [r, g, b] = readColor();
    packed = ((Math.round(alpha * 255) << 24) | (b << 16) | (g << 8) | r) >>> 0;
  };

  const draw = (now) => {
    if (!img) return;
    const t = ((now - origin) / 1000) * 0.35;
    const px = new Uint32Array(img.data.buffer);
    const diag = new Float32Array(w + hgt);
    for (let i = 0; i < diag.length; i += 1) diag[i] = Math.sin(i * 0.045 + t * 0.6);
    for (let y = 0; y < hgt; y += 1) {
      const phase = t * 1.1 + 1.6 * Math.sin(y * 0.06 - t * 0.7);
      const cosP = 0.26 * Math.cos(phase);
      const sinP = 0.26 * Math.sin(phase);
      const row = y * w;
      const brow = (y & 3) * 4;
      for (let x = 0; x < w; x += 1) {
        // sin(a + b) expanded so the per-cell work is multiplies against per-column tables
        const v = (0.5 + sinX[x] * cosP + cosX[x] * sinP + 0.2 * diag[x + y]) * density;
        px[row + x] = v > THRESHOLD[brow + (x & 3)] ? packed : 0;
      }
    }
    ctx.putImageData(img, 0, 0);
  };

  const loop = (now) => {
    raf = requestAnimationFrame(loop);
    if (now - last < 66) return;
    last = now;
    draw(now);
  };

  const resize = () => {
    const rect = canvas.getBoundingClientRect();
    w = Math.max(1, Math.ceil(rect.width / cell));
    hgt = Math.max(1, Math.ceil(rect.height / cell));
    canvas.width = w;
    canvas.height = hgt;
    img = ctx.createImageData(w, hgt);
    sinX = new Float32Array(w);
    cosX = new Float32Array(w);
    for (let x = 0; x < w; x += 1) {
      sinX[x] = Math.sin(x * 0.09);
      cosX[x] = Math.cos(x * 0.09);
    }
    recolor();
    draw(performance.now());
  };

  const sync = () => {
    cancelAnimationFrame(raf);
    raf = 0;
    if (!document.hidden && !motion.matches) raf = requestAnimationFrame(loop);
  };

  const onTheme = () => {
    recolor();
    if (img) draw(performance.now());
  };

  const observer = new ResizeObserver(resize);
  observer.observe(canvas);
  document.addEventListener('visibilitychange', sync);
  motion.addEventListener('change', sync);
  bus.addEventListener('theme', onTheme);
  sync();

  return () => {
    cancelAnimationFrame(raf);
    observer.disconnect();
    document.removeEventListener('visibilitychange', sync);
    motion.removeEventListener('change', sync);
    bus.removeEventListener('theme', onTheme);
  };
}
