import { h, s, clear } from './dom.js';
import { fmtNum, fmtInt, toMs } from './ui.js';

const pad = (n) => String(n).padStart(2, '0');

function niceMax(value) {
  if (value <= 0) return 1;
  const exp = Math.pow(10, Math.floor(Math.log10(value)));
  const f = value / exp;
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nice * exp;
}

export function sparkline(values, { width = 120, height = 32, cls = '' } = {}) {
  const svg = s('svg', { class: ('spark ' + cls).trim(), viewBox: `0 0 ${width} ${height}`, width, height, role: 'img', 'aria-label': 'Trend' });
  if (values.length < 2) return svg;
  const max = Math.max(...values, 1);
  const step = width / (values.length - 1);
  const pts = values.map((v, i) => [i * step, height - 2 - (v / max) * (height - 4)]);
  const line = pts.map(([x, y], i) => (i ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1)).join(' ');
  svg.append(s('path', { class: 'spark-area', d: `${line} L${width} ${height} L0 ${height} Z` }), s('path', { class: 'spark-line', d: line }));
  return svg;
}

function axisLabel(ms, spanMs) {
  const d = new Date(ms);
  if (spanMs <= 36 * 3600 * 1000) return `${pad(d.getHours())}:${pad(d.getMinutes())}`;
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

// Hand-drawn multi-series line chart with a hover crosshair; redraws when its container resizes
export function timeSeriesChart(points, { series }) {
  const holder = h('div', { class: 'chart-holder' });
  const tip = h('div', { class: 'chart-tip', hidden: true });
  const legend = h('div', { class: 'chart-legend' }, series.map((sr) => h('span', { class: 'legend-item' }, h('i', { class: 'swatch ' + sr.cls }), sr.label)));
  const root = h('div', { class: 'chart' }, legend, holder);
  const height = 280;
  const m = { l: 48, r: 14, t: 12, b: 28 };
  let svg = null;

  const build = (width) => {
    const iw = width - m.l - m.r;
    const ih = height - m.t - m.b;
    const n = points.length;
    const times = points.map((p) => toMs(p.ts));
    const spanMs = n > 1 ? times[n - 1] - times[0] : 0;
    const max = niceMax(Math.max(...points.flatMap((p) => series.map((sr) => Number(p[sr.key]) || 0)), 0));
    const xAt = (i) => m.l + (n === 1 ? iw / 2 : (i * iw) / (n - 1));
    const yAt = (v) => m.t + ih - (v / max) * ih;
    const el = s('svg', { class: 'chart-svg', viewBox: `0 0 ${width} ${height}`, width, height, role: 'img', 'aria-label': 'Traffic over time' });
    for (let i = 0; i <= 4; i += 1) {
      const y = m.t + (ih * i) / 4;
      el.append(s('line', { class: 'grid-line', x1: m.l, x2: width - m.r, y1: y, y2: y }),
        s('text', { class: 'axis-label', x: m.l - 8, y: y + 4, 'text-anchor': 'end' }, fmtNum(max - (max * i) / 4)));
    }
    const ticks = Math.min(6, n);
    for (let i = 0; i < ticks; i += 1) {
      const idx = ticks === 1 ? 0 : Math.round((i * (n - 1)) / (ticks - 1));
      el.append(s('text', { class: 'axis-label', x: xAt(idx), y: height - 8, 'text-anchor': i === 0 ? 'start' : i === ticks - 1 ? 'end' : 'middle' }, axisLabel(times[idx], spanMs)));
    }
    series.forEach((sr, si) => {
      const pts = points.map((p, i) => [xAt(i), yAt(Number(p[sr.key]) || 0)]);
      if (!pts.length) return;
      const line = pts.map(([x, y], i) => (i ? 'L' : 'M') + x.toFixed(1) + ' ' + y.toFixed(1)).join(' ');
      if (si === 0) el.append(s('path', { class: 'area ' + sr.cls, d: `${line} L${pts[pts.length - 1][0].toFixed(1)} ${m.t + ih} L${pts[0][0].toFixed(1)} ${m.t + ih} Z` }));
      el.append(s('path', { class: 'line ' + sr.cls, d: line }));
    });
    const cross = s('line', { class: 'crosshair', y1: m.t, y2: m.t + ih, x1: 0, x2: 0, visibility: 'hidden' });
    const dots = series.map((sr) => s('circle', { class: 'hover-dot ' + sr.cls, r: 4, visibility: 'hidden' }));
    const hit = s('rect', { class: 'hit', x: m.l, y: m.t, width: iw, height: ih, fill: 'transparent' });
    el.append(cross, ...dots, hit);

    const show = (evt) => {
      const rect = el.getBoundingClientRect();
      const px = ((evt.clientX - rect.left) / rect.width) * width;
      const idx = n === 1 ? 0 : Math.max(0, Math.min(n - 1, Math.round(((px - m.l) / iw) * (n - 1))));
      const p = points[idx];
      const x = xAt(idx);
      cross.setAttribute('x1', x);
      cross.setAttribute('x2', x);
      cross.setAttribute('visibility', 'visible');
      series.forEach((sr, i) => {
        dots[i].setAttribute('cx', x);
        dots[i].setAttribute('cy', yAt(Number(p[sr.key]) || 0));
        dots[i].setAttribute('visibility', 'visible');
      });
      clear(tip);
      const stamp = new Date(times[idx]);
      tip.append(h('div', { class: 'tip-time' }, `${stamp.getFullYear()}-${pad(stamp.getMonth() + 1)}-${pad(stamp.getDate())} ${pad(stamp.getHours())}:${pad(stamp.getMinutes())}`),
        ...series.map((sr) => h('div', { class: 'tip-row' }, h('i', { class: 'swatch ' + sr.cls }), h('span', {}, sr.label), h('b', { class: 'mono' }, fmtInt(p[sr.key])))));
      tip.hidden = false;
      const tipW = tip.offsetWidth;
      const left = Math.min(Math.max(x * (rect.width / width) + 12, 4), rect.width - tipW - 4);
      tip.style.setProperty('left', left + 'px');
      tip.style.setProperty('top', '16px');
    };
    const hide = () => {
      cross.setAttribute('visibility', 'hidden');
      dots.forEach((d) => d.setAttribute('visibility', 'hidden'));
      tip.hidden = true;
    };
    hit.addEventListener('pointermove', show);
    hit.addEventListener('pointerdown', show);
    hit.addEventListener('pointerleave', hide);
    return el;
  };

  const draw = () => {
    const width = Math.max(280, Math.floor(holder.clientWidth));
    if (svg) svg.remove();
    svg = build(width);
    holder.insertBefore(svg, tip);
    tip.hidden = true;
  };

  if (!points.length) {
    holder.appendChild(h('p', { class: 'muted chart-empty' }, 'No traffic recorded in this window.'));
    holder.appendChild(tip);
    return root;
  }
  holder.appendChild(tip);
  new ResizeObserver(draw).observe(holder);
  return root;
}

export function donut(segments, { centerTop = '', centerBottom = '', size = 160 } = {}) {
  // The radius 15.9155 makes the circumference 100, so dash lengths can be written as percentages.
  const total = segments.reduce((sum, seg) => sum + seg.value, 0);
  const svg = s('svg', { class: 'donut', viewBox: '0 0 42 42', width: size, height: size, role: 'img', 'aria-label': 'Breakdown' },
    s('circle', { class: 'donut-ring', cx: 21, cy: 21, r: 15.9155, fill: 'none' }));
  let offset = 0;
  for (const seg of segments) {
    if (!seg.value || !total) continue;
    const pct = (seg.value / total) * 100;
    svg.append(s('circle', {
      class: 'donut-seg ' + seg.cls, cx: 21, cy: 21, r: 15.9155, fill: 'none',
      'stroke-dasharray': `${Math.max(pct - 0.6, 0.1).toFixed(2)} ${(100 - pct + 0.6).toFixed(2)}`,
      'stroke-dashoffset': (25 - offset).toFixed(2),
    }));
    offset += pct;
  }
  svg.append(s('text', { class: 'donut-top', x: 21, y: 21.5, 'text-anchor': 'middle' }, centerTop),
    s('text', { class: 'donut-bottom', x: 21, y: 26.5, 'text-anchor': 'middle' }, centerBottom));
  return svg;
}

export function hbars(items, { format = fmtNum } = {}) {
  const max = Math.max(...items.map((i) => i.value), 1);
  if (!items.length) return h('p', { class: 'muted' }, 'No data in this window.');
  return h('div', { class: 'hbars' }, items.map((item) => {
    const fill = h('i', { class: 'hbar-fill ' + (item.cls || '') });
    // A 2 percent floor keeps small but non-zero values visible.
    fill.style.setProperty('width',Math.max(2, (item.value / max) * 100).toFixed(1) + '%');
    return h('div', { class: 'hbar' },
      h('span', { class: 'hbar-label', title: item.label }, item.label),
      h('span', { class: 'hbar-track' }, fill),
      h('span', { class: 'hbar-value mono' }, format(item.value)));
  }));
}

export function histogram(buckets, { format = fmtNum } = {}) {
  const max = Math.max(...buckets.map((b) => b.value), 1);
  return h('div', { class: 'hist', role: 'img', 'aria-label': 'Distribution' }, buckets.map((b) => {
    const bar = h('i', { class: 'hist-bar' });
    bar.style.setProperty('height', Math.max(2, (b.value / max) * 100).toFixed(1) + '%');
    return h('div', { class: 'hist-col', title: `${b.title || b.label}: ${fmtInt(b.value)}` },
      h('span', { class: 'hist-value mono' }, format(b.value)), h('div', { class: 'hist-track' }, bar), h('span', { class: 'hist-label' }, b.label));
  }));
}
