const SVG_NS = 'http://www.w3.org/2000/svg';
const LIVE_PROPS = new Set(['checked', 'disabled', 'selected', 'readOnly', 'indeterminate', 'multiple']);

function applyProps(el, props, isSvg) {
  if (!props) return;
  for (const [key, val] of Object.entries(props)) {
    if (val === null || val === undefined || val === false || key === 'value') continue;
    if (key === 'class') {
      if (isSvg) el.setAttribute('class', val);
      else el.className = val;
    } else if (key === 'style' && typeof val === 'object') {
      for (const [name, v] of Object.entries(val)) el.style.setProperty(name, String(v));
    } else if (key === 'dataset') {
      Object.assign(el.dataset, val);
    } else if (key.startsWith('on') && typeof val === 'function') {
      el.addEventListener(key.slice(2).toLowerCase(), val);
    } else if (!isSvg && LIVE_PROPS.has(key)) {
      el[key] = val;
    } else {
      el.setAttribute(key, val === true ? '' : String(val));
    }
  }
}

function append(el, kids) {
  for (const kid of kids) {
    if (kid === null || kid === undefined || kid === false || kid === true) continue;
    if (typeof kid === 'string' || typeof kid === 'number' || typeof kid === 'bigint') {
      el.appendChild(document.createTextNode(String(kid)));
    } else if (Array.isArray(kid)) {
      append(el, kid);
    } else if (kid instanceof Node) {
      el.append(kid);
    } else {
      el.appendChild(document.createTextNode(String(kid)));
    }
  }
}

// Builds an HTML element; text is only ever inserted as text nodes
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  applyProps(el, props, false);
  append(el, children);
  if (props && props.value !== undefined && props.value !== null) el.value = props.value;
  return el;
}

export function s(tag, props, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  applyProps(el, props, true);
  append(el, children);
  return el;
}

export function icon(name, cls = '') {
  return s('svg', { class: ('icon ' + cls).trim(), 'aria-hidden': 'true', focusable: 'false' },
    s('use', { href: '#i-' + name }));
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

export function debounce(fn, ms) {
  let timer = 0;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

const QR_TAGS = new Set(['svg', 'path', 'rect', 'g']);
const QR_ATTRS = new Set(['viewBox', 'width', 'height', 'd', 'x', 'y', 'fill', 'stroke', 'stroke-width',
  'transform', 'shape-rendering', 'fill-rule', 'fill-opacity', 'opacity']);
const UNSAFE_VALUE = /url\s*\(|javascript:|data:|[<>]/i;

// Rebuilds a server supplied SVG from a strict whitelist instead of trusting its markup
export function sanitizeSvg(text) {
  let doc;
  try {
    doc = new DOMParser().parseFromString(String(text), 'image/svg+xml');
  } catch (err) {
    return null;
  }
  const root = doc.documentElement;
  if (!root || root.localName !== 'svg' || root.namespaceURI !== SVG_NS || doc.querySelector('parsererror')) return null;
  const copy = (src) => {
    const out = document.createElementNS(SVG_NS, src.localName);
    for (const attr of Array.from(src.attributes)) {
      if (QR_ATTRS.has(attr.name) && attr.value.length < 200000 && !UNSAFE_VALUE.test(attr.value)) {
        out.setAttribute(attr.name, attr.value);
      }
    }
    for (const child of Array.from(src.children)) {
      if (child.namespaceURI === SVG_NS && QR_TAGS.has(child.localName)) out.appendChild(copy(child));
    }
    return out;
  };
  const svg = copy(root);
  const w = parseFloat(svg.getAttribute('width'));
  const hgt = parseFloat(svg.getAttribute('height'));
  if (!svg.hasAttribute('viewBox') && w > 0 && hgt > 0) svg.setAttribute('viewBox', `0 0 ${w} ${hgt}`);
  svg.removeAttribute('width');
  svg.removeAttribute('height');
  svg.setAttribute('class', 'qr-svg');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Authenticator QR code');
  return svg;
}
