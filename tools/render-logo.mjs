#!/usr/bin/env node
/*
 * tools/render-logo.mjs — renders public/assets/nearbuy-logo.png from the exact
 * brand-mark vector data used by nearbuy.js (const LOGO), so the favicon and the
 * in-app mark are always the same shape.
 *
 * Dependency-free: a small SVG path flattener, an anti-aliased scanline filler
 * and a PNG encoder built on node:zlib. No npm install, no build step.
 *
 *   node tools/render-logo.mjs [--size 512] [--out public/assets/nearbuy-logo.png]
 */
import { deflateSync } from 'node:zlib';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';

/* ------------------------------- cli -------------------------------------- */
const argv = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = argv.indexOf(`--${name}`);
  return i >= 0 && argv[i + 1] ? argv[i + 1] : fallback;
};
const SIZE = Number(arg('size', 512));
const OUT = resolve(arg('out', 'public/assets/nearbuy-logo.png'));

/* The mark, copied verbatim from nearbuy.js (viewBox 0 0 44 44). */
const VB = 44;
const PIN_D =
  'M22 4.5c-7.7 0-14 6.1-14 13.6 0 9.6 11 20.4 13.3 22.4a1 1 0 0 0 1.4 0C25 38.5 36 27.7 36 18.1 36 10.6 29.7 4.5 22 4.5Z';
const SWOOSH_D = 'M6.5 25.5c5.5 4.6 15 6.6 30.5-1.4';
const RING = { cx: 22, cy: 18, r: 7.4, w: 3.4 };

/* --------------------------- path flattening ------------------------------- */
const tokenise = (d) =>
  d
    .replace(/([MmZzLlHhVvCcSsQqTtAa])/g, ' $1 ')
    .replace(/-/g, ' -')
    .replace(/\s+/g, ' ')
    .trim()
    .split(' ')
    .filter(Boolean);

const num = (t) => Number(t);

/** Cubic sample. */
const cubic = (p0, p1, p2, p3, t) => {
  const m = 1 - t;
  return {
    x: m * m * m * p0.x + 3 * m * m * t * p1.x + 3 * m * t * t * p2.x + t * t * t * p3.x,
    y: m * m * m * p0.y + 3 * m * m * t * p1.y + 3 * m * t * t * p2.y + t * t * t * p3.y,
  };
};

/** SVG elliptical-arc endpoint -> centre parameterisation, sampled as a polyline. */
function arcPoints(p0, rx, ry, rotDeg, largeArc, sweep, p1, steps = 24) {
  if (rx === 0 || ry === 0) return [p1];
  const phi = (rotDeg * Math.PI) / 180;
  const cosP = Math.cos(phi);
  const sinP = Math.sin(phi);
  const dx = (p0.x - p1.x) / 2;
  const dy = (p0.y - p1.y) / 2;
  const x1p = cosP * dx + sinP * dy;
  const y1p = -sinP * dx + cosP * dy;
  let rx2 = rx * rx;
  let ry2 = ry * ry;
  const lambda = (x1p * x1p) / rx2 + (y1p * y1p) / ry2;
  if (lambda > 1) {
    const s = Math.sqrt(lambda);
    rx *= s;
    ry *= s;
    rx2 = rx * rx;
    ry2 = ry * ry;
  }
  const sign = largeArc === sweep ? -1 : 1;
  const num0 = rx2 * ry2 - rx2 * y1p * y1p - ry2 * x1p * x1p;
  const den = rx2 * y1p * y1p + ry2 * x1p * x1p;
  const co = den === 0 ? 0 : sign * Math.sqrt(Math.max(0, num0 / den));
  const cxp = (co * (rx * y1p)) / ry;
  const cyp = (co * (-ry * x1p)) / rx;
  const cx = cosP * cxp - sinP * cyp + (p0.x + p1.x) / 2;
  const cy = sinP * cxp + cosP * cyp + (p0.y + p1.y) / 2;
  const angle = (ux, uy, vx, vy) => {
    const dot = ux * vx + uy * vy;
    const len = Math.hypot(ux, uy) * Math.hypot(vx, vy);
    let a = Math.acos(len === 0 ? 1 : Math.max(-1, Math.min(1, dot / len)));
    if (ux * vy - uy * vx < 0) a = -a;
    return a;
  };
  const th1 = angle(1, 0, (x1p - cxp) / rx, (y1p - cyp) / ry);
  let dth = angle((x1p - cxp) / rx, (y1p - cyp) / ry, (-x1p - cxp) / rx, (-y1p - cyp) / ry);
  if (!sweep && dth > 0) dth -= 2 * Math.PI;
  if (sweep && dth < 0) dth += 2 * Math.PI;
  const pts = [];
  for (let i = 1; i <= steps; i++) {
    const th = th1 + (dth * i) / steps;
    const x = rx * Math.cos(th);
    const y = ry * Math.sin(th);
    pts.push({ x: cosP * x - sinP * y + cx, y: sinP * x + cosP * y + cy });
  }
  return pts;
}

/** Flatten a path `d` into a single polyline (the marks here are one contour each). */
function flatten(d, seg = 40) {
  const t = tokenise(d);
  const pts = [];
  let i = 0;
  let cur = { x: 0, y: 0 };
  let start = { x: 0, y: 0 };
  let lastCubic = null;
  let prevCmd = 'M';
  const push = (p) => {
    const prev = pts[pts.length - 1];
    if (!prev || Math.hypot(prev.x - p.x, prev.y - p.y) > 1e-6) pts.push(p);
  };
  const take = (n) => t.slice(i, i + n).map(num);

  while (i < t.length) {
    let cmd = t[i];
    if (!/[A-Za-z]/.test(cmd)) {
      /* Implicit repeat of the previous command (SVG allows this after C/c,
       * and after M/m the repeats become lineTo). */
      cmd = prevCmd === 'M' ? 'L' : prevCmd === 'm' ? 'l' : prevCmd;
    } else {
      i++;
    }
    const rel = cmd === cmd.toLowerCase();
    const base = rel ? cur : { x: 0, y: 0 };
    const lastCmd = cmd.toUpperCase();
    prevCmd = cmd;

    switch (lastCmd) {
      case 'M': {
        const [x, y] = take(2);
        i += 2;
        cur = { x: base.x + x, y: base.y + y };
        start = cur;
        push(cur);
        break;
      }
      case 'L': {
        const [x, y] = take(2);
        i += 2;
        cur = { x: base.x + x, y: base.y + y };
        push(cur);
        break;
      }
      case 'C': {
        const [x1, y1, x2, y2, x, y] = take(6);
        i += 6;
        const p1 = { x: base.x + x1, y: base.y + y1 };
        const p2 = { x: base.x + x2, y: base.y + y2 };
        const p3 = { x: base.x + x, y: base.y + y };
        for (let s = 1; s <= seg; s++) push(cubic(cur, p1, p2, p3, s / seg));
        lastCubic = { p2, p3 };
        cur = p3;
        break;
      }
      case 'S': {
        const [x2, y2, x, y] = take(4);
        i += 4;
        const p1 = lastCubic
          ? { x: 2 * cur.x - lastCubic.p2.x, y: 2 * cur.y - lastCubic.p2.y }
          : cur;
        const p2 = { x: base.x + x2, y: base.y + y2 };
        const p3 = { x: base.x + x, y: base.y + y };
        for (let s = 1; s <= seg; s++) push(cubic(cur, p1, p2, p3, s / seg));
        lastCubic = { p2, p3 };
        cur = p3;
        break;
      }
      case 'A': {
        const [rx, ry, rot, laf, sf, x, y] = take(7);
        i += 7;
        const p1 = { x: base.x + x, y: base.y + y };
        for (const p of arcPoints(cur, rx, ry, rot, !!Number(laf), !!Number(sf), p1)) push(p);
        lastCubic = null;
        cur = p1;
        break;
      }
      case 'Z': {
        cur = start;
        push(cur);
        break;
      }
      default:
        throw new Error(`Unsupported path command: ${cmd}`);
    }
  }
  return pts;
}

/* ------------------------------- painting --------------------------------- */
const buf = new Float32Array(SIZE * SIZE * 4); /* RGBA, straight alpha */

const over = (px, py, r, g, b, a) => {
  if (a <= 0) return;
  const k = (py * SIZE + px) * 4;
  const sa = buf[k + 3];
  const da = a + sa * (1 - a);
  if (da === 0) return;
  buf[k] = (r * a + buf[k] * sa * (1 - a)) / da;
  buf[k + 1] = (g * a + buf[k + 1] * sa * (1 - a)) / da;
  buf[k + 2] = (b * a + buf[k + 2] * sa * (1 - a)) / da;
  buf[k + 3] = da;
};

const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
const lerp = (a, b, t) => a + (b - a) * t;
const mixHex = (h1, h2, t) => {
  const a = hex(h1);
  const b = hex(h2);
  return [lerp(a[0], b[0], t), lerp(a[1], b[1], t), lerp(a[2], b[2], t)];
};

/** objectBoundingBox linear gradient, as in the SVG defs. */
function gradientFn(box, x1, y1, x2, y2, c1, c2) {
  const ax = box.x + x1 * box.w;
  const ay = box.y + y1 * box.h;
  const bx = box.x + x2 * box.w;
  const by = box.y + y2 * box.h;
  const dx = bx - ax;
  const dy = by - ay;
  const len2 = dx * dx + dy * dy || 1;
  return (x, y) => {
    let t = ((x - ax) * dx + (y - ay) * dy) / len2;
    t = Math.max(0, Math.min(1, t));
    return mixHex(c1, c2, t);
  };
}

const bboxOf = (pts) => {
  let x0 = Infinity;
  let y0 = Infinity;
  let x1 = -Infinity;
  let y1 = -Infinity;
  for (const p of pts) {
    x0 = Math.min(x0, p.x);
    y0 = Math.min(y0, p.y);
    x1 = Math.max(x1, p.x);
    y1 = Math.max(y1, p.y);
  }
  return { x: x0, y: y0, w: x1 - x0, h: y1 - y0, x1, y1 };
};

const SS = 3; /* supersamples per axis */
const toPx = (v) => (v / VB) * SIZE; /* viewBox units -> pixels */

/** Anti-aliased scanline fill of a closed polygon (nonzero winding). */
function fillPolygon(pts, paint) {
  const box = bboxOf(pts);
  const pad = 0.6;
  const yTop = Math.max(0, Math.floor(toPx(box.y - pad)));
  const yBot = Math.min(SIZE - 1, Math.ceil(toPx(box.y1 + pad)));
  const n = pts.length;

  for (let py = yTop; py <= yBot; py++) {
    for (let j = 0; j < SS; j++) {
      const sy = ((py * SS + j) + 0.5) / (SIZE * SS); /* 0..1 of canvas */
      const y = sy * VB;
      const xs = [];
      for (let e = 0; e < n; e++) {
        const a = pts[e];
        const b = pts[(e + 1) % n];
        if (a.y === b.y) continue;
        if (y < Math.min(a.y, b.y) || y >= Math.max(a.y, b.y)) continue;
        const t = (y - a.y) / (b.y - a.y);
        xs.push({ x: a.x + t * (b.x - a.x), dir: b.y > a.y ? 1 : -1 });
      }
      if (!xs.length) continue;
      xs.sort((p, q) => p.x - q.x);

      /* nonzero winding: walk crossings, track winding, emit covered spans */
      let winding = 0;
      let spanStart = null;
      for (const c of xs) {
        const before = winding;
        winding += c.dir;
        if (before === 0 && winding !== 0) spanStart = c.x;
        else if (before !== 0 && winding === 0 && spanStart !== null) {
          emitSpan(py, j, spanStart, c.x, paint, y);
          spanStart = null;
        }
      }
    }
  }
}

function emitSpan(py, subRow, x0v, x1v, paint, y) {
  const xf0 = toPx(x0v);
  const xf1 = toPx(x1v);
  const pxStart = Math.max(0, Math.floor(xf0));
  const pxEnd = Math.min(SIZE - 1, Math.ceil(xf1) - 1);
  const w = 1 / SS; /* this sub-row's vertical share of the pixel */
  for (let px = pxStart; px <= pxEnd; px++) {
    const cov = Math.max(0, Math.min(1, xf1 - px)) - Math.max(0, Math.min(1, xf0 - px));
    if (cov <= 0) continue;
    const x = ((px + 0.5) / SIZE) * VB;
    const [r, g, b] = paint(x, y);
    over(px, py, r, g, b, cov * w);
  }
}

/** Anti-aliased stroke by distance to a polyline, with round caps/joins. */
function strokePolyline(pts, width, paint) {
  const box = bboxOf(pts);
  const pad = width / 2 + 0.6;
  const half = width / 2;
  const yTop = Math.max(0, Math.floor(toPx(box.y - pad)));
  const yBot = Math.min(SIZE - 1, Math.ceil(toPx(box.y1 + pad)));
  const xLeft = Math.max(0, Math.floor(toPx(box.x - pad)));
  const xRight = Math.min(SIZE - 1, Math.ceil(toPx(box.x1 + pad)));
  const segs = [];
  for (let i = 0; i + 1 < pts.length; i++) segs.push([pts[i], pts[i + 1]]);

  const distToSeg = (x, y, a, b) => {
    const vx = b.x - a.x;
    const vy = b.y - a.y;
    const len2 = vx * vx + vy * vy;
    let t = len2 === 0 ? 0 : ((x - a.x) * vx + (y - a.y) * vy) / len2;
    t = Math.max(0, Math.min(1, t));
    return Math.hypot(x - (a.x + t * vx), y - (a.y + t * vy));
  };

  for (let py = yTop; py <= yBot; py++) {
    for (let px = xLeft; px <= xRight; px++) {
      let hits = 0;
      for (let j = 0; j < SS; j++) {
        for (let i = 0; i < SS; i++) {
          const x = (((px * SS + i) + 0.5) / (SIZE * SS)) * VB;
          const y = (((py * SS + j) + 0.5) / (SIZE * SS)) * VB;
          let d = Infinity;
          for (const [a, b] of segs) {
            const dd = distToSeg(x, y, a, b);
            if (dd < d) d = dd;
            if (d < half - 0.35) break; /* well inside: stop early */
          }
          if (d <= half) hits++;
        }
      }
      if (!hits) continue;
      const x = ((px + 0.5) / SIZE) * VB;
      const y = ((py + 0.5) / SIZE) * VB;
      const [r, g, b] = paint(x, y);
      over(px, py, r, g, b, hits / (SS * SS));
    }
  }
}

/* ------------------------------- the mark ---------------------------------- */
const pin = flatten(PIN_D, 48);
const swoosh = flatten(SWOOSH_D, 48);
const pinBox = bboxOf(pin);
const swooshBox = bboxOf(swoosh);

const pinPaint = gradientFn(pinBox, 0, 0, 1, 1, '#24467f', '#0f2a55');
const swooshPaint = gradientFn(swooshBox, 0, 0, 1, 0, '#ff9a3d', '#ef6c0a');

/* 1. navy pin */
fillPolygon(pin, pinPaint);

/* 2. white ring (analytic annulus, supersampled) */
{
  const inner = RING.r - RING.w / 2;
  const outer = RING.r + RING.w / 2;
  const yTop = Math.max(0, Math.floor(toPx(RING.cy - outer - 0.6)));
  const yBot = Math.min(SIZE - 1, Math.ceil(toPx(RING.cy + outer + 0.6)));
  const xLeft = Math.max(0, Math.floor(toPx(RING.cx - outer - 0.6)));
  const xRight = Math.min(SIZE - 1, Math.ceil(toPx(RING.cx + outer + 0.6)));
  for (let py = yTop; py <= yBot; py++) {
    for (let px = xLeft; px <= xRight; px++) {
      let hits = 0;
      for (let j = 0; j < SS; j++) {
        for (let i = 0; i < SS; i++) {
          const x = (((px * SS + i) + 0.5) / (SIZE * SS)) * VB;
          const y = (((py * SS + j) + 0.5) / (SIZE * SS)) * VB;
          const d = Math.hypot(x - RING.cx, y - RING.cy);
          if (d >= inner && d <= outer) hits++;
        }
      }
      if (hits) over(px, py, 255, 255, 255, hits / (SS * SS));
    }
  }
}

/* 3. marigold swoosh */
strokePolyline(swoosh, 3.6, swooshPaint);

/* ----------------------------- png encoding ------------------------------- */
const crcTable = (() => {
  const tbl = new Int32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    tbl[n] = c;
  }
  return tbl;
})();

const crc32 = (bytes) => {
  let c = 0xffffffff;
  for (const b of bytes) c = crcTable[(c ^ b) & 0xff] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
};

const chunk = (type, data) => {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const body = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
};

function encodePng(w, h, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; /* bit depth */
  ihdr[9] = 6; /* colour type: RGBA */
  const stride = w * 4;
  const raw = Buffer.alloc((stride + 1) * h);
  for (let y = 0; y < h; y++) {
    raw[y * (stride + 1)] = 0; /* filter: none */
    rgba.copy(raw, y * (stride + 1) + 1, y * stride, y * stride + stride);
  }
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const rgba = Buffer.alloc(SIZE * SIZE * 4);
for (let i = 0; i < SIZE * SIZE; i++) {
  const a = buf[i * 4 + 3];
  rgba[i * 4] = Math.round(Math.max(0, Math.min(255, buf[i * 4])));
  rgba[i * 4 + 1] = Math.round(Math.max(0, Math.min(255, buf[i * 4 + 1])));
  rgba[i * 4 + 2] = Math.round(Math.max(0, Math.min(255, buf[i * 4 + 2])));
  rgba[i * 4 + 3] = Math.round(Math.max(0, Math.min(1, a)) * 255);
}

mkdirSync(dirname(OUT), { recursive: true });
writeFileSync(OUT, encodePng(SIZE, SIZE, rgba));
process.stdout.write(`wrote ${OUT} (${SIZE}x${SIZE}, ${rgba.length} bytes raw)\n`);
