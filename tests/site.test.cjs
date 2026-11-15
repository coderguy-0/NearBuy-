/*
 * Site regression tests — zero dependencies (node:test + global fetch).
 *
 *   npm test
 *
 * Boots server/index.js on an ephemeral port and asserts that:
 *   1. every documented clean URL and legacy page returns 200,
 *   2. every locally referenced asset (img / css / js / font) exists on disk,
 *   3. directory URLs redirect to their trailing-slash form,
 *   4. unknown paths return the styled 404 (not a server error),
 *   5. path traversal is refused.
 */
'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const PORT = 4199;
const BASE = `http://127.0.0.1:${PORT}`;

let child;

before(async () => {
  child = spawn(process.execPath, [path.join(ROOT, 'server', 'index.js')], {
    env: { ...process.env, PORT: String(PORT), HOST: '127.0.0.1' },
    stdio: 'ignore'
  });
  // wait for the port to accept connections
  for (let i = 0; i < 100; i++) {
    try {
      const res = await fetch(`${BASE}/`, { method: 'HEAD' });
      if (res.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((r) => setTimeout(r, 60));
  }
  throw new Error('server did not start in time');
});

after(() => {
  if (child) child.kill();
});

const PAGES = [
  '/',
  '/index.html',
  '/portal.html',
  '/classic.html',
  '/seller.html',
  '/partner.html',
  '/business.html',
  '/delivery-admin.html',
  '/customer/',
  '/customer/login/',
  '/seller/',
  '/seller/register/',
  '/runner/',
  '/runner/register/',
  '/fleet/',
  '/admin/',
  '/control-tower/',
  '/about/',
  '/help/',
  '/roadmap/',
  '/delivery/kit.css',
  '/delivery/logo.svg',
  '/delivery/fonts/dm-sans-latin-wght-normal.woff2',
  '/public/assets/nearbuy-logo.png',
  '/favicon.ico'
];

const ASSETS = [
  '/home.css',
  '/home.js',
  '/nearbuy.css',
  '/nearbuy.js',
  '/styles.css',
  '/app.js',
  '/seller.css',
  '/seller.js',
  '/network.css',
  '/network.js',
  '/public/assets/hero-neighbourhood.jpg',
  '/public/assets/portal-customer.jpg',
  '/public/assets/portal-seller.jpg',
  '/public/assets/portal-runner.jpg',
  '/public/assets/discover-local-market.jpg',
  '/public/assets/discover-milk.jpg',
  '/public/assets/discover-bananas.jpg',
  '/public/assets/discover-bread.jpg',
  '/public/assets/discover-eggs.jpg',
  '/public/assets/showcase-milk.jpg',
  '/public/assets/showcase-bananas.jpg',
  '/public/assets/showcase-bread.jpg',
  '/public/assets/showcase-eggs.jpg'
];

test('documented pages and front doors return 200', async () => {
  for (const p of PAGES) {
    const res = await fetch(BASE + p);
    assert.equal(res.status, 200, `expected 200 for ${p}, got ${res.status}`);
    await res.body?.cancel();
  }
});

test('stylesheets, scripts and images return 200', async () => {
  for (const p of ASSETS) {
    const res = await fetch(BASE + p);
    assert.equal(res.status, 200, `expected 200 for ${p}, got ${res.status}`);
    await res.body?.cancel();
  }
});

test('content types are correct', async () => {
  const cases = [
    ['/home.css', 'text/css'],
    ['/nearbuy.js', 'text/javascript'],
    ['/public/assets/nearbuy-logo.png', 'image/png'],
    ['/public/assets/hero-neighbourhood.jpg', 'image/jpeg'],
    ['/delivery/logo.svg', 'image/svg+xml'],
    ['/delivery/fonts/dm-sans-latin-wght-normal.woff2', 'font/woff2'],
    ['/about/', 'text/html']
  ];
  for (const [p, type] of cases) {
    const res = await fetch(BASE + p);
    assert.ok(
      (res.headers.get('content-type') || '').includes(type),
      `${p} should be ${type}, got ${res.headers.get('content-type')}`
    );
    await res.body?.cancel();
  }
});

test('extensionless directory URLs redirect to trailing slash', async () => {
  const res = await fetch(`${BASE}/about`, { redirect: 'manual' });
  assert.equal(res.status, 301);
  assert.equal(res.headers.get('location'), '/about/');
});

test('unknown paths get the styled 404 page', async () => {
  const res = await fetch(`${BASE}/no-such-street/`);
  assert.equal(res.status, 404);
  const html = await res.text();
  assert.match(html, /Page not found/);
  assert.match(html, /Back to NearBuy home/);
});

test('path traversal is refused', async () => {
  const res = await fetch(`${BASE}/%2e%2e%2fpackage.json`, { redirect: 'manual' });
  assert.ok(res.status === 400 || res.status === 404, `traversal should be refused, got ${res.status}`);
});

test('every asset referenced in the markup exists on disk', () => {
  const htmlFiles = [
    'index.html',
    'portal.html',
    'classic.html',
    'seller.html',
    'partner.html',
    'business.html',
    'delivery-admin.html',
    'about/index.html',
    'help/index.html',
    'roadmap/index.html',
    'customer/index.html',
    'seller/index.html',
    'runner/index.html'
  ];
  const refRe = /(?:href|src)\s*=\s*["'](\/[^"'#?]+)["']/gi;
  const missing = [];
  for (const f of htmlFiles) {
    const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
    for (const m of src.matchAll(refRe)) {
      const p = m[1];
      if (p.startsWith('//') || p === '/') continue;
      const local = path.join(ROOT, p.replace(/^\/+/, ''));
      const ok =
        fs.existsSync(local) ||
        fs.existsSync(local + '.html') ||
        fs.existsSync(path.join(local, 'index.html'));
      if (!ok) missing.push(`${f} -> ${p}`);
    }
  }
  assert.deepEqual(missing, [], `missing referenced files:\n${missing.join('\n')}`);
});

test('the public checklist keeps all 84 items', () => {
  const src = fs.readFileSync(path.join(ROOT, 'roadmap', 'index.html'), 'utf8');
  const items = (src.match(/class="rl-item"/g) || []).length;
  assert.equal(items, 84, `expected 84 checklist items, found ${items}`);
});
