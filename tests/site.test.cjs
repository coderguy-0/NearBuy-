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

test('path traversal and internal server files are refused', async () => {
  const blocked = [
    '/%2e%2e%2fpackage.json',
    '/.gitignore',
    '/package.json',
    '/package-lock.json',
    '/server/index.js',
    '/server/orders.js',
    '/tools/render-logo.mjs',
    '/tests/site.test.cjs'
  ];
  for (const p of blocked) {
    const res = await fetch(`${BASE}${p}`, { redirect: 'manual' });
    assert.ok(res.status === 400 || res.status === 404, `${p} should be refused, got ${res.status}`);
    await res.body?.cancel();
  }
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

test('every HTML surface uses the universal logo and declares a favicon', () => {
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
    'customer/login/index.html',
    'seller/index.html',
    'seller/register/index.html',
    'runner/index.html',
    'runner/register/index.html',
    'fleet/index.html',
    'admin/index.html',
    'control-tower/index.html'
  ];
  for (const f of htmlFiles) {
    const src = fs.readFileSync(path.join(ROOT, f), 'utf8');
    assert.match(src, /rel=["']icon["']/, `${f} should declare a favicon`);
    assert.match(src, /(?:\/public\/assets\/nearbuy-logo\.png|\/delivery\/logo\.svg)/, `${f} should reference universal logo`);
    assert.doesNotMatch(src, /M22 4\.5/, `${f} should not contain the legacy pin vector`);
  }
  const svgSrc = fs.readFileSync(path.join(ROOT, 'delivery', 'logo.svg'), 'utf8');
  assert.match(svgSrc, /data:image\/png;base64,/, 'delivery/logo.svg should embed universal badge PNG');
});

test('all NearBuy One icons and action hooks are registered', () => {
  const nbJs = fs.readFileSync(path.join(ROOT, 'nearbuy.js'), 'utf8');
  const portalHtml = fs.readFileSync(path.join(ROOT, 'portal.html'), 'utf8');

  const pathsBlock = nbJs.match(/const PATHS = \{([\s\S]*?)\n\};/);
  assert.ok(pathsBlock, 'PATHS icon map should exist in nearbuy.js');
  const registeredIcons = new Set([...pathsBlock[1].matchAll(/^\s*([a-zA-Z0-9_]+)\s*:/gm)].map((m) => m[1]));
  const missingIcons = [];
  for (const m of nbJs.matchAll(/\bicon\(\s*['"]([a-zA-Z0-9_]+)['"]/g)) {
    if (!registeredIcons.has(m[1])) missingIcons.push(m[1]);
  }
  assert.deepEqual([...new Set(missingIcons)], [], 'every icon() literal must exist in PATHS');

  const usedActs = new Set([...(nbJs + '\n' + portalHtml).matchAll(/data-act=["']([a-zA-Z0-9_-]+)["']/g)].map((m) => m[1]));
  const handledActs = new Set([
    ...[...nbJs.matchAll(/case\s+['"]([a-zA-Z0-9_-]+)['"]\s*:/g)].map((m) => m[1]),
    ...[...nbJs.matchAll(/act\s*===\s*['"]([a-zA-Z0-9_-]+)['"]/g)].map((m) => m[1]),
    ...[...nbJs.matchAll(/dataset\.act\s*===\s*['"]([a-zA-Z0-9_-]+)['"]/g)].map((m) => m[1]),
    ...[...nbJs.matchAll(/\[data-act=["']([a-zA-Z0-9_-]+)["']\]/g)].map((m) => m[1])
  ]);
  const unhandledActs = [...usedActs].filter((a) => !handledActs.has(a));
  assert.deepEqual(unhandledActs, [], `unhandled data-act attributes: ${unhandledActs.join(', ')}`);
});


