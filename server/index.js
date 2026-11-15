#!/usr/bin/env node
/*
 * NearBuy static server — zero dependencies, no build step.
 *
 * Serves the public site and every clean-URL surface from the repository root:
 *
 *   /                    index.html (universal homepage)
 *   /portal.html         NearBuy One product shell (hash-routed workspaces)
 *   /customer/  /seller/  /runner/  /fleet/  /admin/  /control-tower/
 *   /seller/register/  /runner/register/  /customer/login/
 *   /about/  /help/  /roadmap/  /delivery/  /public/assets/
 *
 * Behaviour notes
 *   - Directory URLs resolve to their index.html (`/about/` -> about/index.html).
 *   - Extensionless directory URLs 301 to the trailing-slash form (`/about` -> `/about/`).
 *   - Conditional requests are honoured (ETag + If-None-Match -> 304).
 *   - Traversal, null bytes and dotfiles are refused; unknown paths get a styled 404.
 *   - `/favicon.ico` maps to the brand mark so browsers never log a missing icon.
 *
 * Configuration (all optional):
 *   PORT      listen port            (default 4173)
 *   HOST      listen address         (default 0.0.0.0)
 *   ROOT      directory to serve     (default: repository root)
 */
'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');

const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || '0.0.0.0';
const ROOT = path.resolve(process.env.ROOT || path.join(__dirname, '..'));

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.htm': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.map': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.gif': 'image/gif',
  '.webp': 'image/webp',
  '.avif': 'image/avif',
  '.ico': 'image/x-icon',
  '.woff2': 'font/woff2',
  '.woff': 'font/woff',
  '.ttf': 'font/ttf',
  '.otf': 'font/otf',
  '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/plain; charset=utf-8',
  '.webmanifest': 'application/manifest+json',
  '.mp4': 'video/mp4',
  '.webm': 'video/webm'
};

const IMMUTABLE = new Set(['.woff2', '.woff', '.png', '.jpg', '.jpeg', '.webp', '.avif', '.svg', '.gif']);

const notFoundHtml = `<!doctype html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Page not found · NearBuy</title>
<link rel="icon" href="/public/assets/nearbuy-logo.png" />
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body {
    margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px;
    background: #fbf7f0; color: #223350;
    font: 400 16px/1.6 'DM Sans', ui-sans-serif, system-ui, -apple-system, 'Segoe UI', sans-serif;
  }
  main { max-width: 560px; text-align: center; }
  .mark { width: 72px; height: 72px; margin: 0 auto 18px; display: block; }
  h1 { font: 800 40px/1.1 'Manrope', ui-sans-serif, system-ui, sans-serif; color: #0c1a33; margin: 0 0 10px; }
  p { margin: 0 0 26px; color: #6f7b8f; }
  a.btn {
    display: inline-block; padding: 12px 22px; border-radius: 999px; text-decoration: none;
    background: #f47718; color: #fff; font: 700 15px/1 'Manrope', system-ui, sans-serif;
    box-shadow: 0 10px 24px rgba(244, 119, 24, .32);
  }
  a.btn:hover { background: #d95f0a; }
  code { background: #f2ece1; border-radius: 6px; padding: 2px 6px; color: #0c1a33; font-size: 14px; }
</style>
</head>
<body>
<main>
  <svg class="mark" viewBox="0 0 44 44" aria-hidden="true">
    <path d="M22 4.5c-7.7 0-14 6.1-14 13.6 0 9.6 11 20.4 13.3 22.4a1 1 0 0 0 1.4 0C25 38.5 36 27.7 36 18.1 36 10.6 29.7 4.5 22 4.5Z" fill="#1b3a72"/>
    <circle cx="22" cy="18" r="7.4" fill="none" stroke="#fff" stroke-width="3.4"/>
    <path d="M6.5 25.5c5.5 4.6 15 6.6 30.5-1.4" fill="none" stroke="#f47718" stroke-width="3.6" stroke-linecap="round"/>
  </svg>
  <h1>This street isn&rsquo;t on our map.</h1>
  <p>The page <code id="path"></code> doesn&rsquo;t exist on NearBuy. Head back to the neighbourhood and pick a portal.</p>
  <a class="btn" href="/">Back to NearBuy home</a>
</main>
<script>document.getElementById('path').textContent = location.pathname;</script>
</body>
</html>
`;

/** Map a request path to an absolute file path inside ROOT, or null when refused. */
function resolvePath(urlPath) {
  let clean;
  try {
    clean = decodeURIComponent(urlPath);
  } catch {
    return null;
  }
  if (clean.includes('\0')) return null;

  if (clean === '/favicon.ico') clean = '/public/assets/nearbuy-logo.png';

  const rel = clean.replace(/^\/+/, '');
  const abs = path.resolve(ROOT, rel || '.');
  if (abs !== ROOT && !abs.startsWith(ROOT + path.sep)) return null;
  return abs;
}

function etagOf(stat) {
  return `"${createHash('sha1')
    .update(`${stat.size}-${stat.mtimeMs}`)
    .digest('base64')
    .slice(0, 27)}"`;
}

function send404(res, method) {
  const body = Buffer.from(notFoundHtml, 'utf8');
  res.writeHead(404, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': body.length,
    'Cache-Control': 'no-cache'
  });
  if (method !== 'HEAD') res.end(body);
  else res.end();
}

function serveFile(req, res, file, stat) {
  const ext = path.extname(file).toLowerCase();
  const type = MIME[ext] || 'application/octet-stream';
  const etag = etagOf(stat);
  const headers = {
    'Content-Type': type,
    'ETag': etag,
    'Cache-Control': IMMUTABLE.has(ext) ? 'public, max-age=86400' : 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'Last-Modified': stat.mtime.toUTCString()
  };

  if (req.headers['if-none-match'] === etag) {
    res.writeHead(304, headers);
    res.end();
    return;
  }

  headers['Content-Length'] = stat.size;
  res.writeHead(200, headers);
  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  const stream = fs.createReadStream(file);
  stream.on('error', () => res.destroy());
  stream.pipe(res);
}

function redirect(res, to, code = 301) {
  res.writeHead(code, { Location: to, 'Cache-Control': 'no-cache' });
  res.end();
}

const server = http.createServer((req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { Allow: 'GET, HEAD', 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Method not allowed');
    return;
  }

  const urlPath = (req.url || '/').split('?')[0].split('#')[0] || '/';
  const abs = resolvePath(urlPath);
  if (!abs) {
    res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Bad request');
    return;
  }

  fs.stat(abs, (err, stat) => {
    if (!err && stat.isDirectory()) {
      // `/about` -> `/about/` so relative asset paths resolve correctly.
      if (!urlPath.endsWith('/')) {
        redirect(res, urlPath + '/' + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : ''));
        return;
      }
      const indexFile = path.join(abs, 'index.html');
      fs.stat(indexFile, (err2, indexStat) => {
        if (err2 || !indexStat.isFile()) return send404(res, req.method);
        serveFile(req, res, indexFile, indexStat);
      });
      return;
    }

    if (!err && stat.isFile()) {
      serveFile(req, res, abs, stat);
      return;
    }

    // Extensionless file URL -> try the .html sibling (`/about` served by about.html).
    if (err && !path.extname(abs)) {
      const htmlFile = abs + '.html';
      fs.stat(htmlFile, (err2, htmlStat) => {
        if (err2 || !htmlStat.isFile()) return send404(res, req.method);
        serveFile(req, res, htmlFile, htmlStat);
      });
      return;
    }

    send404(res, req.method);
  });
});

server.on('error', (err) => {
  if (err && err.code === 'EADDRINUSE') {
    process.stderr.write(`[nearbuy] port ${PORT} is already in use\n`);
    process.exit(1);
  }
  process.stderr.write(`[nearbuy] server error: ${err.message}\n`);
  process.exit(1);
});

server.listen(PORT, HOST, () => {
  process.stdout.write(`[nearbuy] serving ${ROOT}\n`);
  process.stdout.write(`[nearbuy] http://localhost:${PORT}\n`);
});
