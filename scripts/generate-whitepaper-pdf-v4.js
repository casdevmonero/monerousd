// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// generate-whitepaper-pdf-v4.js  — canonical generator for monerousd.org
//
// Produces the downloadable MoneroUSD_Whitepaper.pdf for the
// casdevmonero/monerousd-org-site GitHub Pages repo (monerousd.org).
//
// WHY v4 (vs v1/v2/v3): the earlier scripts each carried their OWN copy of the
// dark print CSS and injected it after stripping the page's @media print block.
// That duplication is exactly what drifted out of sync and let a WHITE-bg PDF
// ship (the page was printed through its @media print block, which used to swap
// the dark theme to white and never set print-color-adjust:exact).
//
// Fix: whitepaper.html's @media print block is now THE dark theme itself
// (#0a0a0a bg / #eaeaea text / #FF6600 accent, full-bleed @page margin:0,
// print-color-adjust:exact). So this generator injects NOTHING — it just loads
// the page and prints it with printBackground:true. One stylesheet, two
// consumers (browser Ctrl-P and this generator) → they can never diverge again.
//
// Usage:
//   SITE_DIR=/path/to/monerousd-org-site node scripts/generate-whitepaper-pdf-v4.js
// Optional env: WP_SOURCE (default whitepaper.html), WP_OUTPUT, CHROME (browser path).
//
// Browser: prefers puppeteer-core + the system Chrome (no Chromium download);
// falls back to a full `puppeteer` install if present.

const http = require('http');
const fs = require('fs');
const path = require('path');

const SITE_DIR = process.env.SITE_DIR || process.cwd();
const SOURCE = process.env.WP_SOURCE || 'whitepaper.html';
const OUTPUT = process.env.WP_OUTPUT || path.join(SITE_DIR, 'MoneroUSD_Whitepaper.pdf');

// Resolve a browser: puppeteer-core (needs executablePath) or bundled puppeteer.
function resolveBrowser() {
  try {
    const p = require('puppeteer-core');
    const candidates = [
      process.env.CHROME,
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
      '/usr/bin/google-chrome',
      '/usr/bin/chromium-browser',
      '/usr/bin/chromium',
    ].filter(Boolean);
    const exe = candidates.find((c) => { try { return fs.existsSync(c); } catch (_) { return false; } });
    if (!exe) throw new Error('no system Chrome found; set CHROME=<path>');
    return { puppeteer: p, launchOpts: { executablePath: exe } };
  } catch (e) {
    if (e && e.code === 'MODULE_NOT_FOUND') return { puppeteer: require('puppeteer'), launchOpts: {} };
    throw e;
  }
}

const MIME = {
  '.html': 'text/html; charset=utf-8', '.css': 'text/css', '.js': 'application/javascript',
  '.svg': 'image/svg+xml', '.woff2': 'font/woff2', '.woff': 'font/woff',
  '.png': 'image/png', '.jpg': 'image/jpeg', '.json': 'application/json',
};

(async () => {
  const { puppeteer, launchOpts } = resolveBrowser();

  // Serve SITE_DIR over loopback so absolute /fonts and /logo.svg URLs resolve.
  const server = http.createServer((req, res) => {
    let rel = decodeURIComponent(req.url.split('?')[0]);
    if (rel === '/') rel = '/' + SOURCE;
    const full = path.join(SITE_DIR, path.normalize(rel));
    if (!full.startsWith(SITE_DIR) || !fs.existsSync(full) || fs.statSync(full).isDirectory()) {
      res.statusCode = 404; res.end('not found'); return;
    }
    res.setHeader('Content-Type', MIME[path.extname(full)] || 'application/octet-stream');
    fs.createReadStream(full).pipe(res);
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const url = `http://127.0.0.1:${server.address().port}/${SOURCE}`;

  const browser = await puppeteer.launch({
    headless: 'new',
    args: ['--no-sandbox', '--disable-setuid-sandbox'],
    ...launchOpts,
  });
  const page = await browser.newPage();
  await page.goto(url, { waitUntil: 'networkidle0', timeout: 60000 });
  await page.evaluate(async () => { if (document.fonts && document.fonts.ready) await document.fonts.ready; });

  await page.pdf({
    path: OUTPUT,
    printBackground: true,     // keep the dark backgrounds
    preferCSSPageSize: true,   // honor @page { size: letter; margin: 0 }
    displayHeaderFooter: false,
    margin: { top: '0', bottom: '0', left: '0', right: '0' },
  });

  await browser.close();
  server.close();
  const stats = fs.statSync(OUTPUT);
  console.log('PDF generated: ' + OUTPUT);
  console.log('Size: ' + (stats.size / 1024).toFixed(1) + ' KB');
})().catch((e) => { console.error(e); process.exit(1); });
