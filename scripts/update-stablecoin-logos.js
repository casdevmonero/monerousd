#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ─────────────────────────────────────────────────────────────────
// update-stablecoin-logos.js — install the official ERC-20 stable-
// coin brand marks (USDC / USDT / DAI) for the v1.2.202 ETH-network
// stablecoin wrappers (wUSDC-ETH / wUSDT-ETH / wDAI-ETH).
//
// Generalizes the v1.2.201 `update-wbnb-logo.js` pattern across three
// assets at once.  For each entry below, the script:
//
//   1. Resolves the input file from the operator's staging dir
//      (`~/Desktop/connect/scripts/logos/<filename>`) or one of the
//      standard drop spots (cwd, ~/Desktop, ~/Downloads, $HOME).
//   2. Embeds the raster (or inlines the SVG) into a 32×32 SVG
//      container — same shape `update-wbnb-logo.js` produces, so
//      the frontend `assets/tokens/<sym>.svg` URL contract stays
//      unchanged across all wrappers.
//   3. Writes the SVG file in the Ion Swap frontend bundle.
//   4. Updates the desktop wallet's inline `ASSET_LOGO_PATHS[<sym>]`
//      string in `build-1261/renderer/app.js`. Idempotent — replaces
//      an existing line, inserts after the `ASSET_LOGO_PATHS['wBNB']`
//      line if absent (the v1.2.202 first-run case).
//
// Usage (no arguments — auto-finds USDClogo.png / USDTlogo.png /
// DAIlogo.png across standard staging spots):
//
//   node scripts/update-stablecoin-logos.js
//
// The canonical staging dir for these is
// `~/Desktop/connect/scripts/logos/` — `scripts/refund-eth-residual.js`
// uses the same dir convention.
//
// Idempotent.  Safe to re-run.  No backups (commit before running
// if you want one).
// ─────────────────────────────────────────────────────────────────

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

// ── Targets — one entry per wrapper. ────────────────────────────

const REPO_ROOT = require('path').join(require('os').homedir(), 'Desktop/connect');
const DESKTOP_APP_JS = path.join(REPO_ROOT, 'build-1261/renderer/app.js');

const TARGETS = [
  {
    symbol:   'wUSDC-ETH',
    logoBase: 'USDClogo',     // looked up as USDClogo.{png,jpg,jpeg,svg,webp,gif}
    frontendSvg: path.join(
      REPO_ROOT, 'ion-monerousd-org/frontend/assets/tokens/wUSDC-ETH.svg',
    ),
  },
  {
    symbol:   'wUSDT-ETH',
    logoBase: 'USDTlogo',
    frontendSvg: path.join(
      REPO_ROOT, 'ion-monerousd-org/frontend/assets/tokens/wUSDT-ETH.svg',
    ),
  },
  {
    symbol:   'wDAI-ETH',
    logoBase: 'DAIlogo',
    frontendSvg: path.join(
      REPO_ROOT, 'ion-monerousd-org/frontend/assets/tokens/wDAI-ETH.svg',
    ),
  },
];

// Search order per target — first match wins.
const HOME = os.homedir();
const SEARCH_DIRS = [
  path.join(REPO_ROOT, 'scripts/logos'),       // canonical staging dir
  process.cwd(),
  path.join(HOME, 'Desktop'),
  path.join(HOME, 'Downloads'),
  HOME,
];
const SUPPORTED_EXTS = ['.png', '.jpg', '.jpeg', '.svg', '.webp', '.gif'];

const MIME_BY_EXT = {
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif':  'image/gif',
};

function fail(msg) { console.error(`✗ ${msg}`); process.exit(1); }
function ok(msg)   { console.log(`  ✓ ${msg}`); }
function note(msg) { console.log(`  · ${msg}`); }

// ── Per-target file resolver ────────────────────────────────────

function findInputFile(logoBase) {
  for (const dir of SEARCH_DIRS) {
    for (const ext of SUPPORTED_EXTS) {
      const candidate = path.join(dir, logoBase + ext);
      if (fs.existsSync(candidate)) return candidate;
    }
  }
  return null;
}

// ── Build SVG + desktop-inline string from input file ───────────

function buildSvgAndInline(inputPath) {
  const bytes = fs.readFileSync(inputPath);
  if (bytes.length === 0) fail(`Input file empty: ${inputPath}`);
  const ext  = path.extname(inputPath).toLowerCase();
  const head = bytes.toString('utf8', 0, Math.min(200, bytes.length));
  const isSvg = ext === '.svg' || head.includes('<svg');

  if (isSvg) {
    const svgText = bytes.toString('utf8');
    const m = svgText.match(/<svg[^>]*>([\s\S]*?)<\/svg>/i);
    if (!m) fail(`SVG file lacks a <svg>...</svg> root: ${inputPath}`);
    return {
      svgFileContent: svgText,
      desktopInline:  m[1].trim().replace(/\s+/g, ' '),
      kind: 'svg',
    };
  }
  const mime = MIME_BY_EXT[ext];
  if (!mime) fail(`Unsupported extension ${ext} for ${inputPath}`);
  const b64 = bytes.toString('base64');
  const imageEl =
    `<image href="data:${mime};base64,${b64}" ` +
    `x="0" y="0" width="32" height="32" preserveAspectRatio="xMidYMid meet"/>`;
  return {
    svgFileContent:
      `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">${imageEl}</svg>\n`,
    desktopInline: imageEl,
    kind: `raster (${mime})`,
  };
}

// ── Wallet rewrite: replace-if-present, insert-after-wBNB-otherwise ──
//
// The wBNB line is the canonical anchor — it's the LAST entry in the
// stablecoin/wrapper LOGO_PATHS block, immediately before the
// `function assetLogoSvg(...)` declaration.  Every new wrapper added
// post-v1.2.201 should land between those two markers.

function rewriteWalletLine(appJsText, symbol, escapedInline) {
  const sym = symbol.replace(/[-]/g, '\\-');     // regex-safe
  const existingRe = new RegExp(
    String.raw`ASSET_LOGO_PATHS\[['"]${sym}['"]\]\s*=\s*'[^']*';`,
    'm',
  );
  const newLine = `ASSET_LOGO_PATHS['${symbol}'] = '${escapedInline}';`;

  if (existingRe.test(appJsText)) {
    return {
      next:   appJsText.replace(existingRe, newLine),
      action: 'replaced existing line',
    };
  }
  // Insert after the wBNB line.  The anchor is the EXACT line shape
  // the v1.2.201 ship uses; if it's absent (e.g. an older build), the
  // script bails so the operator notices the structural drift instead
  // of silently appending in the wrong place.
  const wbnbRe = /(ASSET_LOGO_PATHS\[['"]wBNB['"]\]\s*=\s*'[^']*';\s*\n)/;
  const match = appJsText.match(wbnbRe);
  if (!match) {
    fail(
      `Could not find ASSET_LOGO_PATHS['wBNB'] anchor line in ${DESKTOP_APP_JS}.\n` +
      `  Manual fix required: open the file and add\n` +
      `    ${newLine}\n` +
      `  somewhere inside the LOGO_PATHS block (near the wBNB line).`,
    );
  }
  return {
    next:   appJsText.replace(wbnbRe, `$1${newLine}\n`),
    action: 'inserted after wBNB anchor',
  };
}

// ── Run all three ──────────────────────────────────────────────

console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
console.log('  update-stablecoin-logos — installing official brand');
console.log('  marks for wUSDC-ETH / wUSDT-ETH / wDAI-ETH');
console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');

let appJsText = fs.readFileSync(DESKTOP_APP_JS, 'utf8');
let walletPatches = 0;

for (const tgt of TARGETS) {
  console.log(`\n[${tgt.symbol}]`);
  const inputPath = findInputFile(tgt.logoBase);
  if (!inputPath) {
    console.error(`  ✗ Could not find ${tgt.logoBase}.{png,jpg,jpeg,svg,webp,gif} in:`);
    SEARCH_DIRS.forEach((d) => console.error(`      ${d}`));
    continue;
  }
  ok(`input: ${inputPath}`);
  const built = buildSvgAndInline(inputPath);
  ok(`built (${built.kind})`);

  // Frontend SVG.
  fs.writeFileSync(tgt.frontendSvg, built.svgFileContent);
  ok(`wrote ${tgt.frontendSvg} (${built.svgFileContent.length} bytes)`);

  // Desktop wallet inline.
  const escapedInline = built.desktopInline
    .replace(/\\/g, '\\\\')
    .replace(/'/g, "\\'");
  const result = rewriteWalletLine(appJsText, tgt.symbol, escapedInline);
  appJsText = result.next;
  walletPatches += 1;
  ok(`wallet: ${result.action} (${escapedInline.length} chars inline)`);
}

if (walletPatches > 0) {
  fs.writeFileSync(DESKTOP_APP_JS, appJsText);
  console.log(`\n✓ Wrote ${DESKTOP_APP_JS} (${walletPatches} ASSET_LOGO_PATHS entries)`);
}

// ── Verify ──────────────────────────────────────────────────────

console.log('\n━━━ Verification ━━━');
const verify = fs.readFileSync(DESKTOP_APP_JS, 'utf8');
for (const tgt of TARGETS) {
  const sym = tgt.symbol.replace(/[-]/g, '\\-');
  const re = new RegExp(
    String.raw`ASSET_LOGO_PATHS\[['"]${sym}['"]\]\s*=\s*'`,
    'm',
  );
  if (re.test(verify)) {
    note(`${tgt.symbol}: present in wallet ASSET_LOGO_PATHS ✓`);
  } else {
    console.error(`  ✗ ${tgt.symbol}: NOT FOUND in wallet — manual fix required`);
  }
  if (fs.existsSync(tgt.frontendSvg)) {
    const sz = fs.statSync(tgt.frontendSvg).size;
    note(`${tgt.symbol}: ${tgt.frontendSvg} (${sz} bytes) ✓`);
  } else {
    console.error(`  ✗ ${tgt.symbol}: frontend SVG missing`);
  }
}

console.log('\nNext: rebuild the wallet for OTA + redeploy the Ion Swap frontend.');
console.log('  cd ~/Desktop/connect && \\');
console.log('    bash scripts/safe-deploy-ion-frontend.sh --execute');
