#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// ─────────────────────────────────────────────────────────────────
// update-wbnb-logo.js — drop-in script for swapping the wBNB logo.
//
// Looks for `BNBlogo.jpeg` (the operator's official BNB Chain logo
// file) in common locations, then updates BOTH:
//
//   1. Frontend:  ion-monerousd-org/frontend/assets/tokens/wBNB.svg
//   2. Desktop:   build-1261/renderer/app.js  ASSET_LOGO_PATHS['wBNB']
//
// Search order (first match wins):
//   - ./BNBlogo.jpeg                (current working directory)
//   - $HOME/Desktop/BNBlogen.jpeg   (most common drop-spot)
//   - $HOME/Downloads/BNBlogo.jpeg
//   - $HOME/BNBlogo.jpeg
//   - argv[2] if passed (override)
//
// Frontend loader expects an SVG file at wBNB.svg, so for raster
// input we wrap the JPEG as a base64-embedded <image> inside a
// 32x32 SVG. The URL contract stays unchanged.
//
// Usage (no arguments — auto-finds BNBlogo.jpeg in standard spots):
//   node ~/Desktop/connect/scripts/update-wbnb-logo.js
//
// Optional override:
//   node ~/Desktop/connect/scripts/update-wbnb-logo.js /custom/path.jpeg
//
// Idempotent — safe to re-run with a different file. The previous
// content is overwritten in place. No backups (commit before
// running if you want one).
// ─────────────────────────────────────────────────────────────────

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const REPO_ROOT = require('path').join(require('os').homedir(), 'Desktop/connect');
const FRONTEND_LOGO = path.join(
  REPO_ROOT, 'ion-monerousd-org/frontend/assets/tokens/wBNB.svg',
);
const DESKTOP_APP_JS = path.join(REPO_ROOT, 'build-1261/renderer/app.js');

// File the operator dropped into one of the standard spots.
const TARGET_FILENAME = 'BNBlogo.jpeg';

const HOME = os.homedir();
const SEARCH_PATHS = [
  path.resolve(process.cwd(), TARGET_FILENAME),
  path.join(HOME, 'Desktop',   TARGET_FILENAME),
  path.join(HOME, 'Downloads', TARGET_FILENAME),
  path.join(HOME, TARGET_FILENAME),
];

// ── MIME map for raster wrapping ────────────────────────────────

const MIME_BY_EXT = {
  '.png':  'image/png',
  '.jpg':  'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif':  'image/gif',
};

function fail(msg) { console.error(`✗ ${msg}`); process.exit(1); }
function ok(msg)   { console.log(`✓ ${msg}`); }

// ── Resolve the input file ──────────────────────────────────────

const overridePath = process.argv[2];
let inputPath;

if (overridePath) {
  if (!fs.existsSync(overridePath)) {
    fail(`Override path does not exist: ${overridePath}`);
  }
  inputPath = overridePath;
  ok(`Using override path: ${inputPath}`);
} else {
  for (const candidate of SEARCH_PATHS) {
    if (fs.existsSync(candidate)) {
      inputPath = candidate;
      ok(`Found ${TARGET_FILENAME} at ${candidate}`);
      break;
    }
  }
  if (!inputPath) {
    console.error(`✗ Could not find ${TARGET_FILENAME} in any of:`);
    SEARCH_PATHS.forEach((p) => console.error(`    ${p}`));
    console.error('');
    console.error(`Drop the file in one of those locations, or pass a path:`);
    console.error(`  node ${path.basename(process.argv[1])} /path/to/your/logo.jpeg`);
    process.exit(1);
  }
}

const bytes = fs.readFileSync(inputPath);
if (bytes.length === 0) fail('Input file is empty');
ok(`Read ${bytes.length} bytes`);

// ── Build the SVG file content + the desktop-wallet inline content ─

const ext = path.extname(inputPath).toLowerCase();
let svgFileContent;
let desktopInline;

// Detect SVG vs raster. SVG can have any extension in theory, so
// also peek at the first 200 bytes for a `<svg` tag.
const head = bytes.toString('utf8', 0, Math.min(200, bytes.length));
const isSvg = ext === '.svg' || head.includes('<svg');

if (isSvg) {
  svgFileContent = bytes.toString('utf8');
  const m = svgFileContent.match(/<svg[^>]*>([\s\S]*?)<\/svg>/i);
  if (!m) fail('SVG file does not contain a <svg>...</svg> root element');
  desktopInline = m[1].trim().replace(/\s+/g, ' ');
  ok('Detected SVG input — using verbatim for frontend, extracted inner for desktop');
} else {
  const mime = MIME_BY_EXT[ext];
  if (!mime) {
    fail(
      `Unsupported extension: ${ext}. Supported: SVG, PNG, JPG/JPEG, WebP, GIF.`,
    );
  }
  const b64 = bytes.toString('base64');
  // Embed the raster image inside a 32x32 SVG so the frontend's
  // wBNB.svg URL contract stays unchanged. The <image> element
  // scales the source bytes to 32x32; if the source is non-square,
  // preserveAspectRatio handles the centering.
  const imageEl =
    `<image href="data:${mime};base64,${b64}" ` +
    `x="0" y="0" width="32" height="32" preserveAspectRatio="xMidYMid meet"/>`;
  svgFileContent =
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32">${imageEl}</svg>\n`;
  desktopInline = imageEl;
  ok(`Raster input (${mime}) — wrapping as base64-embedded SVG`);
}

// ── Write the frontend SVG ──────────────────────────────────────

fs.writeFileSync(FRONTEND_LOGO, svgFileContent);
ok(`Wrote ${FRONTEND_LOGO} (${svgFileContent.length} bytes)`);

// ── Update the desktop wallet's inline ASSET_LOGO_PATHS['wBNB'] ──

const appJs = fs.readFileSync(DESKTOP_APP_JS, 'utf8');
const wbnbLineRegex = /ASSET_LOGO_PATHS\[['"]wBNB['"]\]\s*=\s*'[^']*';/;
if (!wbnbLineRegex.test(appJs)) {
  fail(
    `Could not find ASSET_LOGO_PATHS['wBNB'] line in ${DESKTOP_APP_JS}.\n` +
    `  Frontend SVG WAS updated; desktop wallet was NOT.\n` +
    `  Manual fix: paste the SVG inner content into that line yourself.`,
  );
}

// JS-string-escape the inline content so it survives single-quoted embedding.
const escapedInline = desktopInline.replace(/\\/g, '\\\\').replace(/'/g, "\\'");
const newLine = `ASSET_LOGO_PATHS['wBNB'] = '${escapedInline}';`;
const newAppJs = appJs.replace(wbnbLineRegex, newLine);

fs.writeFileSync(DESKTOP_APP_JS, newAppJs);
ok(`Updated ${DESKTOP_APP_JS} — ${escapedInline.length} chars inline`);

// ── Verify by re-reading + spot-checking ────────────────────────

const verify = fs.readFileSync(DESKTOP_APP_JS, 'utf8');
const updatedLine = verify.match(wbnbLineRegex);
const checkSlice = escapedInline.slice(0, Math.min(40, escapedInline.length));
if (!updatedLine || !updatedLine[0].includes(checkSlice)) {
  fail('Verification failed — the desktop wallet line did not update correctly');
}
ok('Verified the desktop wallet line was rewritten correctly');

console.log('');
console.log('To preview:');
console.log(`  open ${FRONTEND_LOGO}`);
console.log('');
console.log('To deploy the new logo to production (frontend-only — no backend redeploy needed):');
console.log(`  cd ${REPO_ROOT} && bash scripts/safe-deploy-ion-frontend.sh --execute`);
console.log('');
console.log('Wallet users get the new desktop logo on their next OTA build.');
