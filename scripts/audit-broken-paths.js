#!/usr/bin/env node
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

// audit-broken-paths.js
//
// Permanent guard against broken file paths + missing globals +
// IPC drift. Run on every safe-deploy invocation (frontend +
// backend + wallet OTA). Fails the build with a non-zero exit
// code on any finding.
//
// What it checks
//   1. Every <script src=...> and <link href=...> in HTML files
//      resolves to an actual file on disk.
//   2. Every static `import X from './path.js'` or
//      `require('./path.js')` in scanned JS resolves on disk.
//   3. Every `window.electronAPI.X()` call has a matching
//      `electronAPI.X` definition in preload.js (per-app).
//   4. Every `ipcRenderer.invoke('X')` call has a matching
//      `ipcMain.handle('X', ...)` in main.js (per-app).
//   5. Every `window.X(...)` call where X is NOT a browser
//      built-in is either defined in renderer code OR called via
//      `window.X?.(...)` (optional-chaining is the explicit
//      "fallback if missing" idiom — exempt).
//
// Usage
//   node scripts/audit-broken-paths.js                  # all roots
//   node scripts/audit-broken-paths.js --root desktop-wallet
//   node scripts/audit-broken-paths.js --root monerousd-wallet-v2/dist
//   node scripts/audit-broken-paths.js --json
//
// --root accepts desktop-wallet, ionswap, or a configured directory path
// relative to the repository. A name selects the legacy deployment directory
// when present, otherwise the public source directory. A path selects it exactly.

import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

// ── Per-root config ─────────────────────────────────────────────
const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const LAYOUTS = {
  'desktop-wallet': [
    { dir: 'build-1261', htmlEntries: ['renderer/index.html'], jsRoots: ['renderer'], preload: 'preload.js', mainProc: 'main.js' },
    { dir: 'monerousd-wallet-v2/dist' },
  ],
  ionswap: [
    { dir: 'ion-monerousd-org/frontend' },
    { dir: 'monerousd-node-zkdag/sites/ionswap-monerousd-org' },
  ],
};

// ── CLI args ────────────────────────────────────────────────────
let options;
try {
  options = parseArgs({ options: { root: { type: 'string' }, json: { type: 'boolean' } } }).values;
} catch (error) {
  console.error(`[audit-broken-paths] ${error.message}`);
  process.exit(2);
}

const roots = [];
for (const [name, layouts] of Object.entries(LAYOUTS)) {
  let layout;
  if (options.root === undefined || options.root === name) {
    layout = layouts.find(({ dir }) => fs.existsSync(path.join(REPO, dir))) ?? layouts.at(-1);
  } else {
    layout = layouts.find(({ dir }) => path.relative(path.resolve(REPO, options.root), path.join(REPO, dir)) === '');
  }
  if (layout) {
    roots.push({ name, base: path.join(REPO, layout.dir), htmlEntries: ['index.html'], jsRoots: ['.'], ...layout });
  }
}
if (!roots.length) {
  console.error(`[audit-broken-paths] Unknown root "${options.root}". Use desktop-wallet, ionswap, or a configured directory path.`);
  process.exit(2);
}

// ── Browser built-ins that are always safe to call without
//    a renderer-side definition. Anything NOT in this list and
//    NOT defined locally and NOT optional-chained is a finding.
const BROWSER_GLOBALS = new Set([
  // Core BOM / DOM
  'addEventListener', 'removeEventListener', 'dispatchEvent',
  'document', 'navigator', 'history', 'location', 'localStorage',
  'sessionStorage', 'crypto', 'console', 'JSON', 'Math', 'Date',
  'Promise', 'Map', 'Set', 'WeakMap', 'WeakSet', 'Symbol',
  'fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource',
  'requestAnimationFrame', 'cancelAnimationFrame',
  'requestIdleCallback', 'cancelIdleCallback',
  'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
  'queueMicrotask', 'AbortController', 'AbortSignal',
  'innerWidth', 'innerHeight', 'outerWidth', 'outerHeight',
  'devicePixelRatio', 'matchMedia', 'getComputedStyle',
  'getSelection', 'scrollTo', 'scroll', 'scrollBy',
  'open', 'close', 'focus', 'blur', 'print',
  'alert', 'confirm', 'prompt',
  'isSecureContext', 'PublicKeyCredential', 'CredentialsContainer',
  'Notification', 'Worker', 'SharedWorker', 'BroadcastChannel',
  'TextEncoder', 'TextDecoder', 'CompressionStream', 'DecompressionStream',
  'CustomEvent', 'Event', 'MessageEvent', 'ErrorEvent',
  'URL', 'URLSearchParams', 'FormData', 'FileReader', 'Blob', 'File',
  'Image', 'Audio', 'HTMLImageElement', 'HTMLAudioElement',
  'IntersectionObserver', 'MutationObserver', 'ResizeObserver',
  'PerformanceObserver', 'performance',
  // Capability-detected Web APIs (always guarded by an `in window`
  // / typeof check before use; not universally supported but a real
  // built-in, NOT a missing local symbol). BarcodeDetector backs the
  // wallet's Scan-to-Pay QR camera (renderer/app.js, feature-gated by
  // `'BarcodeDetector' in window`).
  'BarcodeDetector',
  'caches', 'indexedDB', 'IDBKeyRange',
  'Response', 'Request', 'Headers',
  'name', 'parent', 'top', 'self', 'frames', 'frameElement',
  // Common app-injected globals (electron preload safe set)
  'electronAPI', 'monerousd', 'api',
]);

// ── State ───────────────────────────────────────────────────────
const findings = [];
function found(category, root, file, line, detail) {
  findings.push({ category, root, file: path.relative(REPO, file), line, detail });
}

// ── File walking ────────────────────────────────────────────────
function walk(root, predicate, out = []) {
  if (!fs.existsSync(root)) return out;
  for (const name of fs.readdirSync(root)) {
    if (name === 'node_modules' || name === 'dist' || name === '.git'
        || name === 'tests' || name === '.deploy-backups') continue;
    const full = path.join(root, name);
    let stat;
    try { stat = fs.statSync(full); } catch { continue; }
    if (stat.isDirectory()) walk(full, predicate, out);
    else if (predicate(full)) out.push(full);
  }
  return out;
}

// ── Helpers for reading files with line numbers ─────────────────
function readLines(file) {
  try {
    const raw = fs.readFileSync(file, 'utf8');
    return stripCommentsByLine(raw).split(/\r?\n/);
  } catch { return null; }
}
function stripCommentsByLine(src) {
  // Replace /* … */ block comments with same-length whitespace so
  // line numbers + columns stay accurate but text inside comments
  // doesn't trigger our pattern matchers (the pre-fix audit flagged
  // `electronAPI.sovereign` from a JSDoc comment).
  return src.replace(/\/\*[\s\S]*?\*\//g, (m) =>
    m.replace(/[^\n]/g, ' ')
  );
}

// ── Check 1: HTML script src + link href ────────────────────────
function checkHtml(root, htmlPath) {
  const full = path.join(root.base, htmlPath);
  if (!fs.existsSync(full)) {
    found('html-missing-entry', root.name, full, 0, htmlPath + ' missing');
    return;
  }
  const html = fs.readFileSync(full, 'utf8');
  const rgx = /(?:<script[^>]+src|<link[^>]+href|<img[^>]+src)\s*=\s*["']([^"']+)["']/g;
  const lines = html.split(/\r?\n/);
  let m;
  while ((m = rgx.exec(html)) !== null) {
    const ref = m[1];
    if (!ref || /^https?:|^data:|^blob:|^#/.test(ref)) continue;
    // Strip query string + cache-bust before resolving.
    const clean = ref.split('?')[0].split('#')[0];
    if (!clean) continue;
    const resolved = path.resolve(path.dirname(full), clean);
    if (!fs.existsSync(resolved)) {
      const lineNo = lines.findIndex(l => l.includes(ref)) + 1;
      found('html-broken-asset', root.name, full, lineNo, `${ref} → ${path.relative(REPO, resolved)}`);
    }
  }
}

// ── Check 2: JS import / require resolution ─────────────────────
function checkJsImports(root, jsFile) {
  const lines = readLines(jsFile);
  if (!lines) return;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // AUDIT-EXEMPT escape hatch — for runtime-loaded paths that
    // aren't part of this codebase (e.g. WASM from /pkg/, dynamic
    // CDN). The exempt annotation MUST cite the reason so a future
    // reviewer can decide whether the suppression is still valid.
    if (/AUDIT-EXEMPT:/i.test(line)) continue;
    // Match static imports + dynamic imports + require() with relative paths.
    const importRgx = /(?:^|\s)(?:import\s+(?:[^'"]*?\s+from\s+)?|require\s*\(|import\s*\()\s*['"]([^'"]+)['"]/g;
    let m;
    while ((m = importRgx.exec(line)) !== null) {
      const ref = m[1];
      // Skip bare specifiers (npm package imports) — only check relative.
      if (!ref.startsWith('./') && !ref.startsWith('../') && !ref.startsWith('/')) continue;
      // Skip protocol-prefixed.
      if (/^https?:|^data:/.test(ref)) continue;
      // Strip query (?v=N), hash (#frag), or trailing whitespace.
      const clean = ref.split('?')[0].split('#')[0];
      if (!clean) continue;
      // Resolve. Try .js extension if missing.
      let resolved = path.resolve(path.dirname(jsFile), clean);
      if (!fs.existsSync(resolved)) {
        if (fs.existsSync(resolved + '.js')) resolved += '.js';
        else if (fs.existsSync(path.join(resolved, 'index.js'))) resolved = path.join(resolved, 'index.js');
        else if (fs.existsSync(resolved + '.cjs')) resolved += '.cjs';
        else if (fs.existsSync(resolved + '.mjs')) resolved += '.mjs';
        else if (fs.existsSync(resolved + '.json')) resolved += '.json';
        else {
          found('js-broken-import', root.name, jsFile, i + 1, ref);
          continue;
        }
      }
    }
  }
}

// ── Check 3-4: electronAPI + ipcRenderer round-trip ─────────────
function buildElectronAPISet(root) {
  const set = new Set();
  if (!root.preload) return set;
  const file = path.join(root.base, root.preload);
  if (!fs.existsSync(file)) return set;
  const src = fs.readFileSync(file, 'utf8');
  // Crude but effective: any identifier preceded by `: (` or `:` or
  // followed by `:` inside an object literal. We pick up
  // `<name>:` at the start of a property line.
  const rgx = /^\s*([a-zA-Z_$][a-zA-Z_$0-9]*)\s*:\s*(?:\(|function|async|\(?[^=,\n]*=>)/gm;
  let m;
  while ((m = rgx.exec(src)) !== null) {
    set.add(m[1]);
  }
  return set;
}

function buildIpcHandlerSet(root) {
  const set = new Set();
  if (!root.mainProc) return set;
  const file = path.join(root.base, root.mainProc);
  if (!fs.existsSync(file)) return set;
  const src = fs.readFileSync(file, 'utf8');
  const rgx = /ipcMain\.(?:handle|on)\s*\(\s*['"]([^'"]+)['"]/g;
  let m;
  while ((m = rgx.exec(src)) !== null) set.add(m[1]);
  return set;
}

function checkElectronAPICalls(root, jsFile, apiSet) {
  if (!apiSet || apiSet.size === 0) return;
  const lines = readLines(jsFile);
  if (!lines) return;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Skip comments
    if (/^\s*\/\//.test(line)) continue;
    // Find `electronAPI.X(` calls AND `electronAPI.X` member reads
    // — both should resolve to defined keys. Skip optional-chained
    // forms (`electronAPI?.X` → defensive, exempt).
    const rgx = /(?<!\?)\belectronAPI\.([a-zA-Z_$][a-zA-Z_$0-9]*)/g;
    let m;
    while ((m = rgx.exec(line)) !== null) {
      const name = m[1];
      if (!apiSet.has(name)) {
        found('electronAPI-missing', root.name, jsFile, i + 1, `electronAPI.${name}`);
      }
    }
  }
}

function checkIpcInvocations(root, jsFile, ipcSet) {
  if (!ipcSet || ipcSet.size === 0) return;
  const lines = readLines(jsFile);
  if (!lines) return;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*\/\//.test(line)) continue;
    const rgx = /ipcRenderer\.(?:invoke|send|sendSync)\s*\(\s*['"]([^'"]+)['"]/g;
    let m;
    while ((m = rgx.exec(line)) !== null) {
      const channel = m[1];
      if (!ipcSet.has(channel)) {
        found('ipc-handler-missing', root.name, jsFile, i + 1, `'${channel}'`);
      }
    }
  }
}

// ── Check 5: undefined window.X function calls ──────────────────
function buildLocalWindowExports(root) {
  const set = new Set(BROWSER_GLOBALS);
  const jsFiles = root.jsRoots.flatMap((r) =>
    walk(path.join(root.base, r), (f) => f.endsWith('.js') || f.endsWith('.cjs')));
  if (root.preload) {
    const p = path.join(root.base, root.preload);
    if (fs.existsSync(p)) jsFiles.push(p);
  }
  for (const f of jsFiles) {
    const src = readLines(f);
    if (!src) continue;
    for (const line of src) {
      const m1 = /\bwindow\.([a-zA-Z_$][a-zA-Z_$0-9]*)\s*=/.exec(line);
      if (m1) set.add(m1[1]);
      const m2 = /exposeInMainWorld\s*\(\s*['"]([a-zA-Z_$][a-zA-Z_$0-9]*)['"]/.exec(line);
      if (m2) set.add(m2[1]);
    }
  }
  return set;
}

function checkUndefinedWindowCalls(root, jsFile, exportsSet) {
  const lines = readLines(jsFile);
  if (!lines) return;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/^\s*\/\//.test(line)) continue;
    // Strip inline trailing comment
    const stripped = line.replace(/\/\/[^"']*$/, '');
    // Match `window.X(` calls — NOT optional-chained (`window.X?.(` is exempt).
    const rgx = /(?<!\?)\bwindow\.([a-zA-Z_$][a-zA-Z_$0-9]*)\s*\(/g;
    let m;
    while ((m = rgx.exec(stripped)) !== null) {
      const name = m[1];
      if (!exportsSet.has(name)) {
        found('window-undefined', root.name, jsFile, i + 1, `window.${name}()`);
      }
    }
  }
}

// ── Audit driver ────────────────────────────────────────────────
function auditRoot(root) {
  if (!fs.existsSync(root.base)) {
    found('root-missing', root.name, root.base, 0, 'root path does not exist');
    return;
  }
  for (const e of root.htmlEntries) checkHtml(root, e);
  const jsFiles = root.jsRoots.flatMap((r) =>
    walk(path.join(root.base, r),
      (f) => f.endsWith('.js') || f.endsWith('.cjs') || f.endsWith('.mjs')));
  for (const f of jsFiles) checkJsImports(root, f);
  const apiSet = buildElectronAPISet(root);
  const ipcSet = buildIpcHandlerSet(root);
  for (const f of jsFiles) {
    checkElectronAPICalls(root, f, apiSet);
    checkIpcInvocations(root, f, ipcSet);
  }
  const exportsSet = buildLocalWindowExports(root);
  for (const f of jsFiles) checkUndefinedWindowCalls(root, f, exportsSet);
}

for (const root of roots) auditRoot(root);

if (options.json) {
  process.stdout.write(JSON.stringify({ findings, count: findings.length }, null, 2));
  process.exit(findings.length === 0 ? 0 : 1);
}

if (findings.length === 0) {
  console.log('\x1b[32m[audit-broken-paths]\x1b[0m PASS — no broken references.');
  process.exit(0);
}

console.log(`\x1b[31m[audit-broken-paths]\x1b[0m ${findings.length} finding(s):\n`);
const byCategory = {};
for (const f of findings) {
  byCategory[f.category] = byCategory[f.category] || [];
  byCategory[f.category].push(f);
}
for (const [cat, list] of Object.entries(byCategory)) {
  console.log(`\x1b[33m── ${cat} (${list.length}) ──\x1b[0m`);
  for (const f of list) {
    console.log(`  ${f.file}:${f.line || '?'}  [${f.root}]  ${f.detail}`);
  }
  console.log('');
}
process.exit(1);
