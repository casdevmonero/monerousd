// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/* Editor shell — Monaco mount + textarea fallback.
 *
 * Hosts Monaco in the ISOLATED EDITOR REALM (`editor-realm.html`, a sandboxed opaque-origin frame; see below). If the realm
 * fails (Monaco not yet vendored, or asset 404), we fall back to a single-file
 * textarea editor — no Monaco features, but multi-file editing still works.
 *
 * Public API:
 *   await mountEditor({ host, empty, pageSlot, fallback, fallbackTa, problems })
 *   editorApi() => {
 *     openFile(path),
 *     closeFile(path),
 *     saveActive(),
 *     getActiveContent(),
 *     getActiveLanguage(),
 *     setContent(path, content),
 *     focus(),
 *     getMonaco(),
 *     getModel(path),
 *   }
 *
 * The page modules call `editorApi().getActiveContent()` to feed the compiler.
 */

import * as store          from '../lib/store.js';
import * as idb             from '../lib/idb-projects.js';
import { setCursor, clearCursor } from './status-bar.js';
import { tabsApi }          from './tabs.js';

// ⭐ THE ISOLATED EDITOR REALM (hole scanner T1, 2026-10-28). Vendored Monaco (lib/monaco, ~36 minified files) used to
// run in THIS frame — the frame that can call the wallet bridge. It now runs in `editor-realm.html`, framed here with
// `sandbox="allow-scripts"` and nothing else: an OPAQUE origin that cannot script this page, cannot reach its storage,
// and cannot speak to the wallet (the wallet answers only the app's top frame, by `event.source`). This module is the
// IDE's side of that boundary: a proxy that keeps the same `editorApi()` surface the pages use, mirrors every model's
// text synchronously (the realm posts a `change` on every edit, so `getActiveContent()` stays a sync read), and relays
// cursor, diagnostics and AST messages. Only the realm we framed is listened to (`event.source === frame.contentWindow`).
let editor = null;              // the realm's frame element once mounted
let realmWin = null;            // its contentWindow
let dom    = null;
let mode   = 'pending'; // 'monaco' | 'fallback' | 'pending'
const models = new Map();   // path → { value }  (the text mirror; the realm holds the ITextModels)
let realmReady = false;
const realmQueue = [];      // ops posted before the realm said `ready`

const TYPELESS_PLACEHOLDER = `// Welcome to MoneroUSD IDE

dark contract Counter {
  private uint64 count;

  @batch
  entry increment() {
    count = count + 1;
  }

  @direct
  entry getCount() returns (uint64 when revealed) {
    return count;
  }
}
`;

export async function mountEditor(els) {
  dom = els;
  try {
    await mountRealm();
    mode = 'monaco';
  } catch (err) {
    console.warn('The editor realm is unavailable; using textarea fallback.', err);
    mountFallback();
    mode = 'fallback';
  }

  // Wire tabs callbacks.
  tabsApi().onActivate(async (path) => {
    await openFile(path);
  });
  tabsApi().onClose((path) => {
    void closeFile(path);
  });

  showEmptyIfNoFiles();
  return mode;
}

/* ─── The realm ─── */

function realmPost(msg) {
  if (!realmWin) return;
  if (!realmReady) { realmQueue.push(msg); return; }
  msg.realm = 'monerousd-editor';
  realmWin.postMessage(msg, '*'); // the realm's origin is opaque ("null"); the frame we hold is the only recipient
}

function mountRealm() {
  return new Promise((resolve, reject) => {
    const frame = document.createElement('iframe');
    frame.className = 'editor-realm';
    frame.title = 'Code editor';
    frame.setAttribute('sandbox', 'allow-scripts');   // scripts only: opaque origin, no same-origin, no top navigation, no forms
    frame.setAttribute('referrerpolicy', 'no-referrer');
    frame.src = new URL('editor-realm.html', document.baseURI).href;
    dom.host.appendChild(frame);
    editor = frame;
    realmWin = frame.contentWindow;
    const timer = setTimeout(() => reject(new Error('the editor realm did not report ready in 20 s')), 20_000);
    window.addEventListener('message', (ev) => {
      if (ev.source !== realmWin) return;          // only the realm we framed
      const d = ev.data;
      if (!d || d.realm !== 'monerousd-editor') return;
      switch (d.t) {
        case 'ready': {
          clearTimeout(timer);
          realmReady = true;
          for (const m of realmQueue.splice(0)) realmPost(m);
          resolve();
          break;
        }
        case 'failed': {
          clearTimeout(timer);
          reject(new Error(d.message || 'the editor realm failed'));
          break;
        }
        case 'change': {
          if (typeof d.path !== 'string' || typeof d.value !== 'string') break;
          models.set(d.path, { value: d.value });
          const p = store.get('project');
          if (p.activeFile !== d.path) break;
          const dirty = p.dirty instanceof Set ? new Set(p.dirty) : new Set(p.dirty || []);
          dirty.add(d.path);
          store.set('project', { dirty });
          debouncedAutoSave(d.path);
          debouncedAutoCompile();
          break;
        }
        case 'cursor': {
          const lines = Number(d.lines) || 0;
          if (!lines) clearCursor(); else setCursor(Number(d.line) || 1, Number(d.col) || 1, lines);
          break;
        }
        case 'error': console.warn('[editor-realm]', d.op, d.message); break;
        default: break;
      }
    });
  });
}

/* ─── Fallback ─── */

function mountFallback() {
  if (dom.fallback) dom.fallback.hidden = false;
  if (dom.host)     dom.host.style.display = 'none';
  dom.fallbackTa.addEventListener('input', () => {
    const p = store.get('project');
    if (!p.activeFile) return;
    models.set(p.activeFile, { value: dom.fallbackTa.value });
    const dirty = p.dirty instanceof Set ? new Set(p.dirty) : new Set(p.dirty || []);
    dirty.add(p.activeFile);
    store.set('project', { dirty });
    debouncedAutoSave(p.activeFile);
    debouncedAutoCompile();
  });
  dom.fallbackTa.addEventListener('keyup', () => {
    const ta = dom.fallbackTa;
    const before = ta.value.slice(0, ta.selectionStart);
    const lines = before.split('\n');
    setCursor(lines.length, lines.at(-1).length + 1);
  });
}

/* ─── Public API ─── */

async function openFile(path) {
  if (!path) return;
  const p = store.get('project');
  let openFiles = Array.isArray(p.openFiles) ? [...p.openFiles] : [];
  if (!openFiles.includes(path)) openFiles.push(path);

  // Load content from IDB if we don't already hold the file's text.
  let content = '';
  if (!models.has(path)) {
    if (p.id) {
      const f = await idb.readFile(p.id, path).catch(() => null);
      content = f?.content ?? '';
    }
    models.set(path, { value: content });
  } else {
    content = models.get(path)?.value ?? '';
  }

  if (mode === 'monaco') {
    realmPost({ op: 'open', path, content });
  } else {
    dom.fallbackTa.value = content;
  }

  store.set('project', { openFiles, activeFile: path });
  showEmptyIfNoFiles();
}

async function closeFile(path) {
  const p = store.get('project');
  const openFiles = (p.openFiles || []).filter(x => x !== path);
  // Save before closing if dirty.
  const dirty = p.dirty instanceof Set ? p.dirty : new Set(p.dirty || []);
  if (dirty.has(path)) {
    await saveFile(path);
    dirty.delete(path);
  }

  let activeFile = p.activeFile;
  if (activeFile === path) {
    activeFile = openFiles.at(-1) || null;
  }
  store.set('project', { openFiles, activeFile, dirty });

  if (mode === 'monaco') realmPost({ op: 'close', path });
  models.delete(path);

  if (activeFile) {
    await openFile(activeFile);
  } else if (mode === 'monaco') {
    realmPost({ op: 'clear' });
    showEmptyIfNoFiles();
  } else {
    dom.fallbackTa.value = '';
    showEmptyIfNoFiles();
  }
}

async function saveActive() {
  const p = store.get('project');
  if (!p.activeFile) return;
  await saveFile(p.activeFile);
}

// Read a file's content from the text mirror (the realm posts every change, so the mirror is current).
function readModelContent(path, fallbackText) {
  const m = models.get(path);
  if (!m) return fallbackText ?? '';
  if (typeof m.value === 'string') return m.value;
  return fallbackText ?? '';
}

async function saveFile(path) {
  const p = store.get('project');
  if (!p.id) return;  // No project yet — caller should create one first.
  const content = readModelContent(path, dom.fallbackTa?.value);
  await idb.writeFile(p.id, path, content);
  const dirty = p.dirty instanceof Set ? new Set(p.dirty) : new Set(p.dirty || []);
  dirty.delete(path);
  store.set('project', { dirty });
}

function getActiveContent() {
  const p = store.get('project');
  if (!p.activeFile) return '';
  return readModelContent(p.activeFile, dom.fallbackTa?.value);
}

function getActiveLanguage() {
  const p = store.get('project');
  if (!p.activeFile) return 'plaintext';
  return languageFromPath(p.activeFile);
}

async function setContent(path, content) {
  models.set(path, { value: content });
  if (mode === 'monaco') {
    realmPost({ op: 'setContent', path, content });
  } else if (store.get('project').activeFile === path) {
    dom.fallbackTa.value = content;
  }
  const p = store.get('project');
  if (p.id) await idb.writeFile(p.id, path, content);
}

function focus() {
  if (mode === 'monaco') realmPost({ op: 'focus' });
  else if (mode === 'fallback') dom.fallbackTa.focus();
}

// There is no Monaco object in this frame any more (it lives in the isolated realm): a page that asks for one gets
// `null` and must speak through this API. `getModel` answers a HANDLE — the path and a `getValue()` over the mirror —
// which `setDiagnostics` / `clearDiagnostics` accept in place of the ITextModel the pages used to receive.
function getMonaco() { return null; }
function getModel(path) {
  if (!models.has(path)) return null;
  return { path, uri: `inmemory://project/${encodeURIComponent(path)}`, getValue: () => readModelContent(path, '') };
}
function pathOf(modelOrPath) {
  if (typeof modelOrPath === 'string') return modelOrPath;
  if (modelOrPath && typeof modelOrPath.path === 'string') return modelOrPath.path;
  return null;
}

/* ─── Helpers ─── */

function languageFromPath(path) {
  const ext = path.split('.').pop()?.toLowerCase();
  switch (ext) {
    case 'dsol': return 'dsol';
    case 'html': return 'html';
    case 'css':  return 'css';
    case 'js':
    case 'mjs':  return 'javascript';
    case 'ts':   return 'typescript';
    case 'json': return 'json';
    case 'md':   return 'markdown';
    case 'txt':  return 'plaintext';
    default:     return 'plaintext';
  }
}

function showEmptyIfNoFiles() {
  if (!dom?.empty || !dom?.host) return;
  const hasFiles = (store.get('project').openFiles || []).length > 0;
  if (!hasFiles) {
    dom.empty.style.display = '';
    dom.host.style.visibility = 'hidden';
    if (dom.fallback) dom.fallbackTa.style.visibility = 'hidden';
  } else {
    dom.empty.style.display = 'none';
    dom.host.style.visibility = '';
    if (dom.fallback) dom.fallbackTa.style.visibility = '';
  }
}

/* ─── Auto-save + auto-compile ─── */

let autoSaveTimer = null;
function debouncedAutoSave(path) {
  clearTimeout(autoSaveTimer);
  autoSaveTimer = setTimeout(() => { void saveFile(path); }, 500);
}

let autoCompileTimer = null;
function debouncedAutoCompile() {
  if (!store.get('settings').autoCompile) return;
  const lang = getActiveLanguage();
  if (lang !== 'dsol') return;
  clearTimeout(autoCompileTimer);
  autoCompileTimer = setTimeout(async () => {
    try {
      const mod = await import('../pages/compiler.js');
      await mod.compileNow();
    } catch (err) {
      console.warn('auto-compile failed:', err);
    }
  }, 600);
}

/* ─── Public API factory ─── */

export function editorApi() {
  return {
    openFile,
    closeFile,
    saveActive,
    saveFile,
    getActiveContent,
    getActiveLanguage,
    setContent,
    focus,
    getMonaco,
    getModel,
    setAst:          (uriOrPath, ast) => { const path = pathOf(uriOrPath); if (mode === 'monaco' && path) realmPost({ op: 'setAst', path, ast }); },
    setDiagnostics:  (model, errors, warnings) => { const path = pathOf(model); if (mode === 'monaco' && path) realmPost({ op: 'setDiagnostics', path, errors: errors || [], warnings: warnings || [] }); },
    clearDiagnostics:(model) => { const path = pathOf(model); if (mode === 'monaco' && path) realmPost({ op: 'clearDiagnostics', path }); },
    mode:            () => mode,
  };
}
