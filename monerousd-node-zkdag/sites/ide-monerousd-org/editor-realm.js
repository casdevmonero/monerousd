// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// editor-realm.js — the ISOLATED EDITOR REALM's side of the IDE's editor (see editor-realm.html). Hosts vendored Monaco in
// a sandboxed, opaque-origin frame; the IDE (`components/editor.js`) is a thin proxy that speaks the message protocol
// below. Only the IDE window (this frame's parent) is listened to, and only the parent is spoken to.
//
//   parent → realm   { realm:'monerousd-editor', op:'open', path, content }         open or switch to a file's model
//                    { op:'close', path } · { op:'clear' } · { op:'focus' } · { op:'setContent', path, content }
//                    { op:'setAst', path, ast } · { op:'setDiagnostics', path, errors, warnings } · { op:'clearDiagnostics', path }
//   realm → parent   { realm:'monerousd-editor', t:'ready' } · { t:'failed', message }
//                    { t:'change', path, value }  (every content change: the proxy mirrors the text synchronously)
//                    { t:'cursor', line, col, lines } · { t:'error', op, message }
(function () {
  'use strict';
  var parentWin = window.parent;
  var monaco = null;
  var editor = null;
  var models = new Map(); // path → ITextModel

  function post(msg) {
    msg.realm = 'monerousd-editor';
    try { parentWin.postMessage(msg, '*'); } catch (e) { /* the parent is gone */ }
  }

  function languageFromPath(path) {
    var ext = String(path || '').split('.').pop().toLowerCase();
    switch (ext) {
      case 'dsol': return 'dsol';
      case 'html': return 'html';
      case 'css':  return 'css';
      case 'js':
      case 'mjs':  return 'javascript';
      case 'ts':   return 'typescript';
      case 'json': return 'json';
      case 'md':   return 'markdown';
      default:     return 'plaintext';
    }
  }
  function uriFor(path) { return monaco.Uri.parse('inmemory://project/' + encodeURIComponent(path)); }
  function modelFor(path, content) {
    var m = models.get(path);
    if (!m) {
      m = monaco.editor.createModel(content == null ? '' : String(content), languageFromPath(path), uriFor(path));
      models.set(path, m);
      m.onDidChangeContent(function () { post({ t: 'change', path: path, value: m.getValue() }); });
    }
    return m;
  }
  function reportCursor() {
    if (!editor) return;
    var m = editor.getModel();
    var lines = m ? m.getLineCount() : 0;
    var pos = editor.getPosition();
    post({ t: 'cursor', line: pos ? pos.lineNumber : 1, col: pos ? pos.column : 1, lines: lines });
  }

  var ops = {
    open: function (d) {
      var m = modelFor(d.path, d.content);
      if (typeof d.content === 'string' && m.getValue() !== d.content && d.replace) m.setValue(d.content);
      editor.setModel(m);
      reportCursor();
    },
    close: function (d) {
      var m = models.get(d.path);
      if (m) { if (editor.getModel() === m) editor.setModel(null); m.dispose(); models.delete(d.path); }
      reportCursor();
    },
    clear: function () { editor.setModel(null); reportCursor(); },
    focus: function () { editor.focus(); },
    setContent: function (d) {
      var m = models.get(d.path);
      if (m) m.setValue(d.content == null ? '' : String(d.content)); else modelFor(d.path, d.content);
    },
    setAst: function (d) { window.DsolLanguage.setAst(monaco, uriFor(d.path).toString(), d.ast); },
    setDiagnostics: function (d) {
      var m = models.get(d.path);
      if (m) window.DsolLanguage.setDiagnostics(monaco, m, d.errors || [], d.warnings || []);
    },
    clearDiagnostics: function (d) {
      var m = models.get(d.path);
      if (m) window.DsolLanguage.clearDiagnostics(monaco, m);
    },
  };

  window.addEventListener('message', function (ev) {
    if (ev.source !== parentWin) return; // only the IDE that framed this realm
    var d = ev.data;
    if (!d || d.realm !== 'monerousd-editor' || !editor || !ops[d.op]) return;
    try { ops[d.op](d); } catch (e) { post({ t: 'error', op: d.op, message: String((e && e.message) || e) }); }
  });

  // Monaco via its AMD bundle (vs/loader.js) — the same load the IDE's own frame used to do, now inside the realm.
  // The web workers are stubbed (no 'unsafe-eval'); language services run on this realm's main thread.
  function loadMonaco() {
    window.MonacoEnvironment = {
      getWorker: function () {
        return { postMessage: function () {}, addEventListener: function () {}, removeEventListener: function () {}, terminate: function () {}, onmessage: null, onerror: null };
      },
    };
    return new Promise(function (resolve, reject) {
      var s = document.createElement('script');
      s.src = new URL('lib/monaco/vs/loader.js', document.baseURI).href;
      s.async = false;
      s.onload = function () { resolve(); };
      s.onerror = function () { reject(new Error('Monaco AMD loader failed to load')); };
      document.head.appendChild(s);
    }).then(function () {
      window.require.config({ paths: { vs: new URL('lib/monaco/vs', document.baseURI).href } });
      return new Promise(function (resolve, reject) {
        window.require(['vs/editor/editor.main'], function () { resolve(); }, function (err) {
          reject(new Error('Monaco require(editor.main) failed: ' + ((err && err.message) || err)));
        });
      });
    }).then(function () {
      if (!window.monaco || !window.monaco.editor) throw new Error('Monaco loaded but window.monaco.editor is missing');
      monaco = window.monaco;
    });
  }

  loadMonaco().then(function () {
    window.DsolLanguage.registerDsolLanguage(monaco);
    editor = monaco.editor.create(document.getElementById('host'), {
      value: '',
      language: 'dsol',
      theme: 'monerousd-dark',
      automaticLayout: true,
      fontFamily: 'JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace',
      fontSize: 13,
      fontLigatures: true,
      minimap: { enabled: false },
      smoothScrolling: true,
      cursorSmoothCaretAnimation: 'on',
      renderWhitespace: 'selection',
      scrollBeyondLastLine: false,
      padding: { top: 14, bottom: 14 },
      bracketPairColorization: { enabled: true },
      guides: { indentation: true, bracketPairs: true },
      tabSize: 2,
      insertSpaces: true,
      wordWrap: 'off',
    });
    editor.onDidChangeCursorPosition(reportCursor);
    editor.onDidChangeModel(reportCursor);
    var boot = document.getElementById('boot'); if (boot) boot.remove();
    post({ t: 'ready' });
  }).catch(function (e) {
    var boot = document.getElementById('boot'); if (boot) boot.textContent = 'Editor failed to load: ' + ((e && e.message) || e);
    post({ t: 'failed', message: String((e && e.message) || e) });
  });
})();
