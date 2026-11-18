// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// SOVEREIGN — the browser and publisher of MonerousD Veil (docs/VEIL-SOVEREIGN-INTERNET-SPEC-20261107.md §1, §7;
// user 2026-11-12: "redesign sovereign browser to match the polish of the rest of our ecosystem with sleek moving
// designs. Uploading a site must also be made simple and easy. As easy as drag and drop. Users must have the ability to
// update their site without wasting extra storage").
//
// Four panes on one page, desktop and phone alike:
//   SEARCH    every site published on the Veil, listed and searched by name the way a search engine lists the web
//             (user 2026-11-12: "a google equivalent browser in which all published sites appear on and can be searched
//             up by name"). The list is this wallet's OWN node's state (the chain's names and site records), so a search
//             never leaves the machine and nobody learns what was looked for. Recent and saved sites stay on this device.
//   PUBLISH   drop a folder (or pick files, or start from a template), pick a name you own, see what is new and what it
//             costs in dollars, tap Publish. An update hands over and pays for only the files that changed: the
//             wallet's core compares the new version with the one before it chunk by chunk (`veil_plan`).
//   MY SITES  every site at a name this wallet owns, with Open, Update and Copy.
//   HOSTING   what this node holds for the network, against its budget.
//
// Every byte a site shows is checked by the node against the root the chain anchors for that name; this page never
// reads a site's bytes itself. Nothing typed here leaves the machine: a name resolves from the node's own state.
//
// TWO-PARTY-REVIEWED: page presentation code; every value-moving step is a wallet-core command that asks for the
// user's approval (`veil_publish`, `wallet_register_username`), and this page builds no endpoint of its own.
'use strict';

(function () {
  const PAGE_ID = 'pageSovereignHosting';
  const RECENT_KEY = 'sovereign.recent.v1';
  const SAVED_KEY = 'sovereign.saved.v1';
  const LIST_MAX = 24;
  const calm = window.matchMedia ? window.matchMedia('(prefers-reduced-motion: reduce)') : { matches: false };

  // ── small helpers ────────────────────────────────────────────────────────────────────────────────────────────
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const kb = (n) => {
    const b = Number(n) || 0;
    if (b < 1024) return b + ' B';
    if (b < 1024 * 1024) return (b / 1024).toFixed(b < 10240 ? 1 : 0) + ' KB';
    return (b / (1024 * 1024)).toFixed(2) + ' MB';
  };
  const usd = (n) => {
    const v = Number(n) || 0;
    return v > 0 && v < 0.01 ? 'under $0.01' : '$' + v.toFixed(2);
  };
  const bare = (s) => String(s || '').trim().toLowerCase().replace(/^@+/, '').replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/\.mud(\/.*)?$/, '').replace(/\/.*$/, '');
  const hueOf = (n) => [...n].reduce((h, c) => (h * 31 + c.charCodeAt(0)) % 360, 17);
  const readList = (k) => { try { const v = JSON.parse(localStorage.getItem(k) || '[]'); return Array.isArray(v) ? v : []; } catch (_) { return []; } };
  // LOCAL-STORAGE-REQUIRED: the person's own recent and saved site names are a convenience of THIS device (spec §7:
  // "bookmarks and history kept only on the device"); held anywhere else they would tell someone which sites this
  // person reads. Losing them loses nothing but the list.
  // bound: two lists of at most LIST_MAX (24) short names each, under 2 KB in all; no term in height, blocks or notes.
  const writeList = (k, v) => { try { localStorage.setItem(k, JSON.stringify(v.slice(0, LIST_MAX))); } catch (_) { /* a private window keeps nothing */ } };
  function core(cmd, args) {
    if (typeof walletCore !== 'function') return Promise.reject(new Error('Open the MoneroUSD app to do this.'));
    return walletCore(cmd, args);
  }
  function msg(e) { return String((e && e.message) || e || 'something went wrong'); }

  // ── state ───────────────────────────────────────────────────────────────────────────────────────────────────
  const st = {
    root: null, pane: 'browse',
    files: [],            // [{path, size, base64}]
    packed: null,         // veil_pack's answer
    names: [],            // the @names this wallet owns
    name: '',             // the address picked for the publish
    plan: null,           // veil_plan's answer
    busy: false,
    backend: null,        // a back end to deploy with this publish: { source, feeUsd }; null for none
  };

  // ── the page ────────────────────────────────────────────────────────────────────────────────────────────────
  const ICON = {
    lock: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/></svg>',
    up: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 16V4"/><path d="M7 9l5-5 5 5"/><path d="M4 16v3a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-3"/></svg>',
    star: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"><path d="M12 3l2.7 5.6 6.1.9-4.4 4.3 1 6.1L12 17l-5.4 2.9 1-6.1L3.2 9.5l6.1-.9z"/></svg>',
    check: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5l4.5 4.5L19 7.5"/></svg>',
  };

  function shell() {
    return `
<div class="sv">
  <div class="sv-aurora" aria-hidden="true"><i></i><i></i><i></i><div class="sv-grid"></div></div>
  <header class="sv-top">
    <button type="button" class="sv-brand-sm" id="svBrand" aria-label="Sovereign search home">
      <svg viewBox="0 0 64 64" aria-hidden="true"><path d="M32 6l20 9v14c0 13-8.6 23.4-20 27-11.4-3.6-20-14-20-27V15z" fill="none" stroke="#ff8a33" stroke-width="5"/><path d="M22 33l7 7 14-15" fill="none" stroke="#f5f5f7" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/></svg>
      <span>Sovereign</span>
    </button>
    <nav class="sv-tabs" role="tablist">
      <button role="tab" data-pane="browse" class="on">Search</button>
      <button role="tab" data-pane="publish">Publish</button>
      <button role="tab" data-pane="mine">My sites</button>
      <button role="tab" data-pane="host">Hosting</button>
      <span class="sv-tab-ink" aria-hidden="true"></span>
    </nav>
  </header>

  <section class="sv-pane on" data-pane="browse">
    <div class="sv-home-art" aria-hidden="true">
      <div class="sv-mark">
        <svg viewBox="0 0 64 64"><defs><linearGradient id="svG" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#ff8a33"/><stop offset="1" stop-color="#d94e00"/></linearGradient></defs>
          <path d="M32 6l20 9v14c0 13-8.6 23.4-20 27-11.4-3.6-20-14-20-27V15z" fill="none" stroke="url(#svG)" stroke-width="3"/>
          <path d="M22 33l7 7 14-15" fill="none" stroke="#f5f5f7" stroke-width="3.2" stroke-linecap="round" stroke-linejoin="round"/></svg>
        <span class="sv-orbit"></span><span class="sv-orbit sv-orbit-2"></span>
      </div>
      <h1 class="sv-wordmark">Sovereign</h1>
      <p class="sv-tagline">Search every site on the Veil. Nobody can take one down, and nobody sees what you search for or open.</p>
    </div>
    <form class="sv-omni" id="svOmni" autocomplete="off" role="search">
      <span class="sv-omni-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg></span>
      <input id="svAddress" type="search" inputmode="search" enterkeyhint="search" spellcheck="false" autocapitalize="off"
             placeholder="Search the Veil, or type a name like flame.mud" aria-label="Search the Veil" aria-autocomplete="list" aria-controls="svSuggest" />
      <button type="button" class="sv-omni-clear" id="svClearQ" aria-label="Clear" hidden>×</button>
      <span class="sv-omni-lock" title="Every page is checked against the chain before you see it">${ICON.lock}</span>
      <ul class="sv-suggest" id="svSuggest" role="listbox" hidden></ul>
    </form>
    <div class="sv-home-actions">
      <button type="button" class="sv-btn" id="svSearchBtn">Search the Veil</button>
    </div>
    <div class="sv-serp" id="svSerp" hidden>
      <div class="sv-serp-stats" id="svStats"></div>
      <div class="sv-results" id="svResults"></div>
      <nav class="sv-pager" id="svPager" aria-label="Result pages"></nav>
    </div>

    <div class="sv-shelf" id="svShelf">
      <div class="sv-row-head"><h2>Recent</h2><span class="sv-sub">kept on this device only</span></div>
      <div class="sv-cards" id="svRecent"></div>
      <div class="sv-row-head"><h2>Saved</h2></div>
      <div class="sv-cards" id="svSaved"></div>
    </div>
  </section>

  <section class="sv-pane" data-pane="publish">
    <ol class="sv-steps" id="svSteps">
      <li data-step="1" class="on"><b>1</b><span>Add files</span></li>
      <li data-step="2"><b>2</b><span>Address</span></li>
      <li data-step="3"><b>3</b><span>Review</span></li>
      <li data-step="4"><b>4</b><span>Live</span></li>
    </ol>

    <div class="sv-step on" data-step="1">
      <div class="sv-drop" id="svDrop" tabindex="0" role="button" aria-label="Add your site's files">
        <span class="sv-drop-icon">${ICON.up}</span>
        <strong id="svDropTitle">Drop your site folder here</strong>
        <span class="sv-drop-sub">Any folder with an <code>index.html</code>: pages, styles, pictures, all of it.</span>
        <span class="sv-drop-actions">
          <button type="button" class="sv-btn" id="svPickFolder">Choose a folder</button>
          <button type="button" class="sv-btn sv-btn-ghost" id="svPickFiles">Choose files</button>
        </span>
        <input type="file" id="svFolderInput" webkitdirectory directory multiple hidden />
        <input type="file" id="svFilesInput" multiple hidden />
      </div>
      <div class="sv-files" id="svFiles" hidden></div>
      <div class="sv-or"><span>or start from a template</span></div>
      <div class="sv-templates" id="svTemplates"></div>
      <div class="sv-template-form" id="svTemplateForm" hidden></div>
    </div>

    <div class="sv-step" data-step="2">
      <h2>Where should it live?</h2>
      <p class="sv-sub">A site lives at a name you own: <b>@flame</b> is <b>flame.mud</b>.</p>
      <div class="sv-names" id="svNames"></div>
      <div class="sv-claim" id="svClaim" hidden>
        <div class="sv-claim-field"><span>@</span><input id="svClaimName" type="text" spellcheck="false" autocapitalize="off" placeholder="yourname" /></div>
        <button type="button" class="sv-btn" id="svClaimBtn">Claim it</button>
        <p class="sv-note" id="svClaimNote"></p>
      </div>
      <div class="sv-nav"><button type="button" class="sv-btn sv-btn-ghost" data-back="1">Back</button><span></span></div>
    </div>

    <div class="sv-step" data-step="3">
      <div class="sv-review" id="svReview"></div>
      <div class="sv-nav">
        <button type="button" class="sv-btn sv-btn-ghost" data-back="2">Back</button>
        <button type="button" class="sv-btn sv-btn-primary" id="svPublish">Publish</button>
      </div>
    </div>

    <div class="sv-step" data-step="4">
      <ul class="sv-progress" id="svProgress"></ul>
      <div class="sv-done" id="svDone" hidden></div>
    </div>
    <p class="sv-error" id="svError" role="alert" hidden></p>
  </section>

  <section class="sv-pane" data-pane="mine">
    <div class="sv-row-head"><h2>Your sites</h2><button type="button" class="sv-btn sv-btn-ghost sv-btn-sm" id="svNewSite">New site</button></div>
    <div class="sv-sites" id="svSites"></div>
  </section>

  <section class="sv-pane" data-pane="host">
    <div class="sv-host" id="svHost"></div>
  </section>
</div>`;
  }

  const $ = (sel) => st.root && st.root.querySelector(sel);
  const $$ = (sel) => (st.root ? Array.from(st.root.querySelectorAll(sel)) : []);

  // ── panes and steps ─────────────────────────────────────────────────────────────────────────────────────────
  function show(pane) {
    st.pane = pane;
    if (st.root) st.root.classList.toggle('on-browse', pane === 'browse');
    $$('.sv-tabs [data-pane]').forEach((b) => b.classList.toggle('on', b.dataset.pane === pane));
    $$('.sv-pane').forEach((p) => p.classList.toggle('on', p.dataset.pane === pane));
    moveInk();
    if (pane === 'mine') loadSites();
    if (pane === 'host') loadHost();
    if (pane === 'browse') paintBrowse();
  }
  function moveInk() {
    const on = $('.sv-tabs button.on'); const ink = $('.sv-tab-ink');
    if (!on || !ink) return;
    ink.style.width = on.offsetWidth + 'px';
    ink.style.transform = 'translateX(' + on.offsetLeft + 'px)';
  }
  function step(n) {
    $$('.sv-step').forEach((s) => s.classList.toggle('on', Number(s.dataset.step) === n));
    $$('#svSteps li').forEach((li) => {
      const k = Number(li.dataset.step);
      li.classList.toggle('on', k === n);
      li.classList.toggle('done', k < n);
    });
    error('');
  }
  function error(text) {
    const el = $('#svError'); if (!el) return;
    el.hidden = !text; el.textContent = text || '';
  }

  // ── search ──────────────────────────────────────────────────────────────────────────────────────────────────
  // Like a web search engine: a home with one search bar; Enter (or "Search the Veil") shows a page of ten results,
  // each its title, its address and what its page says, with numbered pages below; typing shows suggestions.
  const PER_PAGE = 10;
  const srch = { q: null, page: 0, total: 0, seq: 0, sugSeq: 0, sugTimer: 0 };
  function serpMode(on) {
    if (!st.root) return;
    st.root.classList.toggle('serp', !!on);
    const serp = $('#svSerp'); const shelf = $('#svShelf');
    if (serp) serp.hidden = !on;
    if (shelf) shelf.hidden = !!on;
  }
  function goHome() {
    srch.q = null; serpMode(false); hideSuggest();
    const i = $('#svAddress'); if (i) { i.value = ''; i.focus(); }
    const c = $('#svClearQ'); if (c) c.hidden = true;
    if (st.pane !== 'browse') show('browse'); else paintBrowse();
  }
  async function ask(q, from, count) {
    return core('node_rpc', { path: '/veil/search', body: JSON.stringify({ q: q, from: from, count: count }) });
  }
  async function runSearch(q, page) {
    hideSuggest();
    srch.q = q; srch.page = page || 0;
    const seq = ++srch.seq; const box = $('#svResults'); const stats = $('#svStats'); const pager = $('#svPager');
    serpMode(true);
    if (box) box.innerHTML = '<div class="sv-shimmer">Searching the Veil on your node…</div>';
    if (pager) pager.innerHTML = '';
    const t0 = performance.now();
    let r;
    try { r = await ask(q, srch.page * PER_PAGE, PER_PAGE); }
    catch (e) { if (seq === srch.seq && box) box.innerHTML = `<div class="sv-empty">${esc(msg(e))}</div>`; return; }
    if (seq !== srch.seq) return;   // a newer search is on its way
    srch.total = Number(r && r.total) || 0;
    const secs = ((performance.now() - t0) / 1000).toFixed(2);
    if (stats) stats.textContent = srch.total ? (srch.page ? 'Page ' + (srch.page + 1) + ' of about ' : 'About ') + srch.total.toLocaleString() + ' site' + (srch.total === 1 ? '' : 's') + ' (' + secs + ' seconds)' : '';
    paintResults(q, (r && r.sites) || []);
    paintPager();
    ((r && r.sites) || []).slice(0, 3).forEach((x) => warm(x.name));
    const top = $('.sv-top'); if (top && srch.page) top.scrollIntoView({ behavior: calm.matches ? 'auto' : 'smooth', block: 'start' });
  }
  function paintResults(q, sites) {
    const box = $('#svResults'); if (!box) return;
    const query = String(q || '').trim();
    if (!sites.length) {
      const n = bare(query);
      box.innerHTML = query
        ? `<div class="sv-noresult"><p>Your search, <b>${esc(query)}</b>, did not match any site on the Veil.</p><ul><li>Try other words, or fewer of them.</li><li>Type a site's name, like <b>flame.mud</b>.</li>${/^[a-z0-9_-]+$/.test(n) ? `<li>No one has published <b>${esc(n)}.mud</b> yet. It could be yours: claim @${esc(n)} and publish it in the Publish tab.</li>` : ''}</ul></div>`
        : '<div class="sv-empty">No sites are published yet. Be the first: open the Publish tab and drop a folder.</div>';
      return;
    }
    const terms = query.toLowerCase().split(/[^a-z0-9]+/).filter((w) => w.length > 2);
    const mark = (text) => {
      let out = esc(text);
      for (const w of terms) out = out.replace(new RegExp('(' + w.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '[a-z]*)', 'gi'), '<b>$1</b>');
      return out;
    };
    box.innerHTML = sites.map((s, i) => `
      <article class="sv-result" style="--h:${hueOf(s.name)};--i:${i}">
        <div class="sv-result-site" data-open="${esc(s.name)}">
          <span class="sv-card-face">${esc(s.name.slice(0, 1).toUpperCase())}</span>
          <span class="sv-result-addr"><b>${esc(s.name)}</b><i>${esc(s.name)}.mud › version ${esc(s.version)}${s.total_len != null ? ' · ' + kb(s.total_len) : ''}</i></span>
          <button type="button" class="sv-card-star${readList(SAVED_KEY).indexOf(s.name) >= 0 ? ' on' : ''}" data-save="${esc(s.name)}" aria-label="Save ${esc(s.name)}.mud">${ICON.star}</button>
        </div>
        <a class="sv-result-title" data-open="${esc(s.name)}" href="#" role="link">${mark(s.title || s.name + '.mud')}</a>
        ${s.snippet ? `<p class="sv-result-snip">${mark(s.snippet)}</p>` : '<p class="sv-result-snip sv-dim">This site\'s front page has not reached your node yet; it opens from the network.</p>'}
      </article>`).join('');
  }
  // INSTANT OPEN: the moment a pointer rests on a result (or a finger touches it), this wallet's own node is asked for
  // the site's front page, so it is ready when the click lands; a site whose pages have not reached the node starts its
  // private fetch then. Nothing leaves the machine but that private read.
  const warmed = new Set();
  function warm(name) {
    if (!name || warmed.has(name) || typeof window.veilBase !== 'function') return;
    warmed.add(name);
    try { fetch(window.veilBase() + '/mud/' + name + '/', { mode: 'no-cors', cache: 'no-store', credentials: 'omit' }).catch(() => warmed.delete(name)); }
    catch (_) { warmed.delete(name); }
  }
  function paintPager() {
    const pager = $('#svPager'); if (!pager) return;
    const pages = Math.ceil(srch.total / PER_PAGE);
    if (pages <= 1) { pager.innerHTML = ''; return; }
    const cur = srch.page;
    const lo = Math.max(0, Math.min(cur - 4, pages - 10)); const hi = Math.min(pages, lo + 10);
    let html = cur > 0 ? `<button type="button" class="sv-page sv-page-step" data-page="${cur - 1}">‹ Previous</button>` : '';
    for (let p = lo; p < hi; p++) html += `<button type="button" class="sv-page${p === cur ? ' on' : ''}" data-page="${p}"${p === cur ? ' aria-current="page"' : ''}>${p + 1}</button>`;
    if (cur + 1 < pages) html += `<button type="button" class="sv-page sv-page-step" data-page="${cur + 1}">Next ›</button>`;
    pager.innerHTML = html;
    pager.querySelectorAll('[data-page]').forEach((b) => { b.onclick = () => runSearch(srch.q, Number(b.dataset.page)); });
  }
  function hideSuggest() { const l = $('#svSuggest'); if (l) { l.hidden = true; l.innerHTML = ''; } }
  function suggest(q) {
    clearTimeout(srch.sugTimer);
    const text = String(q || '').trim();
    const c = $('#svClearQ'); if (c) c.hidden = !q;
    if (!text) { hideSuggest(); return; }
    srch.sugTimer = setTimeout(async () => {
      const seq = ++srch.sugSeq;
      let r; try { r = await ask(text, 0, 6); } catch (_) { return; }
      const l = $('#svSuggest'); if (!l || seq !== srch.sugSeq || ($('#svAddress') || {}).value.trim() !== text) return;
      const sites = (r && r.sites) || [];
      if (!sites.length) { hideSuggest(); return; }
      l.innerHTML = sites.map((s) => `<li role="option" data-open="${esc(s.name)}"><span class="sv-sug-ic">${ICON.lock}</span><b>${esc(s.name)}.mud</b><i>${esc(s.title && s.title !== s.name + '.mud' ? s.title : '')}</i></li>`).join('') +
        `<li role="option" class="sv-sug-all" data-search="${esc(text)}"><span class="sv-sug-ic"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"><circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/></svg></span><b>Search the Veil for “${esc(text)}”</b></li>`;
      l.hidden = false;
    }, 120);
  }
  function submit(q) {
    const text = String(q || '').trim();
    if (!text) return;
    // a whole address (flame.mud) opens the site; anything else is a search
    if (/^[a-z0-9_-]+\.mud(\/.*)?$/i.test(text.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ''))) { const m = text.match(/^(?:[a-z][a-z0-9+.-]*:\/\/)?([a-z0-9_-]+)\.mud(\/.*)?$/i); open(m[1], m[2]); return; }
    runSearch(text, 0);
  }

  // ── browse ──────────────────────────────────────────────────────────────────────────────────────────────────
  function open(name, path) {
    const n = bare(name);
    if (!/^[a-z0-9_-]+$/.test(n)) { flashOmni('Type a site name, like flame.mud'); return; }
    writeList(RECENT_KEY, [n].concat(readList(RECENT_KEY).filter((r) => r !== n)));
    const target = n + '.mud' + (path || '/');
    const url = typeof normBrowserUrl === 'function' ? normBrowserUrl(target) : target;
    if (typeof window.openSovereignSite === 'function') window.openSovereignSite(url);
  }
  function flashOmni(text) {
    serpMode(false);
    const f = $('#svOmni'); const i = $('#svAddress');
    if (!f || !i) return;
    i.value = ''; i.placeholder = text;
    f.classList.remove('shake'); void f.offsetWidth; f.classList.add('shake');
  }
  function siteCard(n) {
    const saved = readList(SAVED_KEY).indexOf(n) >= 0;
    return `<div class="sv-card" data-open="${esc(n)}" tabindex="0" style="--h:${hueOf(n)}">
      <span class="sv-card-face">${esc(n.slice(0, 1).toUpperCase())}</span>
      <span class="sv-card-name">${esc(n)}<i>.mud</i></span>
      <button type="button" class="sv-card-star${saved ? ' on' : ''}" data-save="${esc(n)}" title="${saved ? 'Saved' : 'Save'}" aria-label="Save ${esc(n)}.mud">${ICON.star}</button>
    </div>`;
  }
  function paintBrowse() {
    const recent = readList(RECENT_KEY); const saved = readList(SAVED_KEY);
    const r = $('#svRecent'); const s = $('#svSaved');
    if (r) r.innerHTML = recent.length ? recent.map(siteCard).join('') : '<div class="sv-empty">Sites you open show up here. Type a name above to start.</div>';
    if (s) s.innerHTML = saved.length ? saved.map(siteCard).join('') : '<div class="sv-empty">Tap the star on a site to keep it here.</div>';
  }

  // ── publish: files in ───────────────────────────────────────────────────────────────────────────────────────
  function readFile(file) {
    return new Promise((resolve, reject) => {
      const fr = new FileReader();
      fr.onerror = () => reject(fr.error || new Error('a file could not be read'));
      fr.onload = () => { const s = String(fr.result || ''); resolve(s.slice(s.indexOf(',') + 1)); };
      fr.readAsDataURL(file);
    });
  }
  function walkEntry(entry, prefix, out) {
    return new Promise((resolve) => {
      if (entry.isFile) {
        entry.file((f) => { out.push({ file: f, path: prefix + entry.name }); resolve(); }, () => resolve());
      } else if (entry.isDirectory) {
        const reader = entry.createReader(); const all = [];
        const more = () => reader.readEntries(async (batch) => {
          if (!batch.length) { for (const e of all) await walkEntry(e, prefix + entry.name + '/', out); resolve(); return; }
          all.push(...batch); more();
        }, () => resolve());
        more();
      } else resolve();
    });
  }
  async function take(list) {
    // list: [{file, path}]. Hidden files a system adds (.DS_Store, Thumbs.db) are not part of a site.
    const keep = list.filter((x) => !/(^|\/)(\.[^/]*|Thumbs\.db|desktop\.ini)$/i.test(x.path));
    if (!keep.length) { error('That folder has no files a site can use.'); return; }
    error('');
    const box = $('#svFiles');
    if (box) { box.hidden = false; box.innerHTML = '<div class="sv-shimmer">Reading ' + keep.length + ' file' + (keep.length === 1 ? '' : 's') + '…</div>'; }
    const files = [];
    try { for (const x of keep) files.push({ path: x.path, size: x.file.size, base64: await readFile(x.file) }); }
    catch (e) { if (box) { box.hidden = true; box.innerHTML = ''; } error(msg(e)); return; }
    st.files = files;
    await pack();
  }
  async function takeGenerated(files) {
    const enc = (t) => btoa(unescape(encodeURIComponent(t)));
    st.files = files.map((f) => ({ path: f.path, size: new Blob([f.text]).size, base64: enc(f.text) }));
    await pack();
  }
  async function pack() {
    const box = $('#svFiles');
    st.packed = null; st.plan = null;
    if (box) { box.hidden = false; box.innerHTML = '<div class="sv-shimmer">Packing your site…</div>'; }
    try {
      st.packed = await core('veil_pack', { entries: st.files.map((f) => ({ path: f.path, base64: f.base64 })) });
    } catch (e) {
      if (box) { box.hidden = true; box.innerHTML = ''; }
      error(msg(e)); return;
    }
    paintFiles();
  }
  function paintFiles() {
    const box = $('#svFiles'); if (!box || !st.packed) return;
    const total = st.files.reduce((a, f) => a + f.size, 0);
    const shown = st.files.slice().sort((a, b) => (a.path === 'index.html' ? -1 : b.path === 'index.html' ? 1 : a.path.localeCompare(b.path)));
    box.innerHTML = `
      <div class="sv-files-head">
        <span class="sv-ok">${ICON.check}</span>
        <div><b>${st.files.length} file${st.files.length === 1 ? '' : 's'}</b> · ${kb(total)} · front page found</div>
        <button type="button" class="sv-btn sv-btn-ghost sv-btn-sm" id="svClear">Change</button>
      </div>
      <ul class="sv-file-list">${shown.slice(0, 8).map((f) => `<li><span>${esc(f.path)}</span><i>${kb(f.size)}</i></li>`).join('')}
        ${shown.length > 8 ? `<li class="sv-more">and ${shown.length - 8} more</li>` : ''}</ul>
      <div class="sv-backend" id="svBackend"></div>
      <div class="sv-nav"><span></span><button type="button" class="sv-btn sv-btn-primary" id="svToName">Next: choose its address</button></div>`;
    box.querySelector('#svClear').onclick = () => { st.files = []; st.packed = null; st.backend = null; box.hidden = true; box.innerHTML = ''; };
    paintBackend();
    box.querySelector('#svToName').onclick = () => { step(2); loadNames(st.name); };
  }

  // ── publish: a back end (Veil spec §12) ──────────────────────────────────────────────────────────────────────
  // A site may carry a back end: a small program on the chain that keeps what the site's visitors save (a guestbook, a
  // shop's orders, a profile). It is written in the DSOL assembly the wallet assembles (`veil_assemble`), deployed with
  // the publish (`veil_backend_deploy`, its fee shown in dollars first), and bound by the site's own `veil.json`.
  const hasFile = (p) => st.files.some((f) => f.path === p);
  function fileText(p) { const f = st.files.find((x) => x.path === p); try { return f ? decodeURIComponent(escape(atob(f.base64))) : ''; } catch (_) { return ''; } }
  function paintBackend() {
    const box = $('#svBackend'); if (!box) return;
    if (hasFile('veil.json')) { box.innerHTML = `<div class="sv-be-on">${ICON.check}<div><b>Back end bound</b><span>This site's veil.json names its back end; publishing keeps it.</span></div></div>`; return; }
    if (!st.backend && hasFile('backend.dsl')) st.backend = { source: fileText('backend.dsl'), feeUsd: 0 };
    if (!st.backend) {
      box.innerHTML = '<button type="button" class="sv-btn sv-btn-ghost sv-btn-sm" id="svBeAdd">+ Add a back end</button><span class="sv-be-hint">Keep what visitors save, on the chain. No server.</span>';
      box.querySelector('#svBeAdd').onclick = async () => {
        const ex = await core('veil_assemble', { source: '' }).catch(() => null);
        st.backend = { source: (ex && ex.source) || '', feeUsd: 0 }; paintBackend();
      };
      return;
    }
    box.innerHTML = `<div class="sv-be-card">
        <div class="sv-be-head"><b>Back end</b><span id="svBeCheck" class="sv-be-check">checking…</span><button type="button" class="sv-btn sv-btn-ghost sv-btn-sm" id="svBeDrop">Remove</button></div>
        <textarea id="svBeSource" spellcheck="false" rows="9">${esc(st.backend.source)}</textarea>
        <label class="sv-field sv-be-fee"><span>Fee a visitor pays each save (dollars, 0 for free)</span><input id="svBeFee" type="number" min="0" step="0.01" value="${esc(String(st.backend.feeUsd || 0))}" /></label>
      </div>`;
    const src = box.querySelector('#svBeSource'); const fee = box.querySelector('#svBeFee');
    box.querySelector('#svBeDrop').onclick = () => { st.backend = null; paintBackend(); };
    let t = 0;
    const check = async () => {
      st.backend.source = src.value;
      const out = box.querySelector('#svBeCheck');
      try {
        const r = await core('veil_assemble', { source: src.value });
        st.backend.quote = r;
        out.className = 'sv-be-check ok';
        out.textContent = r.entries + ' entr' + (r.entries === 1 ? 'y' : 'ies') + ' · ' + r.bytes + ' bytes · holds ' + r.slots + ' slots · deploy ' + usd(Number(r.deploy_fee_atomic) / 1e8);
      } catch (e) { st.backend.quote = null; out.className = 'sv-be-check bad'; out.textContent = msg(e); }
    };
    src.oninput = () => { clearTimeout(t); t = setTimeout(check, 350); };
    fee.oninput = () => { st.backend.feeUsd = Math.max(0, Number(fee.value) || 0); };
    check();
  }
  // DEPLOY the back end before the site goes up: the person sees the deploy fee in dollars and confirms; the two files
  // the site then carries (`backend.dsol`, `veil.json`) are added and the site packed again.
  async function deployBackend(name) {
    const q = st.backend && st.backend.quote;
    if (!q) throw new Error('The back end has an error. Fix it, or remove it.');
    if (typeof confirmCost === 'function') {
      const yes = await confirmCost({ title: 'Put ' + name + '.mud\'s back end on the chain', confirmLabel: 'Deploy',
        lines: [{ label: 'Deploy fee (paid once)', usd: Number(q.deploy_fee_atomic) / 1e8, cost: true },
          { label: 'Network fee', usd: Number(q.network_fee_atomic) / 1e8, cost: true },
          { label: 'Each visitor\'s save pays you', usd: Number(st.backend.feeUsd) || 0, detail: 'set by you; visitors see it before they save' }],
        warning: 'The back end keeps at most ' + q.slots + ' entries, each text up to ' + q.text_bytes_max + ' bytes. What it keeps is hidden from the chain; everyone your site serves can read what visitors do not seal to themselves.' });
      if (!yes) throw new Error('Cancelled: nothing was deployed or paid.');
    }
    const r = await core('veil_backend_deploy', { name, source: st.backend.source, publisherFeeUsdm: Number(st.backend.feeUsd) || 0, heightClass: null });
    const b64 = (hex) => btoa(String.fromCharCode.apply(null, (hex.match(/../g) || []).map((h) => parseInt(h, 16))));
    for (const f of r.files || []) {
      st.files = st.files.filter((x) => x.path !== f.path);
      st.files.push({ path: f.path, size: f.hex.length / 2, base64: b64(f.hex) });
    }
    st.backend = null;
    return r;
  }

  // ── publish: templates (for a person who has no files yet) ───────────────────────────────────────────────────
  const TEMPLATES = [
    { id: 'links', title: 'Link page', blurb: 'Your name and the places to find you.',
      fields: [['title', 'Your name', 'Ada Flame'], ['tagline', 'One line about you', 'Builder of quiet things'], ['links', 'Links, one per line: Label | address', 'My shop | flame.mud/shop\nNewsletter | flame.mud/news']] },
    { id: 'post', title: 'Blog post', blurb: 'A page of writing with a headline.',
      fields: [['title', 'Headline', 'Hello from the Veil'], ['tagline', 'Byline', 'by @flame'], ['body', 'Your post', 'Write here. Leave a blank line between paragraphs.']] },
    { id: 'guest', title: 'Guestbook', blurb: 'Visitors leave messages, kept on the chain. No server.',
      fields: [['title', 'Its title', 'Sign my guestbook'], ['tagline', 'One line to visitors', 'Say hello. Every message is kept on the chain.']] },
    { id: 'folio', title: 'Portfolio', blurb: 'A short intro and the work you are proud of.',
      fields: [['title', 'Your name', 'Ada Flame'], ['tagline', 'What you do', 'Designer'], ['links', 'Projects, one per line: Name | one line about it', 'Lantern | A light that runs on sunlight\nKite | A map for walking']] },
  ];
  function paintTemplates() {
    const box = $('#svTemplates'); if (!box) return;
    box.innerHTML = TEMPLATES.map((t) => `<button type="button" class="sv-tpl" data-tpl="${t.id}"><span class="sv-tpl-art sv-tpl-${t.id}" aria-hidden="true"><i></i><i></i><i></i></span><b>${esc(t.title)}</b><span>${esc(t.blurb)}</span></button>`).join('');
    box.querySelectorAll('[data-tpl]').forEach((b) => { b.onclick = () => openTemplate(b.dataset.tpl); });
  }
  function openTemplate(id) {
    const t = TEMPLATES.find((x) => x.id === id); const form = $('#svTemplateForm');
    if (!t || !form) return;
    form.hidden = false;
    form.innerHTML = `<h3>${esc(t.title)}</h3>` + t.fields.map(([k, label, ph]) =>
      (k === 'body' || k === 'links')
        ? `<label class="sv-field"><span>${esc(label)}</span><textarea data-k="${k}" rows="4" placeholder="${esc(ph)}"></textarea></label>`
        : `<label class="sv-field"><span>${esc(label)}</span><input data-k="${k}" type="text" placeholder="${esc(ph)}" /></label>`).join('') +
      '<div class="sv-nav"><button type="button" class="sv-btn sv-btn-ghost" id="svTplCancel">Cancel</button><button type="button" class="sv-btn sv-btn-primary" id="svTplMake">Use this</button></div>';
    form.querySelector('#svTplCancel').onclick = () => { form.hidden = true; form.innerHTML = ''; };
    form.querySelector('#svTplMake').onclick = () => {
      const v = {}; form.querySelectorAll('[data-k]').forEach((el) => { v[el.dataset.k] = el.value.trim() || el.placeholder; });
      form.hidden = true; form.innerHTML = '';
      if (t.id === 'guest') {
        core('veil_assemble', { source: '' }).then((ex) => { st.backend = { source: (ex && ex.source) || '', feeUsd: 0 }; takeGenerated(renderTemplate(t.id, v)); }, (e) => error(msg(e)));
        return;
      }
      takeGenerated(renderTemplate(t.id, v));
    };
    form.scrollIntoView({ behavior: calm.matches ? 'auto' : 'smooth', block: 'nearest' });
  }
  function renderTemplate(id, v) {
    const e = esc;
    const lines = (s) => String(s || '').split('\n').map((x) => x.trim()).filter(Boolean);
    const pairs = lines(v.links).map((l) => { const [a, b] = l.split('|').map((x) => (x || '').trim()); return [a || b, b || '']; });
    const href = (to) => (/^[a-z][a-z0-9+.-]*:/i.test(to) || to.startsWith('/') ? to : (/\.mud(\/|$)/i.test(to) ? 'http://' + to : to));
    let main;
    if (id === 'links') main = `<ul class="links">${pairs.map(([a, b]) => `<li><a href="${e(href(b))}">${e(a)}</a></li>`).join('')}</ul>`;
    else if (id === 'post') main = `<article>${String(v.body || '').split(/\n\s*\n/).map((p) => `<p>${e(p.trim())}</p>`).join('')}</article>`;
    else if (id === 'guest') main = `<form id="gbForm" class="gb-form"><textarea id="gbText" maxlength="600" rows="3" placeholder="Write a message…" required></textarea><button type="submit">Sign</button></form><p id="gbNote" class="gb-note"></p><ol id="gbList" class="gb-list"></ol>`;
    else main = `<div class="work">${pairs.map(([a, b]) => `<section><h2>${e(a)}</h2><p>${e(b)}</p></section>`).join('')}</div>`;
    const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${e(v.title)}</title><link rel="stylesheet" href="style.css"></head>
<body><main><header><h1>${e(v.title)}</h1><p class="tag">${e(v.tagline)}</p></header>${main}</main></body></html>\n`;
    const css = `:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;font:17px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;background:radial-gradient(120% 70% at 50% 120%,rgba(255,106,0,.18),transparent 60%),#0b0b0d;color:#e6e6ea}
main{max-width:640px;margin:0 auto;padding:72px 24px}h1{font-size:40px;line-height:1.1;margin:0 0 8px;color:#fff;letter-spacing:-.02em}.tag{color:#ff8a33;margin:0 0 40px}
.links{list-style:none;padding:0;display:grid;gap:12px}.links a{display:block;padding:16px 20px;border-radius:14px;background:#17171b;border:1px solid #26262e;color:#fff;text-decoration:none;transition:transform .2s,border-color .2s}.links a:hover{transform:translateY(-2px);border-color:#ff6a00}
article p{margin:0 0 1.1em}.work{display:grid;gap:16px}.work section{padding:20px;border-radius:14px;background:#17171b;border:1px solid #26262e}.work h2{margin:0 0 4px;font-size:20px;color:#fff}.work p{margin:0;color:#a9a9b3}\n`;
    if (id === 'guest') {
      const page = html.replace('</body>', '<script src="guestbook.js"></script></body>');
      const gcss = css + `.gb-form{display:grid;gap:10px;margin:0 0 8px}.gb-form textarea{width:100%;padding:14px 16px;border-radius:14px;border:1px solid #26262e;background:#17171b;color:#fff;font:inherit;resize:vertical}
.gb-form textarea:focus{outline:none;border-color:#ff6a00}.gb-form button{justify-self:end;padding:10px 22px;border:0;border-radius:999px;background:#ff6a00;color:#111;font-weight:700;font:inherit;cursor:pointer}
.gb-note{min-height:1.4em;color:#a9a9b3;font-size:14px}.gb-list{list-style:none;padding:0;display:grid;gap:12px}.gb-list li{padding:16px 18px;border-radius:14px;background:#17171b;border:1px solid #26262e;white-space:pre-wrap;animation:gb .4s ease both}
@keyframes gb{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}@media (prefers-reduced-motion:reduce){.gb-list li{animation:none}}\n`;
      const js = `// The guestbook's page: reads its back end through the wallet, and asks the wallet to save a message.
(function () {
  var be = window.monerousd && window.monerousd.backend;
  var list = document.getElementById('gbList'), note = document.getElementById('gbNote'), form = document.getElementById('gbForm'), text = document.getElementById('gbText');
  if (!be) { note.textContent = 'Open this site in the MoneroUSD wallet to read and sign the guestbook.'; form.hidden = true; return; }
  var shown = -1;
  function paint() {
    return be.read(['n']).then(function (v) {
      var n = (v.n && v.n.word) || 0;
      if (n === shown) return n;
      var keys = []; for (var i = n - 1; i >= 0 && i >= n - 50; i--) keys.push({ map: 'm', key: String(i) });
      return be.read(keys).then(function (m) {
        list.innerHTML = '';
        keys.forEach(function (k) { var e = m['m[' + k.key + ']']; if (!e || !e.text) return; var li = document.createElement('li'); li.textContent = e.text; list.appendChild(li); });
        if (!n) note.textContent = 'No messages yet. Be the first.';
        shown = n; return n;
      });
    }).catch(function (e) { note.textContent = String(e.message || e); });
  }
  form.addEventListener('submit', function (ev) {
    ev.preventDefault();
    var msg = text.value.trim(); if (!msg) return;
    note.textContent = 'Waiting for your wallet…';
    be.call('post', msg).then(function () {
      text.value = ''; note.textContent = 'Saved. It appears here once the chain confirms it.';
      var before = shown, tries = 0;
      (function wait() { paint().then(function (n) { if (n > before || ++tries > 40) { if (n > before) note.textContent = ''; return; } setTimeout(wait, 3000); }); })();
    }).catch(function (e) { note.textContent = String(e.message || e); });
  });
  paint();
})();
`;
      return [{ path: 'index.html', text: page }, { path: 'style.css', text: gcss }, { path: 'guestbook.js', text: js }];
    }
    return [{ path: 'index.html', text: html }, { path: 'style.css', text: css }];
  }

  // ── publish: the address ────────────────────────────────────────────────────────────────────────────────────
  async function loadNames(preferred) {
    const box = $('#svNames'); const claim = $('#svClaim');
    if (box) box.innerHTML = '<div class="sv-shimmer">Reading the names you own…</div>';
    let names = [];
    try { const r = await core('wallet_my_username'); names = ((r && r.names) || []).map(bare).filter(Boolean); }
    catch (e) { if (box) box.innerHTML = ''; error(msg(e)); return; }
    st.names = names;
    if (claim) claim.hidden = names.length > 0;
    if (!box) return;
    if (!names.length) { box.innerHTML = '<div class="sv-empty">You do not own a name yet. Claim one below: it is your site\'s address and your payment handle.</div>'; return; }
    box.innerHTML = names.map((n) => `<button type="button" class="sv-name${n === preferred ? ' on' : ''}" data-name="${esc(n)}"><b>${esc(n)}</b><i>.mud</i></button>`).join('') +
      '<button type="button" class="sv-name sv-name-add" id="svAnotherName">+ another name</button>';
    box.querySelectorAll('[data-name]').forEach((b) => { b.onclick = () => pickName(b.dataset.name); });
    const another = box.querySelector('#svAnotherName'); if (another) another.onclick = () => { if (claim) claim.hidden = false; };
    if (preferred && names.indexOf(preferred) >= 0) pickName(preferred);
  }
  async function claimName() {
    const input = $('#svClaimName'); const note = $('#svClaimNote');
    const name = bare(input && input.value);
    if (!/^[a-z0-9_-]{1,32}$/.test(name)) { if (note) note.textContent = 'Use letters, digits, dashes and underscores.'; return; }
    let chain;
    try { chain = await core('wallet_dir_price', { what: 'name', key: name, display: '', topic: '' }); }
    catch (e) { if (note) note.textContent = 'The price of a name could not be read: ' + msg(e); return; }
    if (typeof confirmCost === 'function') {
      const yes = await confirmCost({ title: 'Claim @' + name, confirmLabel: 'Claim',
        lines: [typeof appFeeLine === 'function' ? appFeeLine('Username fee (yearly)', 10) : { label: 'Username fee (yearly)', usd: 10, cost: true },
          { label: 'Chain fee to publish it', usd: Number(chain.usd), cost: true, detail: 'paid once, for the space the name takes on every node' },
          { label: 'Network fee', usd: Number(chain.network_fee_usd), cost: true }],
        warning: '@' + name + ' is published to the chain and is your site\'s address, ' + name + '.mud. If the name is already taken you are not charged.' });
      if (!yes) return;
    }
    if (note) note.textContent = 'Claiming @' + name + '…';
    try {
      const r = await core('wallet_register_username', { name: name });
      if (r && (r.result === 'REGISTERED' || r.result === 'UPDATED')) { await loadNames(name); return; }
      if (note) note.textContent = 'Claim sent. @' + name + ' becomes yours when the chain confirms it, usually within a few minutes.';
      const ask = async () => {
        if (!st.root || !st.root.isConnected) return;
        const mine = await core('wallet_my_username').then((m) => ((m && m.names) || []).map(bare).indexOf(name) >= 0, () => false);
        if (mine) { await loadNames(name); return; }
        const taken = await core('wallet_resolve_username', { name: name }).then((v) => !!(v && v.address), () => false);
        if (taken) { if (note) note.textContent = '@' + name + ' was claimed by someone else first. You were not charged. Try another name.'; return; }
        setTimeout(ask, 5000);
      };
      setTimeout(ask, 5000);
    } catch (e) { if (note) note.textContent = msg(e); }
  }
  async function pickName(n) {
    st.name = n;
    $$('#svNames [data-name]').forEach((b) => b.classList.toggle('on', b.dataset.name === n));
    if (!st.packed) { step(1); return; }
    step(3);
    const box = $('#svReview');
    if (box) { box.classList.remove('in'); box.innerHTML = '<div class="sv-shimmer">Comparing with what is already published…</div>'; }
    try { st.plan = await core('veil_plan', { domain: n, bundle_base64: st.packed.bundleBase64 }); }
    catch (e) { if (box) box.innerHTML = ''; error(msg(e)); return; }
    paintReview();
  }
  function paintReview() {
    const p = st.plan; const box = $('#svReview'); const btn = $('#svPublish');
    if (!p || !box) return;
    const total = Number(p.bundleSize) || 1; const fresh = Number(p.newBytes) || 0; const kept = Number(p.reusedBytes) || 0;
    const share = Math.max(0.02, Math.min(1, fresh / total));
    const C = 2 * Math.PI * 42;
    const changed = p.changedFiles || [];
    box.innerHTML = `
      <div class="sv-review-top">
        <div class="sv-ring-box"><svg class="sv-ring" viewBox="0 0 100 100" aria-hidden="true"><circle cx="50" cy="50" r="42" class="sv-ring-bg"/>
          <circle cx="50" cy="50" r="42" class="sv-ring-new" style="--dash:${(share * C).toFixed(1)};--C:${C.toFixed(1)}"/></svg>
          <span class="sv-ring-label"><b>${p.exists ? Math.floor((kept / total) * 100) + '%' : 'New'}</b><i>${p.exists ? 'reused' : 'site'}</i></span></div>
        <div class="sv-review-main">
          <div class="sv-review-addr">${esc(p.domain)}</div>
          <div class="sv-review-v">${p.exists ? 'Update to version ' + esc(p.version) : 'First version'}</div>
          <div class="sv-review-price">${p.same ? 'Already published' : usd(p.storage_price_usdm)}<span>${p.same ? '' : ' storage, paid once'}</span></div>
        </div>
      </div>
      <dl class="sv-facts">
        <div><dt>New bytes stored</dt><dd>${kb(fresh)}</dd></div>
        <div><dt>${p.exists ? 'Kept from the last version' : 'Files'}</dt><dd>${p.exists ? kb(kept) : esc(p.fileCount)}</dd></div>
        <div><dt>${p.exists ? 'Files changed' : 'Size'}</dt><dd>${p.exists ? changed.length + ' of ' + esc(p.fileCount) : kb(total)}</dd></div>
      </dl>
      ${p.exists && changed.length ? `<ul class="sv-changed">${changed.slice(0, 6).map((f) => `<li>${esc(f)}</li>`).join('')}${changed.length > 6 ? `<li class="sv-more">and ${changed.length - 6} more</li>` : ''}</ul>` : ''}
      ${p.exists ? '<p class="sv-note">Only what changed is uploaded and paid for. Files you did not touch are already on the network and are not stored again.</p>' : ''}
      <p class="sv-warn">A published site cannot be deleted from the network. You can always replace it with a new version.</p>`;
    if (btn) { btn.disabled = !!p.same; btn.textContent = p.same ? 'Nothing changed' : (p.exists ? 'Publish update' : 'Publish'); }
    requestAnimationFrame(() => box.classList.add('in'));
  }

  // ── publish: going live ─────────────────────────────────────────────────────────────────────────────────────
  function progress(rows, extra) {
    const box = $('#svProgress'); if (!box) return;
    box.innerHTML = rows.map(([state, text]) => `<li class="${state}"><span class="sv-pdot">${state === 'done' ? ICON.check : ''}</span><span>${esc(text)}</span></li>`).join('');
    if (extra) box.appendChild(extra);
  }
  async function publish() {
    if (st.busy || !st.packed || !st.name || !st.plan || st.plan.same) return;
    st.busy = true; step(4);
    const p = st.plan; const name = st.name;
    const d = $('#svDone'); if (d) { d.hidden = true; d.innerHTML = ''; }
    const rows = [['done', 'Packed ' + p.fileCount + ' file' + (p.fileCount === 1 ? '' : 's')],
      ['done', p.exists ? 'Found what changed since version ' + (Number(p.version) - 1) : 'Checked the address is yours'],
      ['now', 'Waiting for your approval'], ['', 'Upload ' + kb(p.newBytes) + ' of new pieces to your node'], ['', 'Live on the network']];
    progress(rows);
    try {
      // the back end goes on the chain first, then the site that binds it; a bound back end's state rides the site as
      // its sealed snapshot, so a reader whose node let it go still opens it
      let changed = false;
      if (st.backend) {
        rows.splice(2, 0, ['now', 'Putting the back end on the chain']); progress(rows);
        const d = await deployBackend(name);
        rows[2] = ['done', 'Back end on the chain (' + String(d.cid || '').slice(0, 10) + '…)'];
        changed = true;
      } else if (hasFile('veil.json')) {
        const snap = await core('veil_backend_snapshot', { name }).catch(() => null);
        if (snap && snap.path) {
          const b64 = btoa(String.fromCharCode.apply(null, (snap.hex.match(/../g) || []).map((h) => parseInt(h, 16))));
          st.files = st.files.filter((x) => x.path !== snap.path).concat([{ path: snap.path, size: snap.hex.length / 2, base64: b64 }]);
          changed = true;
        }
      }
      if (changed) {
        const shown = Number(p.storage_price_usdm) || 0;
        await pack();
        st.plan = await core('veil_plan', { domain: name, bundle_base64: st.packed.bundleBase64 });
        if ((Number(st.plan.storage_price_usdm) || 0) > shown + 1e-9) { st.busy = false; step(3); paintReview(); return; }
      }
      const r = await core('veil_publish', { domain: name, bundle_base64: st.packed.bundleBase64 });
      const sent = Number(r.chunksSent);
      const a = rows.length - 3; // the approval row; the upload and the live rows follow it
      rows[a] = ['done', 'Signed by your key'];
      rows[a + 1] = ['done', 'Uploaded ' + (Number.isFinite(sent) ? sent + ' new piece' + (sent === 1 ? '' : 's') : 'the pieces') + ' (' + kb(r.newBytes) + ')'];
      rows[a + 2] = ['now', 'Checking your node serves the new version']; progress(rows);
      const live = await until(async () => { const s = await core('veil_site', { domain: name }); return !!s && s.rootHash === r.rootHash; }, 30);
      rows[a + 2] = live ? ['done', 'Live on the network'] : ['now', 'Your node is still taking it in: it will be live in a moment'];
      progress(rows);
      done(r);
    } catch (e) {
      const at = rows.findIndex((x) => x[0] === 'now');
      rows[at >= 0 ? at : rows.length - 3] = ['bad', msg(e)];
      const nav = document.createElement('div'); nav.className = 'sv-nav';
      nav.innerHTML = '<button type="button" class="sv-btn sv-btn-ghost">Back to review</button><span></span>';
      nav.querySelector('button').onclick = () => step(3);
      progress(rows, nav);
    } finally { st.busy = false; }
  }
  function until(test, tries) {
    return new Promise((resolve) => {
      let n = 0;
      const go = async () => { let ok = false; try { ok = await test(); } catch (_) { ok = false; } if (ok) return resolve(true); if (++n >= tries) return resolve(false); setTimeout(go, 1000); };
      go();
    });
  }
  function done(r) {
    const box = $('#svDone'); if (!box) return;
    const storage = r.storage || {};
    const paidLine = storage.paid > 0 ? 'Paid ' + usd(storage.paid_usdm) + ' to ' + storage.paid + ' node' + (storage.paid === 1 ? '' : 's') + ' that keep it.'
      : (storage.failed ? String(storage.failed) : '');
    box.hidden = false;
    box.innerHTML = `<div class="sv-burst" aria-hidden="true"><i></i><i></i><i></i><i></i><i></i><i></i></div>
      <h2>${esc(r.domain)} is live</h2>
      <p class="sv-sub">Version ${esc(r.version)}${r.reusedBytes ? ' · ' + kb(r.reusedBytes) + ' reused from before, not stored again' : ''}</p>
      ${paidLine ? `<p class="sv-note">${esc(paidLine)}</p>` : ''}
      <div class="sv-nav"><button type="button" class="sv-btn sv-btn-ghost" id="svCopy">Copy address</button><button type="button" class="sv-btn sv-btn-primary" id="svOpenNew">Open it</button></div>`;
    box.querySelector('#svOpenNew').onclick = () => open(r.domain);
    box.querySelector('#svCopy').onclick = (e) => copy(r.domain, e.currentTarget);
  }
  function copy(text, btn) {
    const ok = () => { if (btn) { const t = btn.textContent; btn.textContent = 'Copied'; setTimeout(() => { btn.textContent = t; }, 1400); } };
    try { navigator.clipboard.writeText(text).then(ok, ok); } catch (_) { ok(); }
  }
  function resetPublish(name) {
    st.files = []; st.packed = null; st.plan = null; st.name = name || '';
    const f = $('#svFiles'); if (f) { f.hidden = true; f.innerHTML = ''; }
    const d = $('#svDone'); if (d) { d.hidden = true; d.innerHTML = ''; }
    const t = $('#svDropTitle'); if (t) t.textContent = name ? 'Drop the new version of ' + name + '.mud' : 'Drop your site folder here';
    step(1);
  }

  // ── my sites ────────────────────────────────────────────────────────────────────────────────────────────────
  async function loadSites() {
    const box = $('#svSites'); if (!box) return;
    box.innerHTML = '<div class="sv-shimmer">Reading your sites from your node…</div>';
    let sites = [];
    try { const r = await core('veil_my_sites'); sites = (r && r.sites) || []; }
    catch (e) { box.innerHTML = `<div class="sv-empty">${esc(msg(e))}</div>`; return; }
    if (!sites.length) {
      box.innerHTML = '<div class="sv-empty sv-empty-cta"><b>No sites yet.</b><span>Drop a folder and it is live in a couple of minutes.</span><button type="button" class="sv-btn sv-btn-primary" id="svFirst">Publish your first site</button></div>';
      box.querySelector('#svFirst').onclick = () => { resetPublish(); show('publish'); };
      return;
    }
    box.innerHTML = sites.map((s) => {
      const n = bare(s.domain);
      return `<div class="sv-site">
        <div class="sv-site-face" style="--h:${hueOf(n)}">${esc(n.slice(0, 1).toUpperCase())}</div>
        <div class="sv-site-main"><b>${esc(n)}<i>.mud</i></b><span>Version ${esc(s.version || '1')} · ${esc(String(s.rootHash || '').slice(0, 10))}…</span></div>
        <div class="sv-site-acts">
          <button type="button" class="sv-btn sv-btn-ghost sv-btn-sm" data-copy="${esc(n)}.mud">Copy</button>
          <button type="button" class="sv-btn sv-btn-ghost sv-btn-sm" data-update="${esc(n)}">Update</button>
          <button type="button" class="sv-btn sv-btn-sm" data-open="${esc(n)}">Open</button>
        </div></div>`;
    }).join('');
    box.querySelectorAll('[data-update]').forEach((b) => { b.onclick = () => { resetPublish(b.dataset.update); show('publish'); }; });
    box.querySelectorAll('[data-copy]').forEach((b) => { b.onclick = (e) => copy(b.dataset.copy, e.currentTarget); });
  }

  // ── hosting ─────────────────────────────────────────────────────────────────────────────────────────────────
  async function loadHost() {
    const box = $('#svHost'); if (!box) return;
    box.innerHTML = '<div class="sv-shimmer">Reading your node\'s site store…</div>';
    let h;
    try { h = await core('node_rpc', { path: '/veil/host', body: '' }); } catch (e) { box.innerHTML = `<div class="sv-empty">${esc(msg(e))}</div>`; return; }
    const budget = Number(h.budget) || 0; const used = Number(h.pages_used != null ? h.pages_used : h.used) || 0;
    const pct = budget ? Math.min(100, (used / budget) * 100) : 0;
    box.innerHTML = `
      <div class="sv-meter"><div class="sv-meter-fill" style="--p:${pct.toFixed(2)}%"></div></div>
      <div class="sv-meter-legend"><b>${kb(used)}</b> of ${kb(budget)} used by the sites this node holds for the network</div>
      <dl class="sv-facts">
        <div><dt>Sites held</dt><dd>${esc(h.sites)}</dd></div>
        <div><dt>Paid to keep</dt><dd>${esc(h.paid_sites)}</dd></div>
        <div><dt>Read privately</dt><dd>${esc(h.read_privately)}</dd></div>
      </dl>
      <p class="sv-note">${h.paid_to_wallet ? 'Publishers pay your wallet for the sites this node keeps.' : 'Publishers pay a node through the reward wallet its operator set; this node has none set.'} The store is one file of a fixed size and never grows past its budget.</p>`;
  }

  // ── wiring ──────────────────────────────────────────────────────────────────────────────────────────────────
  function stopStrayDrops(e) {
    // a file dropped anywhere else on the page must not replace the wallet with that file
    if (e.dataTransfer && Array.from(e.dataTransfer.types || []).indexOf('Files') >= 0) e.preventDefault();
  }
  function wire() {
    const r = st.root;
    const addr = r.querySelector('#svAddress');
    r.querySelector('#svOmni').addEventListener('submit', (e) => { e.preventDefault(); submit(addr.value); });
    addr.addEventListener('input', () => suggest(addr.value));
    addr.addEventListener('keydown', (e) => { if (e.key === 'Escape') hideSuggest(); });
    addr.addEventListener('blur', () => setTimeout(hideSuggest, 180));
    const near = (e) => { const t = e.target.closest && e.target.closest('[data-open]'); if (t) warm(t.dataset.open); };
    r.addEventListener('pointerover', near);
    r.addEventListener('pointerdown', near);
    r.addEventListener('focusin', near);
    r.querySelector('#svSearchBtn').addEventListener('click', () => (addr.value.trim() ? submit(addr.value) : addr.focus()));
    r.querySelector('#svClearQ').addEventListener('click', goHome);
    r.querySelector('#svBrand').addEventListener('click', goHome);
    r.querySelectorAll('.sv-tabs [data-pane]').forEach((b) => b.addEventListener('click', () => show(b.dataset.pane)));
    r.addEventListener('click', (e) => {
      const save = e.target.closest('[data-save]');
      if (save) {
        e.stopPropagation();
        const n = save.dataset.save; const saved = readList(SAVED_KEY);
        writeList(SAVED_KEY, saved.indexOf(n) >= 0 ? saved.filter((x) => x !== n) : [n].concat(saved));
        save.classList.toggle('on'); paintBrowse(); return;
      }
      const all = e.target.closest('[data-search]');
      if (all) { e.preventDefault(); runSearch(all.dataset.search, 0); return; }
      const back = e.target.closest('[data-back]');
      if (back) { step(Number(back.dataset.back)); return; }
      const go = e.target.closest('[data-open]');
      if (go) { e.preventDefault(); open(go.dataset.open); }
    });
    r.addEventListener('keydown', (e) => { const c = e.target.closest && e.target.closest('.sv-card[data-open]'); if (c && e.key === 'Enter') open(c.dataset.open); });
    const drop = r.querySelector('#svDrop');
    const folder = r.querySelector('#svFolderInput'); const files = r.querySelector('#svFilesInput');
    r.querySelector('#svPickFolder').addEventListener('click', (e) => { e.stopPropagation(); folder.click(); });
    r.querySelector('#svPickFiles').addEventListener('click', (e) => { e.stopPropagation(); files.click(); });
    drop.addEventListener('click', (e) => { if (!e.target.closest('button')) folder.click(); });
    drop.addEventListener('keydown', (e) => { if (e.target === drop && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); folder.click(); } });
    const fromInput = (input) => take(Array.from(input.files || []).map((f) => ({ file: f, path: f.webkitRelativePath || f.name })));
    folder.addEventListener('change', () => { fromInput(folder); folder.value = ''; });
    files.addEventListener('change', () => { fromInput(files); files.value = ''; });
    let depth = 0;
    drop.addEventListener('dragenter', (e) => { e.preventDefault(); depth++; drop.classList.add('over'); });
    drop.addEventListener('dragover', (e) => { e.preventDefault(); if (e.dataTransfer) e.dataTransfer.dropEffect = 'copy'; });
    drop.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; drop.classList.remove('over'); } });
    drop.addEventListener('drop', async (e) => {
      e.preventDefault(); depth = 0; drop.classList.remove('over'); drop.classList.add('took');
      setTimeout(() => drop.classList.remove('took'), 700);
      const items = e.dataTransfer && e.dataTransfer.items;
      const out = [];
      if (items && items.length && typeof items[0].webkitGetAsEntry === 'function') {
        const entries = Array.from(items).map((it) => it.webkitGetAsEntry()).filter(Boolean);
        for (const ent of entries) await walkEntry(ent, '', out);
      } else {
        for (const f of Array.from((e.dataTransfer && e.dataTransfer.files) || [])) out.push({ file: f, path: f.name });
      }
      take(out);
    });
    r.querySelector('#svClaimBtn').addEventListener('click', claimName);
    r.querySelector('#svPublish').addEventListener('click', publish);
    r.querySelector('#svNewSite').addEventListener('click', () => { resetPublish(); show('publish'); });
    window.addEventListener('resize', moveInk);
  }

  function mount() {
    const host = document.getElementById(PAGE_ID);
    if (!host) return;
    if (!st.root || !host.contains(st.root)) {
      host.innerHTML = shell();
      st.root = host.querySelector('.sv');
      wire();
      paintTemplates();
    }
    if (!document.body.dataset.svDrops) {
      document.body.dataset.svDrops = '1';
      document.addEventListener('dragover', stopStrayDrops);
      document.addEventListener('drop', stopStrayDrops);
    }
    show(st.pane);
    requestAnimationFrame(moveInk);
  }

  window.initSovereignHostingPage = mount;
  // the Browser's Sovereign button: the search home, cleared, its bar ready to type in
  window.sovereignHome = function () { mount(); show('browse'); goHome(); };
})();
