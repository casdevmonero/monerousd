// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
// =========================================================================================
// MonerousD Wallet V2 — frontend controller (clean-room, PQ / ZK-DAG / WHIR shape).
// The UI keeps NO balance cache and NO stored ledger state: every value is read FRESH from the
// Rust core, which runs the PQ crypto in-process and talks to the user's own node (loopback
// :27780). A browser-preview HTTP path lets the design render without the Tauri shell.
// =========================================================================================

const IN_TAURI = !!(window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke);
const NODE_URL = 'http://127.0.0.1:27780';

// ── Asset identity in the UI ──────────────────────────────────────────────────────────────────────────
// The wallet is multi-asset: a note carries a hidden tag saying WHICH asset it is, and the backend reports
// spendable totals per tag. USDm is the all-zero tag, which is why every note sealed before tags existed
// reads as USDm with no migration.
const USDM_ASSET_TAG_HEX = '0'.repeat(48);
// ⛔ THE HTML-SINK CLASS (2026-10-05, ecosystem scanner row "HTML sink fed by an unescaped value"): every value that can
// carry outside text — a @name, a swap id, an address, an asset label, a node reply, an error message — is escaped by
// `escapeHtml` or cast by `Number(…)` BEFORE it reaches innerHTML; `settingsLine` is the one row helper (both cells
// escaped); `sanitizeHtml` is a REAL DOM sanitizer (allowlisted tags, no on* / srcdoc / javascript: / non-image data:)
// used at the composite sinks as the second layer. In this wallet an injected script would reach every wallet command.
function escapeHtml(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }
// ⭐ ADOPTABLE A2 + A3 (user 2026-10-24: "every cost is shown in dollars before the user acts … no action can lose funds
// without a plain-language warning first"): the ONE confirmation every value-moving call awaits before it invokes. It
// draws each line's dollar value (or says plainly that no dollar price exists), the network fee and the warning, and
// resolves true only on Confirm; Cancel, Escape or a click outside resolve false and the caller moves nothing. Focus
// starts on Cancel, so a repeated Enter never confirms a payment. Every value is escaped (one helper, escapeHtml).
// The chain charges no base transfer fee today (params.rs has none); the approved flat $0.001 (spec §12, §BR-14)
// changes this one constant when it lands.
const NETWORK_FEE_USD = 0.001; // §BR-14: the flat network fee, into the chain's pools
const WARN_IRREVERSIBLE = 'This cannot be undone: a payment on MonerousD is final, with no chargeback and no recovery from a wrong address.';
// a sub-cent amount (the $0.001 network fee) shows its third decimal, never a rounded "$0.00"
function usdText(v) { const n = Number(v); const sub = n > 0 && n < 0.01; return '$' + n.toLocaleString('en-US', { minimumFractionDigits: sub ? 3 : 2, maximumFractionDigits: sub ? 3 : 2 }); }
// A COST is shown rounded UP to the shown precision: what the user is charged never exceeds what the dialog said (0.25 % of
// $2.50 is $0.00625 — shown $0.007, never $0.006). Amounts received keep usdText's ordinary rounding.
function usdCostText(v) { const n = Number(v); const d = n > 0 && n < 0.01 ? 1000 : 100; return usdText(Math.max(0, Math.ceil(n * d - 1e-9)) / d); }
// §BR-14: every USDm spend pays the flat network fee once per spend (a cash-out pays it once per piece); an SAT transfer or
// bond, a reward claim and a validator unbond spend no USDm note and pay none — shown as $0.00, never hidden.
// ⭐ §BR-12 — the wallet's own interface fee, shown in dollars before the user acts (paid to the wallet's publisher with
// the other app fees in one ordinary transfer each week; the same action through another app pays none).
const APP_FEE_DETAIL = 'goes to the wallet\'s publisher with your other app fees, once a week';
function appFeeLine(label, usd) { return { label, usd, detail: APP_FEE_DETAIL, cost: true }; }
function feeLine(spends) { const n = spends == null ? 1 : Number(spends); return { label: n > 1 ? 'Network fee (' + n + ' × $0.001)' : 'Network fee', usd: NETWORK_FEE_USD * n, cost: true }; }
// A live dollar price for an asset the wallet can price (BTC, XMR), else null — the dialog then says so, never a guess.
async function assetUsdPrice(asset) {
  try { const p = await walletCore('wallet_asset_price', { asset }); const u = Number(p && p.usd); return u > 0 ? u : null; }
  catch (_) { return null; }
}
function confirmCost({ title, lines, warning, confirmLabel }) {
  return new Promise((resolve) => {
    const prevFocus = document.activeElement;
    const back = document.createElement('div');
    back.className = 'confirm-backdrop';
    const rows = (lines || []).map((l) => '<div class="confirm-row"><span>' + escapeHtml(l.label) + '</span><b>' +
      (l.usd != null && isFinite(l.usd) ? escapeHtml(l.cost ? usdCostText(l.usd) : usdText(l.usd)) : 'No dollar price available') + '</b></div>' +
      (l.detail ? '<div class="confirm-detail">' + escapeHtml(l.detail) + '</div>' : '')).join('');
    back.innerHTML = '<div class="confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="confirmCostTitle" aria-describedby="confirmCostWarning">' +
      '<h3 id="confirmCostTitle">' + escapeHtml(title) + '</h3>' + rows +
      '<p class="confirm-warning" id="confirmCostWarning">⚠ ' + escapeHtml(warning) + '</p>' +
      '<div class="confirm-actions"><button type="button" class="btn btn-ghost" data-confirm="no">Cancel</button>' +
      '<button type="button" class="btn btn-primary" data-confirm="yes">' + escapeHtml(confirmLabel || 'Confirm') + '</button></div></div>';
    const close = (yes) => {
      document.removeEventListener('keydown', onKey, true);
      back.remove();
      if (prevFocus && prevFocus.focus) prevFocus.focus();
      resolve(yes);
    };
    const onKey = (ev) => { if (ev.key === 'Escape') { ev.stopPropagation(); close(false); } };
    back.addEventListener('click', (ev) => {
      if (ev.target === back) return close(false);
      const b = ev.target.closest('[data-confirm]');
      if (b) close(b.dataset.confirm === 'yes');
    });
    document.addEventListener('keydown', onKey, true);
    document.body.appendChild(back);
    back.querySelector('[data-confirm="no"]').focus();
  });
}
function settingsLine(k, val) { return `<div class="settings-row"><span class="settings-k">${escapeHtml(k)}</span><span class="settings-v">${escapeHtml(val)}</span></div>`; }
const SANITIZE_SAFE_TAGS = new Set(['div', 'span', 'b', 'i', 'em', 'strong', 'p', 'br', 'h1', 'h2', 'h3', 'h4', 'pre', 'code', 'button', 'a', 'img', 'small', 'ul', 'ol', 'li', 'table', 'thead', 'tbody', 'tr', 'td', 'th', 'label', 'input', 'select', 'option', 'section', 'header', 'footer', 'nav', 'hr', 'svg', 'path', 'circle', 'ellipse', 'rect', 'g', 'defs', 'lineargradient', 'radialgradient', 'stop', 'text', 'title', 'use', 'polygon', 'polyline', 'line', 'clippath', 'mask', 'filter', 'fegaussianblur', 'feoffset', 'feblend', 'femerge', 'femergenode']);
function sanitizeHtml(markup) {
  const doc = new DOMParser().parseFromString('<body>' + String(markup == null ? '' : markup) + '</body>', 'text/html');
  const walk = (node) => {
    for (const el of Array.from(node.children)) {
      if (!SANITIZE_SAFE_TAGS.has(el.tagName.toLowerCase())) { el.remove(); continue; }
      for (const a of Array.from(el.attributes)) {
        const n = a.name.toLowerCase(), v = String(a.value || '').trim().toLowerCase().replace(/\s+/g, '');
        const url = n === 'href' || n === 'src' || n === 'action' || n === 'xlink:href' || n === 'formaction';
        if (n.startsWith('on') || n === 'srcdoc' || (url && (v.startsWith('javascript:') || v.startsWith('vbscript:') || (v.startsWith('data:') && !v.startsWith('data:image/'))))) el.removeAttribute(a.name);
      }
      walk(el);
    }
  };
  walk(doc.body);
  return doc.body.innerHTML;
}

// What to CALL an asset the wallet holds. A tag is a 3-limb hex string, not a name — the registry that maps
// tags to symbols is the node's, so until a tag is registered the wallet shows a SHORT FINGERPRINT rather
// than inventing a ticker. Showing "asset 4f2a…" is honest about what is known; showing a guessed symbol
// beside someone's money is not, and a wrong ticker on a holding is how a user sends the wrong thing.
function assetLabel(tagHex) {
  if (tagHex === USDM_ASSET_TAG_HEX) return 'USDm';
  const known = (window.__ASSET_SYMBOLS || {})[tagHex];
  if (known) return known;
  // A token or NFT this wallet holds a VERIFIED card for (`rememberAssetCard`): its own symbol, with the start of its tag
  // beside it, because a symbol is not unique (anyone may create another "MOON") and the tag is what tells them apart.
  // ...or one the chain's own record names (`chainAssetRecord`, read from this wallet's own node).
  const card = assetCards()[String(tagHex).toLowerCase()] || _chainAssetRecords.get(String(tagHex).toLowerCase());
  return card ? card.symbol + ' (' + String(tagHex).slice(0, 6) + '…)' : ('asset ' + String(tagHex).slice(0, 6) + '…');
}
// ── ASSET CARDS: the names of created tokens and NFTs, kept on this device ───────────────────────────────────────────
// A card is the line an asset's creator shares. The wallet core recomputes the asset's tag from the card's own facts with
// the chain's derivation (`dapp_provider_asset_card`), so a name is kept ONLY under the tag it truly belongs to. No
// node is asked which asset this wallet looks at.
// LOCAL-STORAGE-REQUIRED: a card names an asset BEFORE the chain's own record of it can be read (its creation's block
//   has not settled on this wallet's node yet), and names one whose creation put no record there. Since spec §12.6 the
//   chain records every new asset's name and this wallet reads it from its OWN node (`chainAssetRecord`), so a card is
//   no longer the only way a name arrives; the cards a person was handed are still theirs to keep, so they stay here.
// bound: at most ASSET_CARDS_KEPT cards of at most 1,024 characters each (the core's own card limit), one key, about
//   0.3 MB at the very most; the oldest-used name is dropped past that. Names only, never funds or authority: a dropped
//   or lost name shows the asset by its tag until its card is added again.
const ASSET_CARDS_KEY = 'monerousd.assetCards';
const ASSET_CARDS_KEPT = 256;
let _assetCards = null;
// ⭐ WHAT THE CHAIN ITSELF RECORDED ABOUT AN ASSET (spec §12.6), by the tag its notes carry: its symbol, name, kind, id
// and collection, read from this wallet's OWN node (one keyed read of the node's own copy of the chain's directory;
// nothing is asked of anyone else). A record is written once and never changes, so one found is kept for this session;
// one not found yet is asked for again next time (a creation's record appears when its block has settled).
const _chainAssetRecords = new Map();
async function chainAssetRecord(tag) {
  const t = String(tag || '').toLowerCase();
  if (t.match(/^[0-9a-f]{48}$/) === null) return null; // a note tag is 24 bytes of hex; anything else is not asked
  if (_chainAssetRecords.has(t)) return _chainAssetRecords.get(t);
  try {
    const r = await nodeRpc('/dir/asset', { tag: t });
    if (r && r.found === true) {
      // a pool's share notes are named by the wallet's node from its pools (kind `share`: no id of its own, and `pool`
      // is the token whose pool they are a part of)
      // (a LOCKED share, spec §14, is a share too, with the Monday it unlocks on: `lock_week` 0 is a plain share)
      const share = r.kind === 'pool_share' || r.kind === 'pool_share_locked';
      const rec = { symbol: String(r.symbol || ''), name: String(r.name || ''), kind: r.kind === 'nft' ? 'nft' : share ? 'share' : 'token', id: String(r.id || ''), collection: String(r.collection || ''), pool: String(r.pool_token || ''),
        lock_week: share ? Math.max(0, Math.floor(Number(r.lock_week) || 0)) : 0, unlock_secs: share ? Math.max(0, Math.floor(Number(r.unlock_secs) || 0)) : 0 };
      _chainAssetRecords.set(t, rec);
      return rec;
    }
  } catch (_) { /* the node did not answer: the asset stays unnamed for now */ }
  return null;
}

function assetCards() {
  if (_assetCards) return _assetCards;
  try { const v = JSON.parse(localStorage.getItem(ASSET_CARDS_KEY) || '{}'); _assetCards = (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; } catch (_) { _assetCards = {}; }
  return _assetCards;
}
async function rememberAssetCard(cardText) {
  const v = await _tauriInvoke('dapp_provider_asset_card', { card: String(cardText || '').trim() });
  const tag = String(v.tag_hex).toLowerCase();
  const all = assetCards();
  delete all[tag];                                   // re-added last: insertion order is the use order
  // A card that carries its asset's picture can be 100 KB, and this store keeps NAMES, so such a card is kept without
  // its picture; the app that showed the picture keeps it.
  // LOCAL-STORAGE-REQUIRED: the same store as declared above `ASSET_CARDS_KEY` (a created asset's name is in no proof,
  //   record or wire field a wallet can read back; it reaches a wallet only as a card a person hands it).
  // bound: at most ASSET_CARDS_KEPT entries, each a symbol, a name and a card of at most 1,024 characters (a longer
  //   card is not stored here): one key, about 0.3 MB at the very most, the oldest-used entry dropped past that.
  const full = String(v.card);
  all[tag] = { symbol: String(v.symbol), name: String(v.name), kind: v.kind === 'nft' ? 'nft' : 'token', card: full.length <= 1024 ? full : null, pictured: full.length > 1024 };
  const tags = Object.keys(all);
  for (let i = 0; i < tags.length - ASSET_CARDS_KEPT; i++) delete all[tags[i]];
  try { localStorage.setItem(ASSET_CARDS_KEY, JSON.stringify(all)); } catch (_) { /* private mode: named for this session */ }
  // the caller gets the whole verified card and its picture; only the names stay here
  return { tag, symbol: all[tag].symbol, name: all[tag].name, kind: all[tag].kind, card: full, art_hex: v.art_hex || null, art_mime: v.art_mime || null };
}
// An amount of an asset as a person reads it: an NFT is one whole thing, a token has 8 decimals.
function assetAmountText(tagHex, atomic) {
  const card = assetCards()[String(tagHex).toLowerCase()];
  if (card && card.kind === 'nft') return 'the NFT ' + card.symbol + ' "' + card.name + '"';
  return (Number(atomic) / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' ' + assetLabel(tagHex);
}

// ── Real asset logos (inline SVG, clean-room from the ecosystem brand assets) ─────────────────────────────────
// The canonical MoneroUSD coin mark (metallic rim + the orange Monero-style M) and the assets the bridge swaps.
// Used for the wallet branding AND the unified swap activity row so a swap shows BOTH assets' real logos.
const LOGO_USDM = '<svg viewBox="0 0 256 256" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="uRimO" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#888"/><stop offset=".2" stop-color="#6a6a6a"/><stop offset=".5" stop-color="#555"/><stop offset=".8" stop-color="#444"/><stop offset="1" stop-color="#3a3a3a"/></linearGradient><linearGradient id="uRimI" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#707070"/><stop offset=".5" stop-color="#505050"/><stop offset="1" stop-color="#404040"/></linearGradient><radialGradient id="uFace" cx=".5" cy=".38" r=".55"><stop offset="0" stop-color="#4d4d4d"/><stop offset="1" stop-color="#2a2a2a"/></radialGradient><linearGradient id="uM" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f7941d"/><stop offset=".5" stop-color="#f5851a"/><stop offset="1" stop-color="#e07517"/></linearGradient></defs><circle cx="128" cy="128" r="122" fill="url(#uRimO)" stroke="#333" stroke-width="2"/><circle cx="128" cy="128" r="112" fill="url(#uRimI)"/><circle cx="128" cy="128" r="102" fill="url(#uFace)"/><circle cx="128" cy="128" r="102" fill="none" stroke="#3a3a3a" stroke-width="1.5"/><polygon points="62,178 62,88 128,154 194,88 194,178 176,178 176,118 128,166 80,118 80,178" fill="url(#uM)"/><rect x="42" y="162" width="38" height="16" rx="2" fill="url(#uM)"/><rect x="176" y="162" width="38" height="16" rx="2" fill="url(#uM)"/></svg>';
// Uniquify the coin's gradient ids per mount so multiple coins on one page never collide into a BLANK logo (the
// SVG-id duplicate-mount trap the front-end guard flags) — each injection gets its own id namespace.
let _logoSeq = 0;
function usdmCoinSvg() { const n = ++_logoSeq; return LOGO_USDM.replace(/(uRimO|uRimI|uFace|uM)\b/g, `$1${n}`); }
// Return a small logo chip for an asset symbol: each coin's OWN mark, read from the chain's own software.
// ⭐ ONE SOURCE (user 2026-11-10: "the real logos must be chain based ... the correct logo automatically anywhere on
// chain"): every node carries the native coins' marks and serves them at /api/token-logo/<SYM>; this wallet asks its
// own node (loopback, never a remote fetch), as it already did for SAT. `SOVEREIGN_BASE` is defined below; this runs at
// render time, after the script has loaded.
// ⛔ FOUND that day (audit lane): everything that was not BTC or SAT was drawn as the MoneroUSD coin, so a Monero swap
// showed MoneroUSD's logo beside "XMR". A symbol the chain has no mark for gets the chain's generated coin for that
// symbol, never another asset's logo.
function assetLogo(sym) {
  const raw = String(sym || '').replace(/[^A-Za-z0-9]/g, '');
  const s = raw.toUpperCase().replace(/^W(?=BTC|XMR|ETH|ZEC|SOL)/, ''); // a wrapped name → its coin
  if (s === 'USDM') return `<span class="asset-logo">${usdmCoinSvg()}</span>`; // the wallet's own coin, drawn inline
  // an asset with no name yet: a plain chip that claims nothing (never MoneroUSD's coin beside something that is not USDm)
  if (s === '') return '<span class="asset-logo" style="display:grid;place-items:center;border-radius:50%;background:#2a2a33;color:#9aa0ad;font-weight:800">?</span>';
  return `<span class="asset-logo"><img src="${SOVEREIGN_BASE}/api/token-logo/${s}" alt="${s}" style="width:100%;height:100%;border-radius:50%;object-fit:cover" /></span>`;
}
// ⭐ SATOSHI — one read of everything the wallet shows about SAT: the asset's tag key (so `assetLabel` names the balance
// row), whether this node seals its mining rewards to THIS wallet (provisioned on the spot if not), how many rewards this
// wallet has located, and this validator's SAT custody weight. Cached for the renderers; refreshed by `loadGovernance`.
let _satStatus = null;
async function loadSatStatus() {
  const st = await walletCore('wallet_sat_status');
  if (st && st.sat_tag_hex) {
    window.__ASSET_SYMBOLS = Object.assign(window.__ASSET_SYMBOLS || {}, { [st.sat_tag_hex]: 'SAT' });
  }
  _satStatus = st;
  return st;
}
// Paint the real MoneroUSD mark into every branding mount ([data-usdm-logo]) — welcome, sidebar, debit card.
function paintLogos() {
  document.querySelectorAll('[data-usdm-logo]').forEach((el) => { el.innerHTML = sanitizeHtml(usdmCoinSvg()); });
}
if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', paintLogos);
else paintLogos();

// Bridge to the node's PQ RPC. In Tauri → the Rust `node_rpc` command (in-process, private).
// In a plain browser (design preview) → direct fetch to the loopback node.
async function nodeRpc(path, body) {
  if (IN_TAURI) {
    return window.__TAURI__.core.invoke('node_rpc', { path, body: body ? JSON.stringify(body) : '' });
  }
  const res = await fetch(NODE_URL + path, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
  });
  return res.json();
}

// Bridge to the Rust wallet core (PQ keygen / scan / WHIR-direct prove — all in-process). These
// commands exist only inside the desktop app; in a browser preview they are unavailable and the
// caller reports that unavailable state honestly, never a success it did not receive.
async function walletCore(cmd, args) {
  // Outside the wallet app (a browser preview) there is no wallet behind the page: say so in words, on any device.
  if (!IN_TAURI) throw Object.assign(new Error('Open the MoneroUSD app to do this.'), { notInApp: true });
  // Tauri v2 binds command args by their camelCase name; the app writes snake_case (amount_usdm, key_id, …).
  // Convert every key snake_case → camelCase here so ALL arg-taking commands (send/stake/bond/pay/…) bind.
  const a = args || {};
  const camel = {};
  for (const k in a) camel[k.replace(/_([a-z])/g, (_, c) => c.toUpperCase())] = a[k];
  return window.__TAURI__.core.invoke(cmd, camel);
}

// ⭐ MAINNET IS CLOSED UNTIL THE PUBLIC LAUNCH (user 2026-11-12: "i would like the wallet mainnet sellection greyed out so
// users cant start their own mainnet"). ONE flag, read by both network switchers below: the Mainnet buttons render
// disabled with the reason, a click on them changes nothing, and a choice stored before this release can never put
// the wallet on mainnet. The node a wallet starts already runs the wallet process's own network (testnet unless
// MONEROUSD_NET says otherwise); this keeps the screen from claiming a network the node is not on. Launch day flips
// it to true in the same release that ships the mainnet genesis.
const MAINNET_OPEN = false;
const NET_OPEN = (net) => net !== 'mainnet' || MAINNET_OPEN;
const state = {
  net: (() => {
    let stored = 'testnet';
    try { stored = localStorage.getItem('monerousd.net') || 'testnet'; } catch (_) { /* private mode: testnet */ }
    return NET_OPEN(stored) ? stored : 'testnet';
  })(),
  view: 'wallet',
};
// Each Mainnet button says why it is greyed out, on the welcome toggle and in the top-bar menu alike.
for (const b of document.querySelectorAll('button[data-net]')) {
  if (NET_OPEN(b.dataset.net)) continue;
  b.disabled = true;
  b.setAttribute('aria-disabled', 'true');
  b.title = 'Mainnet starts at the public launch. This release runs the testnet, with test money only.';
  b.classList.remove('active');
}

function showScreen(id) {
  for (const s of document.querySelectorAll('[data-screen]')) s.classList.toggle('hidden', s.id !== id);
  // The deep-space backdrop persists across welcome/create/restore (full flythrough → sparkling starfield) and hides
  // once the wallet home opens — zero cost inside the app.
  if (typeof WelcomeSpace !== 'undefined') WelcomeSpace.sync(id);
}

// --- network toggle ---
document.getElementById('netToggle').addEventListener('click', (e) => {
  const btn = e.target.closest('button[data-net]');
  if (!btn || btn.disabled || !NET_OPEN(btn.dataset.net)) return;
  state.net = btn.dataset.net;
  for (const b of document.querySelectorAll('#netToggle button')) b.classList.toggle('active', b === btn);
  probeNode();
});

// --- live node status (welcome screen): a LIVE MIRROR of the backend. One O(1) /get_info (sub-1s),
//     then a lightweight poll keeps re-reading so the on-screen block height climbs WITH the chain.
//     The wallet AUTO-manages its node (ensure_node reuses-or-starts exactly one), so a not-yet-reachable
//     node shows "Starting your node…" and the poll retries — the UI never shows a stale "no node". ---
let _statusPoll = null;
async function probeNode() {
  if (_statusPoll) { clearTimeout(_statusPoll); _statusPoll = null; }
  const el = document.getElementById('statusLine');
  const t0 = performance.now();
  try {
    const info = await nodeRpc('/get_info');
    const ms = Math.round(performance.now() - t0);
    if (info && (info.status === 'OK' || info.blocks != null)) {
      // MonerousD is a GHOSTDAG: the canonical chain HEIGHT is the selected tip's blue_score, NOT the count of
      // blocks materialized in the in-memory DAG (`blocks`, which is small after an O(1) #106 frontier-persist
      // restart — it never holds all history). Mirror blue_score so the footer shows the true chain height.
      const h = info.blue_score != null ? info.blue_score : (info.height != null ? info.height : (info.blocks ?? 0));
      // JOIN-MESH-OR-NOTHING mirror: mesh_joined=false means this node has not yet adopted/grafted from a
      // live peer, so its production is gated and the height will NOT climb. Render that state honestly
      // (amber "Joining mesh…") — a green "Connected" is reserved for a node actually on the mesh chain.
      if (info.mesh_joined === false) {
        el.innerHTML = `● Joining mesh… · block <b style="color:var(--text-1)">${Number(h).toLocaleString()}</b> · dialing peers · ${Number(ms)}ms`;
        el.style.color = 'var(--warn, #f5a623)';
        _statusPoll = setTimeout(probeNode, 2000);
        return;
      }
      el.innerHTML = `● Connected · block <b style="color:var(--text-1)">${Number(h).toLocaleString()}</b> · width ${Number(info.dag_width ?? 32)} · ${Number(ms)}ms`;
      el.style.color = 'var(--good)';
      _statusPoll = setTimeout(probeNode, 4000);
      return;
    }
    el.textContent = 'Node reachable, awaiting chain…';
    _statusPoll = setTimeout(probeNode, 2000);
  } catch (_) {
    el.innerHTML = 'Starting your node<span class="blink">…</span>';
    el.style.color = 'var(--text-3)';
    _statusPoll = setTimeout(probeNode, 1500);
  }
}

// --- create / restore navigation (screens are real DOM below) ---
// ADOPTABLE A1 (user 2026-10-24: "getting USDm takes three taps or fewer"): Create draws the seed at once — the words are on
// screen after ONE tap; "I've written it down" is the second; "Add money with Bitcoin" on home is the third.
document.getElementById('btnCreate').addEventListener('click', () => {
  showScreen('screen-create');
  const seed = document.getElementById('createSeed');
  const gen = document.getElementById('btnDoGenerate');
  if (gen && seed && seed.classList.contains('hidden')) gen.click();
});
document.getElementById('btnRestore').addEventListener('click', () => showScreen('screen-restore'));
for (const b of document.querySelectorAll('[data-back]')) b.addEventListener('click', () => showScreen('screen-welcome'));

/* ════════════════════════════════════════════════════════════════════════════════════════════════════════════
   WELCOME DEEP-SPACE FLYTHROUGH  ·  self-contained Canvas 2D (no WebGL, no dependencies — safe for the embedded,
   brotli-packed bundle). A distant orange sun anchors the vanishing point; scientifically-coloured planets
   (Mars, Earth, Jupiter, Saturn's rings, Neptune, Uranus) drift in from far away, spin, and sweep past the card
   single-file as the camera travels forward through a streaming starfield — "travelling through space, seeing the
   planets along the way." Deliberately restrained: only ~2 worlds in frame at once, black stays dominant, a scrim
   keeps the card crisp — impressive, never crowded. Runs ONLY while the welcome screen is visible; freezes to one
   static frame under prefers-reduced-motion; pauses when the tab is hidden. Design reference: the Explorer live
   DAG solar-system view (three.js), distilled here to a lean, dependency-free scene.
   ════════════════════════════════════════════════════════════════════════════════════════════════════════════ */
const WelcomeSpace = (() => {
  const TAU = Math.PI * 2;
  let canvas = null, scrim = null, ctx = null, raf = 0, running = false, initted = false, mode = 'full';
  let W = 0, H = 0, DPR = 1, tPrev = 0;
  let stars = [], flyers = [], order = [], orderI = 0;
  const reduced = matchMedia('(prefers-reduced-motion: reduce)');
  // Phones render this decorative backdrop full-screen; at native 3× DPR + 60fps the per-frame planet-band fills
  // jank. On a coarse-pointer (touch) device we cap the backing-store DPR, throttle to ~30fps, and thin the star
  // field — same look, smooth on mobile (FAST pillar). Desktop keeps the full-fidelity 2× / 60fps path.
  const COARSE = (() => { try { return matchMedia('(pointer: coarse)').matches; } catch (_) { return /iPhone|iPad|iPod|Android/i.test(navigator.userAgent || ''); } })();

  // Scientifically-grounded palettes. R = relative radius (Jupiter the largest). Belts are fixed latitudes;
  // rotation is sold by drifting storms + the terminator, exactly as a real world reads at a glance.
  const BODIES = [
    { name:'Mars',    R:0.62, base:'#a7431e',
      bands:['#c1440e','#9a3416','#d0714a','#8f3013','#b8552b'], atmo:'rgba(232,142,92,0.12)', cap:'#e7d9c8' },
    { name:'Earth',   R:0.78, base:'#12406f', earth:true, atmo:'rgba(120,180,255,0.30)' },
    { name:'Jupiter', R:1.50, base:'#c6a877',
      bands:['#e6d6ac','#c49b6a','#a8794b','#dcc896','#b3794d','#cdb182'], spot:'#c25a3a', atmo:'rgba(224,184,132,0.13)' },
    { name:'Saturn',  R:1.18, base:'#d9c390',
      bands:['#e8d4a2','#ccb583','#ddc891','#c2aa76','#e0cd98'], ring:true, atmo:'rgba(232,212,160,0.12)' },
    { name:'Neptune', R:0.92, base:'#2c53c4',
      bands:['#3a63d6','#264aa6','#4b73e2','#2a3d8c','#3f68d8'], atmo:'rgba(122,152,255,0.24)' },
    { name:'Uranus',  R:0.86, base:'#8ed2d7',
      bands:['#a9dce1','#7ec5cc','#9bd3d8','#8bced3'], atmo:'rgba(162,222,227,0.20)' },
  ];

  function init() {
    canvas = document.getElementById('welcomeSpace');
    if (!canvas) return false;
    scrim = document.getElementById('spaceScrim');
    ctx = canvas.getContext('2d', { alpha: false });
    resize();
    addEventListener('resize', resize, { passive: true });
    // 2026-09-19 (the "cracked screen" on the iPhone welcome): WebKit on iOS composites a full-screen 2D canvas as
    // GPU tiles, and under memory pressure (the in-process node + Tor share the app's budget) it evicts and
    // re-rasterises tiles of the BACKING STORE at different times — a jagged seam with two scales of the same
    // scene on either side, static while the planets keep moving. The DOM above it is untouched. Two measures:
    // an INTEGER backing-store scale on phones (a fractional 1.5× is what the tiler re-samples across the seam),
    // and a self-heal that re-allocates the backing store (a fresh tile set) whenever the app returns to the
    // foreground and, on phones, every REALLOC_MS while the backdrop is live — cheap (one width assignment and
    // one repaint), never a visual jump (reallocation keeps the stars and flyers; only a real size change reseeds).
    document.addEventListener('visibilitychange', () => {
      if (document.hidden) { pause(); return; }
      reallocate();
      if (running && !reduced.matches) play();
    });
    addEventListener('pageshow', () => { reallocate(); }, { passive: true });
    try { reduced.addEventListener('change', () => { seed(); running ? (reduced.matches ? (pause(), drawStatic()) : play()) : drawStatic(); }); } catch (_) {}
    initted = true;
    return true;
  }

  // A phone's backing store is an INTEGER 1× of its CSS size (a 1290×2796 display at 1× is ~14 MB of tiles, at the
  // former 1.5× ~32 MB — the tiler's seam appeared on the fractional scale); desktop keeps up to 2×.
  const REALLOC_MS = 20000;
  let reallocTimer = 0;
  function reallocate() {
    if (!canvas || !ctx) return;
    const w = Math.round(W * DPR), h = Math.round(H * DPR);
    canvas.width = w; canvas.height = h;           // assigning width DISCARDS the backing store: a fresh tile set
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    drawStatic();                                   // never leave it black between the discard and the next frame
  }
  function resize() {
    if (!canvas || !ctx) return;
    const dpr = COARSE ? 1 : Math.min(devicePixelRatio || 1, 2);
    const w = canvas.clientWidth || innerWidth, h = canvas.clientHeight || innerHeight;
    const changed = w !== W || h !== H || dpr !== DPR || stars.length === 0;
    DPR = dpr; W = w; H = h;
    canvas.width = Math.round(W * DPR); canvas.height = Math.round(H * DPR);
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
    if (changed) seed();                             // a same-size event (iOS fires several at launch) keeps the scene
    // Setting canvas.width above CLEARS the backing store, so ALWAYS repaint a frame after a resize — otherwise a
    // resize that lands between the initial paint and the first RAF tick leaves the canvas black (the welcome
    // backdrop bug). When the animated loop is running its next frame repaints anyway; this is the safety net.
    drawStatic();
  }

  const vp = () => ({ x: W * 0.5, y: H * 0.40 });   // vanishing point = the distant sun

  function shuffle(a) { for (let i = a.length - 1; i > 0; i--) { const j = Math.floor(Math.random() * (i + 1)); [a[i], a[j]] = [a[j], a[i]]; } return a; }

  function seed() {
    const n = Math.min(COARSE ? 95 : 320, Math.max(COARSE ? 55 : 130, Math.round(W * H / (COARSE ? 9000 : 6000))));
    stars = []; for (let i = 0; i < n; i++) stars.push(newStar(true));
    order = shuffle([...BODIES.keys()]); orderI = 0;
    flyers = [ newFlyer(2.7, 1), newFlyer(1.35, -1) ];
  }

  function newStar(anywhere) {
    const { x: vx, y: vy } = vp();
    let x, y;
    if (anywhere) { x = Math.random() * W; y = Math.random() * H; }
    else { const a = Math.random() * TAU, r = 6 + Math.random() * 34; x = vx + Math.cos(a) * r; y = vy + Math.sin(a) * r; }
    return { ang: Math.atan2(y - vy, x - vx), r: Math.max(4, Math.hypot(x - vx, y - vy)), x, y,
             z: 0.35 + Math.random() * 0.65,          // parallax depth
             s: 0.7 + Math.random() * 1.9,            // base size (px) — bigger + more pronounced
             tw: Math.random() * TAU,                 // twinkle phase
             tf: 0.5 + Math.random() * 2.6,           // OWN twinkle frequency → each star twinkles at its own rate
             tp: 1 + Math.random() * 3,               // twinkle sharpness → occasional bright sparkle, not a uniform pulse
             br: 0.55 + Math.random() * 0.45,         // peak brightness (some stars noticeably brighter)
             warm: Math.random() < 0.16 };            // a few warm-tinted stars for variety
  }

  function newFlyer(z, side) {
    const bi = order[orderI % order.length]; orderI++;
    return { bi, z, side, worldY: 0.10 + Math.random() * 0.15, rot: Math.random() * TAU, spin: 0.11 + Math.random() * 0.10 };
  }

  const FRAME_MS = COARSE ? 32 : 0;   // hold the decorative backdrop at ~30fps on phones (60fps there is wasteful jank)
  function frame(t) {
    if (!running) return;
    raf = requestAnimationFrame(frame);                        // keep the loop alive even on a skipped frame
    if (FRAME_MS && tPrev && (t - tPrev) < FRAME_MS) return;    // under the interval → skip step+render, hold the cap
    const dt = Math.min(0.05, tPrev ? (t - tPrev) / 1000 : 0.016); tPrev = t;
    step(dt); render(t / 1000);
  }

  function step(dt) {
    const { x: vx, y: vy } = vp();
    for (const s of stars) {
      s.r += (s.r * 0.14 + 5) * dt * s.z;                       // stream outward from the sun (parallax by depth)
      s.x = vx + Math.cos(s.ang) * s.r; s.y = vy + Math.sin(s.ang) * s.r;
      if (s.x < -24 || s.x > W + 24 || s.y < -24 || s.y > H + 24) Object.assign(s, newStar(false));
    }
    for (const f of flyers) {
      f.z -= dt * 0.38;                                          // camera flies forward
      f.rot += dt * f.spin;
      if (f.z < 0.40) Object.assign(f, newFlyer(3.4, -f.side));  // recycle far + alternate side → single-file
    }
    flyers.sort((a, b) => b.z - a.z);                            // painter's order: far first
  }

  function render(time) {
    const g = ctx.createLinearGradient(0, 0, 0, H);
    g.addColorStop(0, '#070610'); g.addColorStop(0.5, '#050409'); g.addColorStop(1, '#030205');
    ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
    // 'full' = the planet flythrough (Welcome). 'stars' = just the sparkling starfield (Create/Restore) with a calm,
    // faint sun for depth — no planets, so the seed forms stay uncluttered.
    drawSun(time, mode === 'full' ? 1 : 0.22);
    drawStars(time);
    if (mode === 'full') for (const f of flyers) drawFlyer(f);
    drawVignette();
  }

  function drawSun(time, intensity) {
    ctx.save(); ctx.globalAlpha = intensity;
    const { x: vx, y: vy } = vp();
    const R = Math.min(W, H) * 0.26 * (1 + Math.sin(time * 0.6) * 0.03);
    const gg = ctx.createRadialGradient(vx, vy, 0, vx, vy, R);
    gg.addColorStop(0, 'rgba(255,214,150,0.92)'); gg.addColorStop(0.12, 'rgba(255,150,40,0.52)');
    gg.addColorStop(0.42, 'rgba(255,106,0,0.15)'); gg.addColorStop(1, 'rgba(255,106,0,0)');
    ctx.fillStyle = gg; ctx.fillRect(0, 0, W, H);
    const core = ctx.createRadialGradient(vx, vy, 0, vx, vy, R * 0.13);
    core.addColorStop(0, 'rgba(255,242,218,1)'); core.addColorStop(1, 'rgba(255,190,110,0)');
    ctx.fillStyle = core; ctx.beginPath(); ctx.arc(vx, vy, R * 0.13, 0, TAU); ctx.fill();
    ctx.restore();
  }

  function drawStars(time) {
    ctx.save(); ctx.globalCompositeOperation = 'lighter';
    for (const s of stars) {
      // each star twinkles on its OWN frequency; the sharpness power turns it into a random sparkle (mostly calm,
      // occasional bright flash) rather than every star pulsing together.
      const tw = Math.pow(Math.abs(Math.sin(time * s.tf + s.tw)), s.tp);
      const a = Math.min(1, (0.18 + 0.82 * tw) * s.br);
      const rad = s.s * (0.7 + 0.5 * s.z);
      const col = s.warm ? '255,232,205' : '255,250,244';
      if (s.s > 1.5) {                                          // soft glow halo on the brighter stars → pronounced
        const g = ctx.createRadialGradient(s.x, s.y, 0, s.x, s.y, rad * 3.4);
        g.addColorStop(0, `rgba(${col},${(0.42 * a).toFixed(3)})`); g.addColorStop(1, `rgba(${col},0)`);
        ctx.globalAlpha = 1; ctx.fillStyle = g;
        ctx.beginPath(); ctx.arc(s.x, s.y, rad * 3.4, 0, TAU); ctx.fill();
      }
      ctx.globalAlpha = a; ctx.fillStyle = `rgb(${col})`;
      ctx.beginPath(); ctx.arc(s.x, s.y, rad, 0, TAU); ctx.fill();
    }
    ctx.restore(); ctx.globalAlpha = 1;
  }

  function proj(f) {   // perspective-project a flyer to screen: emerges near the sun, sweeps out to the side + down
    const { x: vx, y: vy } = vp();
    return {
      cx: vx + (f.side * 0.52 / f.z) * (W * 0.40),
      cy: vy + (f.worldY / f.z) * (H * 0.34),
      R:  (Math.min(W, H) * 0.11) * BODIES[f.bi].R / f.z,
    };
  }

  function drawFlyer(f) {
    const b = BODIES[f.bi];
    const { cx, cy, R } = proj(f);
    if (R < 1.2 || cx < -R * 3 || cx > W + R * 3 || cy - R > H) return;
    // Smooth entrance/exit: a world FADES IN as it emerges from the distant sun and FADES OUT as it drifts past the
    // camera — never a hard pop. (fade-in 3.40→2.85 · fully present 2.85→1.15 · fade-out 1.15→0.50, gone before it
    // recycles at z<0.40.) The whole body dissolves as ONE unit via a shared globalAlpha threaded through the draw.
    let alpha = 1;
    if (f.z > 2.85) alpha = (3.4 - f.z) / 0.55;
    else if (f.z < 1.15) alpha = (f.z - 0.5) / 0.65;
    alpha = Math.max(0, Math.min(1, alpha));
    if (alpha <= 0.02) return;
    ctx.globalAlpha = alpha;
    const { x: vx, y: vy } = vp();
    const lightA = Math.atan2(vy - cy, vx - cx);               // lit hemisphere faces the sun — a real terminator

    if (b.ring) drawRing(cx, cy, R, false);                    // Saturn's rings: back half (behind the disc)

    if (b.atmo) {                                              // atmosphere halo
      const ha = ctx.createRadialGradient(cx, cy, R * 0.92, cx, cy, R * 1.3);
      ha.addColorStop(0, b.atmo); ha.addColorStop(1, 'rgba(0,0,0,0)');
      ctx.fillStyle = ha; ctx.beginPath(); ctx.arc(cx, cy, R * 1.3, 0, TAU); ctx.fill();
    }

    ctx.save();
    ctx.beginPath(); ctx.arc(cx, cy, R, 0, TAU); ctx.clip();
    ctx.fillStyle = b.base; ctx.fillRect(cx - R, cy - R, 2 * R, 2 * R);
    if (b.earth) drawEarth(cx, cy, R, f.rot, alpha);
    else if (b.bands) drawBands(cx, cy, R, b.bands, f.rot, alpha);
    if (b.spot) {                                              // Jupiter's Great Red Spot, scrolling with rotation
      const ph = f.rot * 1.0;
      if (Math.cos(ph) > -0.05) { ctx.globalAlpha = 0.85 * alpha; ctx.fillStyle = b.spot;
        ctx.beginPath(); ctx.ellipse(cx + Math.sin(ph) * R * 0.9, cy + R * 0.22, R * 0.22, R * 0.12, 0, 0, TAU); ctx.fill(); ctx.globalAlpha = alpha; }
    }
    if (b.cap) { ctx.fillStyle = b.cap; ctx.globalAlpha = 0.7 * alpha;  // Mars polar cap
      ctx.beginPath(); ctx.ellipse(cx, cy - R * 0.82, R * 0.5, R * 0.2, 0, 0, TAU); ctx.fill(); ctx.globalAlpha = alpha; }
    // day → night terminator + limb darkening (radial shadow away from the sun)
    const lx = cx + Math.cos(lightA) * R * 0.7, ly = cy + Math.sin(lightA) * R * 0.7;
    const term = ctx.createRadialGradient(lx, ly, R * 0.2, cx, cy, R * 1.35);
    term.addColorStop(0, 'rgba(0,0,0,0)'); term.addColorStop(0.5, 'rgba(0,0,0,0)');
    term.addColorStop(0.86, 'rgba(0,0,0,0.55)'); term.addColorStop(1, 'rgba(0,0,0,0.92)');
    ctx.fillStyle = term; ctx.fillRect(cx - R, cy - R, 2 * R, 2 * R);
    const spec = ctx.createRadialGradient(lx, ly, 0, lx, ly, R * 0.9);  // soft sub-solar highlight
    spec.addColorStop(0, 'rgba(255,240,220,0.13)'); spec.addColorStop(1, 'rgba(255,240,220,0)');
    ctx.globalCompositeOperation = 'lighter'; ctx.fillStyle = spec; ctx.fillRect(cx - R, cy - R, 2 * R, 2 * R);
    ctx.restore();

    ctx.save();                                                // warm rim light on the sunlit edge
    ctx.globalCompositeOperation = 'lighter';
    let rimPx = R * 0.03; if (rimPx < 1) rimPx = 1; ctx.lineWidth = rimPx;
    ctx.strokeStyle = 'rgba(255,214,160,0.22)';
    ctx.beginPath(); ctx.arc(cx, cy, R * 0.99, lightA - 1.1, lightA + 1.1); ctx.stroke();
    ctx.restore();

    if (b.ring) drawRing(cx, cy, R, true);                     // rings: front half (over the disc)
    ctx.globalAlpha = 1;
  }

  function drawBands(cx, cy, R, cols, rot, alpha) {
    const N = cols.length;
    for (let i = 0; i < N; i++) { ctx.fillStyle = cols[i]; ctx.fillRect(cx - R, cy - R + i * (2 * R / N), 2 * R, 2 * R / N + 1); }
    for (let k = 0; k < 3; k++) {                              // drifting storms → the rotation cue
      const ph = rot + k * 2.1;
      if (Math.cos(ph) <= -0.05) continue;                     // hidden as it wraps to the far limb
      ctx.globalAlpha = (0.14 + 0.06 * Math.cos(ph)) * alpha;
      ctx.fillStyle = k % 2 ? 'rgba(255,255,255,0.7)' : 'rgba(60,40,25,0.5)';
      ctx.beginPath(); ctx.ellipse(cx + Math.sin(ph) * R * 0.9, cy + (k - 1) * R * 0.34, R * 0.17, R * 0.06, 0, 0, TAU); ctx.fill();
    }
    ctx.globalAlpha = alpha;
  }

  function drawEarth(cx, cy, R, rot, alpha) {
    ctx.fillStyle = '#2f7d4f';                                 // continents drifting with rotation
    for (let k = 0; k < 5; k++) {
      const ph = rot * 1.1 + k * 1.7;
      if (Math.cos(ph) <= -0.15) continue;
      ctx.globalAlpha = 0.9 * alpha;
      ctx.beginPath(); ctx.ellipse(cx + Math.sin(ph) * R * 0.75, cy + Math.cos(k * 2.1) * R * 0.5,
        R * (0.15 + 0.1 * Math.abs(Math.sin(k))), R * 0.12, k, 0, TAU); ctx.fill();
    }
    ctx.globalAlpha = 0.5 * alpha; ctx.fillStyle = '#eef4ff';  // cloud swirls
    for (let k = 0; k < 4; k++) {
      ctx.beginPath(); ctx.ellipse(cx + Math.sin(rot * 0.8 + k * 2.3) * R * 0.8, cy + (k - 1.5) * R * 0.4, R * 0.3, R * 0.08, 0.3, 0, TAU); ctx.fill();
    }
    ctx.globalAlpha = alpha;
  }

  function drawRing(cx, cy, R, front) {
    ctx.save(); ctx.translate(cx, cy); ctx.rotate(-0.42);      // tilt the ring plane
    const a0 = front ? 0 : Math.PI, a1 = front ? Math.PI : TAU, yr = 0.24;
    const bands = [                                            // radius ×R, thickness ×R, colour (Cassini gap = faint)
      [1.34, 0.14, 'rgba(232,214,168,0.42)'],
      [1.58, 0.26, 'rgba(224,206,160,0.60)'],
      [1.78, 0.06, 'rgba(150,132,96,0.12)'],
      [1.96, 0.24, 'rgba(214,194,150,0.48)'],
      [2.18, 0.16, 'rgba(188,168,124,0.28)'],
    ];
    for (const [rm, th, col] of bands) {
      ctx.strokeStyle = col;
      let bandPx = R * th; if (bandPx < 1) bandPx = 1; ctx.lineWidth = bandPx;
      ctx.beginPath(); ctx.ellipse(0, 0, R * rm, R * rm * yr, 0, a0, a1); ctx.stroke();
    }
    ctx.restore();
  }

  function drawVignette() {
    const g = ctx.createRadialGradient(W * 0.5, H * 0.5, Math.min(W, H) * 0.35, W * 0.5, H * 0.5, Math.max(W, H) * 0.72);
    g.addColorStop(0, 'rgba(0,0,0,0)'); g.addColorStop(1, 'rgba(2,2,6,0.55)');
    ctx.fillStyle = g; ctx.fillRect(0, 0, W, H);
  }

  function drawStatic() { if (ctx) { step(0); render(0); } }
  function play()  {
    if (raf) return; tPrev = 0; raf = requestAnimationFrame(frame);
    if (COARSE && !reallocTimer) reallocTimer = setInterval(() => { if (running && !document.hidden) reallocate(); }, REALLOC_MS);
  }
  function pause() {
    if (raf) cancelAnimationFrame(raf); raf = 0;
    if (reallocTimer) { clearInterval(reallocTimer); reallocTimer = 0; }
  }
  function start() {
    if (!initted && !init()) return;
    running = true;
    // The planets + stars MOVE on mobile exactly like the desktop wallet — the deep-space flythrough is the design.
    // Mobile stays smooth because the COARSE path is already tuned for a phone: the backing store is DPR-capped
    // (an integer 1×, not native 3×), the loop is throttled to ~30fps (FRAME_MS=32), and the star field is thinned — same
    // look, a fraction of the per-frame fill cost. Only `prefers-reduced-motion` (an explicit accessibility opt-out)
    // freezes to a single static frame. Production runs off the main thread (the node is on a Rust bg thread), so
    // the animation never competes with node/Tor bring-up.
    if (reduced.matches) { pause(); drawStatic(); return; }
    if (!document.hidden) play();
  }
  function stop() { running = false; pause(); }

  // Keep the space backdrop live across the onboarding screens: full planet flythrough on Welcome, the calm sparkling
  // starfield on Create + Restore. Hidden once the wallet home opens (display:none → zero cost inside the app).
  const ONBOARDING = { 'screen-welcome': 'full', 'screen-create': 'stars', 'screen-restore': 'stars' };
  function sync(id) {
    if (!initted && !init()) return;
    const m = ONBOARDING[id];
    const show = m != null;
    if (canvas) canvas.style.display = show ? 'block' : 'none';
    if (scrim) scrim.style.display = show ? 'block' : 'none';
    if (!show) { stop(); return; }
    mode = m;
    start();
    drawStatic();   // repaint immediately so the mode switch (planets on Welcome → stars-only on Create/Restore) shows at once
  }

  return { start, stop, sync };
})();

// The welcome screen is the initial view — the backdrop starts here, PERSISTS on Create + Restore, and hides on home.
// DEFERRED to after first layout: at end-of-<body> script time the canvas may not yet have its CSS box, so a paint
// then lands in a 0-size / pre-composite backing store and is lost (the welcome backdrop showed pure black even on
// desktop). Paint on the next animation frame (layout flushed) AND again on `load`, so the planets + stars are up
// within the first frame on every device — no black flash, no missing backdrop.
const startSpace = () => WelcomeSpace.sync(
  ['screen-welcome', 'screen-create', 'screen-restore'].find(id => !document.getElementById(id)?.classList.contains('hidden')) || 'screen-home'
);
requestAnimationFrame(startSpace);
addEventListener('load', startSpace);

// --- restore: hand the seed to the Rust core, which derives the PQ keys + registers the scan key ---
const restoreBtn = document.getElementById('btnDoRestore');
if (restoreBtn) restoreBtn.addEventListener('click', async () => {
  const msg = document.getElementById('restoreMsg');
  const seed = (document.getElementById('restoreSeed').value || '').trim();
  if (!seed) { msg.textContent = 'Enter your 24 words or your master key.'; msg.style.color = 'var(--warn)'; return; }
  msg.textContent = 'Deriving PQ keys + scanning…'; msg.style.color = 'var(--text-2)';
  const t0 = performance.now();
  try {
    const r = await walletCore('wallet_restore', { seed });
    const ms = Math.round(performance.now() - t0);
    resetWalletSessionState(); // new identity ⇒ drop any prior wallet's in-memory swap-tracking before opening
    msg.innerHTML = `Restored in ${Number(ms)}ms — opening wallet…`; msg.style.color = 'var(--good)';
    console.log('[restore] wallet_restore ok in ' + ms + 'ms', r);
    openHome();
  } catch (e) {
    msg.textContent = (e && e.notInApp)
      ? 'Open the MoneroUSD app to restore a wallet.'
      : ('Restore failed: ' + (e && e.message || e));
    msg.style.color = 'var(--bad)';
  }
});

// --- create: the Rust core draws a fresh CSPRNG PQ seed (never a fixed/derived-from-nothing key) ---
const genBtn = document.getElementById('btnDoGenerate');
if (genBtn) genBtn.addEventListener('click', async () => {
  const msg = document.getElementById('createMsg');
  const out = document.getElementById('createSeed');
  msg.textContent = 'Drawing a fresh post-quantum seed…'; msg.style.color = 'var(--text-2)';
  try {
    const r = await walletCore('wallet_generate');
    out.textContent = (r && r.seed) ? r.seed : '';
    out.classList.remove('hidden');
    msg.textContent = 'Write this down and keep it offline. It is the only way to recover your funds.';
    msg.style.color = 'var(--warn)';
    document.getElementById('btnContinueCreate').classList.remove('hidden');
    genBtn.classList.add('hidden'); // one seed per create: drawing another would orphan the one on screen
  } catch (e) {
    msg.textContent = (e && e.notInApp)
      ? 'Open the MoneroUSD app to create a wallet.'
      : ('Create failed: ' + (e && e.message || e));
    msg.style.color = 'var(--bad)';
  }
});
const _btnContinue = document.getElementById('btnContinueCreate');
if (_btnContinue) _btnContinue.addEventListener('click', () => { resetWalletSessionState(); openHome(); });

// =========================================================================================
// HOME — desktop two-pane app. The sidebar nav switches ONE active view; each view LOADS real
// backend data on entry (balance/address/activity from the Rust core; validator set from the
// node). No hidden panels stacked off-screen — every nav click visibly swaps the content pane.
// =========================================================================================

// Render one activity row from a served PQ note (local ML-KEM decap — scan key never leaves).
function activityRowHtml(it) {
  const usdm = (typeof it.usdm === 'number')
    ? it.usdm.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 })
    : '0';
  const h = Number(it.height || 0).toLocaleString();
  if (it.kind === 'swap') {
    // CHAIN-AWARE: swap history is scoped per-(seed,chain) on the backend (swaps_path_scoped), so every row here
    // belongs to THIS wallet on THIS chain — a cross-seed / cross-chain row can never reach the front end (no
    // "not on current chain" annotation, no struck-through leak). Status is a pure live mirror of the node.
    const st = it.swap_status || 'pending';
    const label = ({ awaiting_reserve: 'reserve forming', awaiting_deposit: 'awaiting deposit', deposit_detected: 'deposit seen', minting: 'minting', gathering_quorum: 'quorum signing', published: 'in the next block', minted: 'minted', redeemed: 'redeemed' })[st] || st;
    const done = (st === 'minted' || st === 'redeemed');
    const from = it.from_asset || it.asset || 'BTC';
    const to = it.to_asset || 'USDm';
    // ONE unified swap row: [fromLogo] FROM → [toLogo] TO with BOTH assets' real logos. The node suppresses the
    // settled note this swap produced, so a swap shows as a single exchange row — never a Buy row AND a duplicate
    // Received row (the double-count the user flagged). Neutral amount; the green +USDm belongs only to a real note.
    return `<div class="activity-row"><div class="activity-left">` +
           `<span class="activity-kind k-swap"><span class="swap-logos">${sanitizeHtml(assetLogo(from))}${sanitizeHtml(assetLogo(to))}</span>Swap</span>` +
           `<span class="activity-meta">${escapeHtml(it.swap_id)} · ${escapeHtml(from)} → ${escapeHtml(to)} · ${escapeHtml(label)}</span></div>` +
           `<span class="activity-amt swap${done ? '' : ' pending'}">${escapeHtml(usdm)} USDm</span></div>`;
  }
  const out = it.direction === 'out';
  const staked = it.kind === 'staked';
  const kind = staked ? 'Staked' : (out ? 'Sent' : 'Received');
  const sign = out ? '−' : '+';
  const pending = it.status === 'pending';
  // A send no block ever carried: its money came back. Anything but these words would tell the user it was delivered.
  const dropped = it.status === 'dropped';
  // Sent/Staked carry a LIVE status (pending until the input note's nullifier is spent on-chain, then confirmed);
  // received notes are already on-chain. The status is re-read from the node each render — never cached.
  const spent = !out && it.spent === true; // a received note that has since been spent on-chain (restart-proof)
  const meta = out
    ? (staked ? 'into the stake pool' : ('to ' + (it.to || '—'))) + (dropped ? ' · did not go through — your money is back, send it again' : pending ? ' · pending' : ' · confirmed')
    // A received note whose height is UNKNOWN must not be labelled with a block number it is not in.
    // The backend now sends `null` when the height is unknown (the node serves a RECORD ordinal under the
    // name "height", so storing it as a height would strand the wallet's cursor past the end of the chain).
    // Rendering that as `block 0` told the user the note was in the genesis block. MEASURED 2026-08-10 in the
    // real wallet after a live faucet drip: two `Received +1,000.00 USDm` rows both read `block 0`, and before
    // the backend fix they read `block 18,446,744,073,709,552,000`. The funds were correct both times; the
    // block was not. Say "on chain" when the position is not known, and only print a block when there is one.
    : ((h == null || !Number.isFinite(Number(h)) || Number(h) === 0 ? 'on chain' : 'block ' + Number(h).toLocaleString()) + (spent ? ' · spent' : ''));
  return `<div class="activity-row"><div class="activity-left">` +
         `<span class="activity-kind ${out ? 'k-out' : 'k-in'}">${escapeHtml(kind)}</span>` +
         `<span class="activity-meta">${escapeHtml(meta)}</span></div>` +
         `<span class="activity-amt ${out ? 'out' : 'in'}${pending ? ' pending' : ''}${spent || dropped ? ' spent' : ''}">${dropped ? '' : escapeHtml(sign)}${escapeHtml(usdm)} ${escapeHtml(it.unit || 'USDm')}</span></div>`;
}

// The live balance — NO cache/store: every load RE-READS fresh (fetch-all served notes → local
// ML-KEM decap → sum owned). O(served notes), sub-1s.
let _lastPendingUsdm = 0; // prior render's pending amount — used to TIME the pending→confirmed settle render
let _rbLaterArmed = false;
function renderBalanceLater() {
  if (_rbLaterArmed) return;
  _rbLaterArmed = true;
  setTimeout(() => { _rbLaterArmed = false; renderBalance(); }, 50);
}
// Every non-USDm asset this wallet holds, one row each, into the home card "Your assets". Returns how many.
// Amounts come in atomic units (`assets_atomic`): an NFT is ONE unit and reads "the only one", never 0.00000001.
// A name comes from the asset's verified card when this wallet has one, else its tag's first characters; the logo is
// the chain's own (`assetLogo`: the node's mark for a coin, its generated coin for any other symbol).
function renderHeldAssets(b) {
  const card = document.getElementById('heldAssetsCard');
  const box = document.getElementById('heldAssets');
  if (!card || !box) return 0;
  const atomic = (b && b.assets_atomic) || {};
  const held = Object.keys(atomic).filter((tag) => tag !== USDM_ASSET_TAG_HEX && Number(atomic[tag]) > 0);
  card.hidden = held.length === 0;
  const cards = assetCards();
  box.innerHTML = held.map((tag) => {
    const coin = (window.__ASSET_SYMBOLS || {})[tag];            // SAT and any other coin the core names
    // named by a card this wallet was handed, else by the chain's own record of the asset (read from this wallet's
    // own node; when it arrives the list is drawn again)
    const c = cards[String(tag).toLowerCase()] || _chainAssetRecords.get(String(tag).toLowerCase());
    if (!coin && !c) chainAssetRecord(tag).then((r) => { if (r) renderBalanceLater(); });
    const nft = c && c.kind === 'nft';
    const title = coin || (c ? c.symbol : 'asset ' + String(tag).slice(0, 6) + '…');
    const under = coin ? '' : c ? c.name + ' · ' + String(tag).slice(0, 6) + '…' : 'reading its name from the chain';
    const amount = nft ? (Number(atomic[tag]) >= 1 ? 'the only one' : '') : (Number(atomic[tag]) / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 });
    return '<div class="held-asset">' + sanitizeHtml(assetLogo(coin || (c && c.symbol) || '?')) +
      '<div class="held-asset-name"><b>' + escapeHtml(title) + (nft ? ' <span class="held-asset-kind">NFT</span>' : '') + '</b><span>' + escapeHtml(under) + '</span></div>' +
      '<div class="held-asset-amt">' + escapeHtml(amount) + '</div></div>';
  }).join('');
  return held.length;
}
async function renderBalance() {
  // SAT's symbol must be known before the "also holding" line renders; load it once, retry on failure.
  if (!window.__SAT_STATUS_LOADED) {
    window.__SAT_STATUS_LOADED = true;
    loadSatStatus().then(() => renderBalanceLater()).catch(() => { window.__SAT_STATUS_LOADED = false; });
  }
  const el = document.getElementById('homeBalance');
  const sub = document.getElementById('homeBalanceSub');
  const t0 = performance.now();
  try {
    const b = await walletCore('wallet_balance');
    const ms = Math.round(performance.now() - t0); // press→backend-read wall-clock; the paint is synchronous after
    const usdm = (b && typeof b.usdm === 'number') ? b.usdm : 0;
    // PENDING-MINT (user 2026-07-11): USDm from a Buy whose BTC/XMR deposit is SEEN on-chain (has confirmations)
    // but not yet minted shows as PENDING — visible in the balance yet NOT spendable (Send gates on `usdm`, the
    // confirmed amount only). `pending_usdm` comes straight from the backend (deposit_detected/minting status), so
    // the pending line is keyed on REAL deposit confirmations, not on swap creation. The instant the deposit
    // confirms, the mint note lands in `usdm` and pending drops to 0 → the amount settles into the spendable total
    // automatically. One backend call (no extra swap_history fetch) keeps the render sub-1s.
    const pending = (b && typeof b.pending_usdm === 'number') ? b.pending_usdm : 0;
    // CHANGE IN FLIGHT (owner 2026-09-21): right after a send the input note has left the spendable set while
    // the change note has not landed yet. The backend reports that change as `pending_change_usdm`; the headline
    // shows spendable + change in flight, so a send of 0.50 from 25.00 reads 24.50 at once and never 0. Send
    // still gates on `usdm` (the spendable figure) exactly as before.
    const pendingChange = (b && typeof b.pending_change_usdm === 'number') ? b.pending_change_usdm : 0;
    const headline = usdm + pendingChange;
    el.textContent = headline.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 });
    // ⛔⛔⛔ EVERY ASSET THIS WALLET HOLDS MUST BE VISIBLE. The headline figure is USDm ONLY — the backend
    // stopped summing across assets, because at the atomic level a wrapped note and a USDm note are the
    // same integer and a combined total is units of nothing. That fix makes the headline honest, but on
    // its own it would make a user's OTHER holdings INVISIBLE, and on this project losing the VIEW of
    // funds IS fund loss. So render every non-USDm asset the backend reports beside it: shown as held,
    // never folded into the USDm number, never silently dropped.
    // ⭐ ONE ROW FOR EACH (user 2026-11-10: "nfts and tokens must show up in your wallet when held, dissapear when not
    // held"). The list IS the wallet's own spendable notes as the core just read them: an asset is drawn while it is
    // held and is absent from the next drawing once it is not; nothing here remembers a holding. The one-line summary
    // beside the balance stays as the count, so a holding is never out of sight even with the list scrolled away.
    const heldN = renderHeldAssets(b);
    const otherLine = heldN ? ` · ${heldN} other asset${heldN === 1 ? '' : 's'} below` : '';
    // Spendable is not final: money that arrived a moment ago can be spent now, and the chain finishes settling it within minutes.
    const settling = (b && typeof b.settling_usdm === 'number') ? b.settling_usdm : 0;
    const settlingLine = settling > 0
      ? ` · <span class="bal-pending" title="You can spend this now. Wait for it to finish settling before handing over goods for it.">${settling.toLocaleString(undefined, { maximumFractionDigits: 8 })} still settling</span>`
      : '';
    const changeLine = pendingChange > 0
      ? ` · <span class="bal-pending">${pendingChange.toLocaleString(undefined, { maximumFractionDigits: 8 })} change confirming</span> · ${usdm.toLocaleString(undefined, { maximumFractionDigits: 8 })} spendable now`
      : '';
    sub.innerHTML = pending > 0
      ? `USDm · <span class="bal-pending">+${pending.toLocaleString(undefined, { maximumFractionDigits: 8 })} pending</span> · confirming deposit (not yet spendable)${changeLine} · ${Number(b.scanned_notes ?? 0)} notes in ${ms}ms${otherLine}`
      : `USDm · live${settlingLine}${changeLine} · scanned ${Number(b.scanned_notes ?? 0)} notes in ${Number(ms)}ms${otherLine}`;
    // TIME the settle: when pending falls to 0 and the confirmed balance has absorbed it, log the render latency so
    // we can confirm the pending→confirmed transition renders fast (sub-1s) the moment the on-chain condition is met.
    if (_lastPendingUsdm > 0 && pending === 0) {
      console.log('[home] pending→confirmed SETTLED — balance render ' + ms + 'ms (paint ' + Math.round(performance.now() - t0) + 'ms), now spendable ' + usdm);
    }
    _lastPendingUsdm = pending;
    console.log('[home] wallet_balance ' + ms + 'ms · spendable ' + usdm + ' · pending ' + pending, b);
    // ARRIVING (speed lane 2026-11-10): a payment to this wallet that has reached the network and passed the node's own
    // checks, before any block has settled it. Shown seconds after it is sent, never added to the balance, and it
    // cannot be spent yet. Read after the balance has painted, so it never delays the headline; a failed read shows nothing.
    walletCore('wallet_incoming').then((inc) => {
      const arriving = (inc && typeof inc.usdm === 'number') ? inc.usdm : 0;
      const old = document.getElementById('homeArriving');
      if (old) old.remove();
      if (arriving > 0) {
        const s = document.createElement('span');
        s.id = 'homeArriving';
        s.className = 'bal-pending';
        // LOCKED (speed lane 2026-11-10): the share of validator stake that has signed "no other spend of these notes".
        // ⛔ It is shown as a share and never as "final": the chain does not yet refuse a second spend because of it.
        const lockedPct = (inc && typeof inc.locked_bp === 'number') ? Math.floor(inc.locked_bp / 100) : 0;
        s.title = 'This payment has reached the network and is being settled. It is not part of your balance yet and cannot be spent yet.'
          + (lockedPct > 0 ? ' Validators holding ' + lockedPct + '% of the stake have signed that they will accept no other spend of these notes.' : '');
        s.textContent = ' · ' + arriving.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' arriving, not spendable yet'
          + (lockedPct > 0 ? ' (' + lockedPct + '% locked)' : '');
        sub.appendChild(s);
      }
    }).catch(() => {});
  } catch (e) {
    el.textContent = '—';
    sub.textContent = (e && e.notInApp) ? 'Open the MoneroUSD app to read your balance.'
      : ('Balance unavailable: ' + (e && e.message || e));
  }
}

// Per-view loaders — each reads LIVE from the backend on entry, so the pane is a live mirror.
async function loadWallet() {
  renderBalance();
  const peek = document.getElementById('walletActivityPeek');
  try {
    const r = await walletCore('wallet_activity');
    const items = (r && r.activity) || [];
    peek.innerHTML = items.length
      ? items.slice(0, 4).map(activityRowHtml).join('')
      : '<div class="activity-empty">No activity yet.</div>';
  } catch (e) {
    peek.innerHTML = '<div class="activity-empty">' + ((e && e.notInApp)
      ? 'Open the MoneroUSD app to see activity.' : ('Unavailable: ' + escapeHtml(e && (e.message || e)))) + '</div>';
  }
}
async function loadReceive() {
  const box = document.getElementById('homeAddress');
  const qrBox = document.getElementById('recvQr');
  try {
    const a = await walletCore('wallet_address');
    const addr = (a && a.address) || '—';
    box.textContent = addr;
    // Render a phone-scannable QR of the PQ receive address (same node-side SVG generator the Buy deposit QR uses).
    // Scanning yields exactly what "Copy address" copies — the raw ML-KEM/ML-DSA address. Sub-1s, node-local.
    if (qrBox) {
      if (a && a.address) {
        walletCore('wallet_qr_svg', { data: a.address })
          .then((svg) => { if (qrBox) qrBox.innerHTML = sanitizeHtml(svg); })
          .catch(() => { if (qrBox) qrBox.innerHTML = ''; });
      } else {
        qrBox.innerHTML = '';
      }
    }
  } catch (e) {
    box.textContent = (e && e.notInApp) ? 'Open the MoneroUSD app to see your address.'
      : ('Address unavailable: ' + (e && (e.message || e)));
    if (qrBox) qrBox.innerHTML = '';
  }
  // This wallet's claimed @username, shown on this page above the address: live-verified that it STILL resolves to this
  // address (never a stale claim). With no name, one line leads to claiming one.
  const nameBox = document.getElementById('recvName');
  const claim = document.getElementById('recvClaimName');
  const un = document.getElementById('myUsernameBox');
  let mine = null;
  let inApp = true;
  try { mine = await walletCore('wallet_my_username'); } catch (e) { mine = null; inApp = !(e && e.notInApp); }
  const owned = !!(mine && mine.name && mine.owned);
  if (nameBox) {
    nameBox.hidden = !owned;
    if (owned) document.getElementById('recvUsername').textContent = '@' + mine.name;
  }
  if (claim) claim.hidden = owned || !inApp;
  if (owned) state.myUsername = mine.name;
  if (un) { if (owned) { un.style.display = 'block'; un.textContent = 'You are @' + mine.name; } else un.style.display = 'none'; }
}
document.getElementById('btnCopyUsername')?.addEventListener('click', async (e) => {
  const name = (document.getElementById('recvUsername') || {}).textContent || '';
  if (!name || name === '@—') return;
  const b = e.currentTarget;
  try { await navigator.clipboard.writeText(name); b.textContent = 'Copied'; } catch (_) { b.textContent = name; }
  setTimeout(() => { b.textContent = 'Copy'; }, 1600);
});
document.getElementById('recvClaimName')?.addEventListener('click', () => {
  switchView('send');
  if (window.mobileLayout) window.mobileLayout.open('send', 'Pay');
  setTimeout(() => { const box = document.getElementById('nameInput'); if (box) { box.scrollIntoView({ behavior: 'smooth', block: 'center' }); box.focus({ preventScroll: true }); } }, 350);
});
// A monotonically-rising token so creating a NEW charge cancels the previous charge's live monitor (no two
// checkouts polling at once — the latest charge owns the status line).
let _posToken = 0;
// POS (merchant checkout): build a `monerousd:` charge for an exact amount from the wallet's LIVE address, show +
// copy it, THEN live-monitor the chain for the incoming confidential note of that amount and flip to
// "✓ Payment received" the instant it lands. The scan key never leaves the wallet — wallet_await_payment reuses
// the local delta owned-note scan; each poll is a live read of the chain, not a one-shot.
let _posExpiryTimer = null;
// End the live charge = STOP the MoneroPay BLE advertiser. There is NO local same-device charge store: the buyer's
// tap must reach the charge over the REAL BLE radio (moneropay_ble_pay_nearby) or fail honestly — no fallback that
// could make a two-wallet test pass without the radio. Called on reset / expiry / paid.
function clearActiveCharge() {
  try { walletCore('moneropay_ble_stop_merchant').catch(() => {}); } catch (_) {}
}
// Return the POS panel to the amount-entry state (also stops any running monitor / countdown).
function posReset() {
  _posToken++; // supersede any running monitor
  state.posCharge = null;
  if (_posExpiryTimer) { clearInterval(_posExpiryTimer); _posExpiryTimer = null; }
  clearActiveCharge();
  const entry = document.getElementById('posEntry');
  const term = document.getElementById('posTerminal');
  if (entry) entry.style.display = '';
  if (term) term.style.display = 'none';
}
// POS (merchant checkout) — our OWN private post-quantum TAP-TO-PAY: mint an ML-DSA-signed charge (amount +
// destination welded to the merchant's signature, single-use nonce, 120s expiry — see wallet_pos_charge +
// pos_charge_tamper_rejected), show the Apple-Pay-style terminal, and live-monitor the chain for the incoming
// confidential note. The scan key never leaves the wallet — wallet_await_payment reuses the local delta owned-note
// scan; each poll is a live read of the chain, not a one-shot.
async function doRequest() {
  const amount = parseFloat(document.getElementById('reqAmount').value);
  const entry = document.getElementById('posEntry');
  const term = document.getElementById('posTerminal');
  const status = document.getElementById('posStatus');
  const tap = document.getElementById('posTap');
  const expEl = document.getElementById('posExpiry');
  const token = ++_posToken; // supersede any prior charge's monitor
  if (!(amount > 0)) {
    if (status) { term.style.display = ''; entry.style.display = 'none'; }
    if (status) { status.className = 'pos-status err'; status.textContent = 'Enter a positive amount.'; }
    return;
  }
  let charge;
  try {
    charge = await walletCore('wallet_pos_charge', { amount_usdm: amount });
    // The live charge this terminal advertises — page state only (R7 F12: the headless flow reads it here; a buyer still
    // reaches it over the real BLE radio or not at all). Cleared when the terminal resets.
    state.posCharge = charge;
  } catch (e) {
    term.style.display = ''; entry.style.display = 'none';
    if (status) { status.className = 'pos-status err'; status.textContent = (e && e.notInApp)
      ? 'Open the MoneroUSD app to run the POS.' : ('Unavailable: ' + (e && (e.message || e))); }
    return;
  }
  // Show the tap-to-pay terminal.
  entry.style.display = 'none';
  term.style.display = '';
  if (tap) { tap.classList.remove('paid'); tap.style.display = ''; }
  // DB-319: the terminal shows the amount its charge SIGNED (derived from the signed atomic amount), and watches for
  // exactly that — the payer's wallet pays that same signed amount, never a separately typed or rounded number.
  const signedUsdm = Number(charge.amount_usdm) || amount;
  document.getElementById('posAmount').textContent = signedUsdm.toLocaleString(undefined, { minimumFractionDigits: 2 });
  const mine = (state.myUsername ? ('@' + state.myUsername) : (charge.address ? (charge.address.slice(0, 10) + '…' + charge.address.slice(-6)) : '—'));
  document.getElementById('posMerchant').textContent = 'to ' + mine;
  if (status) { status.className = 'pos-status'; status.textContent = 'Waiting for tap…'; }
  const since = Number(charge.since_height) || 0;
  const expiry = Number(charge.expiry_ms) || (Date.now() + 120000);
  // MoneroPay: BROADCAST the charge over BLE so a nearby wallet can TAP to pay it — the merchant half of tap-to-pay,
  // engrained (pressing Charge advertises; zero setup). The charge is SEALED per-payer (ML-KEM session) before it
  // ever hits the air, so the radio only sees ciphertext. Stopped automatically when the charge clears/expires/pays.
  try { walletCore('moneropay_ble_start_merchant', { charge }).catch(() => {}); } catch (_) {}
  // Live expiry countdown — the charge is single-use and self-expires (no stale charge lingers).
  if (_posExpiryTimer) clearInterval(_posExpiryTimer);
  const tick = () => {
    if (token !== _posToken) { clearInterval(_posExpiryTimer); return; }
    const ms = expiry - Date.now();
    if (ms <= 0) {
      clearInterval(_posExpiryTimer);
      clearActiveCharge(); // an expired charge can no longer be tapped
      if (token === _posToken && status && !status.classList.contains('ok')) {
        status.className = 'pos-status err'; status.textContent = 'Charge expired — start a new one.';
        if (tap) tap.style.display = 'none';
        _posToken++; // supersede the settle-watch poll — an expired charge stops watching (single-use tap window)
      }
      if (expEl) expEl.textContent = '';
      return;
    }
    const s = Math.ceil(ms / 1000);
    if (expEl) expEl.textContent = 'expires in ' + Math.floor(s / 60) + ':' + String(s % 60).padStart(2, '0');
  };
  tick();
  _posExpiryTimer = setInterval(tick, 1000);
  const t0 = Date.now();
  const poll = async () => {
    if (token !== _posToken) return; // a newer charge / cancel superseded this monitor
    try {
      const r = await walletCore('wallet_await_payment', { amount_usdm: signedUsdm, since_height: since });
      if (token !== _posToken) return;
      if (r && r.paid) {
        if (_posExpiryTimer) { clearInterval(_posExpiryTimer); _posExpiryTimer = null; }
        clearActiveCharge(); // settled — the single-use charge is consumed
        const secs = ((Date.now() - t0) / 1000).toFixed(1);
        if (tap) tap.classList.add('paid');
        if (status) {
          status.className = 'pos-status ok';
          status.textContent = '✓ Paid · ' + Number(amount).toLocaleString(undefined, { minimumFractionDigits: 2 }) + ' USDm · ' + secs + 's · block ' + Number(r.height).toLocaleString();
        }
        if (expEl) expEl.textContent = '';
        loadWallet(); // reflect the new balance the moment the charge settles
        return; // settled — stop polling
      }
    } catch (_) { /* keep waiting; a transient read never settles or fails the charge */ }
    setTimeout(poll, 1000);
  };
  setTimeout(poll, 1000);
}
// USDm Pay: claim a @username handle (ML-DSA signed by the spend key; the node binds it to H(pubkey), first-come).
async function doClaimName() {
  const st = document.getElementById('nameStatus');
  const name = (document.getElementById('nameInput').value || '').trim().replace(/^@+/, '');
  if (!name) { st.className = 'send-status err'; st.textContent = 'Enter a username.'; return; }
  // The chain keeps a name on every node for ever, so publishing one is paid for by its size: the price is the chain's
  // own, read from the wallet's core before anything is signed, and shown here in dollars with the yearly fee.
  let chain;
  try { chain = await walletCore('wallet_dir_price', { what: 'name', key: name, display: '', topic: '' }); }
  catch (e) { st.className = 'send-status err'; st.textContent = 'The price of publishing a name could not be read: ' + ((e && e.message) || e); return; }
  if (!(await confirmCost({ title: 'Claim @' + name, confirmLabel: 'Claim',
    lines: [appFeeLine('Username fee (yearly)', 10),
      { label: 'Chain fee to publish it', usd: Number(chain.usd), cost: true, detail: 'paid once, for the space the name takes on every node' },
      { label: 'Network fee', usd: Number(chain.network_fee_usd), cost: true }],
    warning: 'Your @' + name + ' is published to the chain and stands for this wallet in your shop links and your site. It cannot be made private again. If the name is already taken you are not charged. If someone else\'s claim for the same name lands in the same few seconds and wins, this fee is still spent and the name is theirs. Paying by name is not switched on yet.' }))) return;
  st.className = 'send-status'; st.textContent = 'Signing + claiming @' + name + '…';
  try {
    const r = await walletCore('wallet_register_username', { name: name });
    const yours = () => {
      st.className = 'send-status ok';
      st.textContent = '✓ @' + name + ' is yours. Your shop links and your site can carry it.';
      loadSend(); // refresh the Pay hub card holder + "You own @name" mirror (the username panel lives on Pay)
    };
    if (r && (r.result === 'REGISTERED' || r.result === 'UPDATED')) {
      yours();
    } else if (r && r.result === 'PENDING') {
      // The claim is on its way into a block. A name is yours when the chain says so, never before: the first claim
      // the chain orders wins, on every node alike. Ask this wallet's own node until it answers either way.
      st.className = 'send-status';
      st.textContent = 'Claim sent. @' + name + ' becomes yours when the chain confirms it, usually within a few minutes. You can keep using the wallet.';
      const mine = () => walletCore('wallet_my_username').then((m) => !!(m && (m.names || []).indexOf(name.toLowerCase()) >= 0), () => false);
      const taken = () => walletCore('wallet_resolve_username', { name: name }).then((v) => !!(v && v.address), () => false);
      const ask = async () => {
        if (await mine()) return yours();
        if (await taken()) {
          st.className = 'send-status err';
          st.textContent = '@' + name + ' was claimed by someone else first. You were not charged. Try another name.';
          return;
        }
        setTimeout(ask, 5000);
      };
      setTimeout(ask, 5000);
    } else {
      st.className = 'send-status err';
      st.textContent = '@' + name + ' is already claimed by another owner.';
    }
  } catch (e) {
    st.className = 'send-status err';
    st.textContent = 'Failed: ' + ((e && e.notInApp) ? 'open the MoneroUSD app.' : (e && (e.message || e)));
  }
}
async function loadActivity() {
  const list = document.getElementById('activityList');
  list.innerHTML = '<div class="activity-empty">Scanning your notes…</div>';
  const t0 = performance.now();
  try {
    const r = await walletCore('wallet_activity');
    console.log('[activity] wallet_activity ' + Math.round(performance.now() - t0) + 'ms', r);
    const items = (r && r.activity) || [];
    list.innerHTML = items.length ? items.map(activityRowHtml).join('')
      : '<div class="activity-empty">No activity yet.</div>';
  } catch (e) {
    list.innerHTML = '<div class="activity-empty">' + ((e && e.notInApp)
      ? 'Open the MoneroUSD app to see activity.' : ('Activity unavailable: ' + escapeHtml(e && (e.message || e)))) + '</div>';
  }
}
// ⭐ §BR-3 17.5 layer 1 — THE REPAYMENT POT (shown only after a custody theft): buy the slashed SAT at the floor; the USDm paid is
// retired. One confirmation naming the dollars paid, the SAT received and the network fee.
state.pot = null;
async function refreshPot() {
  const card = document.getElementById('potCard');
  try { state.pot = await walletCore('wallet_repayment_pot'); } catch (_) { state.pot = null; }
  const p = state.pot;
  if (!card) return;
  if (!p || !(Number(p.pot_sat) > 0) || !p.floor_usdm_per_sat) { card.classList.add('hidden'); return; }
  card.classList.remove('hidden');
  const el = document.getElementById('potAvail');
  if (el) el.textContent = 'Pot: ' + Number(p.pot_sat).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT at ' + usdText(Number(p.floor_usdm_per_sat)) + ' each';
}
async function doPotBuy() {
  const st = document.getElementById('potStatus');
  const usdm = parseFloat(document.getElementById('potAmount').value || '0');
  const p = state.pot;
  if (!(usdm > 0) || !p || !p.floor_usdm_per_sat) { if (st) st.textContent = 'Enter a positive USDm amount.'; return; }
  const sat = Math.min(usdm / Number(p.floor_usdm_per_sat), Number(p.pot_sat));
  if (!(await confirmCost({ title: 'Buy SAT from the repayment pot?', confirmLabel: 'Buy SAT',
    lines: [{ label: 'You pay', usd: usdm, detail: usdm.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm, retired from the supply' },
      { label: 'You receive', usd: usdm, detail: '≈ ' + sat.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT at the floor price' },
      feeLine()],
    warning: 'The USDm you pay is destroyed to restore the reserve; the SAT arrives once custody frames the purchase (a few blocks). If the floor moves first, nothing is spent and you can buy again.' }))) return;
  try {
    const r = await walletCore('wallet_pot_buy', { usdm });
    if (st) st.textContent = 'Sent to custody: ' + Number(r.sat).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT on its way.';
  } catch (e) { if (st) st.textContent = 'Not bought: ' + (e && (e.message || e)); }
  refreshPot();
}
(function wirePot() {
  const b = document.getElementById('btnPotBuy');
  if (b && !b._wired) { b._wired = true; b.addEventListener('click', doPotBuy); }
})();

async function loadEarn(opts) {
  // A post-action refresh (right after a stake) passes {keepStatus:true} so the fresh green confirmation is NOT
  // wiped by this live-data refresh; a plain tab-entry (VIEW_LOADERS) passes nothing and clears any stale status.
  const st = document.getElementById('stakeStatus');
  if (st && !(opts && opts.keepStatus)) { st.textContent = ''; st.className = 'send-status'; }
  refreshPot(); // §BR-3 17.5: the repayment pot card, only after a theft
  const setStat = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  // Spendable balance drives what you can stake (live mirror, read fresh each entry).
  const avail = document.getElementById('stakeAvail');
  try {
    const b = await walletCore('wallet_balance');
    if (avail) avail.textContent = 'Spendable: ' + Number((b && b.usdm) || 0).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm';
  } catch (e) {
    if (avail) avail.textContent = (e && e.notInApp) ? 'Open the MoneroUSD app to stake.' : 'Spendable: —';
  }
  // Hero stats — YOUR stake (privacy-correct: only the wallet knows its stakes), the LIVE governance-set target APR
  // + stake lock (real consensus params mirrored from the node), and the network's staked-note count.
  try {
    const ms2 = await walletCore('wallet_my_stake');
    const stUsdm = Number((ms2 && ms2.usdm) || 0);
    setStat('earnStaked', (ms2 && ms2.is_staking)
      ? (stUsdm.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' USDm') : '0.00 USDm');
    // HONEST + ADAPTIVE APR (user 2026-07-11): the governance `stake_reward_apr_bps` is a CEILING ("up to X%
    // target"); the LIVE rate is only what the ACTUAL reserve-yield + fee-redistribution surplus currently backs.
    // No fee volume → 0% live (accruing), NEVER a promised flat percent — it adapts to real economics.
    const liveApr = Number((ms2 && ms2.apr_pct) || 0);
    setStat('earnApr', liveApr > 0 ? liveApr.toFixed(2) + '%' : 'Paused');
    // ADOPTABLE (R7 F9): the holder yield in DOLLARS a year on what is staked now — USDm is the dollar, so staked × live APR;
    // an honest $0.00 while nothing is staked or the live rate is 0.
    setStat('earnYieldUsd', usdText(stUsdm * liveApr / 100) + ' / year');
    // §17.6: Stake/Claim follow the core's own state (a paused core says why, in its own words); Unstake and Claim need a
    // stake to act on — never a button that fails after the user presses it.
    const paused = !!(ms2 && ms2.stake_paused);
    const staking = !!(ms2 && ms2.is_staking);
    // §17.6 (lane funds-brb33): Unstake and Claim act only on a stake whose spend can be built NOW — the core's own dry run
    // (`can_unstake`); a stake still confirming is shown as pending with its reason, never offered to a press that would fail.
    const canAct = (ms2 && typeof ms2.can_unstake === 'boolean') ? ms2.can_unstake : staking;
    const pendingStake = Number((ms2 && ms2.pending_usdm) || 0);
    const setDis = (id, d) => { const b = document.getElementById(id); if (b) b.disabled = d; };
    setDis('btnStake', paused);
    setDis('btnClaimReward', paused || !canAct);
    setDis('btnUnstake', paused || !canAct);
    setStat('earnStakePending', pendingStake > 0
      ? (pendingStake.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' USDm confirming — ' + String((ms2 && ms2.pending_reason) || 'ready once the chain folds it'))
      : '');
    if (paused && !(opts && opts.keepStatus)) {
      const st = document.getElementById('stakeStatus');
      if (st) { st.className = 'send-status'; st.textContent = String(ms2.paused_reason || 'Staking is paused.'); }
    }
    // Claimable-reward CARD — the REAL node-derived accrued reward (weight·(index_now − index_at_stake)/scale over
    // your own stakes; rises each reward epoch as the reserve-yield surplus distributes; realized as a confidential
    // note on claim). Node-derived, never fabricated — 0.00 honestly when no surplus has flowed yet.
    const accruedUsdm = Number((ms2 && ms2.accrued_usdm) || 0);
    setStat('earnClaimable', accruedUsdm.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm');
    const rr = document.getElementById('rewardRow');
    if (rr) rr.classList.toggle('has-reward', accruedUsdm > 0);
    if (ms2 && ms2.is_staking) setStat('earnStaked', stUsdm.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' USDm' + (accruedUsdm > 0 ? '  ·  +' + accruedUsdm.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' earned' : ''));
  } catch (_) { setStat('earnStaked', '—'); setStat('earnApr', '—'); setStat('earnLock', '🔒 Lock: —'); setStat('earnAprLine', 'Reward: —'); }
  // The "Network staked" count LEFT 2026-10-04 with the node's stake frontier: a public staked-note COUNT is a volume
  // gauge the digital-cash cardinal forbids, and the node no longer serves one (`/get_stake_tree` answers the staking
  // POLICY parameters only). A staker's own position is `earnStaked`, read from its own wallet above.
}

// Broadcast-on-press: lock USDm into the stake pool via the same 4-gate WHIR carrier as Send.
async function doStake() {
  const btn = document.getElementById('btnStake');
  const st = document.getElementById('stakeStatus');
  const amount = parseFloat(document.getElementById('stakeAmount').value);
  if (!(amount > 0)) { st.className = 'send-status err'; st.textContent = 'Enter a positive amount.'; return; }
  const aprTxt = (document.getElementById('earnApr') || {}).textContent || '';
  if (!(await confirmCost({ title: 'Stake ' + amount.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm', confirmLabel: 'Stake',
    lines: [{ label: 'You stake', usd: amount, detail: amount.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm, private — nobody sees the amount' }, feeLine()],
    warning: 'Staked USDm is not spendable until you unstake, which you can do any time. Rewards (' + aprTxt + ' a year) are paid from the network fees the stakers\' pool has collected; if the pool is short, a claim waits until it has collected enough.' }))) return;
  btn.disabled = true; st.className = 'send-status'; st.textContent = 'Proving + staking…';
  const t0 = performance.now();
  try {
    const r = await walletCore('wallet_stake', { amount_usdm: amount, lock_tier: 0 });
    const ms = Math.round(performance.now() - t0);
    console.log('[stake] wallet_stake ' + ms + 'ms', r);
    st.className = 'send-status ok';
    if (!(r && r.published)) throw new Error('the network did not take the stake yet (' + String((r && r.outcome) || 'unknown') + ') — nothing moved');
    st.textContent = '✓ Staked (' + ms + 'ms) · it shows in Your stake once the next block applies it';
    document.getElementById('stakeAmount').value = '';
    // Refresh the live stake stats but KEEP the green confirmation (it persists until the next action / tab switch).
    setTimeout(() => { renderBalance(); loadEarn({ keepStatus: true }); }, 400);
  } catch (e) {
    st.className = 'send-status err';
    st.textContent = 'Failed: ' + ((e && e.notInApp) ? 'open the MoneroUSD app to stake.' : (e && (e.message || e)));
  } finally { btn.disabled = false; }
}
// EARN — HARVEST the accrued stake-to-earn reward: proves ownership of each staked note + mints a confidential reward
// note bound to exactly the accrued R (node re-verifies the mint weld) + broadcasts /claim_stake_reward. The reward
// lands as a real note the next scan credits, so the balance rises live. Principal stays staked (harvest ≠ unstake).
async function doClaim() {
  const btn = document.getElementById('btnClaimReward');
  const st = document.getElementById('claimStatus');
  if (!(await confirmCost({ title: 'Harvest your stake reward', confirmLabel: 'Harvest', lines: [{ label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
    warning: 'Each staked note re-stakes from today and pays its reward to your spendable balance, privately — no claim links to your stake.' }))) return;
  btn.disabled = true; st.className = 'send-status'; st.textContent = 'Proving ownership + minting reward…';
  const t0 = performance.now();
  try {
    const r = await walletCore('wallet_claim_stake_reward');
    const ms = Math.round(performance.now() - t0);
    console.log('[claim] wallet_claim_stake_reward ' + ms + 'ms', r);
    const usdm = Number((r && r.reward_usdm) || 0);
    const n = Number((r && r.harvested) || 0);
    if (n > 0 && usdm > 0) {
      st.className = 'send-status ok';
      st.textContent = '✓ Harvested ' + usdm.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm from ' + n + ' stake' + (n === 1 ? '' : 's') + ' (' + ms + 'ms)';
    } else {
      st.className = 'send-status';
      st.textContent = 'No reward accrued yet — check back after the next reward epoch.';
    }
    setTimeout(() => { renderBalance(); loadEarn(); }, 400);
  } catch (e) {
    st.className = 'send-status err';
    st.textContent = 'Failed: ' + ((e && e.notInApp) ? 'open the MoneroUSD app to claim.' : (e && (e.message || e)));
  } finally { btn.disabled = false; }
}
// UNSTAKE — every staked note back to spendable USDm with its reward, one private transaction each.
async function doUnstake() {
  const btn = document.getElementById('btnUnstake');
  const st = document.getElementById('claimStatus');
  if (!(await confirmCost({ title: 'Unstake your USDm', confirmLabel: 'Unstake', lines: [{ label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
    warning: 'Your staked USDm returns to your spendable balance with the reward it has earned. It stops earning until you stake again.' }))) return;
  btn.disabled = true; st.className = 'send-status'; st.textContent = 'Proving + unstaking…';
  try {
    const r = await walletCore('wallet_unstake');
    st.className = 'send-status ok';
    st.textContent = '✓ Unstaking ' + Number((r && r.principal_usdm) || 0).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm + ' + Number((r && r.reward_usdm) || 0).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' reward · it returns once the next block applies it';
    setTimeout(() => { renderBalance(); loadEarn({ keepStatus: true }); }, 400);
  } catch (e) {
    st.className = 'send-status err';
    st.textContent = 'Failed: ' + ((e && e.notInApp) ? 'open the MoneroUSD app to unstake.' : (e && (e.message || e)));
  } finally { btn.disabled = false; }
}
async function doBond() {
  const st = document.getElementById('bondStatus');
  const amount = parseFloat(document.getElementById('bondAmount').value);
  if (!(amount > 0)) { st.className = 'send-status err'; st.textContent = 'Enter a positive amount.'; return; }
  if (!(await confirmCost({ title: 'Bond ' + amount.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT', confirmLabel: 'Bond',
    lines: [{ label: 'You bond', usd: null, detail: amount.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT — the wallet has no live SAT dollar price' }, { label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
    warning: 'Bonded SAT is locked until you unbond; unbonding takes 21 days (the governed window). A validator that breaks the protocol rules can lose part of its bond (slashing).' }))) return;
  st.className = 'send-status'; st.textContent = 'Proving + bonding…';
  const t0 = performance.now();
  // Validator bonds are SAT-only (one bond asset, THORChain's shape — the node refuses a USDm bond). Bonding is the
  // user's choice: holding SAT is the default and nothing here runs on its own.
  try {
    const r = await walletCore('wallet_bond_sat', { amount_sat: amount });
    const ms = Math.round(performance.now() - t0);
    console.log('[bond] wallet_bond_sat ' + ms + 'ms', r);
    st.className = 'send-status ok';
    st.textContent = (r && r.rebond)
      ? ('✓ SAT top-up published (' + ms + 'ms) · your validator weight becomes ' + Number((r && r.sat) || 0).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT when the block folds on every node')
      : ('✓ SAT bond published (' + ms + 'ms) · your validator weight seats when the block folds on every node');
    document.getElementById('bondAmount').value = '';
    // Refresh the live validator stats but KEEP the green confirmation (persists until the next action / tab switch).
    setTimeout(() => { renderBalance(); loadGovernance({ keepStatus: true }); }, 400);
  } catch (e) {
    st.className = 'send-status err';
    st.textContent = 'Failed: ' + ((e && e.notInApp) ? 'open the MoneroUSD app to bond.' : (e && (e.message || e)));
  }
}
// ⭐ §22 4 — "BECOME A VALIDATOR" IN ONE TAP: one confirmation naming the bond, the $0.00 fee, what the computer must do, the
// 21-day exit and what each slash costs; the core bonds the largest SAT note (refused on a phone, which is pointed to
// delegation); then the keep-awake question, asked once.
async function doBecomeValidator() {
  const st = document.getElementById('bvStatus');
  if (!(await confirmCost({ title: 'Become a validator', confirmLabel: 'Become a validator',
    lines: [{ label: 'You bond', usd: null, detail: 'your largest SAT note — SAT has no dollar price on the chain yet' }, { label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
    warning: 'This computer must stay on and online; it then validates by itself. Leaving takes 21 days, and seven days offline retires it with nothing burned. If it double-signs or deals a bad key its own bond is burned; if it helps steal from the reserve, its bond and the SAT delegated to it are burned.' }))) return;
  st.className = 'send-status'; st.textContent = 'Proving + bonding…';
  try {
    await walletCore('wallet_become_validator');
    st.className = 'send-status ok';
    st.textContent = '✓ You are becoming a validator — your seat applies when the block folds on every node.';
    const awake = await confirmCost({ title: 'Keep this computer awake while validating?', confirmLabel: 'Keep awake',
      lines: [{ label: 'Cost', usd: 0, detail: 'it uses more power while plugged in' }],
      warning: 'Without it the computer may sleep and its validator rests until it wakes (nothing is lost). A closed laptop lid still sleeps on battery. You can change this any time.' });
    await walletCore('wallet_set_keep_awake', { on: !!awake });
    setTimeout(() => { renderValidatorStatus(); loadGovernance({ keepStatus: true }); }, 400);
  } catch (e) {
    const msg = (e && (e.message || e)) + '';
    st.className = 'send-status err';
    st.textContent = msg.startsWith('Validators must stay online') ? msg + ' (Delegate SAT is below.)' : 'Failed: ' + msg;
    if (msg.startsWith('Validators must stay online')) { const d = document.getElementById('delegateCard'); if (d) d.scrollIntoView({ behavior: 'smooth' }); }
  }
}
// §22 4 — the validator's status card: uptime as the chain records it, whether it is drawn this hour, and what it has earned.
async function renderValidatorStatus() {
  const card = document.getElementById('validatorStatusCard');
  if (!card) return;
  let mb = null;
  try { mb = await walletCore('wallet_my_bond'); } catch (_) { return; }
  const seated = mb && (mb.custody_sat > 0 || mb.retired);
  card.hidden = !seated;
  if (!seated) return;
  document.getElementById('vsUptime').textContent = mb.uptime_windows > 0
    ? (mb.uptime_pct + '% · ' + mb.uptime_active + ' of ' + mb.uptime_windows + ' hours on duty') : 'starting — its first hour is counting';
  document.getElementById('vsDrawn').textContent = mb.retired ? 'retired after seven days offline — unbond to take the SAT back, or bond again'
    : (mb.drawn ? 'on duty' : 'resting — back on duty the hour after it next checks in');
  document.getElementById('vsEarned').textContent = '$' + Number(mb.earned_usdm || 0).toFixed(2) + ' USDm';
  document.getElementById('keepAwakeState').textContent = mb.keep_awake ? 'on' : 'off';
  document.getElementById('keepAwakeToggle').textContent = mb.keep_awake ? 'Turn off' : 'Turn on';
}
async function toggleKeepAwake() {
  const on = document.getElementById('keepAwakeState').textContent !== 'on';
  try { await walletCore('wallet_set_keep_awake', { on }); } catch (_) {}
  renderValidatorStatus();
}
// Broadcast-on-press: withdraw this wallet's validator bond weight (ML-DSA signed; only the key-holder can).
async function doUnbond() {
  const st = document.getElementById('bondStatus');
  if (!(await confirmCost({ title: 'Unbond your validator weight', confirmLabel: 'Unbond', lines: [{ label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
    warning: 'Your validator weight leaves and you stop earning validator fees. The bonded SAT returns once a block carries the unbond; an unbond before the bond matures is refused.' }))) return;
  st.className = 'send-status'; st.textContent = 'Signing + unbonding…';
  try {
    const r = await walletCore('wallet_unbond');
    // ⛔ The node answers `{"verdict":"PUBLISHED"}` (§AS: the unbond is a chain object and a step is not an arrival;
    // the weight leaves and the bonded note returns when a block carries it, on every node). This read `r.unbonded`,
    // a field the route never sends, so every successful unbond showed "Not a bonded validator". A refusal arrives as
    // an error with the node's reason (the catch below).
    if (r && r.verdict === 'PUBLISHED') {
      st.className = 'send-status ok';
      st.textContent = '✓ Unbond published — the weight leaves and your bonded note returns once a block carries it.';
    } else {
      st.className = 'send-status err';
      st.textContent = 'Not a bonded validator (nothing to unbond).';
    }
    setTimeout(loadGovernance, 400);
  } catch (e) {
    st.className = 'send-status err';
    st.textContent = 'Failed: ' + ((e && e.notInApp) ? 'open the MoneroUSD app.' : (e && (e.message || e)));
  }
}
function shortAddr(a) { a = a || ''; return a.length > 22 ? a.slice(0, 12) + '…' + a.slice(-8) : a; }
async function loadSettings() {
  const rows = document.getElementById('settingsRows');
  rows.innerHTML = '<div class="settings-empty">Loading…</div>';
  try {
    const s = await walletCore('wallet_settings');
    rows.innerHTML =
      settingsLine('Network', s.network || 'testnet') +
      settingsLine('Node', s.node_url || '') +
      settingsLine('Data dir', s.data_dir || '') +
      settingsLine('Scan key', s.scan_fingerprint || '') +
      settingsLine('Address', shortAddr(s.address));
  } catch (e) {
    rows.innerHTML = '<div class="settings-empty">' + ((e && e.notInApp)
      ? 'Open the MoneroUSD app to read settings.' : ('Settings unavailable: ' + escapeHtml(e && (e.message || e)))) + '</div>';
  }
  loadDeviceSlot();
  wireUpdates(); // §BR-10: the Updates card
  wireAutoOpsec();
  wireSupportFee();
}
// Support the team: an opt-in 0.10 % of each send, off by default, remembered by the core until the user changes it.
async function refreshSupportFee() {
  try { const r = await walletCore('wallet_support_fee'); state.supportFee = !!(r && r.on); } catch (_) { state.supportFee = false; }
  const s = document.getElementById('settingsSupportState'); if (s) s.textContent = state.supportFee ? 'on — 0.10% of each send' : 'off';
  const b = document.getElementById('settingsSupportToggle'); if (b) b.textContent = state.supportFee ? 'Turn off' : 'Turn on';
}
function wireSupportFee() {
  const b = document.getElementById('settingsSupportToggle');
  if (b && !b._wired) {
    b._wired = true;
    b.addEventListener('click', async () => {
      try { await walletCore('wallet_set_support_fee', { on: !state.supportFee }); } catch (_) {}
      await refreshSupportFee();
    });
  }
  refreshSupportFee();
}
// ⭐ DB-329 step 3 — this seed's DEVICES. Each device writes its change under its own slot, so two devices on one seed
// never give two payments the same tag. The first device (slot 0) adds: it pays a tiny self-note "marker" to the next
// slot, and the new device, restored from the seed, claims that slot as its first act. Every state is read from the
// wallet core (which reads the chain); the button is live only where the core would accept it.
async function loadDeviceSlot() {
  const rows = document.getElementById('deviceSlotRows');
  const btn = document.getElementById('btnAddDevice');
  if (!rows) return;
  try {
    const s = await walletCore('wallet_device_slot_status');
    const status = {
      decided: 'Settled',
      settling: 'Settling — reading the chain for a waiting add (sends wait until this settles)',
      claiming: 'Claiming slot ' + s.claiming_slot + ' — sends wait until the claim confirms',
      needs_add: 'Another device took the slot this one was added for — add this device again from your first device',
    }[s.status] || String(s.status);
    rows.innerHTML =
      settingsLine('This device', s.device_slot === 0 ? 'Slot 0 (first device)' : 'Slot ' + s.device_slot) +
      settingsLine('Status', status) +
      (s.pending_add ? settingsLine('Add waiting', 'Slot ' + s.pending_add + ' — restore the seed on the new device once it confirms') : '');
    if (btn) btn.disabled = !(s.status === 'decided' && s.device_slot === 0 && !s.pending_add);
  } catch (e) {
    rows.innerHTML = '<div class="settings-empty">' + ((e && e.notInApp)
      ? 'Open the MoneroUSD app to manage devices.' : ('Devices unavailable: ' + escapeHtml(e && (e.message || e)))) + '</div>';
    if (btn) btn.disabled = true;
  }
}
const _btnAddDevice = document.getElementById('btnAddDevice');
if (_btnAddDevice) _btnAddDevice.addEventListener('click', async () => {
  const st = document.getElementById('addDeviceStatus');
  // Two clicks (arm + confirm): an add pays a real (tiny) self-note on chain.
  if (_btnAddDevice.dataset.armed !== '1') {
    _btnAddDevice.dataset.armed = '1';
    _btnAddDevice.textContent = 'Tap again to add a device (pays a tiny marker to yourself)';
    setTimeout(() => { _btnAddDevice.dataset.armed = '0'; _btnAddDevice.textContent = 'Add a device'; }, 5000);
    return;
  }
  _btnAddDevice.dataset.armed = '0';
  _btnAddDevice.textContent = 'Add a device';
  if (st) { st.className = 'send-status'; st.textContent = 'Adding — paying the slot marker…'; }
  try {
    const r = await walletCore('wallet_add_device');
    if (st) {
      st.className = 'send-status ok';
      st.textContent = '✓ Device slot ' + r.device_slot + ' is waiting. Once it confirms, restore your seed on the new device; it claims this slot on its own.';
    }
  } catch (e) {
    if (st) { st.className = 'send-status err'; st.textContent = 'Not added: ' + (e && (e.message || e)); }
  }
  setTimeout(loadDeviceSlot, 400);
});
// Show the Pay panel OR the Request(POS) checkout — the two are merged under the debit card.
function setSendMode(mode) {
  for (const b of document.querySelectorAll('#segPay, #segRequest')) b.classList.toggle('active', b.dataset.mode === mode);
  const pay = document.getElementById('payPanel');
  const req = document.getElementById('requestPanel');
  if (pay) pay.style.display = mode === 'pay' ? '' : 'none';
  if (req) req.style.display = mode === 'request' ? '' : 'none';
  // NOTE: an active charge SURVIVES a tab switch (like a Stripe terminal — the merchant can glance at their balance
  // without dropping the sale); the running monitor keeps watching in the background and self-expires at 120s. The
  // explicit Cancel button (or starting a new Charge) is the only reset.
}
// The Pay hub — a MonerousD debit card showing the LIVE balance + this wallet's @username handle (or a short
// address fingerprint if no handle is claimed yet), then the Pay / Request(POS) panels beneath it.
async function loadSend() {
  const st = document.getElementById('sendStatus');
  if (st) { st.textContent = ''; st.className = 'send-status'; }
  setSendMode('pay');
  const bal = document.getElementById('dcBal');
  const holder = document.getElementById('dcHolder');
  try {
    const b = await walletCore('wallet_balance');
    if (bal) bal.textContent = Number((b && b.usdm) || 0)
      .toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
  } catch (e) {
    if (bal) bal.textContent = '—';
  }
  // Card holder line = the wallet's live @username (its public handle) or a short PQ-address fingerprint.
  if (holder) {
    try {
      const m = await walletCore('wallet_my_username');
      if (m && m.name && m.owned) { holder.innerHTML = '<span class="muted">@</span>' + escapeHtml(m.name); }
      else {
        const a = await walletCore('wallet_address');
        const ad = (a && a.address) || '';
        holder.innerHTML = ad ? escapeHtml(ad.slice(0, 6) + '…' + ad.slice(-4)) : '<span class="muted">@</span>—';
      }
    } catch (_) { holder.innerHTML = '<span class="muted">@</span>—'; }
  }
  // Mirror the wallet's claimed @username in the Pay username panel (a tradeable chain asset). Live-verified it
  // STILL resolves to this address — never a stale claim.
  const un = document.getElementById('myUsernameBox');
  if (un) {
    try {
      const m = await walletCore('wallet_my_username');
      if (m && m.name && m.owned) { un.style.display = 'inline'; un.textContent = '✓ @' + m.name + ' · yours'; state.myUsername = m.name; }
      else { un.style.display = 'none'; state.myUsername = null; }
    } catch (_) { un.style.display = 'none'; }
  }
}

// Parse a `monerousd:<address>?amount=<usdm>` payment request (POS). Returns {address, amount} or null. The
// address + amount are public request fields; the payment itself still rides the confidential WHIR Send carrier.
function parsePayUri(s) {
  s = (s || '').trim();
  if (s.indexOf('monerousd:') !== 0) return null;
  // A shop's payment link and a seller's sale link share the scheme but are not an address: goods.js reads them and
  // shows what they offer before anything is paid.
  if (s.indexOf('monerousd:pay?') === 0 || s.indexOf('monerousd:sale?') === 0) return null;
  const rest = s.slice('monerousd:'.length);
  const q = rest.indexOf('?');
  const address = (q === -1 ? rest : rest.slice(0, q)).trim();
  let amount = null;
  if (q !== -1) {
    const m = rest.slice(q + 1).match(/(?:^|&)amount=([^&]+)/);
    if (m) { const a = parseFloat(decodeURIComponent(m[1])); if (a > 0) amount = a; }
  }
  return address ? { address, amount } : null;
}

// Broadcast-on-press: prove the 4-gate WHIR spend carrier locally + submit it to the user's own node.
// Reflects the node's REAL status — honest PENDING on accept, the node's own reason on reject.
async function doSend() {
  const btn = document.getElementById('btnSend');
  const st = document.getElementById('sendStatus');
  let to = (document.getElementById('sendTo').value || '').trim();
  // A pasted POS request auto-fills the recipient + amount (the address + amount are public request fields).
  const uri = parsePayUri(to);
  if (uri) {
    to = uri.address;
    document.getElementById('sendTo').value = to;
    if (uri.amount != null && !document.getElementById('sendAmount').value) document.getElementById('sendAmount').value = uri.amount;
  }
  const amount = parseFloat(document.getElementById('sendAmount').value);
  if (!to) { st.className = 'send-status err'; st.textContent = 'Enter a recipient address.'; return; }
  if (!(amount > 0)) { st.className = 'send-status err'; st.textContent = 'Enter a positive amount.'; return; }
  // ⭐ SATOSHI: SAT rides the asset transfer door (`wallet_send_sat`); the core asks for approval naming the asset, amount and
  // recipient, picks one covering SAT note, and the recipient is credited when the block folds on every node.
  const sendAssetSel = document.getElementById('sendAsset');
  if (sendAssetSel && sendAssetSel.value === 'SAT') {
    if (!(await confirmCost({ title: 'Send ' + amount.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT', confirmLabel: 'Send',
      lines: [{ label: 'You send', usd: null, detail: amount.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT to ' + to.slice(0, 18) + '… — the wallet has no live SAT dollar price' }, { label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
      warning: WARN_IRREVERSIBLE }))) return;
    btn.disabled = true;
    st.className = 'send-status'; st.textContent = 'Proving SAT transfer…';
    const t0 = performance.now();
    try {
      const r = await walletCore('wallet_send_sat', { to, amount_sat: amount });
      const ms = Math.round(performance.now() - t0);
      st.className = 'send-status ok';
      st.textContent = (r && r.verdict === 'PUBLISHED')
        ? ('✓ ' + amount.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT sent (' + ms + 'ms) · credited when the block folds on every node')
        : ('Not published: ' + ((r && r.detail) || (r && r.verdict) || 'unknown'));
      setTimeout(() => renderBalance(), 400);
    } catch (e) {
      st.className = 'send-status err';
      st.textContent = 'Failed: ' + ((e && e.notInApp) ? 'open the MoneroUSD app to send.' : (e && (e.message || e)));
    } finally { btn.disabled = false; }
    return;
  }
  // Pre-flight balance check against the LIVE spendable balance: fail FAST + clearly rather than running the
  // (slower) confidential prove only for it to fail on an uncovered note. A transient read never blocks a valid send.
  try {
    const b = await walletCore('wallet_balance');
    const spend = Number((b && b.usdm) || 0);
    if (amount > spend + 1e-9) {
      st.className = 'send-status err';
      st.textContent = 'Insufficient balance — you have ' + spend.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm.' + confirmingNote(b);
      return;
    }
  } catch (e) {
    if (e && e.notInApp) { st.className = 'send-status err'; st.textContent = 'Open the MoneroUSD app to send.'; return; }
  }
  // ⛔⛔⛔ DB-373 — THE APPROVAL IS THE CORE'S. `wallet_send` itself asks for Touch ID / Face ID / the passcode, naming
  // the recipient and the amount it is about to send, and a refusal comes back as the command's error (shown below).
  // The prompt used to live HERE, which gated this honest page and nothing else: any script that reached `invoke`
  // called `wallet_send` unprompted. The MONEROUSD_SEND_NO_BIOMETRIC bypass (user-authorized 2026-08-10 as temporary,
  // "until cross-node sends are proven" — proven 2026-10-02) and the in-page confirm() fallback are gone with it; a test
  // build compiles the prompt out with the wallet's `unattended-test` feature instead.
  await refreshSupportFee();
  const supportUsd = state.supportFee ? Math.floor(amount * 1e8 * 10 / 10000) / 1e8 : 0;
  if (!(await confirmCost({ title: 'Send ' + usdText(amount), confirmLabel: 'Send',
    lines: [{ label: 'You send', usd: amount, detail: amount.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm to ' + to.slice(0, 18) + '…' }, feeLine(),
      ...(state.supportFee ? [{ label: 'Support the team (0.10%)', usd: supportUsd, cost: true, detail: 'optional — turn off in Settings' }] : []),
      { label: 'Total', usd: amount + NETWORK_FEE_USD + supportUsd }],
    warning: WARN_IRREVERSIBLE }))) return;
  btn.disabled = true; st.className = 'send-status'; st.textContent = '◌ Approve the payment in the system prompt — then proving + broadcasting…';
  const t0 = performance.now();
  try {
    const r = await walletCore('wallet_send', { to, amount_usdm: amount });
    const ms = Math.round(performance.now() - t0);
    console.log('[send] wallet_send ' + ms + 'ms', r);
    const txh = String((r && r.tx_hash) || '').slice(0, 12);
    st.className = 'send-status ok';
    st.textContent = '✓ Broadcast (' + ms + 'ms) · pending · tx ' + txh + '… — confirming…';
    document.getElementById('sendAmount').value = '';
    document.getElementById('sendTo').value = '';
    // Refresh the balance IN PLACE and re-render the DEBIT CARD balance (do NOT call loadSend — it re-renders +
    // wipes the status + resets to the Pay panel), so the card still LIVE-MIRRORS the new balance after paying.
    const refreshAvail = async () => {
      renderBalance();
      try {
        const b = await walletCore('wallet_balance');
        const dc = document.getElementById('dcBal');
        if (dc) dc.textContent = Number((b && b.usdm) || 0).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      } catch (_) {}
    };
    setTimeout(refreshAvail, 800);
    // LIVE CONFIRMATION MONITOR (front-end ↔ back-end live mirror): poll the wallet core's oracle-free
    // send-status verdict until the spend's own named inputs are CERTIFIED-absent from the unspent tree
    // (their deletions folded on-chain — the instant the tx is in a block, ~1s), then flip the status
    // pending → CONFIRMED with the measured latency. Never a stuck-at-pending spinner: the UI tracks the
    // real chain. DEAD-WIRING FIX 2026-09-06: this polled /check_nullifiers_spent, a which-nullifier
    // spent ORACLE the node deliberately REMOVED on 2026-07-15 (DIGITAL-CASH) — the catch below swallowed
    // every 404 and no send could ever flip to confirmed. wallet_send_status computes the same truth from
    // this wallet's OWN input cms via unspent_presence_mask (certified absence, no oracle re-opened).
    const nf = r && r.nullifier_hex;
    if (nf) {
      const t1 = performance.now();
      const poll = async () => {
        let spent = false;
        try {
          const s = await walletCore('wallet_send_status', { nullifier_hex: nf });
          spent = !!(s && s.confirmed === true);
        } catch (_) {}
        if (spent) {
          const secs = ((performance.now() - t1) / 1000).toFixed(1);
          st.className = 'send-status ok';
          st.textContent = '✓ Confirmed in ' + secs + 's · on-chain · tx ' + txh + '…';
          refreshAvail();
          return;
        }
        // ⛔⛔⛔ THIS WAS A 30-SECOND WINDOW, AND IT IS WHY THE SENDER SAT AT "pending · confirming…" FOREVER.
        //
        // user 2026-08-11: "i see the send worked. The wallet just didnt update the tx as confirmed on the
        // sender side."  Exactly right — MEASURED the same day: the payment settled and the recipient's
        // wallet showed +100.00 USDm on the OTHER node, while the sender's status line still read
        // "pending · confirming…". The money had moved; only this poll had given up.
        //
        // `if (elapsed < 30000)` is a cap on how far the UI will look for its own confirmation. A tx that
        // confirms at 30.1s is then reported as unconfirmed for the rest of the session, with no error and
        // no way back — the UI states the OPPOSITE of the chain. Caps in any costume are banned here for
        // exactly this reason, and a confirmation cap makes the wallet lie about settled money.
        //
        // The DA layer is the ledger and the nullifier is there permanently, so there is no honest moment to
        // stop looking. Poll until it lands, easing the interval so a long wait costs little. The interval
        // grows; the search never ends.
        const elapsed = performance.now() - t1;
        const nextIn = elapsed < 10000 ? 1000 : (elapsed < 60000 ? 2000 : 5000);
        setTimeout(poll, nextIn);
      };
      setTimeout(poll, 900);
    }
  } catch (e) {
    st.className = 'send-status err';
    st.textContent = 'Failed: ' + ((e && e.notInApp)
      ? 'open the MoneroUSD app to send.' : (e && (e.message || e)));
  } finally { btn.disabled = false; }
}

// GOVERNANCE — read the open bicameral proposals + tallies LIVE; propose + validator-chamber vote.
async function loadGovernance(opts) {
  wireBondRewards(); wireRewardsBtc(); wireRemix(); // §BR-11: the "Bond my rewards" switch on the validator card
  wireDelegations(); // §BR-3 17.3: the Delegate SAT card
  // {keepStatus:true} from a post-bond refresh preserves the fresh bond confirmation; a tab-entry clears stale status.
  const bst = document.getElementById('bondStatus');
  if (bst && !(opts && opts.keepStatus)) { bst.textContent = ''; bst.className = 'send-status'; }
  const ps = document.getElementById('propStatus');
  if (ps) { ps.textContent = ''; ps.className = 'send-status'; }
  const setStat = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
  // Spendable SAT drives what you can bond (live mirror, read fresh each entry) — validator bonds are SAT-only.
  const bavail = document.getElementById('bondAvail');
  try {
    const [b, st] = await Promise.all([walletCore('wallet_balance'), loadSatStatus()]);
    const sat = Number(((b && b.assets) || {})[(st && st.sat_tag_hex) || ''] || 0);
    if (bavail) bavail.textContent = 'Spendable: ' + sat.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT';
  } catch (e) {
    if (bavail) bavail.textContent = (e && e.notInApp) ? 'Open the MoneroUSD app to bond.' : 'Spendable: —';
  }
  // Validator-set network view (moved here from Earn) + the bond/validator hero stats.
  const rows = document.getElementById('earnRows');
  if (rows) rows.innerHTML = '<div class="settings-empty">Reading the validator set…</div>';
  try {
    const v = await nodeRpc('/get_validator_bond_tree');
    const bondUsdm = (Number(v && v.total_bond || 0) / 1e8).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    const nValidators = Number(v && v.validators || 0);
    setStat('govValidators', nValidators.toLocaleString());
    let myBondLine = '';
    try {
      // The mirror truth, labeled as what it IS: `wallet_my_bond` reads THE ATTACHED NODE's validator
      // bond (live-mirror design). Calling that "Your bond" told a fresh wallet the founding node's
      // 100,000 self-bond was its own (user-reported 2026-08-25); the HERO stat is the live REQUIRED
      // bond — the actual price to become a validator — filled below from /get_governance.
      const mb = await walletCore('wallet_my_bond');
      renderValidatorStatus(); // §22 4: the status card follows the same read
      const myUsdm = Number((mb && mb.usdm) || 0);
      const mySat = Number((mb && mb.sat) || 0);
      const isVal = mb && mb.is_validator;
      // SATOSHI: finality weight (USDm) and the reserve's CUSTODY weight (SAT) are two numbers, shown as two.
      myBondLine = settingsLine("This node's bond", isVal
        ? (myUsdm.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' USDm finality · '
          + mySat.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 }) + ' SAT custody')
        : 'not bonded');
    } catch (_) { myBondLine = settingsLine("This node's bond", '—'); }
    // SATOSHI §8: who this node's mining rewards go to, and this wallet's located rewards / custody weight.
    try {
      const ss = await loadSatStatus();
      const rr = (ss && ss.reward_recipient) || {};
      const mine = !!rr.mine;
      setStat('satRewardLine', '⛏ Mining rewards → this wallet: ' + (mine ? ('yes · ' + Number(ss.rewards_located || 0) + ' reward(s) found') : ('no' + (rr.error ? ' · ' + String(rr.error).slice(0, 120) : ''))));
      setStat('satCustodyLine', 'Custody weight: ' + Number(ss.sat || 0).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT'
        + (ss.takeover_cost_sat != null ? (' · cost to buy 2/3 of custody: ' + Number(ss.takeover_cost_sat).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' SAT') : ''));
      // §BR-11: a figure the node did not serve is said to be unknown — never shown as "no payout"
      setStat('minerPoolLine', '⛏ Miner pool: ' + (ss.miner_pool_per_block_usdm == null
        ? 'unknown — the node has not answered yet'
        : ss.miner_pool_per_block_usdm > 0
          ? usdText(ss.miner_pool_per_block_usdm) + ' per block this week, paid to whoever mines it (on top of the SAT reward)'
          : 'no payout this week yet (it fills from 10% of every network fee)'));
      myBondLine += settingsLine('Mining rewards', mine ? 'sealed to this wallet (hold by default; bond is your choice)' : 'not this wallet');
    } catch (_) { setStat('satRewardLine', '⛏ Mining rewards → this wallet: —'); }
    if (rows) rows.innerHTML = sanitizeHtml(
      myBondLine +
      settingsLine('Bonded validators', nValidators.toLocaleString()) +
      settingsLine('Total bonded', bondUsdm + ' USDm'));
  } catch (e) {
    if (rows) rows.innerHTML = '<div class="settings-empty">Network unavailable: ' + escapeHtml(e && (e.message || e)) + '</div>';
    setStat('minerPoolLine', '⛏ Miner pool: unknown — the node has not answered yet');
  }
  // #92 ADAPTIVE validator bond — the LIVE required_bond_floor = max(BASE, bond_tvl_multiple × bridge_tvl), read
  // straight from the node's consensus state. bridge_tvl = the TOTAL PROJECT TVL: the gross collateral bridged in
  // through the wallet's Buy-USDm peg-in AND the Ion Swap bridge (both settle into one peg ledger), so the required
  // bond scales with the WHOLE project's value at stake — anti-buyout / anti-drain across every bridge entry point.
  try {
    const gov = await nodeRpc('/get_governance');
    const reqBond = Number((gov && gov.required_bond_floor) || 0);
    const tvl = Number((gov && gov.bridge_tvl) || 0);
    const mult = Number((gov && gov.bond_tvl_multiple) || 2);
    // required_bond_floor = max(BASE, mult × TVL). The adaptive term is BINDING only once mult×TVL reaches the
    // floor; below that the base floor holds. Show the honest live state (mirror), not a blanket "adaptive".
    const adaptiveBinding = tvl > 0 && (mult * tvl) >= reqBond;
    // THE HERO IS THE PRICE: the live adaptive requirement (max(base, multiple × total project TVL)),
    // which at TVL 0 is honestly the base floor — never any node's own bond amount.
    setStat('govReqBondHero', reqBond.toLocaleString() + ' USDm');
    const heroLbl = document.getElementById('govReqBondLbl');
    if (heroLbl) heroLbl.textContent = adaptiveBinding
      ? ('Required bond · adaptive (' + mult + '× TVL)')
      : 'Required bond · base floor (grows with TVL)';
    setStat('govReqBond', '🛡 Required bond: ' + reqBond.toLocaleString() + ' USDm'
      + (adaptiveBinding ? ' · adaptive (' + mult + '× total project TVL)' : ' · base floor (grows with TVL)'));
    setStat('govBridgeTvl', 'Total project TVL: ' + tvl.toLocaleString() + ' USDm · wallet + Ion Swap bridges');
  } catch (_) {
    setStat('govReqBondHero', '—');
    setStat('govReqBond', '🛡 Required bond: —');
    setStat('govBridgeTvl', 'Total project TVL: —');
  }
  // Bicameral proposals + your chamber weight.
  const grows = document.getElementById('govRows');
  if (grows) grows.innerHTML = '<div class="settings-empty">Reading proposals…</div>';
  try {
    const g = await walletCore('wallet_governance');
    const props = (g && g.proposals) || [];
    const vt = Number((g && g.validator_total) || 0);
    // YOUR governance power first: the validator-chamber weight IS this wallet's bonded stake, read live.
    let myWeightHtml = '';
    try {
      const mb = await walletCore('wallet_my_bond');
      const myW = Number((mb && mb.bond) || 0);
      const myPct = vt > 0 ? Math.round(myW * 100 / vt) : 0;
      setStat('govMyWeight', myW > 0 ? (myPct + '%') : '0%');
      // this wallet's own vote, first: what it weighs in the validators' chamber
      myWeightHtml = '<div class="gp gp-me"><div class="gp-top"><b class="gp-name">Your vote</b>' +
        '<span class="gp-chip' + (myW > 0 ? ' on' : '') + '">' + (myW > 0 ? (myPct + '% of the validators') : 'not bonded') + '</span></div>' +
        '<div class="gp-sub">' + (myW > 0
          ? (Number(mb.usdm).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' USDm bonded. Your vote counts for that much.')
          : 'Bond as a validator to vote in the validators\' chamber.') + '</div></div>';
    } catch (_) { setStat('govMyWeight', '—'); }
    if (!props.length) {
      if (grows) grows.innerHTML = sanitizeHtml(myWeightHtml + '<div class="gp-empty"><b>No open proposals</b><span>The network runs at DAG width ' +
        Number((g && g.dag_width) || 0) + '. Anyone can propose a change below.</span></div>');
      return;
    }
    // one chamber's progress toward the two thirds a change needs; the mark on the track is that line
    const chamber = function (name, share, text, passed) {
      return '<div class="gp-bar"><span class="gp-k">' + name + '</span><span class="gp-track"><i class="gp-fill' + (passed ? ' pass' : '') +
        '" style="width:' + Math.max(0, Math.min(100, Number(share) || 0)) + '%"></i><em class="gp-mark"></em></span><span class="gp-v">' + escapeHtml(text) + '</span></div>';
    };
    const kindName = function (kind) {
      const named = Array.from(document.querySelectorAll('#propKind option')).find(function (o) { return o.value === kind; });
      return named ? named.textContent : String(kind);
    };
    const minerTotal = Number((g && g.miner_total) || 0);
    if (grows) grows.innerHTML = sanitizeHtml(myWeightHtml + props.map(function (p) {
      const tally = Number(p.validator_tally || 0);
      const pct = vt > 0 ? Math.round(tally * 100 / vt) : 0;
      const miners = Number(p.miner_tally || 0);
      // the miners' chamber is drawn as a share only when the node says what the whole is; else as the count it is
      const minersRow = minerTotal > 0
        ? chamber('Miners', Math.round(miners * 100 / minerTotal), Math.round(miners * 100 / minerTotal) + '% · ' + miners + ' of ' + minerTotal, miners * 3 >= minerTotal * 2)
        : '<div class="gp-bar"><span class="gp-k">Miners</span><span class="gp-v gp-v-wide">' + miners + (miners === 1 ? ' vote' : ' votes') + '</span></div>';
      return '<div class="gp"><div class="gp-top"><b class="gp-name">' + escapeHtml(kindName(p.kind)) + '</b><span class="gp-to">→ ' + escapeHtml(p.value) + '</span>' +
        '<button class="btn btn-primary gov-vote" data-pid="' + escapeHtml(p.id) + '">Vote</button></div>' +
        chamber('Validators', pct, pct + '% · ' + tally.toLocaleString() + ' of ' + vt.toLocaleString(), vt > 0 && tally * 3 >= vt * 2) + minersRow + '</div>';
    }).join(''));
    if (grows) grows.querySelectorAll('.gov-vote').forEach(function (b) { b.addEventListener('click', function () { doVote(b.dataset.pid); }); });
  } catch (e) {
    if (grows) grows.innerHTML = '<div class="settings-empty">' + ((e && e.notInApp)
      ? 'Open the MoneroUSD app to see governance.' : ('Unavailable: ' + escapeHtml(e && (e.message || e)))) + '</div>';
  }
}
// Broadcast-on-press: open a permissionless parameter proposal (the anti-capture threshold is at enact).
async function doPropose() {
  const ps = document.getElementById('propStatus');
  const kind = document.getElementById('propKind').value;
  const value = document.getElementById('propValue').value;
  if (!(parseInt(value, 10) > 0)) { ps.className = 'send-status err'; ps.textContent = 'Enter a positive value.'; return; }
  ps.className = 'send-status'; ps.textContent = 'Creating proposal…';
  try {
    const r = await walletCore('wallet_propose', { kind: kind, value: String(value) });
    ps.className = 'send-status ok';
    ps.textContent = '✓ Proposal ' + String((r && r.proposal_id) || '').slice(0, 12) + '…';
    document.getElementById('propValue').value = '';
    setTimeout(loadGovernance, 300);
  } catch (e) {
    ps.className = 'send-status err';
    ps.textContent = 'Failed: ' + ((e && e.notInApp) ? 'open the MoneroUSD app.' : (e && (e.message || e)));
  }
}
// Broadcast-on-press: ML-DSA-sign a validator-chamber vote (weight = your bonded stake, credited by the node).
async function doVote(pid) {
  const ps = document.getElementById('propStatus');
  ps.className = 'send-status'; ps.textContent = 'Signing + submitting vote…';
  try {
    const r = await walletCore('wallet_gov_vote', { proposal_id: pid });
    ps.className = 'send-status ok';
    ps.textContent = '✓ Voted · weight ' + Number((r && r.weight) || 0).toLocaleString();
    setTimeout(loadGovernance, 300);
  } catch (e) {
    ps.className = 'send-status err';
    ps.textContent = 'Failed: ' + ((e && e.notInApp) ? 'open the MoneroUSD app.' : (e && (e.message || e)));
  }
}
// BUY — a SIMPLE atomic swap with a PERSISTENT, live-tracked record: the swap gets a locateable swap_id + a
// bidirectional stage tracker, is never lost (persisted), and shows in Swap history + Recent activity.
const SWAP_STAGES = [
  { label: 'Swap created', sub: 'id issued' },
  { label: 'Reserve ready', sub: 'quorum + address' },
  { label: 'You deposit', sub: 'send BTC/XMR' },
  { label: 'USDm minted', sub: 'lands in wallet' },
];
// How many stages are complete for a given status (1..4). The "moving" stage is the next one after that.
function swapStage(status) {
  return ({ awaiting_reserve: 1, awaiting_deposit: 2, deposit_detected: 3, minting: 3, gathering_quorum: 3, published: 3, minted: 4 })[status] || 1;
}
function swapTrackerHtml(status) {
  const active = swapStage(status);
  const steps = SWAP_STAGES.map((s, i) => {
    const done = i < active;
    const now = i === active && status !== 'minted';
    return `<div class="swap-step${done ? ' done' : ''}${now ? ' now' : ''}">` +
      `<span class="swap-dot">${done ? '✓' : i + 1}</span>` +
      `<span class="swap-step-label">${s.label}</span>` +
      `<span class="swap-step-sub">${s.sub}</span></div>`;
  }).join('');
  const pct = Math.min(active, SWAP_STAGES.length - 1) / (SWAP_STAGES.length - 1) * 100;
  return `<div class="swap-tracker"><div class="swap-track-fill" style="width:${pct}%"></div>${steps}</div>`;
}

// The furthest stage the LIVE on-chain poll has observed for the active swap (monotonic — a transient failed
// deposit lookup never rewinds the timeline). Reset when a new swap becomes active. This is what advances the
// tracker to "deposit seen" the instant the deposit hits the mempool, without waiting for the persisted status.
let _liveSwapStage = 0;
let _liveSwapId = null;

// Turn the timeline steps green LIVE by updating the existing `.swap-step` / `.swap-dot` / `.swap-track-fill`
// nodes IN PLACE — never rebuilding the card's innerHTML. That keeps the page from re-laying-out on every 3s
// poll, so the user's scroll position is preserved and the wallet never "sticks" mid-Buy. `active` = the number
// of completed stages (1..4); step i is green(done) when i < active, orange(now) when i === active.
function advanceSwapTracker(active, status) {
  const tracker = document.querySelector('#buyRows .swap-tracker');
  if (!tracker) return;
  tracker.querySelectorAll('.swap-step').forEach((el, i) => {
    const done = i < active;
    const now = i === active && status !== 'minted';
    el.classList.toggle('done', done);
    el.classList.toggle('now', now);
    const dot = el.querySelector('.swap-dot');
    if (dot) dot.textContent = done ? '✓' : String(i + 1);
  });
  const fill = tracker.querySelector('.swap-track-fill');
  if (fill) fill.style.width = Math.min(active, SWAP_STAGES.length - 1) / (SWAP_STAGES.length - 1) * 100 + '%';
}

// Render the tracked-swap card: swap_id (copyable), the live stage tracker, then the deposit address (once a
// reserve quorum exists) or an honest "reserve forming" note — but ALWAYS with the saved swap_id so it's locateable.
let _lastSwapSig = null;
function renderSwapCard(q) {
  const rows = document.getElementById('buyRows');
  if (!rows) return;
  // Anti-flicker: the 3s live poll re-calls this every tick. Only rebuild (and re-fetch the QR) when the
  // RENDERED state actually changed — otherwise the innerHTML rebuild + async QR re-inject flash the card.
  const sig = (q.swap_id || '') + '|' + (q.status || '') + '|' + (q.deposit_address || '') + '|' + (q.threshold || '') + '|' + (q.validators || '') + '|' + (q.then_pay ? q.then_pay.status : '');
  if (sig === _lastSwapSig && rows.querySelector('.swap-idbar')) return;
  _lastSwapSig = sig;
  const st = q.status || 'awaiting_reserve';
  // The purchase-amount / deposit / quorum summary rows render UNDER the QR + address (user layout), so the
  // scannable deposit QR is the first thing you see once the reserve is ready.
  const summary =
    settingsLine('Purchase amount', q.coin_atomic ? 'SAT, once your deposit mints' : Number(q.usdm_out).toLocaleString() + ' USDm') +
    // Reserve % = the LIVE governance backing the badge shows (q.backing_pct). Fall back to pay_usd/usdm_out with a
    // TINY epsilon guard — the old Math.max(1, usdm_out) clamped the denominator to 1, so any sub-1-USDm swap (e.g.
    // 0.667 USDm) mis-displayed 100% instead of the real 150%.
    settingsLine('You deposit · ' + (q.backing_pct != null
            ? Math.round(Number(q.backing_pct))
            : Math.round((Number(q.pay_usd) / Math.max(1e-8, Number(q.usdm_out))) * 100)) + '% reserve',
         // DB-124: the node's peg ledger counts one atomic unit of the asset (a sat, a piconero) as one USDm cent, so the
         // amount the custodians confirm is pay_usd × 1e8 atomic — stated here in the asset's own units, exactly, never
         // as a dollar figure the node does not use (a buyer who sent "$30 worth" would strand the coin).
         (q.deposit_amount != null
            ? Number(q.deposit_amount)
            : (q.asset === 'XMR' ? Number(q.pay_usd) * 1e8 / 1e12 : Number(q.pay_usd))) + ' ' + escapeHtml(q.asset) + ' — send exactly this amount');
  let html =
    `<div class="swap-idbar"><span>Swap <b>${escapeHtml(q.swap_id)}</b></span><button class="swap-copy" id="btnCopySwapId">Copy ID</button>` +
    ((st !== 'minted' && st !== 'redeemed') ? `<button class="swap-cancel" id="btnCancelSwap" title="Delete this open swap">Cancel</button>` : '') +
    `</div>` +
    swapTrackerHtml(st);
  if (st === 'redeemed') {
    html += summary + '<div class="card-note swap-ok">✓ Redeemed — ' + Number(q.usdm_out).toLocaleString() + ' USDm burned and your ' + escapeHtml(q.asset) + ' deposit released. This swap is closed.</div>';
  } else if (st === 'minted') {
    html += summary + '<div class="card-note swap-ok">✓ Minted — ' + Number(q.usdm_out).toLocaleString() + ' USDm landed in your wallet' + (q.mint_height ? ' at block ' + Number(q.mint_height).toLocaleString() : '') + '. To sell USDm back to ' + escapeHtml(q.asset) + ', switch to the <b>Sell</b> tab.</div>';
  } else if (q.deposit_address && q.deposit_address.length) {
    html +=
      '<div class="field-label" style="margin-top:12px">Send your ' + escapeHtml(q.asset) + ' to this reserve address</div>' +
      '<div class="dep-qr" id="buyDepQr" title="Scan to pay from your ' + escapeHtml(q.asset) + ' wallet"></div>' +
      '<pre class="addr-box" id="buyDepAddr">' + escapeHtml(q.deposit_address) + '</pre>' +
      '<button class="btn btn-ghost full" id="btnCopyDep">Copy address</button>' +
      '<div class="dep-explorer" id="buyDepExplorer"></div>' +
      summary +
      settingsLine('Reserve quorum', Number(q.threshold) + '-of-' + Number(q.validators) + ' bonded validators') +
      '<div class="card-note">Send your ' + q.asset + ' to the reserve address above. Each bonded validator independently watches the ' + escapeHtml(q.asset) + ' chain; the moment your deposit confirms on-chain, the ≥2/3 threshold authorizes the mint and USDm lands in your wallet — no single party controls it, and nothing mints before your deposit is confirmed.</div>';
  } else {
    html += summary + '<div class="card-note">The PQ-FROST reserve quorum is still forming — this swap (<b>' + q.swap_id + '</b>) is saved and moves to “awaiting deposit” automatically the moment validators bond the reserve. Nothing is lost; watch it live above or in Swap history.</div>';
  }
  // §BR-2: a co-signed Bitcoin deposit is the user's own until it mints — the refund leaf opens to their key alone after
  // one week (1,008 Bitcoin blocks), whatever the custody quorum does.
  if (q.asset === 'BTC' && q.depositor_index != null && !['minted', 'redeemed', 'reclaimed'].includes(st)) {
    html += '<div class="card-note">' + (st === 'cancelled' ? 'This swap is cancelled and will not mint. ' : '') +
      'If your deposit does not mint, you can take your Bitcoin back yourself one week after it confirms (1,008 Bitcoin blocks) — nobody can stop you.</div>' +
      '<button class="btn btn-ghost full" id="btnReclaimDeposit">Reclaim my Bitcoin</button><div id="reclaimMsg"></div>';
  }
  // ⭐ a coin swap's second leg: where the minted USDm goes, and how far it has got
  if (q.then_pay) {
    const tp = q.then_pay, coin = tp.asset === 'XMR' ? 'Monero' : 'Bitcoin', ts = String(tp.status || 'pending');
    const to = tp.payout_to ? escapeHtml(String(tp.payout_to).slice(0, 14)) + '…' : 'your vault';
    html += '<div class="card-note' + (ts === 'sent' ? ' swap-ok' : '') + '">' + (ts === 'sent' ? '✓ Swapped — your USDm is cashing out to ' + coin + ' at ' + to + ' (follow it under Sell)'
      : ts.startsWith('failed') ? '⚠ ' + escapeHtml(ts.slice(8)) : ts === 'sending' ? 'Starting the ' + coin + ' cash-out…'
      : 'Then: the minted USDm cashes out to ' + coin + ' at ' + to + ' on its own') + '</div>';
  }
  if (st === 'reclaimed') {
    html += '<div class="card-note swap-ok">✓ Reclaimed — your Bitcoin went back to your vault' + (q.reclaim && q.reclaim[1] ? ' (transaction ' + escapeHtml(String(q.reclaim[1]).slice(0, 16)) + '…)' : '') + '. This swap is closed.</div>';
  }
  rows.innerHTML = sanitizeHtml(html);
  const rcl = document.getElementById('btnReclaimDeposit');
  if (rcl) rcl.onclick = () => doReclaimDeposit(q.swap_id);
  // Robust copy — works on the FIRST click even if the async clipboard API is unavailable in the webview
  // (falls back to a hidden-textarea execCommand copy), so "copy didn't work first click" can't happen.
  const copyText = (text) => {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) { navigator.clipboard.writeText(text).catch(() => {}); }
    } catch (_) {}
    try {
      const ta = document.createElement('textarea');
      ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
    } catch (_) {}
  };
  const cid = document.getElementById('btnCopySwapId');
  if (cid) cid.onclick = () => { copyText(q.swap_id); cid.textContent = 'Copied ✓'; };
  // Cancel + delete an OPEN swap (minted/redeemed swaps show no Cancel — they already moved real value on-chain).
  const cx = document.getElementById('btnCancelSwap');
  if (cx) cx.onclick = async () => {
    // INLINE two-click confirm — native window.confirm/alert are unreliable in the Tauri webview. First click ARMS
    // (button turns solid red "Confirm delete?"); a second click within 4s deletes; otherwise it disarms. This
    // guards against an accidental one-click delete with no blocking dialog.
    if (cx.dataset.armed !== '1') {
      cx.dataset.armed = '1';
      cx.textContent = 'Confirm delete?';
      cx.classList.add('armed');
      cx._disarm = setTimeout(() => { cx.dataset.armed = '0'; cx.textContent = 'Cancel'; cx.classList.remove('armed'); }, 4000);
      return;
    }
    clearTimeout(cx._disarm);
    cx.disabled = true; cx.textContent = 'Cancelling…';
    try {
      await walletCore('wallet_cancel_swap', { swap_id: q.swap_id });
      stopSwapPoll();
      state.activeSwap = null;
      _lastSwapSig = '';                       // reset the anti-flicker signature so the next swap re-renders
      const r2 = document.getElementById('buyRows');
      if (r2) r2.innerHTML = '';               // remove the on-screen swap card
      renderSwapHistory();                     // refresh Swap history — the row is gone
    } catch (e) {
      cx.disabled = false; cx.dataset.armed = '0'; cx.classList.remove('armed'); cx.textContent = 'Cancel';
      console.error('[swap] cancel failed', e);
    }
  };
  const cd = document.getElementById('btnCopyDep');
  if (cd) cd.onclick = () => { copyText(q.deposit_address); cd.textContent = 'Copied ✓'; };
  // NO manual "confirm deposit" — USDm mints ONLY when the bonded validators independently confirm the real
  // deposit on the external chain (wallet_swap_status polls the node, which watches the BTC/XMR chain). The
  // deposit-watch line above reflects that live pending state until the on-chain confirmation fires the mint.
  // Real, phone-scannable deposit QR (BIP21 `bitcoin:` / `monero:` URI) + a block-explorer link for the address.
  if (q.deposit_address && q.deposit_address.length && st !== 'minted') {
    const addr = q.deposit_address;
    const isBtc = String(q.asset || '').toUpperCase() === 'BTC';
    const uri = (isBtc ? 'bitcoin:' : 'monero:') + addr; // scannable to pay from a BTC/XMR wallet
    walletCore('wallet_qr_svg', { data: uri })
      .then((svg) => { const box = document.getElementById('buyDepQr'); if (box) box.innerHTML = sanitizeHtml(svg); })
      .catch(() => {});
    const ex = document.getElementById('buyDepExplorer');
    if (ex) {
      let url = '';
      if (isBtc) url = 'https://mempool.space/' + (addr.startsWith('tb1') ? 'testnet4/' : '') + 'address/' + addr; // testnet4 = the chain btc_watch actually watches
      else if (addr.length > 0) url = 'https://www.exploremonero.com/receiver/' + addr; // XMR: scan-to-pay wallet view
      if (url) {
        // Tauri webviews don't follow target="_blank" — hand the external explorer URL to the OS opener command.
        ex.innerHTML = '<a href="#" class="explorer-link">View this ' + escapeHtml(q.asset) + ' address on a block explorer ↗</a>';
        const a = ex.querySelector('a.explorer-link');
        if (a) a.onclick = (e) => { e.preventDefault(); walletCore('wallet_open_url', { url: url }).catch(() => {}); };
      }
    }
  }
}

// LIVE bidirectional tracking: poll wallet_swap_status so the stage MOVES on screen as the backend advances it.
let _swapPoll = null;
let _lastPolledStatus = null; // last swap status the poll rendered — gates the heavy balance/history re-render
function stopSwapPoll() { if (_swapPoll) { clearTimeout(_swapPoll); _swapPoll = null; } }
// CHAIN-AWARE seed switch: restoring a seed or creating a wallet = a brand-new identity (and possibly a different
// chain). DROP every in-memory swap-tracker so no prior wallet's live poll or rendered stage can carry into the new
// wallet's view. Balance / activity / history are re-read fresh from the now per-(seed,chain)-scoped backend on
// openHome(), so a switch is a clean slate on BOTH ends — never a cross-seed / cross-chain flash.
function resetWalletSessionState() {
  stopSwapPoll();
  _liveSwapId = null; _liveSwapStage = 0; _lastPolledStatus = null; state.activeSwap = null;
  const list = document.getElementById('activityList');
  if (list) list.innerHTML = '<div class="activity-empty">Scanning your notes…</div>';
}
function startSwapPoll(swapId) {
  stopSwapPoll();
  // Reset the monotonic live-stage only when switching to a DIFFERENT swap (so re-entering the same swap keeps
  // its already-observed "deposit seen" progress instead of briefly rewinding the timeline).
  if (swapId !== _liveSwapId) { _liveSwapId = swapId; _liveSwapStage = 0; _lastPolledStatus = null; }
  const tick = async () => {
    if (state.view !== 'buy' || state.activeSwap !== swapId) { stopSwapPoll(); return; }
    try {
      // Honest auto-mint: ask the node whether the REAL deposit confirmed on-chain; it mints ONLY when it has.
      // The deposit-status read is O(1) instant (node-side self-maintaining cache), so this no longer stalls.
      const m = await walletCore('wallet_try_mint', { swap_id: swapId }).catch(() => null);
      // LIVE front↔back mirror of the on-chain deposit — drive the TIMELINE (turn the steps green), never a text
      // banner. The moment the deposit is SEEN in the mempool (pending) OR confirmed, advance to stage 3 so the
      // "You deposit" step goes green ✓ and "USDm minted" lights up. Monotonic (Math.max) so a transient failed
      // lookup can't rewind the tracker mid-poll.
      if (m && m.minted === false && m.reason !== 'reserve_forming') {
        const conf = Number(m.confirmed_sats || 0), pend = Number(m.pending_sats || 0), min = Number(m.min_sats || 0);
        if (pend > 0 || (min > 0 && conf >= min)) _liveSwapStage = Math.max(_liveSwapStage, 3);
      }
      const rec = await walletCore('wallet_swap_status', { swap_id: swapId });
      renderSwapCard(rec); // guarded — only rebuilds innerHTML when the rendered state actually changed
      // Surgically advance the timeline (updates step classes in place → NEVER rebuilds the card, so scroll is
      // preserved). Base stage = the persisted status; the live mempool observation can push it one step further.
      advanceSwapTracker(Math.max(swapStage(rec.status), _liveSwapStage), rec.status);
      // PERF: only re-render the HEAVY lists (balance + swap history rebuild their innerHTML) when the swap STATUS
      // actually changed — not on every idle tick. Rebuilding them every ~1.2s was a re-render storm that thrashed
      // layout and made the page scroll janky mid-Buy. The status only changes on real progress (deposit seen /
      // minted), which is exactly when the headline total + history need a refresh.
      if (rec.status !== _lastPolledStatus) {
        _lastPolledStatus = rec.status;
        renderBalance();
        renderSwapHistory();
      }
      if (rec.status === 'minted') { renderBalance(); stopSwapPoll(); return; }
    } catch (_) {}
    // Idle cadence: the deposit-status is instant-cached node-side, so there is no need to hammer — a calmer
    // 2.5s poll keeps the mirror live while leaving the main thread free for smooth scrolling.
    _swapPoll = setTimeout(tick, 2500);
  };
  _swapPoll = setTimeout(tick, 2500);
}

// §BR-2 RECLAIM — the dollars-first quote, then the depositor's own refund signature over the week-old coin. Honest when the
// refund is not open yet (the blocks left, in days), and never a press that can lose funds without the warning first.
async function doReclaimDeposit(swapId) {
  const msg = document.getElementById('reclaimMsg');
  const say = (h) => { if (msg) msg.innerHTML = sanitizeHtml(h); };
  const err = (e) => say('<div class="settings-empty" style="color:var(--red,#e2686b)">' + escapeHtml(String(e && (e.message || e)).replace(/^Error:\s*/, '')) + '</div>');
  let q = null;
  try { q = await walletCore('wallet_reclaim_deposit_quote', { swap_id: swapId }); } catch (e) { err(e); return; }
  const left = Number(q.opens_in_blocks);
  if (left > 0) { say('<div class="card-note">The refund opens in ' + left.toLocaleString() + ' more Bitcoin blocks (about ' + (left / 144).toFixed(1) + ' days). Your deposit is safe at its address until then.</div>'); return; }
  if (q.dust) { err('This deposit is smaller than the Bitcoin fee to move it.'); return; }
  const px = await assetUsdPrice('BTC').catch(() => null);
  const keep = Number(q.keep_sats) / 1e8, fee = Number(q.fee_sats) / 1e8;
  if (!(await confirmCost({ title: 'Reclaim your Bitcoin deposit', confirmLabel: 'Reclaim',
    lines: [{ label: 'You get back', usd: px ? keep * px : null, detail: keep.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' BTC to a fresh vault address' },
      { label: 'Bitcoin network fee', usd: px ? fee * px : null, detail: fee.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' BTC' }],
    warning: WARN_IRREVERSIBLE + ' Reclaiming takes the deposit back: this swap will never mint USDm.' }))) return;
  const btn = document.getElementById('btnReclaimDeposit');
  if (btn) { btn.disabled = true; btn.textContent = 'Signing your refund…'; }
  try {
    const r = await walletCore('wallet_reclaim_deposit', { swap_id: swapId });
    say('<div class="card-note swap-ok">✓ ' + (Number(r.sats) / 1e8).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' BTC is on its way back to your vault.</div>');
    renderSwapHistory();
  } catch (e) { err(e); if (btn) { btn.disabled = false; btn.textContent = 'Reclaim my Bitcoin'; } }
}

// SWAP HISTORY — every swap this wallet made, newest first, locateable by swap_id; click one to re-track it live.
async function renderSwapHistory() {
  const el = document.getElementById('swapHistory');
  if (!el) return;
  try {
    const r = await walletCore('wallet_swap_history');
    const swaps = (r && r.swaps) || [];
    if (!swaps.length) { el.innerHTML = ''; return; }
    const label = { awaiting_reserve: 'reserve forming', awaiting_deposit: 'awaiting deposit', deposit_detected: 'deposit seen', minting: 'minting', gathering_quorum: 'quorum signing', published: 'in the next block', minted: 'minted' };
    el.innerHTML = '<div class="panel-head"><span>Swap history</span></div>' +
      swaps.map((s) => {
        const done = s.status === 'minted';
        return `<div class="swap-hist-row" data-swap="${escapeHtml(s.swap_id)}"><div class="swap-hist-left">` +
          `<span class="swap-hist-id">${escapeHtml(s.swap_id)}</span>` +
          `<span class="swap-hist-meta">${escapeHtml(s.asset)} → ${Number(s.usdm_out).toLocaleString()} USDm</span></div>` +
          `<span class="swap-hist-status ${done ? 'ok' : 'pending'}">${escapeHtml(label[s.status] || s.status)}</span></div>`;
      }).join('');
    el.querySelectorAll('.swap-hist-row').forEach((row) => {
      row.onclick = async () => {
        const id = row.dataset.swap; state.activeSwap = id;
        try { const rec = await walletCore('wallet_swap_status', { swap_id: id }); renderSwapCard(rec); startSwapPoll(id); } catch (_) {}
      };
    });
  } catch (_) {}
}

async function loadBuy() {
  state.buyAsset = state.buyAsset || 'BTC';
  state.buyInputMode = state.buyInputMode || 'USD'; // 'USD' = enter dollars (default, live-converted), 'ASSET' = enter BTC/XMR
  stopSwapPoll();
  const rows = document.getElementById('buyRows');
  if (rows) rows.innerHTML = '<div class="settings-empty">Enter an amount — you\'ll get a tracked swap with a reserve address to send your ' + escapeHtml(state.buyAsset) + ' to.</div>';
  applyBuyInputMode();
  // ⭐ COIN SWAP: "You get" USDm (a plain buy) or the OTHER coin (Bitcoin ↔ Monero in one action: the deposit mints USDm, which
  // the wallet then cashes out to the other coin on its own). The coin button always names the coin you are not paying with.
  state.buyGet = state.buyGet || 'USDM';
  const syncBuyGet = () => {
    const other = (state.buyAsset || 'BTC') === 'BTC' ? 'Monero' : 'Bitcoin';
    const coinBtn = document.getElementById('buyGetCoin'); if (coinBtn) coinBtn.textContent = other;
    document.querySelectorAll('#buyGetSeg .seg-btn').forEach((x) => x.classList.toggle('active', x.dataset.get === state.buyGet));
    const addr = document.getElementById('buyPayoutAddr');
    if (addr) {
      addr.classList.toggle('hidden', state.buyGet !== 'COIN');
      addr.placeholder = other === 'Monero' ? 'Your Monero address to receive the swap' : 'A Bitcoin address to receive the swap — leave empty to receive in this wallet\'s own vault';
    }
    const go = document.getElementById('btnBuyQuote');
    if (go) go.textContent = state.buyGet === 'COIN' ? 'Swap to ' + other : 'Generate swap address';
  };
  document.querySelectorAll('#buyGetSeg .seg-btn').forEach((b) => { b.onclick = () => { state.buyGet = b.dataset.get; syncBuyGet(); }; });
  state.syncBuyGet = syncBuyGet;
  syncBuyGet();
  document.querySelectorAll('#buyAssetSeg .seg-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.asset === state.buyAsset);
    b.onclick = () => {
      state.buyAsset = b.dataset.asset;
      document.querySelectorAll('#buyAssetSeg .seg-btn').forEach((x) => x.classList.toggle('active', x === b));
      state.buyPrice = null; // force a refetch of the live price for the newly-selected asset
      applyBuyInputMode();
      buyRecompute();
      if (state.syncBuyGet) state.syncBuyGet(); // the swap's "You get" coin is always the one you are not paying with
    };
  });
  const tog = document.getElementById('buyUnitToggle');
  if (tog) tog.onclick = () => {
    state.buyInputMode = (state.buyInputMode || 'USD') === 'USD' ? 'ASSET' : 'USD';
    applyBuyInputMode();
    buyRecompute();
  };
  const inp = document.getElementById('buyAmount');
  if (inp && !inp._buyWired) { inp._buyWired = true; inp.addEventListener('input', buyRecompute); }
  state.buyPrice = null;
  buyRecompute();
  // Buy/Sell mode toggle: Buy = mint (deposit → USDm), Sell = burn (USDm → deposit released). Same card, both ways.
  state.buyMode = state.buyMode || 'buy';
  document.querySelectorAll('#buyModeSeg .seg-btn').forEach((b) => { b.onclick = () => applyBuyMode(b.dataset.mode); });
  wireSellForm();
  applyBuyMode(state.buyMode);
  renderSwapHistory();
}

// Show the Buy form (mint) or the Sell form (burn) + reflect it in the segmented toggle, the view title, and the
// active poll (Sell has no live deposit poll). A first-class direction toggle — NOT a buried redeem button.
function applyBuyMode(mode) {
  state.buyMode = mode === 'sell' || mode === 'sat' || mode === 'earn' ? mode : 'buy';
  const sell = state.buyMode === 'sell';
  const sat = state.buyMode === 'sat';
  const earn = state.buyMode === 'earn';
  const bf = document.getElementById('buyForm'); if (bf) bf.classList.toggle('hidden', sell || sat || earn);
  const sf = document.getElementById('sellForm'); if (sf) sf.classList.toggle('hidden', !sell);
  const tf = document.getElementById('satForm'); if (tf) tf.classList.toggle('hidden', !sat);
  const ef = document.getElementById('earnForm'); if (ef) ef.classList.toggle('hidden', !earn);
  document.querySelectorAll('#buyModeSeg .seg-btn').forEach((b) => b.classList.toggle('active', b.dataset.mode === state.buyMode));
  const t = document.getElementById('buySellTitle'); if (t) t.textContent = earn ? 'Earn' : sat ? 'Trade SAT' : sell ? 'Cash out' : 'Buy USDm';
  const s = document.getElementById('buySellSub'); if (s) s.textContent = earn ? 'Deposit SAT into a pool · earn every trade\'s fee · withdraw any time' : sat ? 'Buy with Bitcoin or Monero · sell for either, any time' : sell ? 'Standard pieces · fresh addresses · a private delay (§BR-1)' : 'Atomic swap · send BTC or XMR, get USDm';
  if (sell) { stopSwapPoll(); sellRecompute(); renderCashOutPlans(); startCashOutPoll(); } else { stopCashOutPoll(); }
  if (sat) { wireSatForm(); startSatPoll(); startSatChart(); } else { stopSatPoll(); stopSatChart(); }
  if (earn) { wireEarnForm(); startEarnPoll(); } else { stopEarnPoll(); }
}

// Wire the Sell form: asset toggle, live receive-calc, and the Sell button → wallet_sell_usdm (confidential burn + peg-out).
function wireSellForm() {
  state.sellAsset = state.sellAsset || 'BTC';
  document.querySelectorAll('#sellAssetSeg .seg-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.asset === state.sellAsset);
    b.onclick = () => {
      state.sellAsset = b.dataset.asset;
      document.querySelectorAll('#sellAssetSeg .seg-btn').forEach((x) => x.classList.toggle('active', x === b));
      state.sellPrice = null; sellRecompute();
    };
  });
  const inp = document.getElementById('sellAmount');
  if (inp && !inp._sellWired) { inp._sellWired = true; inp.addEventListener('input', sellRecompute); }
  const btn = document.getElementById('btnSellUsdm');
  if (btn && !btn._sellWired) { btn._sellWired = true; btn.addEventListener('click', doCashOut); }
  // §BR-6: the destination — the wallet's own vault (a fresh address per piece, the default) or an outside address
  state.sellDest = state.sellDest || 'vault';
  document.querySelectorAll('#sellDestSeg .seg-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.dest === state.sellDest);
    b.onclick = () => {
      state.sellDest = b.dataset.dest;
      document.querySelectorAll('#sellDestSeg .seg-btn').forEach((x) => x.classList.toggle('active', x === b));
      const ta = document.getElementById('sellPayoutAddr'); if (ta) ta.classList.toggle('hidden', state.sellDest !== 'outside');
      sellRecompute();
    };
  });
  wireAutoOpsec();
}

// ⭐ §BR-11 "BOND MY REWARDS" — OFF by default (bonding is the holder's choice). Turning it ON passes one confirmation that
// names the cost ($0.00) and the 21-day unbonding; every later mining reward then goes straight into the custody bond.
state.bondRewards = false;
async function refreshBondRewards() {
  try { const r = await walletCore('wallet_bond_rewards'); state.bondRewards = !!(r && r.on); } catch (_) { state.bondRewards = false; }
  const on = state.bondRewards;
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  set('bondRewardsState', on ? 'on' : 'off');
  set('bondRewardsToggle', on ? 'Turn off' : 'Turn on');
  set('bondRewardsHint', on
    ? 'On: each SAT reward your node mines goes straight into your custody bond and earns the bonders\' fee share. Unbond any time — unbonding takes 21 days.'
    : 'Off: the SAT your node mines lands in your spendable balance. On: each reward goes straight into your custody bond (unbonding takes 21 days).');
}
async function toggleBondRewards() {
  const turnOn = !state.bondRewards;
  if (turnOn && !(await confirmCost({ title: 'Bond my rewards?', confirmLabel: 'Bond my rewards',
    lines: [{ label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
    warning: 'Each SAT your node mines goes straight into your validator custody bond instead of your spendable balance, and earns the bonders\' share (25%) of every network fee, paid weekly. Your rewards stay yours: unbond any time — unbonding takes 21 days.' }))) return;
  try { await walletCore('wallet_set_bond_rewards', { on: turnOn }); } catch (_) {}
  await refreshBondRewards();
}
function wireBondRewards() {
  const b = document.getElementById('bondRewardsToggle');
  if (b && !b._wired) { b._wired = true; b.addEventListener('click', toggleBondRewards); }
  refreshBondRewards();
}

// ⭐ §BR-8 "TAKE MY REWARDS IN BITCOIN" — OFF by default. Turning it ON passes one confirmation naming what each cash-out
// costs; every claimed reward is then tallied and cashed out privately (standard pieces, the privacy delay) to the vault.
state.rewardsBtc = false;
async function refreshRewardsBtc() {
  let tally = 0;
  try { const r = await walletCore('wallet_rewards_in_btc'); state.rewardsBtc = !!(r && r.on); tally = Number((r && r.tally_usdm) || 0); } catch (_) { state.rewardsBtc = false; }
  const on = state.rewardsBtc;
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  set('rewardsBtcState', on ? 'on' : 'off');
  set('rewardsBtcToggle', on ? 'Turn off' : 'Turn on');
  set('rewardsBtcHint', on
    ? 'On: rewards are cashed out privately to your Bitcoin vault once they reach one payout piece (' + usdText(tally) + ' waiting).'
    : 'Off: rewards stay USDm. On: once your rewards reach one payout piece, they are cashed out privately to your Bitcoin vault.');
}
async function toggleRewardsBtc() {
  const turnOn = !state.rewardsBtc;
  if (turnOn && !(await confirmCost({ title: 'Take my rewards in Bitcoin?', confirmLabel: 'Take rewards in Bitcoin',
    lines: [{ label: 'Network fee per payout piece', usd: 0.001, detail: 'the flat network fee on each piece burned' },
      appFeeLine('Wallet fee (0.10% of each cash-out)', 0)],
    warning: 'Each reward you claim is cashed out to a fresh address in your Bitcoin vault once it reaches one payout piece (0.0001 BTC). The privacy delay applies: pieces arrive within about 1–24 hours. Under one piece stays as USDm until more rewards arrive.' }))) return;
  try { await walletCore('wallet_set_rewards_in_btc', { on: turnOn }); } catch (_) {}
  await refreshRewardsBtc();
}
// ⭐ §BR-8 B8-b THE REMIXER — OFF by default; one confirmation naming the per-round Bitcoin fee in dollars.
state.remix = false;
async function refreshRemix() {
  try { const r = await walletCore('wallet_remix'); state.remix = !!(r && r.on); } catch (_) { state.remix = false; }
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  set('remixState', state.remix ? 'on' : 'off');
  set('remixToggle', state.remix ? 'Turn off' : 'Turn on');
}
async function toggleRemix() {
  const turnOn = !state.remix;
  if (turnOn && !(await confirmCost({ title: 'Remix to widen private rounds?', confirmLabel: 'Start remixing',
    lines: [{ label: 'Bitcoin network fee per round', usd: 0.3, detail: 'paid to Bitcoin miners from your vault coin' }],
    warning: 'Bitcoin in your vault keeps joining private deposit rounds, becomes USDm, then cashes back out to your vault after the privacy delay. Your coins stay yours at every step; each round costs a Bitcoin network fee. Remixing is paid through the bonders\' share of network fees.' }))) return;
  try { await walletCore('wallet_set_remix', { on: turnOn }); } catch (_) {}
  await refreshRemix();
}
function wireRemix() {
  const b = document.getElementById('remixToggle');
  if (b && !b._wired) { b._wired = true; b.addEventListener('click', toggleRemix); }
  refreshRemix();
}
function wireRewardsBtc() {
  const b = document.getElementById('rewardsBtcToggle');
  if (b && !b._wired) { b._wired = true; b.addEventListener('click', toggleRewardsBtc); }
  refreshRewardsBtc();
}

// ⭐ §BR-3 17.3 — DELEGATE SAT: one tap delegates to a validator (any seated one by default), one tap undelegates all; a
// matured undelegation returns to the balance by itself. Every value-moving tap passes one confirmation naming the cost
// ($0.00), the 21-day unbonding and the slashing risk.
async function refreshDelegations() {
  const list = document.getElementById('delegateList');
  const avail = document.getElementById('delegateAvail');
  let r = null;
  try { r = await walletCore('wallet_delegations'); } catch (_) { r = null; }
  if (avail) avail.textContent = 'Validators: ' + (r && r.validators_to_delegate_to != null ? r.validators_to_delegate_to : '—');
  const vl = document.getElementById('delegateValidators');
  if (vl) {
    const vs = (r && r.validators) || [];
    vl.innerHTML = vs.length ? vs.map((v) => '<div class="validator-row" data-vid="' + escapeHtml(v.validator) + '">' + escapeHtml(String(v.validator).slice(0, 12)) + '… · ' +
      escapeHtml(Number(v.sat).toLocaleString(undefined, { maximumFractionDigits: 8 })) + ' SAT bonded · tap to choose</div>').join('') : '';
    vl.querySelectorAll('.validator-row').forEach((el) => el.addEventListener('click', () => {
      const f = document.getElementById('delegateValidator'); if (f) f.value = el.getAttribute('data-vid');
    }));
  }
  if (!list) return;
  const rows = (r && r.delegations) || [];
  if (!rows.length) { list.textContent = 'You have no delegated SAT.'; return; }
  list.innerHTML = rows.map((d) => {
    if (d.state === 'delegated') return '<div>' + escapeHtml(String(d.sat)) + ' SAT delegated to ' + escapeHtml(String(d.validator).slice(0, 12)) + '…' +
      (d.earned_usdm > 0 ? ' · earned ' + escapeHtml(usdText(d.earned_usdm)) + ' (paid to your balance automatically)' : '') + '</div>';
    if (d.state === 'releasing') return '<div>' + escapeHtml(String(d.sat)) + ' SAT unbonded — returning to your balance now</div>';
    return '<div>' + escapeHtml(String(d.sat)) + ' SAT unbonding — back in about ' + escapeHtml(String(Math.max(0, Math.ceil(d.days_left || 0)))) + ' days</div>';
  }).join('');
}
async function doDelegate() {
  const st = document.getElementById('delegateStatus');
  const amt = parseFloat((document.getElementById('delegateAmount') || {}).value || '0');
  const vid = ((document.getElementById('delegateValidator') || {}).value || '').trim();
  if (!(amt > 0)) { st.className = 'send-status err'; st.textContent = 'Enter a SAT amount to delegate.'; return; }
  if (!(await confirmCost({ title: 'Delegate ' + amt + ' SAT?', confirmLabel: 'Delegate',
    lines: [{ label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
    warning: 'Your SAT joins ' + (vid ? 'this validator\'s' : 'a validator\'s') + ' custody weight and earns the bonders\' share of every network fee. Undelegating takes 21 days. It earns at that validator\'s uptime. If the validator is slashed for double-signing or a bad key, only its own bond is burned and your SAT comes back; if it is slashed for helping steal from the reserve, the SAT delegated to it is lost with it.' }))) return;
  st.className = 'send-status'; st.textContent = 'Delegating…';
  try {
    const r = await walletCore('wallet_delegate_sat', { amountSat: amt, vidHex: vid });
    st.className = 'send-status ok';
    st.textContent = (r && r.verdict === 'PUBLISHED') ? ('Delegated ' + amt + ' SAT — it counts once the block carrying it settles.') : ('Not delegated: ' + ((r && r.detail) || 'the node did not accept it'));
  } catch (e) { st.className = 'send-status err'; st.textContent = 'Not delegated: ' + (e && (e.message || e)); }
  refreshDelegations();
}
async function doUndelegate() {
  const st = document.getElementById('delegateStatus');
  if (!(await confirmCost({ title: 'Undelegate all your SAT?', confirmLabel: 'Undelegate',
    lines: [{ label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
    warning: 'Your delegated SAT stops earning now and returns to your spendable balance by itself after the 21-day unbonding period.' }))) return;
  st.className = 'send-status'; st.textContent = 'Undelegating…';
  try {
    const r = await walletCore('wallet_undelegate_sat');
    const n = (r && r.undelegated) ? r.undelegated.length : 0;
    st.className = 'send-status ok'; st.textContent = 'Undelegated ' + n + ' delegation' + (n === 1 ? '' : 's') + ' — back in your balance in 21 days.';
  } catch (e) { st.className = 'send-status err'; st.textContent = 'Not undelegated: ' + (e && (e.message || e)); }
  refreshDelegations();
}
function wireDelegations() {
  const d = document.getElementById('btnDelegate');
  if (d && !d._wired) { d._wired = true; d.addEventListener('click', doDelegate); }
  const u = document.getElementById('btnUndelegate');
  if (u && !u._wired) { u._wired = true; u.addEventListener('click', doUndelegate); }
  refreshDelegations();
}

// ⭐ §BR-10 — UPDATES, THE BITCOIN MODEL: the wallet never installs anything on its own. A release is offered only when three
// independent builders attest the same hash on chain; an emergency release says so plainly; a network upgrade shows its live
// signalling status. "Check a downloaded release" verifies a file against the attested hash before the user installs it.
async function refreshUpdates() {
  let r = null;
  try { r = await walletCore('wallet_update_status'); } catch (_) { r = null; }
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  const btn = document.getElementById('btnVerifyRelease');
  if (!r) { set('updateState', 'could not check'); return; }
  const dl = document.getElementById('btnDownloadRelease');
  if (r.available) {
    set('updateState', (r.emergency ? 'Security update — only blocks an attack; changes nothing else · ' : 'Update available · ') + 'v' + r.version + ' (' + r.builders + ' builders agree)');
    set('updateNotes', r.notes || '');
    if (btn) btn.classList.remove('hidden');
    if (dl && !state.releasePath) dl.classList.remove('hidden');
  } else {
    set('updateState', 'Up to date (v' + r.current + ')');
    set('updateNotes', '');
    if (btn) btn.classList.add('hidden');
    if (dl) dl.classList.add('hidden');
  }
  const rules = (r.deployments || []).map((d) => d.name + ': ' + d.state).join(' · ');
  set('updateRules', (r.update_needed ? 'Update needed to keep validating new rules — your node keeps following the network safely meanwhile. ' : '')
    + (rules ? 'Network upgrades: ' + rules : ''));
}
async function doVerifyRelease() {
  const st = document.getElementById('updateStatus');
  const path = window.prompt('Path of the downloaded release file');
  if (!path) return;
  st.className = 'send-status'; st.textContent = 'Checking…';
  try {
    const r = await walletCore('wallet_verify_release', { path });
    st.className = r && r.matches ? 'send-status ok' : 'send-status err';
    st.textContent = r && r.matches ? 'This file is the release three builders attested — safe to install.' : 'This file is NOT the attested release. Do not install it.';
  } catch (e) { st.className = 'send-status err'; st.textContent = 'Could not check: ' + (e && (e.message || e)); }
}
// One tap downloads the attested release over Tor through this wallet's node (each part checked against the builders' hash
// as it lands); the wallet then re-checks the whole file and offers "Open installer" — it never installs anything by itself.
async function doDownloadRelease() {
  const st = document.getElementById('updateStatus');
  const dl = document.getElementById('btnDownloadRelease');
  if (dl) dl.disabled = true;
  st.className = 'send-status';
  for (let tries = 0; tries < 1800; tries++) {
    let r = null;
    try { r = await walletCore('wallet_download_release'); }
    catch (e) { st.className = 'send-status err'; st.textContent = 'Download stopped: ' + (e && (e.message || e)); if (dl) dl.disabled = false; return; }
    if (r && r.done) {
      state.releasePath = r.path;
      st.className = 'send-status ok';
      st.textContent = 'Downloaded and checked against the builders\' hash — saved to ' + r.path;
      if (dl) dl.classList.add('hidden');
      const op = document.getElementById('btnOpenRelease'); if (op) op.classList.remove('hidden');
      return;
    }
    st.textContent = r && r.chunks ? ('Downloading over Tor · ' + r.held + ' of ' + r.chunks + ' parts checked') : 'Asking peers for the release…';
    await new Promise((res) => setTimeout(res, 2000));
  }
  st.className = 'send-status err'; st.textContent = 'No peer has served the release yet — try again later.';
  if (dl) dl.disabled = false;
}
async function doOpenRelease() {
  const st = document.getElementById('updateStatus');
  if (!state.releasePath) return;
  if (!(await confirmCost({ title: 'Open the installer?', confirmLabel: 'Open installer', lines: [{ label: 'Cost', usd: 0, detail: 'free' }],
    warning: 'This opens the release three builders attested. Your wallet and funds stay as they are; your node resumes where it stopped after the update.' }))) return;
  try { await walletCore('wallet_open_release', { path: state.releasePath }); st.className = 'send-status ok'; st.textContent = 'The installer is open.'; }
  catch (e) { st.className = 'send-status err'; st.textContent = 'Not opened: ' + (e && (e.message || e)); }
}
// The update is offered on the Wallet page too, where the owner looks first: the same on-chain attestation the Updates
// card reads. A tap opens Settings at the Updates card and starts the download over Tor; nothing is installed by a tap
// here (opening the installer is its own confirmed step).
async function refreshUpdateBanner() {
  const b = document.getElementById('updateBanner');
  if (!b) return;
  let r = null;
  try { r = await walletCore('wallet_update_status'); } catch (_) { r = null; }
  const on = !!(r && r.available);
  b.hidden = !on;
  if (!on) return;
  document.getElementById('updateBannerText').textContent = (r.emergency ? 'Security update' : 'Update available') + ' · v' + r.version + ' · ' + r.builders + ' builders agree';
  if (!b._wired) {
    b._wired = true;
    b.addEventListener('click', () => {
      switchView('settings');
      if (window.mobileLayout) window.mobileLayout.schedule();
      setTimeout(() => {
        const card = document.getElementById('updateCard');
        if (card) card.scrollIntoView({ behavior: 'smooth', block: 'start' });
        if (!state.releasePath) doDownloadRelease();
      }, 350);
    });
  }
}
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(refreshUpdateBanner, 5000);
  setInterval(() => { if (document.visibilityState === 'visible') refreshUpdateBanner(); }, 30 * 60 * 1000);
});
function wireUpdates() {
  const b = document.getElementById('btnVerifyRelease');
  if (b && !b._wired) { b._wired = true; b.addEventListener('click', doVerifyRelease); }
  const d = document.getElementById('btnDownloadRelease');
  if (d && !d._wired) { d._wired = true; d.addEventListener('click', doDownloadRelease); }
  const o = document.getElementById('btnOpenRelease');
  if (o && !o._wired) { o._wired = true; o.addEventListener('click', doOpenRelease); }
  refreshUpdates();
}

// ⭐ AUTO-OPSEC (user 2026-10-28): ON by default — every privacy step is automatic and the wallet refuses the ones that
// would break it. Turning it OFF (for funds now, or no need for privacy) passes through ONE warning popup; ON needs none.
// One switch in the core (`wallet_auto_opsec`), shown in Settings and on the Cash out panel.
state.autoOpsec = true;
const AUTO_OPSEC_OFF_WARNING = 'Without Auto-OPSEC your transactions will NOT be private: cash-outs pay in the next batch, ' +
  'can go to any address — even one that sent you a deposit — and can be matched to your deposits by anyone watching Bitcoin. ' +
  'Turn it back on any time.';
async function refreshAutoOpsec() {
  try { const r = await walletCore('wallet_auto_opsec'); state.autoOpsec = !!(r && r.on); } catch (_) { state.autoOpsec = true; }
  const on = state.autoOpsec;
  const set = (id, txt) => { const el = document.getElementById(id); if (el) el.textContent = txt; };
  set('sellOpsecState', on ? 'Auto-OPSEC: on' : 'Auto-OPSEC: off — not private');
  set('settingsOpsecState', on ? 'on' : 'off — not private');
  set('sellOpsecToggle', on ? 'Turn off' : 'Turn on');
  set('settingsOpsecToggle', on ? 'Turn off' : 'Turn on');
  set('sellOpsecHint', on
    ? 'Each piece pays in a random batch within 24 hours, among many same-size payouts, to a fresh address — automatically.'
    : 'Pieces pay in the next batch. Not private: they can be matched to your deposits.');
  const row = document.getElementById('sellOpsecRow'); if (row) row.classList.toggle('opsec-off', !on);
}
async function toggleAutoOpsec() {
  if (state.autoOpsec) {
    if (!(await confirmCost({ title: 'Turn off Auto-OPSEC?', confirmLabel: 'Turn off — not private', lines: [], warning: AUTO_OPSEC_OFF_WARNING }))) return;
  }
  try { await walletCore('wallet_set_auto_opsec', { on: !state.autoOpsec }); } catch (_) {}
  await refreshAutoOpsec();
  if (state.view === 'buy') { sellRecompute(); renderCashOutPlans(); }
}
function wireAutoOpsec() {
  for (const id of ['sellOpsecToggle', 'settingsOpsecToggle']) {
    const b = document.getElementById(id);
    if (b && !b._opsecWired) { b._opsecWired = true; b.addEventListener('click', toggleAutoOpsec); }
  }
  refreshAutoOpsec();
  wireNetworkChoice();
}

// Which networks this node may use. Moving between them changes how bytes travel and never touches a balance. Automatic stays on unless
// the user picks otherwise, and a manual pick says plainly what it gives up before it applies.
const NETWORK_WARNINGS = {
  tor: 'If Tor goes down or is attacked, your node stops reaching the network until Tor returns or you switch back. Your money stays safe, but payments wait. Tor also hides less than our network from someone watching the whole internet.',
  own: 'Our own network is still small. Until it reaches a thousand relays it hides you less than Tor does: your payments stay encrypted and your money stays safe, but there are fewer people to hide among.',
};
async function refreshNetworkChoice() {
  let r = null;
  try { r = await nodeRpc('/network_choice'); } catch (_) { return; }
  if (typeof r === 'string') { try { r = JSON.parse(r); } catch (_) { return; } }
  if (!r || !r.choice) return;
  state.networkChoice = r.choice;
  const seg = document.getElementById('settingsNetworkSeg');
  if (seg) seg.querySelectorAll('[data-network]').forEach((b) => b.classList.toggle('active', b.dataset.network === r.choice));
  const carrying = { tor: 'on Tor', mix: 'on our own network', none: 'looking for a network' }[r.carrying] || '';
  const picked = { auto: 'Automatic', tor: 'Tor only', own: 'Our network only' }[r.choice];
  const el = document.getElementById('settingsNetworkState');
  if (el) el.textContent = carrying ? picked + ', ' + carrying : picked;
  state.networkCrowd = { crowd: r.crowd | 0, large: r.crowd_large | 0 };
  showNetworkNotice(r);
}
// What the strip at the top of the page says, read from the node every 5 s. It speaks only when our network is carrying the wallet AND
// its crowd (relays known for a day, each an equally likely sender) is still below the node's `crowd_large`; once the crowd is large it
// goes quiet by itself. ✕ hides it until the message changes.
function networkNoticeFor(r) {
  const onOurs = r.carrying === 'mix';
  const small = !(r.crowd_large > 0 && r.crowd >= r.crowd_large);
  if (!onOurs || !small) return null;
  const crowd = (r.crowd | 0).toLocaleString();
  const size = 'It is small right now (' + crowd + ' relay' + (r.crowd === 1 ? '' : 's') + ' of the ' + (r.crowd_large | 0).toLocaleString() + ' it needs to hide you well).';
  if (r.choice === 'auto') {
    return {
      line: 'Tor is down · using our network (small: ' + crowd + ')',
      detail: 'Tor is unreachable everywhere, not just slow, so your wallet moved to MonerousD\'s own network. Your money is safe and payments keep working. ' + size + ' Your wallet moves back once Tor has been working again for a minute. You can choose a network in Settings.',
    };
  }
  return {
    line: 'Our network is small: ' + crowd + ' relays',
    detail: 'You chose MonerousD\'s own network. ' + size + ' Payments stay encrypted and your money is safe, but a watcher of the whole internet has fewer people to pick you out from until it grows. You can choose a network in Settings.',
  };
}
function showNetworkNotice(r) {
  const notice = document.getElementById('networkNotice');
  if (!notice) return;
  const msg = networkNoticeFor(r);
  const key = msg ? r.choice : ''; // not the count, so a hidden notice stays hidden while the crowd grows
  if (key !== state.networkNoticeKey) {
    state.networkNoticeKey = key;
    state.networkNoticeHidden = false;
  }
  notice.hidden = !msg || state.networkNoticeHidden;
  if (!msg) return;
  document.getElementById('networkNoticeText').textContent = msg.line;
  document.getElementById('networkNoticeDetail').textContent = msg.detail;
  if (!notice._wired) {
    notice._wired = true;
    const more = document.getElementById('networkNoticeMore');
    more.addEventListener('click', () => {
      const d = document.getElementById('networkNoticeDetail');
      d.hidden = !d.hidden;
      more.setAttribute('aria-expanded', String(!d.hidden));
    });
    document.getElementById('networkNoticeClose').addEventListener('click', () => {
      state.networkNoticeHidden = true;
      notice.hidden = true;
    });
  }
}
// The node moves between networks by itself, so what the wallet says about it is re-read all the time.
setInterval(refreshNetworkChoice, 5000);
async function chooseNetwork(choice) {
  if (choice === state.networkChoice) return;
  // Our network's warning is about its crowd, so it is only shown while the crowd is still small.
  const crowd = state.networkCrowd || { crowd: 0, large: 0 };
  const largeCrowd = crowd.large > 0 && crowd.crowd >= crowd.large;
  if (NETWORK_WARNINGS[choice] && !(choice === 'own' && largeCrowd)) {
    const names = { tor: 'Tor only', own: 'Our network only' };
    if (!(await confirmCost({ title: 'Use ' + names[choice] + '?', confirmLabel: 'Use ' + names[choice], lines: [], warning: NETWORK_WARNINGS[choice] }))) return;
  }
  try { await nodeRpc('/network_choice', { choice }); } catch (_) {}
  await refreshNetworkChoice();
}
function wireNetworkChoice() {
  const seg = document.getElementById('settingsNetworkSeg');
  if (seg && !seg._networkWired) {
    seg._networkWired = true;
    seg.addEventListener('click', (e) => {
      const b = e.target.closest('[data-network]');
      if (b) chooseNetwork(b.dataset.network);
    });
  }
  refreshNetworkChoice();
}

function cashOutInputs() {
  const amount = parseFloat((document.getElementById('sellAmount') || {}).value || '0');
  const asset = state.sellAsset || 'BTC';
  const outside = state.sellDest === 'outside';
  const payout = outside ? ((document.getElementById('sellPayoutAddr') || {}).value || '').trim() : '';
  const fast = !state.autoOpsec; // Auto-OPSEC off = pay now (next batch); on = the random batch, always
  return { amount, asset, outside, payout, fast };
}

// The plan, rendered in dollars: pieces, the delay window, what stays USDm. One line per piece.
function cashOutPlanHtml(q, px) {
  const pieces = (q.pieces || []);
  const per = q.asset === 'XMR' ? 1e12 : 1e8; // a piece is piconero on Monero's ledger, satoshis on Bitcoin's
  const coins = (n) => (Number(n) / per).toLocaleString(undefined, { maximumFractionDigits: q.asset === 'XMR' ? 12 : 8 });
  const usdOf = (units) => (px ? ' (' + usdText(Number(units) / per * px) + ')' : '');
  const list = pieces.map((c, i) => {
    const st = c.status || 'pending';
    const label = st === 'redeemed' ? '✓ burned at its batch, in the payout queue' : st === 'claimed' ? '✓ private claim sent — burned and paid at its batch (your device can be off)' : st === 'staged' ? '… set aside; keep the app open about 10 minutes to send its private claim' : st.startsWith('failed') ? '⚠ ' + escapeHtml(st.slice(7)) : 'waiting for funds to settle';
    const when = Number(c.pay_after) > 0 && Number(q.tip) > 0 ? ' · pays after block ' + Number(c.pay_after).toLocaleString() + ' (≈ ' + Math.max(0, (Number(c.pay_after) - Number(q.tip)) * 0.5 / 3600).toFixed(1) + ' h)' : (Number(c.pay_after) === 0 ? ' · next batch' : '');
    return '<div class="cashout-piece"><span>Part ' + (i + 1) + ': <b>' + coins(c.piece_atomic) + ' ' + escapeHtml(q.asset) + '</b>' + usdOf(c.piece_atomic) + ' → <code>' + escapeHtml(String(c.payout_to).slice(0, 14)) + '…</code></span><span class="cashout-piece-st">' + label + when + '</span></div>';
  }).join('');
  const rem = Number(q.remainder_usdm || 0);
  return '<div class="cashout-plan" data-plan="' + escapeHtml(q.plan_id || '') + '">' +
    '<div class="cashout-head"><b>' + Number(q.parts_sent || 0) + ' of ' + Number(q.parts_total || 0) + ' parts sent</b>' +
    (q.fast ? ' · fast' : ' · about ' + Number(q.about_hours_left || 0).toFixed(1) + ' h left') +
((q.parts_pending || 0) > 0 && !q.fast && !state.autoOpsec ? ' <button class="chip" data-fast-now="' + escapeHtml(q.plan_id || '') + '">Send the rest now</button>' : '') + '</div>' +
    list + (rem > 0 ? '<div class="cashout-rem">' + rem.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm stays USDm (below the smallest piece)</div>' : '') + '</div>';
}

let _cashOutPoll = null;
function stopCashOutPoll() { if (_cashOutPoll) { clearTimeout(_cashOutPoll); _cashOutPoll = null; } }
function startCashOutPoll() {
  stopCashOutPoll();
  const tick = async () => {
    if (state.view !== 'buy' || state.buyMode !== 'sell') { stopCashOutPoll(); return; }
    await renderCashOutPlans();
    _cashOutPoll = setTimeout(tick, 4000);
  };
  _cashOutPoll = setTimeout(tick, 4000);
}
async function renderCashOutPlans(fastNow) {
  const el = document.getElementById('cashOutPlans');
  if (!el) return;
  try {
    const px = await assetUsdPrice(state.sellAsset || 'BTC').catch(() => null);
    const r = await walletCore('wallet_cash_out_progress', { fast_now: fastNow || null });
    const plans = (r && r.plans) || [];
    if (!plans.length) { el.innerHTML = ''; return; }
    el.innerHTML = '<div class="panel-head"><span>Cash-outs</span></div>' + plans.map((q) => cashOutPlanHtml(q, px)).join('');
    el.querySelectorAll('[data-fast-now]').forEach((b) => { b.onclick = async () => {
      if (!(await confirmCost({ title: 'Send the rest now', confirmLabel: 'Send now', lines: [feeLine()],
        warning: 'The remaining parts pay in the next batch instead of a random one. Less private: their timing can be matched to this cash-out.' }))) return;
      renderCashOutPlans(b.dataset.fastNow);
    }; });
  } catch (e) { el.innerHTML = '<div class="settings-empty">' + escapeHtml(String(e && (e.message || e))) + '</div>'; }
}

// LIVE sell receive-calc: burning N USDm releases ≈ $N of reserve value → that USD ÷ the live asset price in BTC/XMR.
async function sellRecompute() {
  const el = document.getElementById('sellReceiveCalc');
  if (!el) return;
  const { amount, asset, outside, payout, fast } = cashOutInputs();
  if (!(amount > 0)) { el.textContent = 'Enter a USDm amount to see your pieces and how much ' + asset + ' you\'ll receive.'; return; }
  if (asset !== 'BTC') { el.textContent = 'Monero cash-outs pay through the Monero lane: enter a Monero address.'; return; }
  el.textContent = 'Pricing your cash-out at the chain\'s certified mark…';
  try {
    const q = await walletCore('wallet_cash_out_quote', { usdm_amount: amount, asset, payout_to: payout, fast });
    if (parseFloat((document.getElementById('sellAmount') || {}).value || '0') !== amount) return;
    const px = await assetUsdPrice(asset).catch(() => null);
    const per = asset === 'XMR' ? 1e12 : 1e8; // piconero on Monero's ledger, satoshis on Bitcoin's
    // A-F21 / A-F35: each Bitcoin piece arrives less its equal share of the miner fee of the payout that pays it (the reserve
    // never pays a fee). The figure is the most a piece pays at the node's current reading (alone in its payout).
    const total = (q.pieces || []).reduce((a, c) => a + Number(c.piece_atomic), 0) - Number(q.bitcoin_fee_sats || 0);
    const btcFeeUnknown = asset === 'BTC' && q.bitcoin_fee_known === false;
    el.innerHTML = 'You\'ll receive ' + (Number(q.bitcoin_fee_sats) > 0 ? 'at least ' : '') + '<b>' + (total / per).toLocaleString(undefined, { maximumFractionDigits: asset === 'XMR' ? 12 : 8 }) + ' ' + escapeHtml(asset) + '</b> in <b>' + Number(q.parts_total) + ' piece' + (Number(q.parts_total) === 1 ? '' : 's') + '</b>' +
      (px ? ' <span style="opacity:.7">(' + usdText(total / per * px) + ' at the chain\'s mark)</span>' : '') +
      (Number(q.remainder_usdm) > 0 ? ' · <span style="opacity:.75">' + Number(q.remainder_usdm).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm stays USDm</span>' : '') +
      (Number(q.bitcoin_fee_sats) > 0 ? ' · <span style="opacity:.75">after the Bitcoin network fee: up to ' + Number(q.bitcoin_fee_sats_per_piece).toLocaleString() + ' sats a piece' + (px ? ' (' + usdText(Number(q.bitcoin_fee_sats) / 1e8 * px) + ' in all)' : '') + ', less when pieces share a Bitcoin transaction</span>' : '') +
      (btcFeeUnknown ? ' · <span style="color:var(--warn,#e5a54b)">the Bitcoin network fee comes out of each piece; this node has no reading of that fee right now</span>' : '') +
      (fast ? ' · <span style="color:var(--warn,#e5a54b)">next batch (less private)</span>' : ' · <span style="opacity:.75">paid within 24 h in random batches</span>') +
      (outside && !payout ? ' · <span style="color:var(--warn,#e5a54b)">enter the outside address</span>' : '');
  } catch (e) { el.innerHTML = '<span style="color:var(--warn,#e5a54b)">' + escapeHtml(String(e && (e.message || e)).replace(/^Error:\s*/, '')) + '</span>'; }
}

// Sell = BURN USDm → release BTC/XMR (the reverse of Buy). Spends the USDm confidentially (a real PQ nullifier spend +
// change back to self, fast folded WHIR carrier) and the bonded reserve quorum releases the crypto to the payout
// address — no single party controls it. Broadcasts a real PQ-DAG tx; live status; balance auto-falls on burn.
// CASH OUT (§BR-1/5/6): the dollars-first plan is confirmed, then the pieces burn (each a real PQ nullifier spend with
// change back to self) and the bonded reserve quorum pays each piece to its own fresh address in its drawn batch.
function burnedOf(q) { return (q.pieces || []).reduce((a, c) => a + Number(c.burn_atomic), 0) / 1e8; }
async function doCashOut() {
  const rows = document.getElementById('sellRows');
  const { amount, asset, outside, payout, fast } = cashOutInputs();
  if (!(amount > 0)) { if (rows) rows.innerHTML = '<div class="settings-empty">Enter a USDm amount above 0.</div>'; return; }
  if (outside && !payout) { if (rows) rows.innerHTML = '<div class="settings-empty">Enter the ' + escapeHtml(asset) + ' address, or pay to your vault.</div>'; return; }
  const btn = document.getElementById('btnSellUsdm');
  let q = null;
  try { q = await walletCore('wallet_cash_out_quote', { usdm_amount: amount, asset, payout_to: payout, fast }); }
  catch (e) { if (rows) rows.innerHTML = '<div class="settings-empty" style="color:var(--red,#e2686b)">' + escapeHtml(String(e && (e.message || e)).replace(/^Error:\s*/, '')) + '</div>'; return; }
  const px = await assetUsdPrice(asset).catch(() => null);
  const btcFeeSats = Number(q.bitcoin_fee_sats || 0); // A-F21 / A-F35: the most the pieces pay in Bitcoin miner fee at the node's current reading
  const btcFeeUnknown = asset === 'BTC' && q.bitcoin_fee_known === false;
  const total = (q.pieces || []).reduce((a, c) => a + Number(c.piece_atomic), 0) - btcFeeSats;
  // Monero releases the burn's dollars 1:1 (one whole-USDm burn); Bitcoin pieces are sats
  const recvUnits = asset === 'XMR' ? total / 1e12 : total / 1e8; // the chain's priced release, in the coin's own units
  const burned = (q.pieces || []).reduce((a, c) => a + Number(c.burn_atomic), 0) / 1e8;
  if (!(await confirmCost({ title: 'Cash out ' + usdText(amount) + ' of USDm to ' + asset, confirmLabel: 'Cash out',
    lines: [{ label: 'You burn', usd: burned, detail: burned.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm in ' + Number(q.parts_total) + ' piece' + (Number(q.parts_total) === 1 ? '' : 's') },
      { label: 'You receive', usd: recvUnits != null && px ? recvUnits * px : null, detail: (recvUnits == null ? '?' : recvUnits.toLocaleString(undefined, { maximumFractionDigits: 8 })) + ' ' + asset + (outside ? ' to ' + payout.slice(0, 12) + '…' : ' to fresh vault addresses') },
      { label: 'Stays USDm', usd: Number(q.remainder_usdm || 0), detail: 'below the smallest piece — nothing is lost' },
      appFeeLine('Wallet fee (0.10%)', amount * 0.001),
      ...(btcFeeSats > 0 ? [{ label: 'Bitcoin network fee (at most)', usd: px ? btcFeeSats / 1e8 * px : null, detail: 'up to ' + Number(q.bitcoin_fee_sats_per_piece).toLocaleString() + ' sats a piece, paid to Bitcoin miners from your pieces: each piece pays its share of the Bitcoin transaction that pays it, less when pieces share one. The fee follows Bitcoin\'s fee market until the payout is sent; a piece that would lose more than half to it waits for a lower fee.', cost: true }] : []),
      ...(btcFeeUnknown ? [{ label: 'Bitcoin network fee', usd: null, detail: 'comes out of each piece (its share of the Bitcoin transaction that pays it). This node has no reading of Bitcoin\'s fee right now, so no figure can be shown; a piece that would lose more than half to it waits for a lower fee.', cost: true }] : []),
      feeLine(Number(q.parts_total) || 1)],
    warning: WARN_IRREVERSIBLE + (fast ? ' Fast is on: the pieces pay in the next batch, so their timing can be matched to this cash-out.' : ' Each piece pays in a random batch within 24 hours; your wallet need not stay open.') + (outside ? ' Check the ' + asset + ' address: a payout to a wrong address is lost, and reusing an address links your pieces.' : '') }))) return;
  if (btn) { btn.disabled = true; btn.textContent = 'Burning the pieces via the reserve quorum…'; }
  if (rows) rows.innerHTML = '<div class="settings-empty">Proving each piece\'s confidential burn + gathering the bonded threshold…</div>';
  const t0 = performance.now();
  try {
    const r = await walletCore('wallet_cash_out', { usdm_amount: amount, asset, payout_to: payout, fast });
    const ms = Math.round(performance.now() - t0);
    if (rows) rows.innerHTML = '<div class="card-note swap-ok">✓ ' + Number(r.parts_sent) + ' of ' + Number(r.parts_total) + ' pieces set aside in ' + ms + 'ms' + (Number(r.parts_pending) > 0 ? ' — the rest follow as your change settles (this screen keeps going)' : '') + '. Each is paid privately at its batch.</div>';
    renderBalance();
    renderSwapHistory();
    renderCashOutPlans();
  } catch (e) {
    if (rows) rows.innerHTML = '<div class="settings-empty" style="color:var(--red,#e2686b)">' + escapeHtml(String(e).replace(/^Error:\s*/, '')) + '</div>';
  } finally {
    if (btn) { btn.disabled = false; btn.textContent = 'Cash out'; }
  }
}

// Reflect the current input mode on the field: the unit label + input granularity. USD mode enters dollars (default),
// ASSET mode enters the raw BTC/XMR amount. The small toggle icon flips between them for ease of use.
function applyBuyInputMode() {
  const asset = state.buyAsset || 'BTC';
  const usd = (state.buyInputMode || 'USD') === 'USD';
  const u = document.getElementById('buyAmountUnit'); if (u) u.textContent = usd ? 'USD' : asset;
  const inp = document.getElementById('buyAmount'); if (inp) inp.step = usd ? '0.01' : '0.00000001';
  const tog = document.getElementById('buyUnitToggle');
  if (tog) tog.title = usd ? ('Entering a USD amount — click to enter ' + asset + ' instead')
                            : ('Entering a ' + asset + ' amount — click to enter USD instead');
}

// The 150% over-collateralization: USDm received = deposit_value_usd / 1.5 (governance-set backing).
const BUY_RATIO = 1.5;

// LIVE receive-calc. In USD mode the typed number is dollars (auto-converted to the crypto to send at the live price);
// in ASSET mode it is the crypto amount. Either way, show — small orange — the USDm received AND the crypto to send.
async function buyRecompute() {
  const el = document.getElementById('buyReceiveCalc');
  if (!el) return;
  const asset = state.buyAsset || 'BTC';
  const usdMode = (state.buyInputMode || 'USD') === 'USD';
  const typed = parseFloat((document.getElementById('buyAmount') || {}).value || '0');
  if (!(typed > 0)) { el.textContent = 'Enter a ' + (usdMode ? 'USD' : asset) + ' amount to see how much USDm you\'ll receive.'; return; }
  if (!state.buyPrice || state.buyPrice.asset !== asset) {
    el.textContent = 'Fetching live ' + asset + ' price…';
    try { const p = await walletCore('wallet_asset_price', { asset }); state.buyPrice = { asset, usd: Number(p.usd), source: p.source }; }
    catch (_) { el.textContent = 'Live price unavailable — try again.'; return; }
  }
  // Re-read after the async fetch (the input, asset, or mode may have changed).
  const t2 = parseFloat((document.getElementById('buyAmount') || {}).value || '0');
  if (!(t2 > 0) || (state.buyAsset || 'BTC') !== asset) return;
  const price = state.buyPrice.usd;
  const nowUsd = (state.buyInputMode || 'USD') === 'USD';
  const usdValue = nowUsd ? t2 : t2 * price;   // dollar value of the deposit
  const cryptoAmt = nowUsd ? t2 / price : t2;  // crypto amount the user actually sends to the reserve
  const usdm = usdValue / BUY_RATIO;
  const cryptoStr = cryptoAmt.toLocaleString(undefined, { maximumFractionDigits: 8 });
  el.innerHTML = 'You\'ll receive <b>≈ ' + usdm.toLocaleString(undefined, { maximumFractionDigits: 2 }) + ' USDm</b> ' +
    '<span style="opacity:.7">· send ≈ <b style="opacity:1">' + cryptoStr + ' ' + escapeHtml(asset) + '</b> ($' +
    usdValue.toLocaleString(undefined, { maximumFractionDigits: 2 }) + ' @ $' + price.toLocaleString() + ' · 150% reserve)</span>';
}

// Generate + persist a tracked swap. Convert the typed amount (USD or crypto) → the USDm the user receives.
async function doBuyQuote() {
  const rows = document.getElementById('buyRows');
  const typed = parseFloat(document.getElementById('buyAmount').value || '0');
  const asset = state.buyAsset || 'BTC';
  const usdMode = (state.buyInputMode || 'USD') === 'USD';
  if (!(typed > 0)) { rows.innerHTML = '<div class="settings-empty">Enter a ' + (usdMode ? 'USD' : escapeHtml(asset)) + ' amount above 0.</div>'; return; }
  rows.innerHTML = '<div class="settings-empty">Preparing your swap…</div>';
  try {
    if (!state.buyPrice || state.buyPrice.asset !== asset) {
      const p = await walletCore('wallet_asset_price', { asset }); state.buyPrice = { asset, usd: Number(p.usd), source: p.source };
    }
    const usdValue = usdMode ? typed : typed * state.buyPrice.usd;
    const usdm = usdValue / BUY_RATIO; // deposit_value / 150% over-collateral
    const cryptoAmt = usdMode ? typed / state.buyPrice.usd : typed;
    if (state.buyGet === 'COIN') { await doCoinSwap(asset, usdValue, usdm, cryptoAmt, rows); return; }
    // §BR-6: with Auto-OPSEC on (the default) a Bitcoin deposit is made private on its own — the entry mix
    if (asset === 'BTC' && state.autoOpsec) { await doPrivateBtcDeposit(cryptoAmt, rows); return; }
    if (!(await confirmCost({ title: 'Buy USDm with ' + asset, confirmLabel: 'Get deposit address',
      lines: [{ label: 'You deposit', usd: usdValue, detail: '≈ ' + cryptoAmt.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' ' + asset + ' at ' + usdText(state.buyPrice.usd) },
        { label: 'You receive', usd: usdm, detail: usdm.toLocaleString(undefined, { maximumFractionDigits: 2 }) + ' USDm (the deposit over the 150% reserve backing)' },
        appFeeLine('Wallet fee (0.10%, once the deposit mints)', usdm * 0.001), feeLine()],
      warning: (asset === 'BTC' ? 'Auto-OPSEC is off: this deposit is NOT private — anyone can link your Bitcoin to it. Turn Auto-OPSEC on to deposit privately. ' : '') +
        (asset === 'XMR' ? 'Monero has no self-refund: if a Monero deposit never mints, you cannot take it back yourself (a Bitcoin deposit can be reclaimed after one week). ' : '') +
        'Send exactly the amount shown on the next screen, on the ' + asset + ' network, to that deposit address only. Crypto sent to a wrong address or network cannot be recovered.' }))) {
      rows.innerHTML = ''; return;
    }
    const q = await walletCore('wallet_buy_swap', { asset, usdm_amount: usdm });
    const badge = document.getElementById('buyBackingBadge'); if (badge) badge.textContent = Number(q.backing_pct).toFixed(0) + '%';
    state.activeSwap = q.swap_id;
    renderSwapCard(q);
    startSwapPoll(q.swap_id);
    renderSwapHistory();
  } catch (e) {
    rows.innerHTML = '<div class="settings-empty">Swap unavailable: ' + escapeHtml(e && (e.message || e)) + '</div>';
  }
}
// ⭐ §BR-15 + §18.14 TRADE SAT: buy with Bitcoin or Monero, sell for either, any time, every cost in dollars first.
// §18.10 THE MAXIMUM PRICE: each buy names how far above the last price it will pay (+2 %, +10 %, +50 %, or no maximum) — sealed like its amount.
function satMaxBucket() {
  const sel = document.getElementById('buySatMax');
  const v = sel ? parseInt(sel.value, 10) : NaN;
  return Number.isInteger(v) ? v : 1;
}
function satCoin() { return state.satCoin || 'BTC'; }
function coinText(v, coin) { return Number(v).toLocaleString(undefined, { maximumFractionDigits: coin === 'XMR' ? 8 : 8 }) + ' ' + coin; }
function satText(v) { return Number(v).toLocaleString(undefined, { maximumFractionDigits: 4 }) + ' SAT'; }
// The coin's dollar price from the chain's mark; null when the chain holds no mark yet (trading never needs one: a pool reads no mark, only these dollar labels do).
async function satCoinUsd(coin) {
  try { const p = await walletCore('wallet_asset_price', { asset: coin }); const u = Number(p.usd); return u > 0 ? u : null; } catch (_) { return null; }
}
function satMaxWords(b, usd) {
  const k = satMaxBucket();
  const p = (b.max_prices || [])[k];
  if (p == null) return 'with no maximum price';
  return 'only up to ' + (usd ? usdText(Number(p) * usd) : coinText(p, b.coin)) + ' per SAT (+' + (b.max_percent || [])[k] + '%)';
}
function launchPoolWords(b) {
  const d = Number(b.launch_donation_sat || 0);
  return d > 0 ? 'The launch pools hold ' + d.toLocaleString() + ' SAT donated publicly and locked for ever: no key can withdraw them, so they can never be emptied or pulled. ' : '';
}
function wireSatForm() {
  const f = document.getElementById('satForm');
  if (!f || f._wired) { syncSatForm(); return; }
  f._wired = true;
  state.satCoin = state.satCoin || 'BTC';
  state.satSide = state.satSide || 'buy';
  state.satInput = state.satInput || 'USD';
  document.querySelectorAll('#satCoinSeg .seg-btn').forEach((b) => { b.onclick = () => { state.satCoin = b.dataset.coin; syncSatForm(); startSatChart(); }; });
  document.querySelectorAll('#satSideSeg .seg-btn').forEach((b) => { b.onclick = () => { state.satSide = b.dataset.side; syncSatForm(); }; });
  document.getElementById('satUnitToggle').onclick = () => { state.satInput = state.satInput === 'USD' ? 'COIN' : 'USD'; syncSatForm(); };
  document.getElementById('satAmount').addEventListener('input', satRecompute);
  document.getElementById('buySatMax').addEventListener('change', satRecompute);
  document.getElementById('btnSatGo').onclick = doSatGo;
  syncSatForm();
}
function syncSatForm() {
  const coin = satCoin();
  const sell = state.satSide === 'sell';
  const usdEntry = !sell && state.satInput === 'USD';
  document.querySelectorAll('#satCoinSeg .seg-btn').forEach((x) => x.classList.toggle('active', x.dataset.coin === coin));
  document.querySelectorAll('#satSideSeg .seg-btn').forEach((x) => x.classList.toggle('active', x.dataset.side === state.satSide));
  document.getElementById('satAmountLabel').textContent = sell ? 'You sell' : 'You pay';
  document.getElementById('satAmountUnit').textContent = sell ? 'SAT' : usdEntry ? 'USD' : coin;
  document.getElementById('satAmount').step = usdEntry ? '0.01' : '0.00000001';
  document.getElementById('satUnitToggle').classList.toggle('hidden', sell);
  document.getElementById('buySatMaxRow').classList.toggle('hidden', sell);
  const pay = document.getElementById('satPayout');
  pay.classList.toggle('hidden', !sell);
  pay.placeholder = 'Your ' + (coin === 'XMR' ? 'Monero' : 'Bitcoin') + ' address to receive the coin';
  document.getElementById('btnSatGo').textContent = sell ? 'Sell SAT for ' + coin : 'Buy SAT with ' + coin;
  document.getElementById('satUnitCoin').textContent = coin;
  satRecompute();
}
// The coin amount the form states, from dollars or the coin; `null` when it asks for dollars and the chain holds no mark.
async function satTypedCoin(typed) {
  if (state.satInput !== 'USD') return typed;
  const usd = await satCoinUsd(satCoin());
  return usd ? typed / usd : null;
}
async function satRecompute() {
  const el = document.getElementById('satReceive'); if (!el) return;
  const typed = parseFloat(document.getElementById('satAmount').value || '0');
  const coin = satCoin();
  if (!(typed > 0)) { el.textContent = 'Enter an amount to see what you\'ll receive.'; return; }
  try {
    const usd = await satCoinUsd(coin);
    if (state.satSide === 'sell') {
      const b = await walletCore('wallet_defi_book', { coin, quote_coin: 0, quote_sat: typed });
      el.innerHTML = 'You\'ll receive <b>≈ ' + escapeHtml(coinText(b.quote_coin, coin)) + '</b>' + (usd ? ' <span style="opacity:.7">(' + usdText(b.quote_coin * usd) + ') at the last price</span>' : ' <span style="opacity:.7">at the last price</span>');
    } else {
      const c = await satTypedCoin(typed);
      if (c == null) { el.textContent = 'The chain has no dollar price for ' + coin + ' right now: enter the amount in ' + coin + ' instead (⇅).'; return; }
      const b = await walletCore('wallet_defi_book', { coin, quote_coin: c, quote_sat: 0 });
      el.innerHTML = 'You\'ll receive <b>≈ ' + escapeHtml(satText(b.quote_sat)) + '</b> <span style="opacity:.7">· pay ' + escapeHtml(coinText(c, coin)) + ' at the last price</span>';
    }
  } catch (_) { el.textContent = 'The SAT market could not be read — try again.'; }
}
async function doSatGo() {
  const rows = document.getElementById('satRows');
  const typed = parseFloat(document.getElementById('satAmount').value || '0');
  if (!(typed > 0)) { rows.innerHTML = '<div class="settings-empty">Enter an amount above 0.</div>'; return; }
  try {
    if (state.satSide === 'sell') await doSellSat(typed, rows); else await doBuySat(typed, rows);
  } catch (e) { rows.innerHTML = '<div class="settings-empty">' + escapeHtml(String(e && e.message || e)) + '</div>'; }
  startSatPoll();
}
// Buy: coin this wallet already holds goes straight in; otherwise a deposit (private first with Auto-OPSEC on) mints it, with no backing ratio and no price read.
async function doBuySat(typed, rows) {
  const coin = satCoin();
  const c = await satTypedCoin(typed);
  if (c == null) { rows.innerHTML = '<div class="settings-empty">The chain has no dollar price for ' + coin + ' right now: enter the amount in ' + coin + ' instead (⇅).</div>'; return; }
  const usd = await satCoinUsd(coin);
  const b = await walletCore('wallet_defi_book', { coin, quote_coin: c, quote_sat: 0 });
  if (!b.open) { rows.innerHTML = '<div class="settings-empty">The SAT market is not open on this chain yet.</div>'; return; }
  const held = Number(b.coin_held || 0) >= c;
  if (!held && coin === 'BTC' && state.autoOpsec) { await doBuySatPrivate(c, usd, rows); return; }
  const dollars = usd ? c * usd : 0;
  const px = Number(b.price_coin_per_sat || 0);
  if (!(await confirmCost({ title: 'Buy SAT with ' + coin, confirmLabel: held ? 'Buy SAT' : 'Get deposit address',
    lines: [{ label: held ? 'You pay' : 'You deposit', usd: dollars, detail: coinText(c, coin) + (held ? ' from this wallet' : '') },
      { label: 'You receive', usd: dollars, detail: '≈ ' + satText(b.quote_sat) + ' at the last price, ' + (usd ? usdText(px * usd) : coinText(px, coin)) + ' per SAT' },
      { label: 'Maximum price', usd: 0, detail: satMaxWords(b, usd) + ' — above it the order does not fill and your ' + coin + ' comes back' }],
    warning: (!held && coin === 'BTC' ? 'Auto-OPSEC is off: this deposit is NOT private — anyone can see your Bitcoin reached the reserve (your SAT order itself stays private). Turn Auto-OPSEC on to deposit privately. ' : '') +
      (!held && coin === 'XMR' ? 'Monero has no self-refund: if a Monero deposit never mints, you cannot take it back yourself. ' : '') +
      'Your order fills at the next batch\'s clearing price, one price for every order in it, so a large batch can move it from the last one shown. If the batch does not settle, your ' + coin + ' comes back on its own. ' + launchPoolWords(b) +
      (held ? '' : 'Send exactly the amount shown, on the ' + coin + ' network, to that address only.') }))) {
    rows.innerHTML = ''; return;
  }
  if (held) {
    const r = await walletCore('wallet_buy_sat', { coin, amount: c, max_bucket: satMaxBucket() });
    rows.innerHTML = '<div class="settings-empty">' + (r.preparing ? 'Making a note of exactly this amount (one private payment to yourself), then the order goes out on its own.' : 'Order sent. It fills in the next batch, and your SAT arrives here.') + '</div>';
    return;
  }
  const q = await walletCore('wallet_buy_sat_deposit', { coin, amount: c, max_bucket: satMaxBucket() });
  renderSatDeposit(q, coin, rows);
}
function renderSatDeposit(q, coin, rows) {
  const amount = Number(q.deposit_atomic) / (coin === 'XMR' ? 1e12 : 1e8);
  rows.innerHTML = '<div class="settings-row"><div><b>Send exactly ' + escapeHtml(coinText(amount, coin)) + '</b></div><div class="mono selectable">' + escapeHtml(q.deposit_address || 'Waiting for the reserve address…') + '</div>' +
    (q.deposit_address ? '<button class="chip" data-copy="' + escapeHtml(q.deposit_address) + '">Copy address</button>' : '') +
    '<div class="muted">Your order goes out on its own once the deposit confirms and mints, and your SAT arrives here.</div></div>';
  rows.querySelectorAll('[data-copy]').forEach((b) => b.addEventListener('click', () => { try { navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copied'; } catch (_) {} }));
}
// Bitcoin with Auto-OPSEC: the private deposit (its rounds and mints), then one sealed order per minted note, placed on their own. Every cost in dollars first.
async function doBuySatPrivate(btc, usd, rows) {
  const q = await walletCore('wallet_mix_quote', { btc });
  const fees = Number(q.bitcoin_fees_btc), vault = Number(q.left_in_vault_btc);
  const netBtc = Math.max(0, btc - fees - vault);
  const b = await walletCore('wallet_defi_book', { coin: 'BTC', quote_coin: netBtc, quote_sat: 0 });
  const px = usd || 0;
  if (!(await confirmCost({ title: 'Buy SAT with Bitcoin, privately', confirmLabel: 'Get my private deposit address',
    lines: [{ label: 'You send', usd: btc * px, detail: coinText(btc, 'BTC') + ' from any wallet or exchange' },
      { label: 'You receive', usd: netBtc * px, detail: '≈ ' + satText(b.quote_sat) + ' at the last price' },
      { label: 'Bitcoin network fees', usd: fees * px, detail: 'paid to Bitcoin miners; the mixing itself is free' },
      { label: 'Stays in your Bitcoin vault', usd: vault * px, detail: 'under 0.0001 BTC is not deposited' },
      { label: 'Maximum price', usd: 0, detail: satMaxWords(b, usd) + ' — above it the order does not fill and your Bitcoin comes back' }],
    warning: 'Making your deposit private takes about ' + Math.ceil(Number(q.minutes)) + ' min with this wallet open; your SAT orders are placed on their own when it mints and fill at that batch\'s clearing price.' }))) {
    rows.innerHTML = ''; return;
  }
  const r = await walletCore('wallet_buy_sat_private_btc', { max_bucket: satMaxBucket() });
  state.mixPlanId = r.plan && r.plan.plan_id;
  renderMixPlans([r.plan]);
  startMixPoll();
}
// Sell: the same sealed order spending SAT; once it clears the wallet burns the coin and custody pays the address. A pool with no coin to pay returns the SAT.
async function doSellSat(sat, rows) {
  const coin = satCoin();
  const to = (document.getElementById('satPayout').value || '').trim();
  const name = coin === 'XMR' ? 'Monero' : 'Bitcoin';
  if (!to) { rows.innerHTML = '<div class="settings-empty">Enter the ' + name + ' address that receives your coin.</div>'; return; }
  const usd = await satCoinUsd(coin);
  const b = await walletCore('wallet_defi_book', { coin, quote_coin: 0, quote_sat: sat });
  if (!b.open) { rows.innerHTML = '<div class="settings-empty">The SAT market is not open on this chain yet.</div>'; return; }
  const dollars = usd ? b.quote_coin * usd : 0;
  if (!(await confirmCost({ title: 'Sell SAT for ' + coin, confirmLabel: 'Sell SAT',
    lines: [{ label: 'You sell', usd: dollars, detail: satText(sat) },
      { label: 'You receive', usd: dollars, detail: '≈ ' + coinText(b.quote_coin, coin) + ' at the last price, to ' + to.slice(0, 12) + '…' }],
    warning: 'Your sell fills at the next batch\'s clearing price, and a sell has no minimum price: a large batch can pay less than the last price shown. ' +
      'If the pool does not hold enough ' + name + ' to pay that batch\'s sells, your SAT comes back in full and you can sell again. ' +
      'The custody set sees this address when it pays. Whatever is below the smallest payout piece stays in this wallet as ' + name + '. A payment to the wrong address cannot be taken back: check it.' }))) {
    rows.innerHTML = ''; return;
  }
  const r = await walletCore('wallet_sell_sat', { coin, sat, payout_to: to });
  rows.innerHTML = '<div class="settings-empty">' + (r.preparing ? 'Making a note of exactly this amount (one private payment to yourself), then the sell goes out on its own.' : 'Sell sent. It fills in the next batch, then your ' + name + ' is paid to your address.') + '</div>';
}
let _satPoll = null;
function stopSatPoll() { if (_satPoll) { clearTimeout(_satPoll); _satPoll = null; } }
// The trade progress: orders in flight, claims made, deposits waiting, payouts on their way — every 1 s while one is in flight, else 3 s.
function startSatPoll() {
  stopSatPoll();
  const tick = async () => {
    if (state.view !== 'buy' || state.buyMode !== 'sat') { stopSatPoll(); return; }
    let inFlight = false;
    try { const p = await walletCore('wallet_defi_progress'); renderSatOrders(p); inFlight = (p.orders || []).length > 0 || (p.intents || []).length > 0 || (p.payouts || []).length > 0; } catch (_) {}
    _satPoll = setTimeout(tick, inFlight ? 1000 : 3000);
  };
  tick();
}
function renderSatOrders(p) {
  const el = document.getElementById('satOrderRows'); if (!el) return;
  const row = (t) => { const d = document.createElement('div'); d.className = 'settings-row'; d.textContent = t; return d; };
  const num = (v) => Number(v).toLocaleString(undefined, { maximumFractionDigits: 8 });
  const orderWords = (o) => {
    const side = o.sell ? 'Sell ' + num(o.paid) + ' SAT for ' + o.coin : 'Buy SAT with ' + num(o.paid) + ' ' + o.coin;
    const got = num(o.got) + (o.pays_coin ? ' ' + o.coin : ' SAT');
    const state_ = o.status === 'open' ? 'waiting for its batch'
      : o.status === 'filled' ? 'filled, claiming ' + got
      : o.status === 'returned' ? 'the pool could not pay this batch\'s sells, your SAT is coming back'
      : o.status === 'above_max' ? 'the price went above your maximum, your ' + o.coin + ' is coming back'
      : o.status === 'refunded' ? 'the batch did not settle, your ' + o.coin + ' is coming back' : o.status;
    return side + ' · ' + state_;
  };
  const nodes = (p.claimed || []).map((c) => row(c.status === 'returned' ? 'Your ' + num(c.got_coin) + ' SAT came back: the pool could not pay that batch\'s sells. You can sell again.'
      : c.pays_coin && c.sell ? 'Sold for ' + num(c.got_coin) + ' ' + c.coin + ', paying it out now'
      : c.pays_coin ? 'Your ' + num(c.got_coin) + ' ' + c.coin + ' came back to this wallet'
      : 'Received ' + num(c.got_coin) + ' SAT'))
    .concat((p.orders || []).map((o) => row(orderWords(o))))
    .concat((p.payouts || []).map((x) => row('Paying ' + num(x.left) + ' ' + x.coin + ' to ' + String(x.to).slice(0, 12) + '… · ' + num(x.sent) + ' ' + x.coin + ' handed to custody')))
    .concat((p.intents || []).map((i) => row('A deposit of ' + num(Number(i.amount) / (i.pair === 1 ? 1e12 : 1e8)) + (i.pair === 1 ? ' XMR' : ' BTC') + ' · the order goes out once it mints')))
    .concat(p.preparing ? [row(p.preparing + ' order(s) waiting for their note, then sent')] : []);
  el.classList.toggle('hidden', nodes.length === 0);
  el.replaceChildren(...nodes);
  if ((p.claimed || []).length) renderBalance();
}
// ⭐ EARN: deposit SAT into a pool and earn every trade's fee; the positions this wallet holds (kept on this device only);
// withdraw one at the pool's next Earn batch. Every cost and every payout in dollars before the user acts.
function earnCoin() { return state.earnCoin || 'BTC'; }
// A SAT's dollar price: the pool's last price in the coin times the coin's dollar mark; null with no mark (the screen then speaks in SAT).
async function earnSatUsd(coin, coinPerSat) {
  const usd = await satCoinUsd(coin);
  return usd && coinPerSat > 0 ? { sat: coinPerSat * usd, coin: usd } : null;
}
function earnUsdWords(v, px) { return px ? ' <span style="opacity:.7">(' + usdText(v) + ')</span>' : ''; }
function wireEarnForm() {
  const f = document.getElementById('earnForm');
  if (!f || f._wired) { syncEarnForm(); return; }
  f._wired = true;
  document.querySelectorAll('#earnCoinSeg .seg-btn').forEach((b) => { b.onclick = () => { state.earnCoin = b.dataset.coin; syncEarnForm(); refreshEarn(); }; });
  document.getElementById('earnAmount').addEventListener('input', earnRecompute);
  document.getElementById('btnEarnGo').onclick = doEarnGo;
  syncEarnForm();
}
function syncEarnForm() {
  const coin = earnCoin();
  document.querySelectorAll('#earnCoinSeg .seg-btn').forEach((x) => x.classList.toggle('active', x.dataset.coin === coin));
  document.getElementById('btnEarnGo').textContent = 'Deposit SAT into the ' + coin + ' pool';
  earnRecompute();
}
async function earnRecompute() {
  const el = document.getElementById('earnReceive'); if (!el) return;
  const sat = parseFloat(document.getElementById('earnAmount').value || '0');
  const coin = earnCoin();
  if (!(sat > 0)) { el.textContent = 'Enter how much SAT to deposit to see what it earns.'; return; }
  try {
    const q = await walletCore('wallet_earn_quote', { coin, sat });
    const px = await earnSatUsd(coin, Number(q.price_coin_per_sat));
    const worth = px ? q.withdraw_sat * px.sat + q.withdraw_coin * px.coin : 0;
    const cost = px ? Math.max(0, sat * px.sat - worth) : 0;
    el.innerHTML = 'Your position would be worth <b>' + escapeHtml(satText(q.withdraw_sat)) + ' + ' + escapeHtml(coinText(q.withdraw_coin, coin)) + '</b>' + earnUsdWords(worth, px) +
      ' at the last price' + (px ? ', after a one-time cost of ' + escapeHtml(usdText(cost)) + ' (the fee on the half that is sold)' : '') + '. It then earns its share of every trade\'s fee.';
  } catch (e) { el.textContent = String(e && e.message || e); }
}
async function doEarnGo() {
  const rows = document.getElementById('earnRows');
  const sat = parseFloat(document.getElementById('earnAmount').value || '0');
  const coin = earnCoin();
  if (!(sat > 0)) { rows.innerHTML = '<div class="settings-empty">Enter an amount of SAT above 0.</div>'; return; }
  try {
    const b = await walletCore('wallet_defi_book', { coin, quote_coin: 0, quote_sat: 0 });
    if (!b.open) { rows.innerHTML = '<div class="settings-empty">The ' + coin + ' pool is not open on this chain yet.</div>'; return; }
    if (Number(b.sat_held || 0) < sat) { rows.innerHTML = '<div class="settings-empty">This wallet holds ' + escapeHtml(satText(b.sat_held || 0)) + '. Buy SAT first (Trade SAT), then deposit it here.</div>'; return; }
    const q = await walletCore('wallet_earn_quote', { coin, sat });
    const px = await earnSatUsd(coin, Number(q.price_coin_per_sat));
    const worth = px ? q.withdraw_sat * px.sat + q.withdraw_coin * px.coin : 0;
    if (!(await confirmCost({ title: 'Deposit SAT into the ' + coin + ' pool', confirmLabel: 'Deposit SAT',
      lines: [{ label: 'You deposit', usd: px ? sat * px.sat : 0, detail: satText(sat) + ' from this wallet' },
        { label: 'Half is sold', usd: px ? q.sold_sat * px.sat : 0, detail: satText(q.sold_sat) + ' for ≈ ' + coinText(q.sold_for_coin, coin) + ' in the pool\'s next deposit batch (one each hour), at its one price' },
        { label: 'Your position', usd: worth, detail: '≈ ' + satText(q.withdraw_sat) + ' + ' + coinText(q.withdraw_coin, coin) + ' if withdrawn at the last price' },
        { label: 'One-time cost', usd: px ? Math.max(0, sat * px.sat - worth) : 0, detail: 'the fee on the sold half, and rounding that stays in the pool' }],
      warning: 'Your position holds SAT and ' + coin + ' in the pool\'s ratio, so what it is worth moves with the SAT price (like any pool, a large price move can leave it worth less than holding SAT alone). ' +
        'It joins the pool at the hour\'s deposit batch and earns from the next hour on. If that batch\'s sells do not settle, your SAT comes back whole. Withdraw any time: it pays at the pool\'s next Earn batch (one in every ' + (b.earn_every || 8) + '), your share plus the fees it earned. ' +
        'Nothing on the chain names you, your deposit or its size.' }))) {
      rows.innerHTML = ''; return;
    }
    const r = await walletCore('wallet_earn_deposit', { coin, sat });
    const msg = r.waiting === 'deposit_batch'
      ? 'Deposit queued. Deposits join the pool once an hour, in its deposit batch (right after the hour\'s income is paid out). It goes out on its own then; nothing is spent until it does.'
      : r.preparing ? 'Making a note of exactly this amount (one private payment to yourself), then the deposit goes out on its own.'
      : 'Deposit sent for this hour\'s deposit batch. It joins the pool when that batch clears, and your position appears below.';
    rows.innerHTML = '<div class="settings-empty">' + msg + '</div>';
  } catch (e) { rows.innerHTML = '<div class="settings-empty">' + escapeHtml(String(e && e.message || e)) + '</div>'; }
  startEarnPoll();
}
async function doEarnWithdraw(p) {
  const rows = document.getElementById('earnRows');
  try {
    const b = await walletCore('wallet_defi_book', { coin: p.coin, quote_coin: 0, quote_sat: 0 });
    const px = await earnSatUsd(p.coin, Number(b.price_coin_per_sat));
    const share = px ? p.withdraw_sat * px.sat + p.withdraw_coin * px.coin : 0;
    const income = px ? p.income_sat * px.sat : 0;
    if (!(await confirmCost({ title: 'Withdraw this position', confirmLabel: 'Withdraw',
      lines: [{ label: 'Your share', usd: share, detail: '≈ ' + satText(p.withdraw_sat) + ' + ' + coinText(p.withdraw_coin, p.coin) + ' at the last price' },
        { label: 'Fees it earned', usd: income, detail: satText(p.income_sat) + ', paid with the SAT' },
        { label: 'Withdrawal fee', usd: 0, detail: 'none' }],
      warning: 'It pays at the pool\'s next Earn batch (one in every ' + (b.earn_every || 8) + ' batches), at that batch\'s price. If that batch cannot pay every withdrawal, your position stays whole and is withdrawn at the next one, on its own.' }))) return;
    const r = await walletCore('wallet_earn_withdraw', { index: p.index });
    const wmsg = r.placed ? 'Withdrawal sent for this Earn batch: your SAT and ' + escapeHtml(p.coin) + ' arrive here when it clears.'
      : String(r.waiting || '').includes('income posts') ? 'Withdrawal queued: this hour\'s income is being paid out first, so your withdrawal includes it. It goes out on its own at the next Earn batch.'
      : 'Withdrawal queued: it goes out on its own when the pool\'s next Earn batch opens.';
    rows.innerHTML = '<div class="settings-empty">' + wmsg + '</div>';
  } catch (e) { rows.innerHTML = '<div class="settings-empty">' + escapeHtml(String(e && e.message || e)) + '</div>'; }
  refreshEarn();
}
let _earnPoll = null;
function stopEarnPoll() { if (_earnPoll) { clearTimeout(_earnPoll); _earnPoll = null; } }
// The progress poll moves deposits and withdrawals on (placing a waiting withdrawal when its Earn batch opens, collecting the claims), then lists the positions.
async function refreshEarn() {
  let inFlight = false;
  try { const pr = await walletCore('wallet_defi_progress'); inFlight = (pr.orders || []).some((o) => o.kind === 'deposit' || o.kind === 'withdraw'); renderEarnFlight(pr); } catch (_) {}
  try { renderEarnPositions(await walletCore('wallet_earn_positions')); } catch (_) {}
  return inFlight;
}
function startEarnPoll() {
  stopEarnPoll();
  const tick = async () => {
    if (state.view !== 'buy' || state.buyMode !== 'earn') { stopEarnPoll(); return; }
    const inFlight = await refreshEarn();
    _earnPoll = setTimeout(tick, inFlight ? 1000 : 3000);
  };
  tick();
}
function renderEarnFlight(pr) {
  const el = document.getElementById('earnRows'); if (!el) return;
  const lines = (pr.orders || []).filter((o) => o.kind === 'deposit' || o.kind === 'withdraw').map((o) => {
    const d = document.createElement('div'); d.className = 'settings-row';
    d.textContent = o.kind === 'deposit'
      ? 'Depositing ' + satText(o.paid) + ' into the ' + o.coin + ' pool · ' + (o.status === 'open' ? 'waiting for its batch' : o.status === 'returned' ? 'the batch\'s sells did not settle, your SAT is coming back' : o.status)
      : 'Withdrawing a position from the ' + o.coin + ' pool · ' + (o.status === 'open' ? 'waiting for its Earn batch' : o.status === 'withdrawn' ? 'paid, collecting your SAT and ' + o.coin : o.status);
    return d;
  });
  if (lines.length) el.replaceChildren(...lines);
}
async function renderEarnPositions(r) {
  const el = document.getElementById('earnPositionRows'); if (!el) return;
  const ps = r.positions || [];
  if (!ps.length) { el.innerHTML = '<div class="settings-empty">No positions yet. A deposit becomes one once its batch clears.</div>'; return; }
  const prices = {};
  for (const c of [...new Set(ps.map((p) => p.coin))]) {
    try { const b = await walletCore('wallet_defi_book', { coin: c, quote_coin: 0, quote_sat: 0 }); prices[c] = await earnSatUsd(c, Number(b.price_coin_per_sat)); } catch (_) { prices[c] = null; }
  }
  el.replaceChildren(...ps.map((p) => {
    const px = prices[p.coin];
    const share = px ? p.withdraw_sat * px.sat + p.withdraw_coin * px.coin : 0;
    const d = document.createElement('div'); d.className = 'settings-row';
    const words = document.createElement('div');
    words.innerHTML = '<b>' + escapeHtml(p.coin) + ' pool</b> · ' + escapeHtml(satText(p.withdraw_sat)) + ' + ' + escapeHtml(coinText(p.withdraw_coin, p.coin)) + earnUsdWords(share, px) +
      '<div class="muted">Fees earned: ' + escapeHtml(satText(p.income_sat)) + earnUsdWords(px ? p.income_sat * px.sat : 0, px) +
      (p.deposited_sat != null ? ' · deposited ' + escapeHtml(satText(p.deposited_sat)) : '') + '</div>';
    d.appendChild(words);
    if (p.status === 'open') {
      const btn = document.createElement('button'); btn.className = 'chip'; btn.textContent = 'Withdraw';
      btn.onclick = () => doEarnWithdraw(p);
      d.appendChild(btn);
    } else {
      const s = document.createElement('div'); s.className = 'muted'; s.textContent = p.status === 'withdrawing' ? 'Withdrawing at the next Earn batch' : p.status;
      d.appendChild(s);
    }
    return d;
  }));
}
// ⭐ §18.15 THE LIVE CHART: the price the chain publishes every batch, as a line with a crosshair; never volume or depth, which the chain does not hold.
let _satChartTimer = null;
function stopSatChart() { if (_satChartTimer) { clearTimeout(_satChartTimer); _satChartTimer = null; } }
function startSatChart() {
  stopSatChart();
  state.satRange = state.satRange == null ? 86400 : state.satRange;
  state.satChartUnit = state.satChartUnit || 'USD';
  document.querySelectorAll('#satRangeSeg .sat-range').forEach((b) => {
    b.classList.toggle('active', Number(b.dataset.range) === state.satRange);
    b.onclick = () => { state.satRange = Number(b.dataset.range); startSatChart(); };
  });
  document.querySelectorAll('#satUnitSeg .seg-btn').forEach((b) => {
    b.classList.toggle('active', b.dataset.unit === state.satChartUnit);
    b.onclick = () => { state.satChartUnit = b.dataset.unit; startSatChart(); };
  });
  const tick = async () => {
    if (state.view !== 'buy' || state.buyMode !== 'sat') { stopSatChart(); return; }
    try { await drawSatChart(); } catch (_) {}
    _satChartTimer = setTimeout(tick, 5000);
  };
  tick();
}
function satPriceText(v, unit, coin) {
  if (unit === 'USD') return usdText(v);
  return Number(v).toLocaleString(undefined, { maximumSignificantDigits: 6 }) + ' ' + coin;
}
async function drawSatChart() {
  const coin = satCoin();
  const [r, usd] = await Promise.all([walletCore('wallet_defi_prices', { coin, range_secs: state.satRange }), satCoinUsd(coin)]);
  if (coin !== satCoin()) return;
  const unit = state.satChartUnit === 'USD' && usd ? 'USD' : 'COIN';
  const scale = unit === 'USD' ? usd : 1;
  const raw = (r.points || []).map((p) => [Number(p[0]), Number(p[1]) * scale]);
  if (!raw.length) return;
  const pts = raw.length === 1 ? [[raw[0][0] - 60, raw[0][1]], raw[0]] : raw;
  const last = pts[pts.length - 1][1];
  const first = pts[0][1];
  const change = first > 0 ? (last - first) / first * 100 : 0;
  document.getElementById('satChartPrice').textContent = satPriceText(last, unit, coin) + ' per SAT';
  const rangeName = (document.querySelector('#satRangeSeg .sat-range.active') || {}).textContent || '';
  document.getElementById('satChartSub').textContent = (raw.length < 2 ? 'Launch price, no trades in this range yet' : (change >= 0 ? '▲ ' : '▼ ') + Math.abs(change).toFixed(2) + '% · ' + rangeName) + (unit === 'USD' ? ' · dollars at today\'s ' + coin + ' price' : '');
  const plot = document.getElementById('satChartPlot');
  const W = Math.max(280, plot.clientWidth || 480), H = 180, L = 4, R = 64, T = 10, B = 22;
  let lo = Math.min(...pts.map((p) => p[1])), hi = Math.max(...pts.map((p) => p[1]));
  if (hi - lo < hi * 0.002) { lo = hi * 0.95; hi = hi * 1.05; } else { const pad = (hi - lo) * 0.08; lo -= pad; hi += pad; }
  const t0 = pts[0][0], t1 = Math.max(pts[pts.length - 1][0], t0 + 1);
  const x = (t) => L + (t - t0) / (t1 - t0) * (W - L - R);
  const y = (v) => T + (1 - (v - lo) / (hi - lo)) * (H - T - B);
  const line = pts.map((p, i) => (i ? 'L' : 'M') + x(p[0]).toFixed(1) + ' ' + y(p[1]).toFixed(1)).join(' ');
  const area = line + ' L' + x(t1).toFixed(1) + ' ' + (H - B) + ' L' + x(t0).toFixed(1) + ' ' + (H - B) + ' Z';
  const short = (v) => unit === 'USD' ? usdText(v) : Number(v).toLocaleString(undefined, { maximumSignificantDigits: 4 });
  const when = (t) => { const d = new Date(t * 1000); return (t1 - t0) > 172800 ? d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' }) : d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }); };
  const grid = [0, 0.5, 1].map((f) => { const v = lo + (hi - lo) * f; const gy = y(v).toFixed(1); return '<line class="sat-grid" x1="' + L + '" x2="' + (W - R) + '" y1="' + gy + '" y2="' + gy + '"/><text class="sat-axis" x="' + (W - R + 6) + '" y="' + (Number(gy) + 4) + '"></text>'; }).join('');
  plot.innerHTML = '<svg viewBox="0 0 ' + W + ' ' + H + '" width="100%" height="' + H + '" preserveAspectRatio="none">' + grid +
    '<path class="sat-area" d="' + area + '"/><path class="sat-line" d="' + line + '"/>' +
    '<line class="sat-cross hidden" y1="' + T + '" y2="' + (H - B) + '"/><circle class="sat-dot" r="4" cx="' + x(pts[pts.length - 1][0]).toFixed(1) + '" cy="' + y(last).toFixed(1) + '"/>' +
    '<text class="sat-axis" x="' + L + '" y="' + (H - 6) + '"></text><text class="sat-axis" text-anchor="end" x="' + (W - R) + '" y="' + (H - 6) + '"></text></svg><div class="sat-tip hidden"></div>';
  const texts = plot.querySelectorAll('text');
  [0, 0.5, 1].forEach((f, i) => { texts[i].textContent = short(lo + (hi - lo) * f); });
  texts[3].textContent = when(t0); texts[4].textContent = when(t1);
  const cross = plot.querySelector('.sat-cross'), dot = plot.querySelector('.sat-dot'), tip = plot.querySelector('.sat-tip');
  const reset = () => { cross.classList.add('hidden'); tip.classList.add('hidden'); dot.setAttribute('cx', x(pts[pts.length - 1][0]).toFixed(1)); dot.setAttribute('cy', y(last).toFixed(1)); };
  const at = (px) => {
    const t = t0 + (px - L) / (W - L - R) * (t1 - t0);
    let best = pts[0];
    for (const p of pts) if (Math.abs(p[0] - t) < Math.abs(best[0] - t)) best = p;
    return best;
  };
  const show = (p) => {
    const cx = x(p[0]).toFixed(1);
    cross.setAttribute('x1', cx); cross.setAttribute('x2', cx); cross.classList.remove('hidden');
    dot.setAttribute('cx', cx); dot.setAttribute('cy', y(p[1]).toFixed(1));
    tip.textContent = satPriceText(p[1], unit, coin) + ' · ' + new Date(p[0] * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
    tip.classList.remove('hidden');
    const rect = plot.getBoundingClientRect();
    tip.style.left = Math.min(Math.max(0, Number(cx) / W * rect.width - 70), Math.max(0, rect.width - 170)) + 'px';
  };
  plot.onpointermove = (e) => { const rect = plot.getBoundingClientRect(); show(at((e.clientX - rect.left) / rect.width * W)); };
  plot.onpointerleave = reset;
  plot.onblur = reset;
  plot.onkeydown = (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    plot._i = Math.min(pts.length - 1, Math.max(0, (plot._i == null ? pts.length - 1 : plot._i) + (e.key === 'ArrowLeft' ? -1 : 1)));
    show(pts[plot._i]);
  };
  const table = document.getElementById('satChartTable');
  const tr = (a, b, tag) => { const row = document.createElement('tr'); [a, b].forEach((v) => { const c = document.createElement(tag); c.textContent = v; row.appendChild(c); }); return row; };
  const t = document.createElement('table');
  t.appendChild(tr('Time', 'Price per SAT', 'th'));
  pts.slice(-24).reverse().forEach((p) => t.appendChild(tr(new Date(p[0] * 1000).toLocaleString(), satPriceText(p[1], unit, coin), 'td')));
  table.replaceChildren(t);
}
// ⭐ COIN SWAP — Bitcoin ↔ Monero in one action, every cost in dollars before anything is sent: the deposit mints USDm on its
// own coin's ledger, and the wallet cashes that USDm out to the other coin on its own (a private Bitcoin deposit first when
// Auto-OPSEC is on). What does not fit a payout piece stays USDm in this wallet.
async function doCoinSwap(asset, usdValue, usdm, cryptoAmt, rows) {
  const to = asset === 'BTC' ? 'XMR' : 'BTC';
  const toName = to === 'XMR' ? 'Monero' : 'Bitcoin';
  const payout = ((document.getElementById('buyPayoutAddr') || {}).value || '').trim();
  if (to === 'XMR' && !payout) { rows.innerHTML = '<div class="settings-empty">Enter the Monero address that receives your XMR.</div>'; return; }
  let toUsd = 0;
  try { toUsd = Number((await walletCore('wallet_asset_price', { asset: to })).usd) || 0; } catch (_) {}
  const fees = usdm * 0.002; // cash in 0.10 % + cash out 0.10 %
  const outUsd = Math.max(0, (to === 'XMR' ? Math.floor(usdm - fees) : usdm - fees));
  if (!(await confirmCost({ title: 'Swap ' + asset + ' to ' + to, confirmLabel: 'Get deposit address',
    lines: [{ label: 'You deposit', usd: usdValue, detail: '≈ ' + cryptoAmt.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' ' + asset + ' at ' + usdText(state.buyPrice.usd) },
      { label: 'You receive', usd: outUsd, detail: toUsd > 0 ? '≈ ' + (outUsd / toUsd).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' ' + to + ' to ' + (payout ? payout.slice(0, 14) + '…' : 'your vault') : 'at the chain\'s ' + to + ' price' },
      { label: 'Stays in your wallet', usd: Math.max(0, usdm - fees - outUsd), detail: 'USDm that does not fit a payout piece — never lost' },
      appFeeLine('Wallet fees (0.10% in + 0.10% out)', fees), feeLine()],
    warning: 'Send exactly the amount shown on the next screen, on the ' + asset + ' network, to that deposit address only. ' +
      (asset === 'XMR' ? 'Monero has no self-refund: a deposit that never mints cannot be reclaimed by you. ' : '') +
      'The ' + toName + ' leg starts on its own once your USDm mints — keep the wallet open until it says sent.' }))) {
    rows.innerHTML = ''; return;
  }
  const q = await walletCore('wallet_coin_swap', { from: asset, to, usdm_amount: usdm, payout_to: payout });
  if (q.private) { state.mixPlanId = q.plan && q.plan.plan_id; renderMixPlans([q.plan]); startMixPoll(); return; }
  state.activeSwap = q.swap_id;
  renderSwapCard(q);
  startSwapPoll(q.swap_id);
  renderSwapHistory();
}
// ── §BR-6 — ADD MONEY WITH BITCOIN, PRIVATELY. Every cost in dollars before the user sends anything; then one address to
// send to, and the wallet does the rest (mixing rounds with other people, each private deposit minting on its own).
async function doPrivateBtcDeposit(btc, rows) {
  const q = await walletCore('wallet_mix_quote', { btc });
  const px = (state.buyPrice && state.buyPrice.usd) || 0;
  if (!(await confirmCost({ title: 'Add money with Bitcoin, privately', confirmLabel: 'Get my private deposit address',
    lines: [{ label: 'You send', usd: btc * px, detail: '≈ ' + btc.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' BTC from any wallet or exchange' },
      { label: 'You receive', usd: Number(q.usdm), detail: Number(q.usdm).toLocaleString(undefined, { maximumFractionDigits: 2 }) + ' USDm in ' + q.deposits + ' private deposit(s)' },
      { label: 'Bitcoin network fees', usd: Number(q.bitcoin_fees_btc) * px, detail: 'paid to Bitcoin miners; the mixing itself is free' },
      { label: 'Stays in your Bitcoin vault', usd: Number(q.left_in_vault_btc) * px, detail: 'under 0.0001 BTC is not deposited' },
      appFeeLine('Wallet fee (0.10%, once each deposit mints)', Number(q.usdm) * 0.001)],
    warning: 'Making your deposit private takes about ' + Math.ceil(Number(q.minutes)) + ' min with this wallet open. Send Bitcoin only, to the address on the next screen.' }))) {
    rows.innerHTML = ''; return;
  }
  const r = await walletCore('wallet_mix_start');
  state.mixPlanId = r.plan && r.plan.plan_id;
  renderMixPlans([r.plan]);
  startMixPoll();
}
function renderMixPlans(plans) {
  const rows = document.getElementById('buyRows'); if (!rows) return;
  rows.innerHTML = (plans || []).map(p => '<div class="settings-row mix-plan" data-mix="' + escapeHtml(p.plan_id || '') + '">' +
    '<div><b>Private Bitcoin deposit</b> · ' + escapeHtml(p.note || '') + '</div>' +
    (p.status === 'awaiting_funds' ? '<div class="mono selectable">' + escapeHtml(p.receive_address || '') + '</div><button class="chip" data-copy="' + escapeHtml(p.receive_address || '') + '">Copy address</button>' : '') +
    '<div class="muted">' + (p.rounds_done || 0) + ' step(s) done · ' + (p.minting || 0) + ' private deposit(s) minting · ' + (p.minted || 0) + ' minted' +
    (p.left_in_vault_btc > 0 ? ' · ' + Number(p.left_in_vault_btc).toFixed(8) + ' BTC stays in your vault' : '') + '</div></div>').join('');
  rows.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => { try { navigator.clipboard.writeText(b.dataset.copy); b.textContent = 'Copied'; } catch (_) {} }));
}
let _mixPoll = null;
// While the wallet is INSIDE a round its output must reach the coordinator inside the outputs window (the send time is drawn
// at random up to 8 s before the window closes) and its signature inside the signing window, so the poll runs every second
// then; otherwise every 5 s. A 5 s poll could miss the 8 s margin and the round's transaction left this wallet's deposit out
// (MEASURED in the shipped add-money flow) — the coin stays the user's, but the round is lost for everyone in it.
function startMixPoll() {
  if (_mixPoll) return;
  const tick = async () => {
    let again = true, fast = false;
    try {
      const r = await walletCore('wallet_mix_progress');
      // a plan is open while it mixes OR while a finished round's deposit is still minting (the core mints them each poll)
      const open = (r.plans || []).filter(p => p.status !== 'done' || Number(p.minting || 0) > 0);
      if (state.view === 'buy' || !state.view) renderMixPlans(r.plans || []);
      fast = open.some(p => p.in_round);
      if (!open.length) { again = false; renderSwapHistory(); }
    } catch (_) {}
    _mixPoll = again ? setTimeout(tick, fast ? 1000 : 5000) : null;
  };
  _mixPoll = setTimeout(tick, 0);
}
// a wallet reopened mid-mix keeps mixing
setTimeout(() => { walletCore('wallet_mix_progress').then(r => { if ((r.plans || []).some(p => p.status !== 'done')) startMixPoll(); }).catch(() => {}); }, 4000);

// ── BROWSER / LAUNCHPAD — imported from the old pre-greenfield wallet (build-1261/renderer, user-authorized
// 2026-07-18). The MoneroUSD Launchpad: the SAME verified-dApp registry + card grid + browser chrome as the old
// wallet. Each app offers BOTH paths (user 2026-07-18): the clearnet domain (opened as the normal https:// site)
// AND the node's SOVEREIGN mirror — served locally by THIS wallet's own node on 127.0.0.1:27752 (`usdmd-node
// serve-sites`), private + node-first, only in sovereign mode. The shield button toggles between them; both are
// always available. The apps' backend is the node's WHIR-only PQ RPC (the old VPS backend is retired).
// The address of this wallet's own node's site host (it serves the apps and the native coins' marks on this computer
// only). The address is the CORE's to say: the shell that hosts this page may state it before any script runs
// (`__MONEROUSD_SITE_HOST__`), and the core's network descriptor states it again (`learnSiteHost`); the number written
// here is only what both say on an ordinary install.
// TWO-PARTY-REVIEWED: this is product code naming an address, not a test. Its two parties (this page and the site host
// process it names) are exercised together, as two processes, by the real-node check `web3-connect`.
let SOVEREIGN_BASE = (typeof window !== 'undefined' && /^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(String(window.__MONEROUSD_SITE_HOST__ || '')))
  ? window.__MONEROUSD_SITE_HOST__ : 'http://127.0.0.1:27752';
// Take the site host's address from the core's network descriptor (`wallet_network_info`): an address on this computer,
// or it is ignored.
function learnSiteHost(info) {
  const h = info && info.site_host;
  if (typeof h === 'string' && /^http:\/\/127\.0\.0\.1:\d{2,5}$/.test(h)) SOVEREIGN_BASE = h;
  return info;
}
// Real dApp logos — inline SVG data URIs (self-contained, no remote fetch → renders under the wallet CSP),
// ported 1:1 from the old wallet's launchpad marks (user-authorized design port). Each tile shows its true
// brand mark; the letter chip renders via onerror only if a mark ever fails to decode (an inline data-URI won't).
const ION_LOGO_SVG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><defs><linearGradient id="ig" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#FF7A00"/><stop offset="100%" stop-color="#c44d00"/></linearGradient></defs><rect width="40" height="40" rx="8" fill="#1a1a1a"/><path d="M11 16 H27 l-4 -4 M29 24 H13 l4 4" fill="none" stroke="url(#ig)" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"/></svg>');
const EXPLORER_LOGO_SVG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><defs><linearGradient id="eg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#FF6600"/><stop offset="100%" stop-color="#c44d00"/></linearGradient></defs><rect width="40" height="40" rx="8" fill="#1a1a1a"/><circle cx="16" cy="16" r="8" fill="none" stroke="url(#eg)" stroke-width="2.5"/><path d="M22 22 L31 31" stroke="url(#eg)" stroke-width="3" stroke-linecap="round"/><circle cx="16" cy="16" r="3" fill="url(#eg)"/></svg>');
const MONEROUSD_ORG_LOGO_SVG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><defs><linearGradient id="og" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stop-color="#FF6600"/><stop offset="100%" stop-color="#a03800"/></linearGradient></defs><rect width="40" height="40" rx="8" fill="#1a1a1a"/><polygon points="20,6 33,13.5 20,21 7,13.5" fill="url(#og)" opacity="0.35"/><polygon points="20,13 33,20.5 20,28 7,20.5" fill="url(#og)" opacity="0.65"/><polygon points="20,20 33,27.5 20,35 7,27.5" fill="url(#og)"/><text x="20" y="31.5" text-anchor="middle" font-family="system-ui,sans-serif" font-weight="800" font-size="10" fill="#fff">$</text></svg>');
const IDE_LOGO_SVG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><rect width="40" height="40" rx="8" fill="#1a1a1a"/><polygon points="20,5 35,13.5 35,26.5 20,35 5,26.5 5,13.5" fill="none" stroke="#FF6600" stroke-width="2"/><polygon points="20,11 30,16.5 30,25.5 20,31 10,25.5 10,16.5" fill="#FF6600" fill-opacity="0.18" stroke="#FF6600" stroke-width="1.5"/><text x="20" y="24" text-anchor="middle" font-family="ui-monospace,monospace" font-weight="800" font-size="8" fill="#FF6600">IDE</text></svg>');
const SOVEREIGN_LOGO_SVG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><defs><linearGradient id="sg" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#8b5cf6"/><stop offset="100%" stop-color="#5b21b6"/></linearGradient></defs><rect width="40" height="40" rx="8" fill="#1a1a1a"/><path d="M20 7 l10 4 v7 c0 6 -4 11 -10 14 c-6 -3 -10 -8 -10 -14 v-7 z" fill="none" stroke="url(#sg)" stroke-width="2.2" stroke-linejoin="round"/><path d="M16 20 l3 3 l6 -7" fill="none" stroke="url(#sg)" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"/></svg>');
const LETTER_LOGO_SVG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><defs><linearGradient id="lgt" x1="4" y1="2" x2="44" y2="46" gradientUnits="userSpaceOnUse"><stop stop-color="#ffb15c"/><stop offset="0.45" stop-color="#ff7a00"/><stop offset="1" stop-color="#b53e00"/></linearGradient><linearGradient id="lgs" x1="20" y1="22" x2="28" y2="30" gradientUnits="userSpaceOnUse"><stop stop-color="#ffb15c"/><stop offset="1" stop-color="#c44d00"/></linearGradient></defs><rect x="2" y="2" width="44" height="44" rx="13" fill="url(#lgt)"/><rect x="2.75" y="2.75" width="42.5" height="42.5" rx="12.25" fill="none" stroke="#fff" stroke-opacity="0.22" stroke-width="1.5"/><rect x="12" y="15.5" width="24" height="18" rx="3.4" fill="none" stroke="#fff" stroke-width="2.7"/><path d="M13.2 17.6 L24 26 L34.8 17.6" fill="none" stroke="#fff" stroke-width="2.7" stroke-linecap="round" stroke-linejoin="round"/><circle cx="24" cy="26" r="4.2" fill="#fff"/><circle cx="24" cy="26" r="2.5" fill="url(#lgs)"/></svg>');
const FAUCET_LOGO_SVG = 'data:image/svg+xml;utf8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 40 40"><defs><linearGradient id="fcl" x1="0" y1="0" x2="1" y2="1"><stop offset="0%" stop-color="#3ddc84"/><stop offset="100%" stop-color="#16a34a"/></linearGradient></defs><rect width="40" height="40" rx="8" fill="#1a1a1a"/><path d="M14 11 h12 v4 l-4 4 v6 a2 2 0 0 1 -4 0 v-6 l-4 -4 z" fill="none" stroke="url(#fcl)" stroke-width="2.1" stroke-linejoin="round"/><circle cx="20" cy="31" r="1.7" fill="url(#fcl)"/></svg>');
const LAUNCHPAD_APPS = [
  { id: 'ion-swap', site: 'ionswap-monerousd-org', url: 'https://ion.monerousd.org', logo: ION_LOGO_SVG, name: 'Ion Swap', verified: true,
    blurb: 'Swap coins, trade tokens, turn a photo into an NFT collection · private by default', tags: ['Swap', 'Tokens', 'NFTs'] },
  { id: 'explorer', site: 'explorer-monerousd-org', url: 'https://explorer.monerousd.org', logo: EXPLORER_LOGO_SVG, name: 'Block Explorer', verified: true,
    blurb: 'Inspect blocks, txes, and tokens on the MoneroUSD chain', tags: ['Data', 'Tools'] },
  { id: 'monerousd-org', site: 'monerousd-org', url: 'https://monerousd.org', logo: MONEROUSD_ORG_LOGO_SVG, name: 'MoneroUSD.org', verified: true,
    blurb: 'The privacy stablecoin — whitepaper, mining, reserves, download', tags: ['Docs', 'Home'] },
  { id: 'monerousd-ide', site: 'ide-monerousd-org', url: 'https://ide.monerousd.org', logo: IDE_LOGO_SVG, name: 'MoneroUSD IDE', verified: true,
    blurb: 'Build dark contracts. Publish sovereign sites. Strengthen the peg.', tags: ['Dev tools', 'DSOL', 'Publish'] },
  { id: 'letter', site: 'letter-monerousd-org', url: 'https://letter.monerousd.org', verified: true, name: 'Letter', logo: LETTER_LOGO_SVG,
    blurb: 'Send a letter — 100% private P2P messaging, PQ-sealed end-to-end, zero metadata', tags: ['Messaging', 'Private', 'PQ'] },
  { id: 'faucet', site: 'faucet-monerousd-org', url: 'https://faucet.monerousd.org', verified: true, name: 'Testnet Tap', logo: FAUCET_LOGO_SVG, testnetOnly: true,
    blurb: 'Get free testnet USDm sent to any wallet address — testnet-only, no node or funding needed', tags: ['Dev tools', 'Testnet', 'Faucet'] },
  { id: 'sovereign', site: null, url: null, native: true, logo: SOVEREIGN_LOGO_SVG, name: 'Sovereign', verified: true,
    blurb: 'Open and publish .mud sites nobody can take down, served by your own node. Drop a folder to go live.', tags: ['Publish', 'Browse', 'Veil'] },
];
const _lpState = { sovereign: false };            // false = clearnet (normal domain); true = node-served mirror
function sovUrl(app) { return SOVEREIGN_BASE + '/' + app.site + '/'; }
// ⛔⛔⛔ THE NODE IS THE BACKEND — a dApp we host locally is NEVER fetched over clearnet.
//
// Every tile resolved to `app.url` (a public https:// domain) unless the user had manually flipped the
// Sovereign Hosting toggle. So the default path for the testnet faucet was an outbound clearnet request to
// faucet.monerousd.org: it broke the onion-only rule the whole transport is built on, made an in-wallet tile
// depend on a host we do not control, and left the tile dead whenever that host was unreachable — which read
// as "the faucet is broken" while the faucet itself was fine.
//
// If we ship the site (`app.site`), it is served by THIS user's own node on loopback. `app.url` remains only
// for tiles we do not host, and the toggle now only affects those.
function appUrl(app) { return app.site ? sovUrl(app) : app.url; }
function normBrowserUrl(v) {
  v = (v || '').trim();
  if (!v) return '';
  // TWO-PARTY-REVIEWED: this only reads the address the user typed; no second party is involved.
  // A MonerousD Veil site: `name.mud` or `name.mud/page` is served by this wallet's own node, every byte checked
  // against the root the chain anchors for that name. Nothing leaves the machine to find out whose site it is.
  const mud = /^([a-z0-9_-]+)\.mud(\/.*)?$/i.exec(v.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ''));
  if (mud) return veilBase() + '/mud/' + mud[1].toLowerCase() + (mud[2] || '/');
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) return v;
  if (/^(localhost|127\.|\[::1\]|0\.0\.0\.0)/i.test(v)) return 'http://' + v;
  return 'https://' + v;
}
// Open a clearnet url as the real domain — Tauri opener/shell if present, else a new browser context.
function openExternal(url) {
  try {
    const T = window.__TAURI__;
    if (T && T.opener && T.opener.openUrl) { T.opener.openUrl(url); return; }
    if (T && T.shell && T.shell.open) { T.shell.open(url); return; }
    if (T && T.core && T.core.invoke) { T.core.invoke('plugin:opener|open_url', { url }); return; }
  } catch (e) { void e; }
  window.open(url, '_blank', 'noreferrer');
}
function browserViewportEl() { return document.getElementById('browserViewport'); }

// ── EMBEDDED dApp WEBVIEW bridge ───────────────────────────────────────────────────────────────────────────
// Each launchpad app renders in a REAL Tauri child webview (a TOP-LEVEL browsing context, exactly like the old
// Electron <webview>) — NOT an <iframe>. `dapp_show/navigate/bounds/hide` are Rust commands; the webview floats
// over #browserViewport at the rect we report, and re-syncs on resize / when returning to the Browser tab. This
// is why the sovereign node's CSP `frame-ancestors 'none'` (kept for privacy) no longer blanks the app: a
// webview is not a nested frame. Both networks embed here — sovereign (127.0.0.1:27752/<site>/) AND the real
// clearnet subdomain (ion.monerousd.org …); the shield toggles which.
// `nav` is what the open app last reported about its OWN pages (`monerousd:navstate`, sites' lib/wallet-nav.js): how many
// steps back it can take and how many forward. null = the page in the frame has not reported (it does not carry the script).
const _dapp = { url: null, history: [], pos: -1, nav: null, fromSovereign: false, page: { depth: 0, top: 0, len: 0, step: 0, loaded: false } };  // current app URL (null on the grid) + a wallet-level nav stack.
function _tauriInvoke(cmd, args) {
  try {
    const T = window.__TAURI__;
    if (T && T.core && T.core.invoke) return T.core.invoke(cmd, args || {});
  } catch (e) { void e; }
  return null;                 // non-Tauri context (e.g. a plain-browser harness) — no embedded webview.
}

// ── Node-first dApp provider bridge ─────────────────────────────────────────────
// A launchpad app framed in the Browser tab (clearnet ion.monerousd.org, explorer,
// ide, …) is a FOREIGN origin — the parent can't staple `window.monerousd` onto it.
// So we speak the MetaMask-style postMessage protocol: the framed page posts
// {type:'monerousd:rpc', id, method, params} and the wallet ANSWERS it against the
// LOCAL NODE. This is what makes "the clearnet backend = the blockchain": the VPS
// ships only the static frontend bytes at the domain; every balance / price / pool /
// token / swap / connect call is serviced here by the chain, never the VPS. The
// wallet stays the gatekeeper — a spend routes through dapp_provider_transfer, which
// clears the wallet's own auth gate, so a remote page can never move funds silently.
function _isDappOrigin(origin) {
  if (!origin) return false;
  try {
    const h = new URL(origin).hostname;
    // ⛔ DB-373: ONLY this user's own node serves the apps the bridge answers (every launchpad tile names a `site` the
    // node serves on loopback). A clearnet `*.monerousd.org` origin was trusted here, so any page served from — or a DNS
    // hijack of — any such host could call the wallet bridge.
    return h === '127.0.0.1' || h === 'localhost' || h === '[::1]';
  } catch (e) { console.debug('[dapp-bridge] bad origin', origin, e); return false; }
}
// ── SAFE BROWSING ON THE VEIL (user 2026-11-12: "Add some securities to browsing so browsing doesnt open you up to
// losing your funds or getting your computer hacked. The goal is safe private browsing.") ──────────────────────────
// A `.mud` site is anyone's code, served from the same loopback address as this wallet's own apps. The wallet treats it
// as a stranger: (1) its frame is sandboxed (an opaque origin of its own: no app's or other site's storage, no
// camera, microphone, payment or clipboard, no popups, no downloads, and it cannot navigate this window); (2) the
// bridge answers it as THAT NAMED SITE, not as one of the wallet's apps: it may read public chain facts; it sees this
// wallet's address or balance only after the person allows that site by name, for this visit; it may ASK for a
// payment, which the person approves or not, naming the site and the amount; everything else an app may do (letters,
// swaps, names, tokens, app back ends) is refused to it. The node serves its pages under a matching policy
// (`sovereign.rs`, `veil_csp`: nothing sent anywhere, code only from the site's own path, programs served as text).
// Nothing a page says can make the wallet pay, sign, reveal or install: every one of those is a sheet the person
// answers, and the wallet never asks for recovery words.
// Where `.mud` pages are served: inside the app, by the wallet core's own `veil:` scheme on every device (desktop and
// phone alike, `src-tauri/src/veil_site.rs` serve_scheme); outside it (a browser preview), by the node's site host.
let _veilBase = null;
function veilBase() {
  if (_veilBase) return _veilBase;
  try {
    const T = window.__TAURI__;
    if (T && T.core && typeof T.core.convertFileSrc === 'function') _veilBase = T.core.convertFileSrc('', 'veil').replace(/\/+$/, '');
  } catch (_) { /* not inside the app */ }
  return _veilBase || SOVEREIGN_BASE;
}
window.veilBase = veilBase;
function _veilOf(url) {
  const u = String(url || '');
  for (const base of [veilBase(), SOVEREIGN_BASE]) {
    if (u.indexOf(base + '/mud/') !== 0) continue;
    const m = /^([a-z0-9_-]+)(\/|$)/i.exec(u.slice(base.length + 5));
    if (m) return m[1].toLowerCase();
  }
  return null;
}
const _veilGrants = new Map();   // site name → true once the person let it see this wallet's address, this run only
const VEIL_READS = new Set(['getNetwork', 'getHeight', 'qrSvg']);
const VEIL_IDENTITY = new Set(['connect', 'getAddress', 'listAddresses', 'getBalance', 'newAddress']);
async function _veilSiteCall(name, method, p) {
  const site = name + '.mud';
  if (VEIL_READS.has(method)) return _dappProviderCall(method, p);
  if (VEIL_IDENTITY.has(method) || method === 'transfer' || method === 'signAndBroadcast') {
    if (!_veilGrants.get(name)) {
      const yes = await confirmCost({ title: site + ' wants to see your address and balance', confirmLabel: 'Allow for this visit',
        lines: [{ label: 'Cost', usd: 0, detail: 'nothing is spent' }],
        warning: site + ' is a site on the Veil, not one of your wallet\'s own apps. A site that knows your address can recognise you when it sees it again.' });
      if (!yes) throw new Error('USER_DECLINED: the user did not allow ' + site);
      _veilGrants.set(name, true);
    }
    if (method === 'transfer' || method === 'signAndBroadcast') {
      const amt = Number(p.amount != null ? p.amount : p.amountUsdm);
      if (!(amt > 0) || !p.to) throw new Error('BAD_REQUEST: a payment names an amount and an address');
      if (!(await confirmCost({ title: site + ' asks you to send ' + usdText(amt), confirmLabel: 'Send',
        lines: [{ label: 'You send', usd: amt, detail: String(amt) + ' USDm to ' + String(p.to).slice(0, 18) + '…' }, feeLine()],
        warning: WARN_IRREVERSIBLE + ' This request comes from ' + site + ', a site on the Veil. Only send if you meant to pay this site.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_transfer', { to: p.to, amountUsdm: amt });
    }
    return _dappProviderCall(method, p);
  }
  // ⭐ ITS OWN BACK END (Veil spec §12): the contract the site's `veil.json` binds, and only that one. A read is answered
  // from the back end's state as this wallet reads it from its own node (checked against the chain); a write is a call
  // the person approves in dollars; a person's own data is sealed by their wallet before it is written.
  const toHex = (t) => Array.from(new TextEncoder().encode(String(t))).map(b => b.toString(16).padStart(2, '0')).join('');
  if (method === 'backendRead') return _tauriInvoke('veil_backend_read', { name, keys: Array.isArray(p.keys) ? p.keys.slice(0, 256) : [] });
  if (method === 'seal') return _tauriInvoke('veil_seal', { name, text: String(p.text == null ? '' : p.text) });
  if (method === 'open') return _tauriInvoke('veil_open', { name, sealed: String(p.sealed || '') });
  if (method === 'backendCall') {
    const entry = String(p.entrypoint || '').slice(0, 64);
    if (!entry) throw new Error('BAD_REQUEST: a back-end call names an entrypoint');
    const argvHex = p.argvHex != null ? String(p.argvHex) : toHex(p.argv == null ? '' : p.argv);
    if (argvHex.length > 8192) throw new Error('BAD_REQUEST: a back-end call carries at most 4096 bytes');
    const price = await _tauriInvoke('veil_backend_price', { name });
    const fee = Math.max(0, Number(price && price.publisher_fee_atomic) || 0) / 1e8;
    if (!(await confirmCost({ title: site + ' asks to save this (' + entry + ')', confirmLabel: 'Save',
      lines: [{ label: 'Back-end fee (to its publisher, ' + String(price && price.cid || '').slice(0, 10) + '…)', usd: fee, cost: true }, feeLine()],
      warning: 'This writes to ' + site + '\'s back end on the chain. What it keeps is hidden from the chain; everyone this site serves can read what is not sealed to you. The fee is paid only if the chain accepts it.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
    return _tauriInvoke('veil_backend_call', { name, entrypoint: entry, argvHex });
  }
  throw new Error('REFUSED: ' + site + ' is a site on the Veil. It may read the chain and its own back end, ask to see your address, and ask you to approve a payment or a write to its back end; nothing else.');
}
// App-backend proxy to the node's SOVEREIGN server (:27752) — the surface that serves the apps'
// /api/config, /api/prices, /api/tokens, /rpc/… routes with real node logic. The tx-node (:27780,
// nodeRpc) serves get_height/submit. BOTH are THIS wallet's own co-located node → the app's backend
// IS the chain, zero VPS. In Tauri → the Rust dapp_provider_api proxy (loopback, no CORS); else fetch.
async function sovApi(path, body) {
  if (IN_TAURI) return _tauriInvoke('dapp_provider_api', { path, body: body || '' });
  const res = await fetch(SOVEREIGN_BASE + path, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'content-type': 'application/json' } : undefined,
    body: body || undefined,
  });
  return res.json();
}
// Map one provider method → a node-backed result. Reads hit the node RPC; a spend
// clears the wallet auth gate inside dapp_provider_transfer.
async function _dappProviderCall(method, params, ctx) {
  const p = params || {};
  const site = ctx && ctx.site ? ctx.site : ''; // set only for a request a WEBSITE made through the connect door
  switch (method) {
    // Wallet-scoped reads (address / balance) are self-custodial: they come from THIS wallet's own keystore,
    // never a node route (the node must never vend "the wallet's address"). In Tauri that's the dapp_provider_*
    // command; outside Tauri walletCore() throws DESKTOP_ONLY — the same clean signal the Receive page uses —
    // so a framed app gets a structured "open the desktop app" reply, never a raw "Failed to fetch" on a route
    // the node was never meant to serve.
    case 'connect':
    case 'getAddress': return IN_TAURI ? _tauriInvoke('dapp_provider_connect') : walletCore('wallet_address');
    case 'listAddresses': {   // portfolio/balance aggregation asks for every subaddress; return the connected one in the expected shape
      const c = await (IN_TAURI ? _tauriInvoke('dapp_provider_connect') : walletCore('wallet_address'));
      const addr = c && (c.address || (Array.isArray(c.addresses) && c.addresses[0]));
      return { addresses: addr ? [{ address: addr, index: 0, is_main: true }] : [] };
    }
    case 'getBalance': return IN_TAURI ? _tauriInvoke('dapp_provider_balance') : walletCore('wallet_balance');
    // A FRESH receive address (the Receive page's rotation) for an app that files payments per address (USDm Pay
    // cards); consent-gated like getAddress.
    case 'newAddress': {
      // A website never learns an address by connecting: it asks, and its user decides here, knowing what an address gives away.
      if (site && !(await confirmCost({ title: site + ' asks for a receive address', confirmLabel: 'Share an address',
        lines: [{ label: 'Cost', usd: 0, detail: 'nothing is spent' }],
        warning: 'With an address the site can pay you, and it can recognise this address if it sees it again. Share one only if you asked the site to pay you.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      if (site) return _tauriInvoke('web3_site_address', { origin: site }); // the core asks again, naming this site
      return IN_TAURI ? _tauriInvoke('dapp_provider_new_address') : walletCore('wallet_new_address');
    }
    // Staking reward claim — the wallet's own approval-gated claim (it states the paused reason while the stake
    // door is refused); never a node route.
    case 'claimStakeReward': {
      if (!(await confirmCost({ title: 'An app asks to harvest your stake reward', confirmLabel: 'Harvest', lines: [{ label: 'Network fee', usd: 0, detail: 'no USDm is spent' }],
        warning: 'Harvesting publishes a transaction from your staked notes; your principal stays staked. Only confirm if you started this in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return IN_TAURI ? _tauriInvoke('wallet_claim_stake_reward') : walletCore('wallet_claim_stake_reward');
    }
    case 'getNetwork': return IN_TAURI ? _tauriInvoke('dapp_provider_network') : { network: state.net };
    case 'getHeight':  return IN_TAURI ? _tauriInvoke('dapp_provider_height')  : nodeRpc('/get_height');
    // A QR of PUBLIC data (an app's deposit address), drawn by the wallet's own encoder so no app loads a third-party
    // script from a clearnet CDN to draw one (hole scanner 2026-10-03: Ion Swap imported qrcode from esm.sh).
    case 'qrSvg':      return walletCore('wallet_qr_svg', { data: String((p && p.data) || '').slice(0, 1024) });
    case 'request':                      // generic chain-data read (blocks, tokens, pools, prices, swaps)
    case 'nodeRpc': {
      const path = p.path || '';
      // App-backend routes (/api,/v1,/rpc) → the node's sovereign server (:27752); everything else
      // (get_height, submit, wallet reads) → the tx-node (:27780). Both are the wallet's own node.
      if (/^\/(testnet\/|mainnet\/)?(api|v1|rpc)(\/|$|\?)/.test(path)) return sovApi(path, p.body || '');
      return IN_TAURI ? _tauriInvoke('dapp_provider_node_rpc', { path, body: p.body || '' }) : nodeRpc(path, p.body || null);
    }
    case 'daemonRpc': {   // the explorer SPA speaks Monero-style JSON-RPC; translate each method → the O(1) node's real endpoints
      const m = p.method, prm = p.params || {};
      if (m === 'get_info') return nodeRpc('/get_info');
      if (m === 'get_block_count') { const h = await nodeRpc('/get_height'); const n = h && (h.height != null ? h.height : h.count); return { count: Number(n || 0), status: 'OK' }; }
      // Block-body / tx methods (get_block, get_transactions, get_recent_blocks) ride the node's /json_rpc shim,
      // which serves recent DAG headers + tx blobs from live node state (history beyond the window lives in the indexer).
      const body = { jsonrpc: '2.0', id: '0', method: m, params: prm };
      return nodeRpc('/json_rpc', body);
    }
    case 'transfer':
    case 'signAndBroadcast': {
      const amt = Number(p.amount != null ? p.amount : p.amountUsdm);
      if (!(await confirmCost({ title: 'An app asks you to send ' + (amt > 0 ? usdText(amt) : 'USDm'), confirmLabel: 'Send',
        lines: [{ label: 'You send', usd: amt > 0 ? amt : null, detail: String(amt) + ' USDm to ' + String(p.to || '').slice(0, 18) + '…' }, feeLine()],
        warning: WARN_IRREVERSIBLE + ' Only confirm if you started this payment in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_transfer', { to: p.to, amountUsdm: p.amount != null ? p.amount : p.amountUsdm });
    }
    // ── LETTER — self-custodial private messaging. Seal/open run in THIS wallet (never the framed page); the
    // node only relays the opaque sealed blob mesh-wide. One identity for money AND messages (the wallet addr).
    // DEAD-WIRING FIX 2026-09-06: the non-Tauri arms named wallet_letter_* commands that are registered
    // NOWHERE in the core (phantom symbols). Behaviour is unchanged — walletCore throws DESKTOP_ONLY
    // before any invoke when !IN_TAURI — but a reference must resolve to a REAL registered command
    // (no-dead-buttons static standard), so both arms now name the same registered dapp_provider_* cmds.
    case 'letterAddress': return IN_TAURI ? _tauriInvoke('dapp_provider_letter_address') : walletCore('dapp_provider_letter_address');
    case 'letterSend':    return IN_TAURI ? _tauriInvoke('dapp_provider_letter_send', { to: p.to, msg: p.msg }) : walletCore('dapp_provider_letter_send', { to: p.to, msg: p.msg });
    case 'letterInbox':   return IN_TAURI ? _tauriInvoke('dapp_provider_letter_inbox') : walletCore('dapp_provider_letter_inbox');
    case 'letterHistory': return _tauriInvoke('dapp_provider_letter_history', { from: p.from || 0 }); // page the ON-CHAIN chat history (seed-restore walk)
    // ON-CHAIN @username / group-handle sign-up and the profile (display, bio, letter fee, picture), wallet-signed. Each is
    // a PAID directory entry: the chain keeps it on every node, so it is priced by its size. THIS wallet reads the chain's
    // price from its core and shows it in dollars in its own sheet before the app's request goes any further.
    case 'dirRegister': {
      const what = p.kindGroup ? 'group' : 'name';
      const shown = (p.kindGroup ? 'the group handle ' : '@') + String(p.key || '');
      const price = await walletCore('wallet_dir_price', { what, key: String(p.key || ''), display: p.display || '', topic: p.topic || '' });
      if (!(await confirmCost({ title: 'Publish ' + shown, confirmLabel: 'Publish',
        lines: [{ label: 'Chain fee to publish it', usd: Number(price.usd), cost: true, detail: 'paid once, for the space it takes on every node' }, { label: 'Network fee', usd: Number(price.network_fee_usd), cost: true }],
        warning: shown + ' is published to the chain for everyone to read and cannot be made private again. If it is already taken you are not charged; if someone else\'s claim for the same name lands in the same few seconds and wins, this fee is still spent. Only confirm if you started this in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_dir_register', { kindGroup: !!p.kindGroup, key: p.key, display: p.display || '', topic: p.topic || '' });
    }
    case 'profileSet': {
      const feeMicro = Math.max(0, Math.round(Number(p.feeMicro) || 0));
      const avatar = p.avatar || '';
      // the same packing the core signs (bio, letter fee, picture), so the price shown is the price of what is published
      const topic = (p.bio || '') + '\u001f' + feeMicro + (avatar ? '\u001f' + avatar : '');
      const price = await walletCore('wallet_dir_price', { what: 'profile', key: '', display: p.display || '', topic });
      if (!(await confirmCost({ title: 'Publish your profile', confirmLabel: 'Publish',
        lines: [{ label: 'Chain fee to publish it', usd: Number(price.usd), cost: true, detail: (avatar ? 'with your picture: ' : '') + 'paid once, for the space it takes on every node' }, { label: 'Network fee', usd: Number(price.network_fee_usd), cost: true }],
        warning: 'Your name, bio' + (avatar ? ', picture' : '') + ' and letter fee are published to the chain for everyone to read and cannot be made private again. Only confirm if you started this in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_profile_set', { display: p.display || '', bio: p.bio || '', feeMicro, avatar });
    }
    case 'profileGet':    return _tauriInvoke('dapp_provider_profile_get', { address: p.address }); // any address → its published profile (mesh-raced)
    case 'noteOwned':     return _tauriInvoke('dapp_provider_note_owned', { cm: p.cm });
    // ── IONSWAP — NATIVE ASSET SWAPS (user 2026-11-10). The app shows; THIS wallet prices, asks in its own sheet
    //    (every cost in dollars, drawn above the app, which can neither draw it nor press it) and acts through the same
    //    commands its own Buy / Sell page uses. Auto-OPSEC is the wallet's one setting: the app reads it, and turning it
    //    off goes through the wallet's own warning.
    case 'nativeAssets':
    case 'nativeSwap':
    case 'nativeProgress':
    case 'autoOpsec':
    case 'setAutoOpsec':  return _nativeSwapCall(method, p);
    // ── IONSWAP — TOKENS AND NFTs (2026-11-10): create one, name one from its creator's card, see what this wallet
    //    holds, send one. The app asks; THIS wallet prices the action in dollars in its own sheet and acts.
    case 'assets': {       // what this wallet holds in atomic units, each with the name its verified card gives it
      // a website's holdings answer rests on THAT site's own grant (the core checks it); an app in this wallet's own
      // browser rests on the app-wide consent
      const b = await (site ? _tauriInvoke('web3_site_balance', { origin: site }) : IN_TAURI ? _tauriInvoke('dapp_provider_balance') : walletCore('wallet_balance'));
      const atomic = (b && b.assets_atomic) || {};
      const cards = assetCards();
      const tags = Array.from(new Set(Object.keys(atomic).concat(Object.keys(cards))));
      // an asset no card names is named by the chain's own record, read from this wallet's own node by the tag its
      // notes carry (the creation wrote the record on every node), so a token or an NFT that simply arrives has its
      // name with no card handed over
      const onChain = {};
      await Promise.all(tags.map(async (t) => {
        const known = t === USDM_ASSET_TAG_HEX || (window.__ASSET_SYMBOLS || {})[t] || cards[String(t).toLowerCase()];
        if (!known) onChain[t] = await chainAssetRecord(t);
      }));
      return { assets: tags.map((t) => {
        const c = cards[String(t).toLowerCase()] || onChain[t];
        const core = t === USDM_ASSET_TAG_HEX ? 'USDm' : (window.__ASSET_SYMBOLS || {})[t];
        return { tag: t, atomic: Number(atomic[t] || 0), symbol: core || (c && c.symbol) || null,
          name: core ? (core === 'USDm' ? 'MoneroUSD' : core) : ((c && c.name) || null),
          kind: core ? 'coin' : ((c && c.kind) || 'unknown'), card: (c && c.card) || null,
          id: (c && c.id) || null, collection: (c && c.collection) || '', pool: (c && c.pool) || '',
          lock_week: (c && c.lock_week) || 0, unlock_secs: (c && c.unlock_secs) || 0 };
      }) };
    }
    case 'assetCard':     return rememberAssetCard(p.card);
    case 'createFee': {    // the chain's price for creating this symbol, from this wallet's own node
      const sym = String(p.symbol || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
      // `artBytes`: the size of the picture the creation will put on the chain (its kilobytes are part of the price)
      return sovApi('/api/tokens/create_fee?symbol=' + encodeURIComponent(sym) + '&kind=' + (p.kind === 'nft' ? 'nft' : 'token') + '&art_bytes=' + Math.max(0, Math.floor(Number(p.artBytes) || 0)));
    }
    case 'createToken': {
      const kind = p.kind === 'nft' ? 'nft' : 'token';
      const symbol = String(p.symbol || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 32);
      const name = String(p.name || '').trim().slice(0, 128);
      if (!symbol || !name) throw new Error('A symbol and a name are needed. Nothing was created.');
      const whole = Math.floor(Number(p.supply));
      if (kind === 'token' && !(whole >= 1)) throw new Error('The supply must be at least 1. Nothing was created.');
      // the picture goes on the chain with the creation, so its size is part of the price the chain states
      const artBytes = Math.floor(String(p.artHex || '').length / 2);
      const q = await sovApi('/api/tokens/create_fee?symbol=' + encodeURIComponent(symbol) + '&kind=' + kind + '&art_bytes=' + artBytes);
      const price = Number(q && q.fee_atomic) / 1e8;
      if (!(price >= 0) || !isFinite(price)) throw new Error('Your node did not state the creation price. Nothing was created.');
      if (artBytes && q.art_max_bytes && artBytes > Number(q.art_max_bytes)) throw new Error('The picture must be at most ' + Math.floor(Number(q.art_max_bytes) / 1024) + ' KB to be kept on the chain. Nothing was created.');
      const collection = String(p.collection || '').trim().toLowerCase();
      if (!(await confirmCost({ title: 'An app asks to create ' + (kind === 'nft' ? 'the NFT ' : 'the token ') + symbol + ' ("' + name + '")', confirmLabel: 'Create',
        lines: [{ label: 'Creation price', usd: price, cost: true, detail: 'set by the chain; it goes into the chain\'s pools, not to the app' + (artBytes ? '. It includes keeping the ' + Math.ceil(artBytes / 1024) + ' KB picture on the chain' : '') },
          ...(collection ? [{ label: 'Filed under', usd: null, detail: 'your collection ' + collection }] : []),
          { label: kind === 'nft' ? 'You receive' : 'You receive the whole supply', usd: null, detail: kind === 'nft' ? 'one NFT, the only one there will ever be' : whole.toLocaleString() + ' ' + symbol + ', fixed for ever: nobody can create more' },
          feeLine()],
        warning: WARN_IRREVERSIBLE + ' The creation price is not refunded. Only confirm if you started this in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      // `artHex`: the asset's own picture. The core checks it, binds its digest into the asset, and returns a card that carries it.
      const made = await _tauriInvoke('dapp_provider_create_token', { params: { name, symbol, maxSupply: kind === 'nft' ? '1' : String(whole), decimals: 8, kind, logoDigestHex: p.logoDigestHex || undefined, artHex: p.artHex || undefined, collection: collection || undefined } });
      if (made && made.card) { try { await rememberAssetCard(made.card); } catch (_) { /* created all the same; its card is in the reply */ } }
      return made;
    }
    // The card (and so the tag) of an asset THIS wallet made or would make, from its facts and picture. Nothing is created.
    case 'cardFor':       return _tauriInvoke('dapp_provider_card_for', { params: { kind: p.kind === 'nft' ? 'nft' : 'token', symbol: String(p.symbol || ''), name: String(p.name || ''), artHex: p.artHex || undefined } });
    // ⭐ A WHOLE NFT COLLECTION WITH ONE APPROVAL. The wallet prices every NFT from the chain's own rule, shows the count
    //    and the total in dollars once, and then makes them one after another; the app reads `collectionProgress`.
    case 'createCollection': {
      const items = (Array.isArray(p.items) ? p.items : []).map((it) => ({
        symbol: String((it && it.symbol) || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 32),
        name: String((it && it.name) || '').trim().slice(0, 128),
        artHex: String((it && it.artHex) || ''),
      }));
      if (!items.length || items.some((it) => !it.symbol || !it.name || !it.artHex)) throw new Error('Every NFT needs a symbol, a name and a picture. Nothing was created.');
      // the collection itself, when the app names one: its handle, title, words and cover go on the chain
      const handle = String(p.handle || '').trim().toLowerCase();
      const params = handle
        ? { items, handle, title: String(p.title || '').trim().slice(0, 64), text: String(p.text || '').trim().slice(0, 1024), coverHex: String(p.coverHex || '') }
        : { items };
      // ONE question to the wallet's own core: what this whole request will do and cost, from the chain's own price
      // functions (each picture's size, and the collection's entry when it is not on the chain yet). The job that runs
      // after the confirmation reads the same plan, so what is shown here is what is charged.
      const q = await _tauriInvoke('dapp_provider_collection_quote', { params });
      const nfts = Number(q && q.nft_price_atomic) / 1e8, col = Number(q && q.collection_price_atomic) / 1e8;
      if (!isFinite(nfts) || !isFinite(col)) throw new Error('Your wallet could not price this collection. Nothing was created.');
      const steps = items.length + (q.publish_collection ? 1 : 0);
      if (!(await confirmCost({ title: 'An app asks to create ' + items.length + ' NFT' + (items.length === 1 ? '' : 's') + (handle ? ' in the collection ' + handle : ''), confirmLabel: 'Create them',
        lines: [{ label: 'Creation price, ' + items.length + ' NFT' + (items.length === 1 ? '' : 's'), usd: nfts, cost: true, detail: 'set by the chain; it goes into the chain\'s pools, not to the app. It includes keeping ' + Math.ceil(Number(q.picture_bytes || 0) / 1024) + ' KB of pictures on the chain' },
          ...(q.publish_collection ? [{ label: 'Publishing the collection ' + handle, usd: col, cost: true, detail: 'its handle, title and cover, kept on the chain; the handle is yours from then on' }]
            : handle ? [{ label: 'Filed under', usd: null, detail: 'your collection ' + handle + ', already on the chain' }] : []),
          { label: 'You receive', usd: null, detail: items.length + ' NFT' + (items.length === 1 ? '' : 's') + ', each the only one of its kind, made one after another' },
          feeLine(steps)],
        warning: WARN_IRREVERSIBLE + ' The creation price is not refunded. Keep the wallet open until all of them are made; closing it makes no more and loses none. Only confirm if you started this in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_create_collection', { params });
    }
    case 'collectionProgress': return _tauriInvoke('dapp_provider_collection_progress');
    case 'sendAsset': {
      const tag = String(p.asset || '').toLowerCase();
      const atomic = Math.max(0, Math.round(Number(p.atomic) || 0));
      if (!atomic || !p.to) throw new Error('An amount and a recipient are needed. Nothing was sent.');
      // `to: 'self'`: a note of exactly this size, cut by sending it to this wallet's own address (how an order's lot is
      // set aside). The wallet fills its own address in, so a page never needs to be told one.
      const toSelf = String(p.to).trim() === 'self';
      const to = toSelf ? String(((await walletCore('wallet_address')) || {}).address || '') : String(p.to).trim();
      if (!to) throw new Error('This wallet could not read its own address. Nothing was sent.');
      if (!(await confirmCost({ title: toSelf ? 'An app asks to set aside ' + assetAmountText(tag, atomic) + ' in this wallet' : 'An app asks you to send ' + assetAmountText(tag, atomic), confirmLabel: toSelf ? 'Set aside' : 'Send',
        lines: [{ label: toSelf ? 'You keep' : 'You send', usd: null, detail: assetAmountText(tag, atomic) + (toSelf ? ', as one note in this wallet' : ' to ' + to.slice(0, 18) + '…') }, feeLine()],
        warning: (toSelf ? 'Nothing leaves this wallet: the amount becomes one note of its own, ready to be listed.' : WARN_IRREVERSIBLE) + ' Only confirm if you started this in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_send_asset', { to, assetTagHex: tag, atomic });
    }
    // The keyless SAT pools' PUBLISHED line and nothing else: one price per pair per batch and when the open batch
    // closes (the DeFi layer's closed list). Never depth, volume, an order or a fill.
    case 'nativePools': {
      const pools = [];
      await loadBridgeCoins(); // one keyless SAT pool per coin the bridge holds (the chain's one table)
      for (const coin of BRIDGE_COINS.map((c) => c.sym)) {
        try {
          const b = await walletCore('wallet_defi_book', { coin, quote_coin: 0, quote_sat: 0 });
          const h = await walletCore('wallet_defi_prices', { coin, range_secs: 86400 });
          pools.push({ coin, open: !!b.open, taking_orders: !!b.taking_orders, price_coin_per_sat: b.price_coin_per_sat,
            closes_in_blocks: b.closes_in_blocks, donation_sat: b.launch_donation_sat, points: (h && h.points) || [] });
        } catch (e) { pools.push({ coin, error: String((e && e.message) || e) }); }
      }
      return { pools };
    }
    // ── IONSWAP — the DEX surface. A framed page NEVER holds a key or builds a proof: it asks for a
    //    quote or a fill, and every proof is built in THIS wallet from notes this wallet owns.
    //    `swapQuote` is read-only (nothing is built or spent) so a page may poll it as the user types.
    case 'swapQuote':     return _tauriInvoke('dapp_provider_swap_quote', {
                            assetAHex: p.assetA, assetBHex: p.assetB,
                            budget: Math.max(0, Math.round(Number(p.budget) || 0)),
                            fromLevel: p.fromLevel != null ? Number(p.fromLevel) : null,
                            span: p.span != null ? Number(p.span) : null });
    // ⛔ minOut IS THE USER'S FLOOR and the wallet re-checks it against a FRESHLY read book before
    //    building anything — a quote the page is showing may be seconds stale, and a plan that no longer
    //    clears the floor is REFUSED rather than filled at whatever the book now offers.
    // ⭐ §BR-12 F13 — A DSOL CONTRACT CALL FROM A LAUNCHPAD APP: the wallet shows the PUBLISHER FEE in dollars (the deployed
    //    manifest the app hands over) and the network fee BEFORE anything is paid. The core then verifies that manifest and
    //    the app's storage against the chain's contract-state root before it spends a note, so a false fee is refused by the
    //    node and nothing is paid: the user is never charged more than shown. Cancel tells the app the user declined. The call
    //    is proven by this wallet's own per-contract pseudonym and paid from this wallet's notes.
    case 'dsolCall': {
      const call = (p && p.call) || p;
      const feeAtomic = Math.max(0, Math.round(Number(call && call.manifest && call.manifest.publisher_fee_atomic) || 0));
      const cidShort = String((call && call.cid) || '').slice(0, 12);
      const what = call && call.entrypoint ? ' (' + String(call.entrypoint).slice(0, 32) + ')' : '';
      if (!(await confirmCost({ title: 'An app asks to call contract ' + cidShort + '…' + what, confirmLabel: 'Call',
        lines: [{ label: 'Publisher fee (set by the contract\'s publisher)', usd: feeAtomic / 1e8, cost: true }, feeLine()],
        warning: WARN_IRREVERSIBLE + ' The publisher fee is paid only if the chain accepts the call, and the wallet checks the fee against the chain before paying. Only confirm if you started this in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_dsol_call', { call });
    }
    case 'swapExecute': {
      // USDm is the one asset the wallet prices exactly ($1 floor, 1e8 atomic); any other leg says plainly it has no price.
      const legUsd = (hex, atomic) => (String(hex || '').toLowerCase() === USDM_ASSET_TAG_HEX ? Number(atomic) / 1e8 : null);
      // ⛔ THE SIDES are the core's (`quote_buy`): asset A is what the user RECEIVES, asset B is what the budget PAYS.
      //    FOUND 2026-11-10: this sheet named them the other way round, so a user buying a token with 2 USDm was shown
      //    "You pay 2 <token>, no dollar price" and "You receive 0.00000001 USDm". Every cost here is now the paid side's.
      if (!(await confirmCost({ title: 'An app asks to buy ' + assetLabel(p.assetA) + ' with ' + assetLabel(p.assetB), confirmLabel: 'Swap',
        lines: [{ label: 'You pay (at most)', usd: legUsd(p.assetB, p.budget), detail: assetAmountText(p.assetB, p.budget) },
          { label: 'You receive (at least)', usd: legUsd(p.assetA, p.minOut), detail: assetAmountText(p.assetA, p.minOut) },
          { label: 'Trading fee (about 0.10% of the fill)', usd: legUsd(p.assetB, Number(p.budget) * 0.001) },
          appFeeLine('Wallet fee (0.25%, at most)', legUsd(p.assetB, Number(p.budget) * 0.0025) != null ? legUsd(p.assetB, Number(p.budget) * 0.0025) : legUsd(p.assetA, Number(p.minOut) * 0.0025)),
          feeLine()],
        warning: WARN_IRREVERSIBLE + ' The fill never pays out less than the minimum shown. Only confirm if you started this swap in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_swap_execute', {
                            assetAHex: p.assetA, assetBHex: p.assetB,
                            budget: Math.max(0, Math.round(Number(p.budget) || 0)),
                            minOut: Math.max(0, Math.round(Number(p.minOut) || 0)),
                            fromLevel: p.fromLevel != null ? Number(p.fromLevel) : null,
                            span: p.span != null ? Number(p.span) : null });
    }
    // ── IONSWAP POOLS — pools people make. `ionPools` and `ionPool` read what every node publishes for a pool (its two
    //    balances, its share count, its price). `ionPosition` is THIS wallet's own notes, so the bridge answers it only
    //    under the site's "balances" grant. An order (add, remove, buy, sell) is shown here in dollars first; the core then
    //    asks this device's own approval and only then proves and sends. A page never holds a key or builds a proof.
    //    TWO-PARTY-REVIEWED: a handler of the wallet's page, not a test. What crosses a boundary here (a site's page to
    //    this wallet, this wallet to its node, that node to the other nodes) is exercised with the real wallet and
    //    real nodes by scratchpad/net/pool.py (an order placed on one node, held and paid on the others) and
    //    web3_connect.py (a site in an ordinary browser reaching these methods through the wallet's door).
    case 'ionPools':      return _tauriInvoke('dapp_provider_ion_pools', { q: String(p.q || '').slice(0, 64), skip: Math.max(0, Math.floor(Number(p.skip) || 0)), max: Math.max(1, Math.min(100, Math.floor(Number(p.max) || 50))) });
    case 'ionPool':       return _tauriInvoke('dapp_provider_ion_pool', { token: String(p.token || '').toLowerCase() });
    case 'ionPosition':   return _tauriInvoke('dapp_provider_ion_position', { token: String(p.token || '').toLowerCase() });
    // the pool orders this run of the wallet sent and what each was paid: this wallet's own notes (the "balances" grant)
    case 'ionOrders':     return _tauriInvoke('dapp_provider_ion_orders', {});
    case 'ionAdd':
    case 'ionRemove':
    case 'ionRemoveLocked':
    case 'ionLock':
    case 'ionUnlock':
    case 'ionBuy':
    case 'ionLaunch':
    case 'ionClaim':
    case 'ionSell': {
      const token = String(p.token || '').toLowerCase();
      // whole atomic units, exactly (a page sends decimal strings; a number this wide is never rounded through a float)
      const units = (v) => { const t = String(v == null ? '' : v).trim(); if (!/^\d{1,19}$/.test(t)) throw new Error('That amount does not read. Nothing was sent.'); return BigInt(t); };
      // handed to the core as decimal text and parsed there, exactly (a token's supply passes what a JavaScript number holds)
      const fits = (b) => { if (b > 18446744073709551615n) throw new Error('That amount is too large. Nothing was sent.'); return b.toString(); };
      // the pool's own words, read from this wallet's node (never from the page): the token's symbol and the pool's price
      const seen = await _tauriInvoke('dapp_provider_ion_pool', { token });
      const pool = (seen && seen.pool) || {};
      const sym = String(pool.symbol || (seen && seen.asset && seen.asset.symbol) || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 32) || ('token ' + token.slice(0, 6) + '…');
      const price = pool.price_e12 != null ? Number(pool.price_e12) / 1e12 : null; // USDm for one whole token
      const tokText = (b) => (Number(b) / 1e8).toLocaleString('en-US', { maximumFractionDigits: 8 }) + ' ' + sym;
      const tokUsd = (b) => (price == null ? null : (Number(b) / 1e8) * price);
      const ONLY = ' Only confirm if you started this in the app.';
      if (method === 'ionAdd') {
        const x = units(p.tokenAtomic), y = units(p.usdmAtomic);
        if (x <= 0n || y <= 0n) throw new Error('Adding liquidity brings both assets. Nothing was sent.');
        if (!(await confirmCost({ title: 'An app asks to add liquidity to the ' + sym + ' pool', confirmLabel: 'Add liquidity',
          lines: [{ label: 'You add', usd: Number(y) / 1e8, cost: true, detail: 'USDm' },
            { label: 'You add', usd: tokUsd(x), cost: true, detail: tokText(x) },
            { label: 'You receive', usd: null, detail: 'shares of the pool, held in this wallet. They are yours to hand back for both assets at any time' },
            feeLine()],
          warning: 'You can remove this liquidity whenever you want; nobody can refuse it. While it is in the pool its mix of ' + sym + ' and USDm follows the price: if the price moves you get back more of one and less of the other. What does not fit the pool\'s own ratio comes straight back.' + ONLY }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
        return _tauriInvoke('dapp_provider_ion_order', { kind: 2, token, x: fits(x), y: fits(y), shares: '0', minOut: '0' });
      }
      if (method === 'ionClaim') {
        const owedX = BigInt(String(pool.creator_owed_token_atomic || '0')), owedY = BigInt(String(pool.creator_owed_usdm_atomic || '0'));
        if (!(seen && seen.found) || (owedX <= 0n && owedY <= 0n)) throw new Error('This pool holds no creator fees to collect right now. Nothing was sent.');
        if (!(await confirmCost({ title: 'An app asks to collect your creator fees from the ' + sym + ' pool', confirmLabel: 'Collect fees',
          lines: [{ label: 'You receive (about)', usd: Number(owedY) / 1e8, detail: 'USDm' },
            { label: 'You receive (about)', usd: tokUsd(owedX), detail: tokText(owedX) },
            feeLine()],
          warning: 'These are the creator\'s part of this pool\'s trading fees, paid to the wallet that created ' + sym + '. The amounts are the pool\'s as it stands when your claim is paid, a block or two from now.' + ONLY }))) throw new Error('USER_DECLINED: the user cancelled collecting the fees.');
        return _tauriInvoke('dapp_provider_ion_claim', { token });
      }
      if (method === 'ionLaunch') {
        const x = units(p.tokenAtomic);
        if (x <= 0n) throw new Error('A launch puts tokens on the curve. Nothing was sent.');
        if (seen && seen.found) throw new Error('This token already has a pool or a curve. Nothing was sent.');
        if (!(await confirmCost({ title: 'An app asks to put ' + sym + ' on a launch curve', confirmLabel: 'Launch for good',
          lines: [{ label: 'You put on the curve', usd: null, cost: true, detail: tokText(x) },
            { label: 'You receive', usd: null, detail: 'nothing now. As the creator you earn part of every trade\'s fee' },
            feeLine()],
          warning: 'These ' + sym + ' do not come back to you. Buyers buy them along the curve, and what buyers pay becomes the pool\'s permanent liquidity: nobody, you included, can ever take it out. This cannot be undone.' + ONLY }))) throw new Error('USER_DECLINED: the user cancelled the launch.');
        return _tauriInvoke('dapp_provider_ion_order', { kind: 4, token, x: fits(x), y: '0', shares: '0', minOut: '0' });
      }
      // ⭐ LIQUIDITY LOCKS (spec §14). A lock week is the Monday 00:00 UTC it begins on (the chain's own grid); the sheet
      // states that date in words, read from the week itself, never from the page's text.
      const week = (v) => { const w = Math.floor(Number(v)); if (!Number.isFinite(w) || w < 0 || w > 4294967295) throw new Error('That date does not read. Nothing was sent.'); return w; };
      const weekDate = (w) => new Date((345600 + w * 604800) * 1000).toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
      const nowWeek = pool.lock && Number.isFinite(Number(pool.lock.now_week)) ? Number(pool.lock.now_week) : null;
      const shareWorth = (s) => { const total = BigInt(String(pool.shares || '0')), bx = BigInt(String(pool.token_atomic || '0')), by = BigInt(String(pool.usdm_atomic || '0')); return total > 0n ? [(bx * s) / total, (by * s) / total] : [0n, 0n]; };
      if (method === 'ionLock') {
        const shares = units(p.shares), from = week(p.fromWeek || 0), until = week(p.untilWeek);
        if (!(seen && seen.found)) throw new Error('This token has no pool. Nothing was sent.');
        if (nowWeek == null || until <= nowWeek || until > nowWeek + 208) throw new Error('A lock ends on a Monday after this week and at most four years away. Nothing was sent.');
        if (until <= from) throw new Error('A lock can only be made longer. Nothing was sent.');
        const [ox, oy] = shareWorth(shares);
        if (!(await confirmCost({ title: 'An app asks to LOCK your liquidity in the ' + sym + ' pool', confirmLabel: 'Lock until ' + weekDate(until),
          lines: [{ label: 'You lock (worth about)', usd: Number(oy) / 1e8 * 2, detail: (shares === 0n ? 'all of these shares' : 'your shares') + ' — about ' + tokText(ox) + ' and ' + (Number(oy) / 1e8).toFixed(2) + ' USDm today' },
            { label: 'Unlocks on', usd: null, detail: weekDate(until) + ' (00:00 UTC)' },
            { label: 'Meanwhile', usd: null, detail: 'the shares stay in this wallet and keep earning their part of every trade\'s fee' },
            feeLine()],
          warning: 'Until ' + weekDate(until) + ' NOBODY can take this liquidity out — not you, not the token\'s creator, not anyone. A lock can be made longer later, never shorter, and it cannot be undone. Anyone can see that this many shares of the pool are locked until that day; nobody can see that they are yours.' + ONLY }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
        return _tauriInvoke('dapp_provider_ion_lock', { token, shares: fits(shares), fromWeek: from, untilWeek: until });
      }
      if (method === 'ionUnlock') {
        const shares = units(p.shares), w = week(p.week);
        if (nowWeek == null || nowWeek < w) throw new Error('These shares are locked until ' + weekDate(w) + '. Nothing was sent.');
        if (!(await confirmCost({ title: 'An app asks to unlock your liquidity in the ' + sym + ' pool', confirmLabel: 'Unlock',
          lines: [{ label: 'Locked until', usd: null, detail: weekDate(w) + ' (that day has come)' },
            { label: 'You receive', usd: null, detail: 'the same number of ordinary shares, yours to take out at any time' },
            feeLine()],
          warning: 'Your liquidity stays in the pool and keeps earning; only the lock ends.' + ONLY }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
        return _tauriInvoke('dapp_provider_ion_unlock', { token, shares: fits(shares), week: w });
      }
      if (method === 'ionRemoveLocked') {
        const shares = units(p.shares), w = week(p.week);
        if (nowWeek == null || nowWeek < w) throw new Error('These shares are locked until ' + weekDate(w) + ': they can be taken out from that day on. Nothing was sent.');
        const [ox, oy] = shareWorth(shares);
        if (!(await confirmCost({ title: 'An app asks to take your unlocked liquidity out of the ' + sym + ' pool', confirmLabel: 'Remove liquidity',
          lines: [{ label: 'You receive (about)', usd: Number(oy) / 1e8, detail: 'USDm' },
            { label: 'You receive (about)', usd: tokUsd(ox), detail: tokText(ox) },
            { label: 'You hand back', usd: null, detail: 'your shares that were locked until ' + weekDate(w) },
            feeLine()],
          warning: 'Both assets return to this wallet. The exact amounts are the pool\'s as it stands when your order is paid, a block or two from now.' + ONLY }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
        return _tauriInvoke('dapp_provider_ion_remove_locked', { token, shares: fits(shares), week: w });
      }
      if (method === 'ionRemove') {
        const shares = units(p.shares);
        const total = BigInt(String(pool.shares || '0')), bx = BigInt(String(pool.token_atomic || '0')), by = BigInt(String(pool.usdm_atomic || '0'));
        const outX = total > 0n ? (bx * shares) / total : 0n, outY = total > 0n ? (by * shares) / total : 0n;
        if (!(await confirmCost({ title: 'An app asks to take your liquidity out of the ' + sym + ' pool', confirmLabel: 'Remove liquidity',
          lines: [{ label: 'You receive (about)', usd: Number(outY) / 1e8, detail: 'USDm' },
            { label: 'You receive (about)', usd: tokUsd(outX), detail: tokText(outX) },
            { label: 'You hand back', usd: null, detail: 'your shares of the pool' },
            feeLine()],
          warning: 'Both assets return to this wallet. The exact amounts are the pool\'s as it stands when your order is paid, a block or two from now.' + ONLY }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
        return _tauriInvoke('dapp_provider_ion_remove', { token, shares: fits(shares) });
      }
      const least = units(p.minOut);
      if (method === 'ionBuy') {
        const y = units(p.usdmAtomic);
        if (y <= 0n) throw new Error('Enter what you pay. Nothing was sent.');
        const fee = pool.kind === 'curve' ? 0.008 : 0.003;
        if (!(await confirmCost({ title: 'An app asks to buy ' + sym + ' from its pool', confirmLabel: 'Buy',
          lines: [{ label: 'You pay', usd: Number(y) / 1e8, cost: true, detail: 'USDm' },
            { label: 'You receive (at least)', usd: tokUsd(least), detail: tokText(least) },
            { label: 'Pool fee (' + (fee * 100).toFixed(2) + '% of what you pay, inside the amount above)', usd: (Number(y) / 1e8) * fee },
            feeLine()],
          warning: WARN_IRREVERSIBLE + ' If the block\'s price would give you less than the amount shown, your whole payment comes back instead.' + ONLY }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
        return _tauriInvoke('dapp_provider_ion_order', { kind: 0, token, x: '0', y: fits(y), shares: '0', minOut: fits(least) });
      }
      const x = units(p.tokenAtomic);
      if (x <= 0n) throw new Error('Enter what you sell. Nothing was sent.');
      if (!(await confirmCost({ title: 'An app asks to sell ' + sym + ' into its pool', confirmLabel: 'Sell',
        lines: [{ label: 'You sell', usd: tokUsd(x), cost: true, detail: tokText(x) },
          { label: 'You receive (at least)', usd: Number(least) / 1e8, detail: 'USDm' },
          feeLine()],
        warning: WARN_IRREVERSIBLE + ' If the block\'s price would give you less than the amount shown, everything you sold comes back instead.' + ONLY }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_ion_order', { kind: 1, token, x: fits(x), y: '0', shares: '0', minOut: fits(least) });
    }
    // ── A SWAP OF ONE TOKEN FOR ANOTHER, IN ONE ORDER: the sale's USDm is spent by the chain itself in the second
    //    token's pool. Both pools' words are read from this wallet's own node (never from the page), and the sheet
    //    shows both floors: the least of the second token, and the least USDm the person is left with if the second
    //    pool cannot give that.
    case 'ionSwap': {
      const from = String(p.from || '').toLowerCase(), to = String(p.to || '').toLowerCase();
      if (!/^[0-9a-f]{64}$/.test(from) || !/^[0-9a-f]{64}$/.test(to) || from === to) throw new Error('A swap names two different tokens. Nothing was sent.');
      const units = (v) => { const t = String(v == null ? '' : v).trim(); if (!/^\d{1,19}$/.test(t)) throw new Error('That amount does not read. Nothing was sent.'); return BigInt(t); };
      const fits = (b) => { if (b > 18446744073709551615n) throw new Error('That amount is too large. Nothing was sent.'); return b.toString(); };
      const [seenA, seenB] = [await _tauriInvoke('dapp_provider_ion_pool', { token: from }), await _tauriInvoke('dapp_provider_ion_pool', { token: to })];
      if (!(seenA && seenA.found)) throw new Error('The token you are selling has no pool yet. Nothing was sent.');
      if (!(seenB && seenB.found)) throw new Error('The token you want has no pool yet. Nothing was sent.');
      const word = (seen, id) => String((seen.pool && seen.pool.symbol) || '').replace(/[^A-Za-z0-9]/g, '').slice(0, 32) || ('token ' + id.slice(0, 6) + '…');
      const [symA, symB] = [word(seenA, from), word(seenB, to)];
      const priceOf = (seen) => (seen.pool && seen.pool.price_e12 != null ? Number(seen.pool.price_e12) / 1e12 : null);
      const [priceA, priceB] = [priceOf(seenA), priceOf(seenB)];
      const text = (b, sym) => (Number(b) / 1e8).toLocaleString('en-US', { maximumFractionDigits: 8 }) + ' ' + sym;
      const worth = (b, price) => (price == null ? null : (Number(b) / 1e8) * price);
      const x = units(p.tokenAtomic), leastUsdm = units(p.minUsdm), least = units(p.minOut);
      if (x <= 0n) throw new Error('Enter what you sell. Nothing was sent.');
      if (leastUsdm <= 0n || least <= 0n) throw new Error('A swap states the least it accepts on each leg. Nothing was sent.');
      const feeOf = (seen) => (seen.pool && seen.pool.kind === 'curve' ? 0.008 : 0.003);
      const sold = worth(x, priceA);
      if (!(await confirmCost({ title: 'An app asks to swap ' + symA + ' for ' + symB, confirmLabel: 'Swap',
        lines: [{ label: 'You sell', usd: sold, cost: true, detail: text(x, symA) },
          { label: 'You receive (at least)', usd: worth(least, priceB), detail: text(least, symB) },
          { label: 'Or, if the ' + symB + ' pool cannot give that (at least)', usd: Number(leastUsdm) / 1e8, detail: 'USDm instead' },
          { label: 'Pool fees (' + (feeOf(seenA) * 100).toFixed(2) + '% in the ' + symA + ' pool, then ' + (feeOf(seenB) * 100).toFixed(2) + '% in the ' + symB + ' pool, inside the amounts above)', usd: sold == null ? null : sold * (feeOf(seenA) + feeOf(seenB)) },
          feeLine()],
        warning: WARN_IRREVERSIBLE + ' The swap runs through two pools, one block after the other, each at its pool\'s one price for that block. If the first pool would give less USDm than shown, everything you sold comes back. If the second pool would give less ' + symB + ' than shown, you receive the USDm instead. Only confirm if you started this in the app.' }))) throw new Error('USER_DECLINED: the user cancelled in the wallet');
      return _tauriInvoke('dapp_provider_ion_swap', { from, to, x: fits(x), minUsdm: fits(leastUsdm), minOut: fits(least) });
    }
    // What an LP position would COST, per asset, before they commit to it. Read-only.
    // ⭐ DEPTH — what a user calls "the pool": everyone's resting orders counted per price level. Every
    //    order is one lot, so count IS depth and counting discloses no size. Never who, never balances.
    case 'bookDepth':     return _tauriInvoke('dapp_provider_book_depth', {
                            assetAHex: p.assetA, assetBHex: p.assetB,
                            fromLevel: p.fromLevel != null ? Number(p.fromLevel) : null,
                            span: p.span != null ? Number(p.span) : null });
    // ⭐ POST an LP ladder: every rung is an authorisation over a note that STAYS in this wallet —
    //    nothing is transferred, so there is no moment where funds have left but the position does not
    //    yet exist. A partial ladder is reported as partial, never rounded up to success.
    // ⭐ ONE limit order, one side. `give`/`get` are the two assets; a bid and an ask are the same
    //    primitive with the assets exchanged. Nothing is transferred — the order is an authorisation
    //    over a note this wallet already holds. NOT the ladder, which always posts both sides.
    case 'orderPost':     return _tauriInvoke('dapp_provider_order_post', {
                            giveHex: p.give, getHex: p.get,
                            lot: Number(p.lot) || 0,
                            pay: Number(p.pay) || 0,
                            expiresAtHeight: Number(p.expires) || 0 });
    case 'ladderPost':    return _tauriInvoke('dapp_provider_ladder_post', {
                            baseHex: p.base, quoteHex: p.quote,
                            lot: Number(p.lot) || 0,
                            midPricePerLot: Number(p.mid) || 0,
                            step: Number(p.step) || 0,
                            rungs: Number(p.rungs) || 0,
                            expiresAtHeight: Number(p.expires) || 0 });
    case 'ladderCancelTargets': return _tauriInvoke('dapp_provider_ladder_cancel_targets', {
                            baseHex: p.base, quoteHex: p.quote,
                            lot: Number(p.lot) || 0,
                            midPricePerLot: Number(p.mid) || 0,
                            step: Number(p.step) || 0,
                            rungs: Number(p.rungs) || 0,
                            expiresAtHeight: Number(p.expires) || 0 });
    case 'ladderPreview': return _tauriInvoke('dapp_provider_ladder_preview', {
                            baseHex: p.base, quoteHex: p.quote,
                            lot: Number(p.lot) || 0,
                            midPricePerLot: Number(p.mid) || 0,
                            step: Number(p.step) || 0,
                            rungs: Number(p.rungs) || 0,
                            expiresAtHeight: Number(p.expires) || 0 }); // DM-fee gate: does MY wallet own the note with this cm, and how much
    default: throw new Error('unsupported provider method: ' + method);
  }
}
// ── IonSwap's native swaps, answered by the wallet (see the `nativeAssets` cases above) ─────────────────────────────
// The coins the bridge holds on their own chains, and the two this chain mints. `chain` says what an outside observer
// of that coin's own chain can see: everything (public), nothing of amounts or owners (shielded), nothing at all (private).
// WHICH coins the bridge holds is the chain's one table, handed over by the core (`wallet_bridge_coins`): this file keeps
// no coin list of its own, so a coin the bridge gains is here the day its row is. The two this chain mints are its own.
const OWN_ASSETS = [
  { sym: 'USDm', name: 'MoneroUSD', chain: 'private', decimals: 8 },
  { sym: 'SAT', name: 'SAT', chain: 'private', decimals: 8 },
];
let BRIDGE_COINS = [];
let NATIVE_ASSETS = OWN_ASSETS;
async function loadBridgeCoins() {
  if (BRIDGE_COINS.length) return;
  const r = await walletCore('wallet_bridge_coins');
  if (!r || !Array.isArray(r.coins) || !r.coins.length) throw new Error('the wallet did not list the coins the bridge holds');
  BRIDGE_COINS = r.coins;
  NATIVE_ASSETS = BRIDGE_COINS.concat(OWN_ASSETS);
}
// How each pair is traded: `coin` = one action here (deposit one coin, the other is paid out); `add` / `cashout` = one leg
// of the same bridge; `wallet` = the sealed-batch SAT market, placed on the wallet's own Buy / Sell page.
function _nativeRoute(from, to) {
  const coin = (s) => BRIDGE_COINS.some((c) => c.sym === s);
  if (coin(from) && coin(to) && from !== to) return { kind: 'coin', fee_pct: 0.20, legs: [from, 'USDm', to] };
  if (coin(from) && to === 'USDm') return { kind: 'add', fee_pct: 0.10, legs: [from, 'USDm'] };
  if (from === 'USDm' && coin(to)) return { kind: 'cashout', fee_pct: 0.10, legs: ['USDm', to] };
  if ((coin(from) && to === 'SAT') || (from === 'SAT' && coin(to))) return { kind: 'wallet', fee_pct: null, legs: [from, to] };
  return null;
}
async function _nativeSwapCall(method, p) {
  // A coin's dollar price is the CHAIN'S PRICE MARK, read from this wallet's own node (`wallet_asset_price`): the
  // bond-weighted median its validators signed for the epoch, the number a deposit is minted at. Never a company feed.
  // SAT has no mark of its own: its dollar figure is its last batch's price in Bitcoin times the chain's Bitcoin mark.
  const priced = async (sym) => {
    if (sym === 'USDm') return { usd: 1 };
    try {
      if (sym === 'SAT') {
        const [b, btc] = [await walletCore('wallet_defi_book', { coin: 'BTC', quote_coin: 0, quote_sat: 0 }), await priced('BTC')];
        const per = Number(b && b.price_coin_per_sat);
        return per > 0 && btc.usd ? { usd: per * btc.usd, price_source: 'its last batch, in Bitcoin' } : { usd: null };
      }
      const p = await walletCore('wallet_asset_price', { asset: sym });
      const m = /epoch (\d+)/.exec(String((p && p.source) || ''));
      const epoch = p && p.epoch != null ? Number(p.epoch) : m ? Number(m[1]) : null;
      return { usd: Number(p && p.usd) || null, price_source: 'chain price mark', price_epoch: epoch };
    } catch (_) { return { usd: null }; }
  };
  const price = async (sym) => (await priced(sym)).usd;
  await loadBridgeCoins();
  if (method === 'autoOpsec') { await refreshAutoOpsec(); return { on: state.autoOpsec }; }
  if (method === 'setAutoOpsec') {
    // ON needs no question; OFF passes the wallet's one warning (the same sheet Settings shows)
    if (!!p.on !== state.autoOpsec) await toggleAutoOpsec();
    return { on: state.autoOpsec };
  }
  if (method === 'nativeAssets') {
    await refreshAutoOpsec();
    const assets = [];
    for (const a of NATIVE_ASSETS) assets.push(Object.assign(await priced(a.sym), a));
    const routes = [];
    for (const a of NATIVE_ASSETS) for (const b of NATIVE_ASSETS) { const r = _nativeRoute(a.sym, b.sym); if (r) routes.push(Object.assign({ from: a.sym, to: b.sym }, r)); }
    return { assets, routes, auto_opsec: state.autoOpsec, network: state.net };
  }
  if (method === 'nativeProgress') {
    const safe = async (cmd, args) => { try { return await walletCore(cmd, args); } catch (e) { return { error: String((e && e.message) || e) }; } };
    return {
      swaps: await safe('wallet_swap_history'),
      cash: await safe('wallet_cash_out_progress', { fast_now: null }),
      sat: await safe('wallet_defi_progress'),
      mix: await safe('wallet_mix_progress'),
      auto_opsec: state.autoOpsec,
    };
  }
  // nativeSwap { from, to, usd, payoutTo }
  const from = String(p.from || ''), to = String(p.to || '');
  const route = _nativeRoute(from, to);
  if (!route) throw new Error('that pair is not traded');
  const usd = Number(p.usd);
  if (!(usd > 0)) throw new Error('enter an amount above 0');
  const payout = String(p.payoutTo || '').trim();
  await refreshAutoOpsec();
  const opsec = state.autoOpsec;
  if (route.kind === 'wallet') {
    // the SAT market is a sealed batch with a maximum price the buyer picks: that choice is made on the wallet's own page
    switchView('buy');
    return { kind: 'wallet_page', note: 'SAT trades are placed on the wallet\'s Buy / Sell page: it is open now.' };
  }
  const [pf, pt] = [await price(from), await price(to)];
  if (!pf || !pt) throw new Error('the chain has not priced this pair yet — try again in a moment');
  const fees = usd * route.fee_pct / 100;
  const outUsd = Math.max(0, usd - fees);
  const delivery = to === 'USDm' ? 'in this wallet, private'
    : (opsec ? 'in standard pieces, each to ' + (to === 'BTC' && !payout ? 'a fresh address of your own vault' : 'your address') + ', each in its own later batch (Auto-OPSEC)'
             : 'in the next batch — NOT private (Auto-OPSEC is off)');
  const ok = await confirmCost({
    title: 'Swap ' + from + ' to ' + to, confirmLabel: route.kind === 'cashout' ? 'Swap' : 'Get deposit address',
    lines: [
      { label: 'You pay', usd, detail: '≈ ' + (usd / pf).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' ' + from },
      { label: 'You receive', usd: outUsd, detail: '≈ ' + (outUsd / pt).toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' ' + to + ' · ' + delivery },
      appFeeLine('Wallet fees (' + route.fee_pct.toFixed(2) + '%)', fees), feeLine()],
    warning: (route.kind === 'cashout' ? 'What does not fit a payout piece stays USDm in this wallet — never lost. '
      : 'Send exactly the amount shown next, on the ' + from + ' network, to that address only. ' + (from === 'XMR' ? 'Monero has no self-refund: a deposit that never mints cannot be reclaimed by you. ' : '')) +
      (opsec ? 'Auto-OPSEC is on: the pieces arrive spread out so nobody watching the two chains can match what came in to what went out.' : 'Auto-OPSEC is OFF: this swap can be matched across the two chains by anyone watching them.') });
  if (!ok) return { kind: 'declined' };
  if (route.kind === 'cashout') {
    const r = await walletCore('wallet_cash_out', { usdm_amount: usd, asset: to, payout_to: payout, fast: !opsec });
    return { kind: 'cashout', plan: r };
  }
  if (route.kind === 'add') {
    if (from === 'BTC' && opsec) {
      // the private Bitcoin deposit (entry rounds with other people's coins) is funded from the vault's own address
      const q = await walletCore('wallet_mix_quote', { btc: usd / pf });
      const r = await walletCore('wallet_mix_start');
      state.mixPlanId = r.plan && r.plan.plan_id; renderMixPlans([r.plan]); startMixPoll();
      return { kind: 'private_deposit', plan: r.plan, quote: q };
    }
    const q = await walletCore('wallet_buy_swap', { asset: from, usdm_amount: usd });
    state.activeSwap = q.swap_id; startSwapPoll(q.swap_id);
    return { kind: 'deposit', swap: q };
  }
  const q = await walletCore('wallet_coin_swap', { from, to, usdm_amount: usd, payout_to: payout });
  if (q.private) { state.mixPlanId = q.plan && q.plan.plan_id; renderMixPlans([q.plan]); startMixPoll(); return { kind: 'private_deposit', plan: q.plan }; }
  state.activeSwap = q.swap_id; startSwapPoll(q.swap_id);
  return { kind: 'deposit', swap: q };
}
// Announce presence to a freshly-loaded framed app so it installs its window.monerousd
// shim and points its backend at the wallet bridge (→ node), not its serving origin (VPS).
function _dappSayHello(frame) {
  if (!frame) return;
  let origin = '*';
  try { origin = new URL(frame.getAttribute('src')).origin; } catch (e) { console.debug('[dapp-bridge] hello origin', e); }
  try { frame.contentWindow.postMessage({ type: 'monerousd:hello', provider: 'wallet-bridge', network: state.net }, origin); }
  catch (e) { console.debug('[dapp-bridge] hello failed', e); }
}
// ── Letter unread badge — the launchpad tile's red circle. The wallet polls ITS OWN inbox (self-custodial
// keys, local node) every few seconds; letters not yet seen in this session light the badge. Opening the
// Letter tile marks the current inbox seen. Session-memory only — no store, no growth axis.
const _letterSeen = new Set();
let _letterUnread = 0;
function _paintLetterBadge() {
  document.querySelectorAll('[data-app-badge="letter"]').forEach((el) => {
    if (_letterUnread > 0) { el.textContent = _letterUnread > 9 ? '9+' : String(_letterUnread); el.style.display = 'flex'; }
    else { el.style.display = 'none'; }
  });
}
function _letterKey(m) { return (m && (m.from || '') + '|' + (m.msg || '')); }
function _letterMarkAllSeen(msgs) { (msgs || []).forEach((m) => _letterSeen.add(_letterKey(m))); _letterUnread = 0; _paintLetterBadge(); }
async function _pollLetterUnread() {
  try {
    if (!IN_TAURI) return;
    // DB-373: the wallet's OWN window reads its own inbox (main-window-only command); the bridge read is for apps and
    // asks the user's session consent.
    const r = await _tauriInvoke('wallet_letter_inbox');
    const msgs = (r && r.messages) || [];
    const letterOpen = !!(_dapp.url && _dapp.url.indexOf('letter') >= 0);
    if (letterOpen) { _letterMarkAllSeen(msgs); return; }
    let n = 0;
    for (const m of msgs) { if (!_letterSeen.has(_letterKey(m))) n++; }
    _letterUnread = n; _paintLetterBadge();
  } catch (e) { void e; /* wallet locked / no node yet — badge stays as-is */ }
}
setInterval(_pollLetterUnread, 5000);
// LIVE MIRROR OF INCOMING MONEY (owner 2026-09-21: an incoming note took long enough to appear that the funds
// looked lost). The Wallet view re-reads the balance and the activity peek every 5 s while it is on screen, so a
// note that landed in a block shows within one poll of the node serving it — the same sub-1s local read the view
// makes on entry, never a remote query. Other views keep their own loaders; nothing polls while the app is hidden.
setInterval(() => {
  if (document.hidden || !state) return;
  if (state.view === 'wallet') loadWallet();
  // §17.6 (lane funds-brb33): the Earn view is a live mirror too — a stake the chain has not folded yet reads "confirming"
  // with Unstake disabled, and must flip to ready on its own while the user watches, never only on a tab re-entry. MEASURED
  // (brb33/p1-pins.log, F9): the one post-stake read left Unstake disabled for the flow's whole 15-minute wait.
  // `keepStatus` leaves the fresh "✓ Staked" line in place.
  else if (state.view === 'earn') loadEarn({ keepStatus: true });
}, 5000);
(function _letterBadgeCss() {
  const st = document.createElement('style');
  st.textContent = '.launchpad-unread{position:absolute;top:-6px;left:28px;min-width:18px;height:18px;padding:0 5px;' +
    'border-radius:9px;background:#e5484d;color:#fff;font-size:11px;font-weight:700;display:flex;align-items:center;' +
    'justify-content:center;box-shadow:0 0 0 2px rgba(0,0,0,.55),0 2px 8px rgba(229,72,77,.55);z-index:3;pointer-events:none}';
  document.head.appendChild(st);
})();
(function wireDappProviderBridge() {
  window.addEventListener('message', async (ev) => {
    const d = ev.data;
    if (!d || d.type !== 'monerousd:rpc') return;
    const f = document.getElementById('dappFrame');
    if (!f || ev.source !== f.contentWindow) return;          // only the app we actually framed
    if (f.dataset.veil === '1') return;                        // a Veil site is answered as itself, below
    if (!_isDappOrigin(ev.origin)) { console.debug('[dapp-bridge] ignored foreign origin', ev.origin); return; }
    const reply = (payload) => { try { ev.source.postMessage(Object.assign({ type: 'monerousd:res', id: d.id }, payload), ev.origin); } catch (e) { console.debug('[dapp-bridge] reply failed', e); } };
    try { reply({ ok: true, result: await _dappProviderCall(d.method, d.params) }); }
    catch (e) { reply({ ok: false, error: String((e && e.message) || e) }); }
  });
  // A VEIL SITE's requests: its sandboxed frame has an opaque origin ("null"), so it is known by the frame it is in and
  // the site this wallet opened there, and answered only as that site (`_veilSiteCall`).
  window.addEventListener('message', async (ev) => {
    const d = ev.data;
    const f = document.getElementById('dappFrame');
    if (!d || !f || ev.source !== f.contentWindow || f.dataset.veil !== '1') return;
    const name = _veilOf(_dapp.url);
    if (!name) return;
    if (d.type === 'monerousd:veil-page') {
      // the page now showing (a link inside the site, or to another site): kept in the wallet's history so Back steps to it
      const href = typeof d.href === 'string' && d.href.length < 2048 ? d.href : '';
      if (_veilOf(href) && href !== _dapp.url) { _dapp.url = href; paintBrowserBar(); }
      return;
    }
    if (d.type === 'monerousd:veil-back') { const b = document.getElementById('browserBack'); if (b && !b.disabled) b.click(); return; }
    if (d.type !== 'monerousd:rpc') return;
    const reply = (payload) => { try { ev.source.postMessage(Object.assign({ type: 'monerousd:res', id: d.id }, payload), '*'); } catch (e) { console.debug('[veil-bridge] reply failed', e); } };
    try { reply({ ok: true, result: await _veilSiteCall(name, String(d.method || ''), d.params || {}) }); }
    catch (e) { reply({ ok: false, error: String((e && e.message) || e) }); }
  });
})();
// ── WEBSITE CONNECT ─────────────────────────────────────────────────────────────────────────────────────────────
// A site opened in an ordinary browser on this computer (the official ion.monerousd.org, or the same pages served by
// this wallet's own node) reaches this wallet through the core's loopback door (src-tauri/src/web3_bridge.rs). The
// door hands each request to THIS page, which answers it with the same provider every app in this wallet's own
// browser uses, so a website and a framed app see one wallet. The door is only a carrier: every transaction a site
// asks for is built, proved and broadcast by this wallet through its own node, and every pool, token and NFT a site
// shows is read from that node. What a site may see is decided in the core (a grant per site); what a site may DO is
// decided by the user, one action at a time, in the sheets below.
const _web3 = { sites: [], waiting: [], asking: new Set(), armed: false, error: '' };
function web3Host(o) { try { return new URL(o).host; } catch (_) { return String(o || ''); } }
async function web3Refresh() {
  if (!IN_TAURI) return;
  try {
    const r = await _tauriInvoke('web3_sites');
    _web3.sites = (r && r.sites) || []; _web3.waiting = (r && r.waiting) || [];
  } catch (e) { console.debug('[web3] sites read failed', e); }
  paintWeb3Sites();
  for (const w of _web3.waiting) web3AskToConnect(w);
}
// The list under the launchpad: the sites linked now, each ended with one tap, and the way to link one.
function paintWeb3Sites() {
  const box = document.getElementById('launchpadWeb3'); if (!box) return;
  const rows = _web3.sites.map((s) => '<div class="web3-site"><span class="web3-dot"></span><b>' + escapeHtml(web3Host(s.origin)) + '</b>' +
    '<span class="web3-note">' + (s.balances ? 'sees your balances' : 'balances hidden') + '</span>' +
    (s.balances ? '<button type="button" class="btn btn-ghost btn-sm" data-web3-hide="' + escapeHtml(s.origin) + '">Hide balances</button>' : '') +
    '<button type="button" class="btn btn-ghost btn-sm" data-web3-end="' + escapeHtml(s.origin) + '">End</button></div>').join('');
  box.innerHTML = '<div class="web3-head"><b>Websites</b><span class="web3-note">' +
      (_web3.sites.length ? _web3.sites.length + ' linked to this wallet' : 'Use this wallet on a website in your own browser') + '</span></div>' + rows +
    '<div class="web3-actions"><button type="button" class="btn btn-primary btn-sm" id="web3Arm">Connect a website</button>' +
    '<button type="button" class="btn btn-ghost btn-sm" id="web3Local">Open IonSwap in my browser</button></div>' +
    '<div class="web3-note" id="web3Said">' + escapeHtml(_web3.error || (_web3.armed ? 'Ready: press Connect on the website now. This closes by itself after five minutes.' : '')) + '</div>';
  const arm = box.querySelector('#web3Arm');
  if (arm) arm.onclick = async () => {
    try { await _tauriInvoke('web3_arm'); _web3.armed = true; _web3.error = ''; }
    catch (e) { _web3.armed = false; _web3.error = String((e && e.message) || e); }
    paintWeb3Sites();
  };
  // the same IonSwap pages, served by THIS wallet's own node: the route that works when the official site is down
  const local = box.querySelector('#web3Local');
  if (local) local.onclick = async () => {
    try { await _tauriInvoke('web3_arm'); _web3.armed = true; _web3.error = ''; } catch (e) { _web3.error = String((e && e.message) || e); }
    openExternal(SOVEREIGN_BASE + '/ionswap-monerousd-org/');
    paintWeb3Sites();
  };
  box.querySelectorAll('[data-web3-end]').forEach((b) => { b.onclick = async () => { await _tauriInvoke('web3_end', { origin: b.dataset.web3End }); web3Refresh(); }; });
  box.querySelectorAll('[data-web3-hide]').forEach((b) => { b.onclick = async () => { await _tauriInvoke('web3_grant', { origin: b.dataset.web3Hide, what: 'balances', on: false }); web3Refresh(); }; });
}
// One site asks to connect: shown once, by name. Approving goes to the core, which asks again in its own prompt.
async function web3AskToConnect(r) {
  if (!r || !r.request || _web3.asking.has(r.request)) return;
  _web3.asking.add(r.request);
  let ok = false;
  try {
    const here = /^http:\/\/(127\.0\.0\.1|localhost)(:|$)/.test(String(r.origin));
    ok = await confirmCost({
      title: 'Connect ' + web3Host(r.origin) + ' to this wallet?', confirmLabel: 'Connect',
      lines: [{ label: 'Cost of connecting', usd: 0, detail: r.origin + (here ? ' (served by this computer)' : '') }],
      warning: 'Only connect a site you opened yourself. It will be able to read the chain through your node and to ask you for actions; each payment, swap, listing or creation it asks for is shown to you here with its cost before anything moves. It cannot see your address or your balances unless you allow that. End it at any time under Browser, Websites.',
    });
    const res = await _tauriInvoke('web3_decide', { request: r.request, approve: !!ok, balances: false });
    if (ok && res && res.linked) { _web3.armed = false; _web3.error = ''; }
  } catch (e) {
    _web3.error = 'The site was not connected: ' + String((e && e.message) || e);
    if (ok) { try { await _tauriInvoke('web3_decide', { request: r.request, approve: false, balances: false }); } catch (_) { /* already answered */ } }
  } finally { _web3.asking.delete(r.request); web3Refresh(); }
}
// One request a linked site made. A grant is the user's decision here; everything else is the wallet's own provider.
async function web3Answer(q) {
  if (!q || !q.id) return;
  const reply = (ok, result, error) => _tauriInvoke('web3_respond', { id: q.id, ok, result: result === undefined ? null : result, error: error || '' });
  try {
    if (q.method === 'grant') {
      // the one grant a website can be given (the core refuses any other: letters stay in the wallet)
      const what = String((q.params && q.params.what) || '');
      if (what !== 'balances') return reply(false, null, 'there is no such grant');
      const words = 'see your balances, what you hold and your activity';
      if (!(await confirmCost({ title: web3Host(q.origin) + ' asks to see your balances', confirmLabel: 'Allow',
        lines: [{ label: 'Cost', usd: 0, detail: 'nothing is spent' }],
        warning: 'If you allow it, ' + q.origin + ' can ' + words + ' until you end its connection. It still cannot move anything without your approval. Keep it hidden if you did not ask for this.' }))) return reply(true, { granted: false });
      await _tauriInvoke('web3_grant', { origin: q.origin, what, on: true });
      web3Refresh();
      return reply(true, { granted: true });
    }
    return reply(true, await _dappProviderCall(q.method, q.params, { site: q.origin }));
  } catch (e) { return reply(false, null, String((e && e.message) || e)); }
}
(function wireWeb3Connect() {
  const T = window.__TAURI__;
  if (!IN_TAURI || !(T && T.event && T.event.listen)) return;
  T.event.listen('web3:connect-request', (ev) => { web3AskToConnect(ev && ev.payload); });
  T.event.listen('web3:request', (ev) => { web3Answer(ev && ev.payload); });
  T.event.listen('web3:armed', () => { _web3.armed = true; _web3.error = ''; web3Refresh(); });
  T.event.listen('web3:door-error', (ev) => { _web3.armed = false; _web3.error = String((ev && ev.payload && ev.payload.error) || 'the connect door could not open'); paintWeb3Sites(); });
  // a phone's browser handed a page to this wallet's own browser
  const browse = (url) => { if (url && typeof loadDapp === 'function') { try { switchView('browser'); } catch (_) { /* already there */ } loadDapp(url); } };
  T.event.listen('web3:browse', (ev) => browse(ev && ev.payload && ev.payload.url));
  _tauriInvoke('web3_pending_browse').then(browse).catch(() => {});
  web3Refresh(); // a request that arrived before this page was listening (the app was opened BY a site's link)
})();
// The launchpad apps render in a real inline <iframe> that FLOWS in the page layout: it fills #browserViewport
// (strictly below the toolbar band), hides with display:none, and truly detaches with about:blank — it NEVER
// composites over the wallet chrome (no native child webview, no floating overlay, no stuck box). Sovereign sites
// frame under the node CSP that names the wallet origin; clearnet subdomains send no frame-ancestors so they frame
// directly. The address bar mirrors the loaded URL (same-origin nav is read back on the frame's load event).
function dappFrameEl() {
  let f = document.getElementById('dappFrame');
  if (!f) {
    const vp = browserViewportEl(); if (!vp) return null;
    f = document.createElement('iframe');
    f.id = 'dappFrame'; f.className = 'dapp-frame';
    // `credentialless` gives the embedded site a FRESH, first-party-like storage partition instead of the blocked
    // third-party partition — so a site that reads localStorage on boot (every launchpad app does) doesn't throw and
    // render blank. `allow=storage-access` lets it request full storage on user activation when it needs to persist.
    try { f.credentialless = true; } catch (_) { /* older engines ignore it; the attribute below still applies */ }
    f.setAttribute('credentialless', '');
    if (_veilOf(_dapp.url)) {
      // a Veil site: an opaque origin of its own, scripts and forms only; no permission of any kind
      f.dataset.veil = '1';
      f.setAttribute('sandbox', 'allow-scripts allow-forms');
      f.setAttribute('allow', '');
      f.setAttribute('referrerpolicy', 'no-referrer');
    } else {
      f.setAttribute('allow', 'storage-access; clipboard-read; clipboard-write; fullscreen; payment; camera; microphone');
    }
    f.style.display = 'none';
    f.addEventListener('load', () => {
      const vp0 = browserViewportEl(); if (vp0) vp0.classList.remove('loading');
      // PAGE BY PAGE (user 2026-11-12: "our back bar doesnt take you back one page"): this window's own history holds
      // only the framed site's pages (the wallet never adds an entry of its own), so a load that lengthened it is a new
      // page, a load after a step is that step, and any other load replaced the page it was on.
      const pg = _dapp.page; const len = window.history.length;
      if (!pg.loaded) { pg.loaded = true; pg.depth = 0; pg.top = 0; }
      else if (pg.step) { pg.depth = Math.max(0, Math.min(pg.top, pg.depth + pg.step)); }
      else if (len > pg.len) { pg.depth += 1; pg.top = pg.depth; }
      pg.step = 0; pg.len = len;
      // a new page is in the frame: what the last one reported about its history no longer describes it
      _dapp.nav = null; paintBrowserBar();
      // Mirror same-origin (sovereign) in-page navigation into the address bar; cross-origin stays at the tile URL.
      try { const href = f.contentWindow.location.href; if (href && href !== 'about:blank') { _dapp.url = href; paintBrowserBar(); } } catch (_) { /* cross-origin — keep the tile URL */ }
      // Tell the framed app the wallet is here + the node is its backend, so it routes chain calls to us (not the VPS).
      _dappSayHello(f);
    });
    vp.appendChild(f);
  }
  return f;
}
function loadDapp(url, fromHistory) {
  const u = normBrowserUrl(url); if (!u) return;
  // a Veil site and a wallet app never share a frame: the sandbox is set when the frame is made
  const veil = !!_veilOf(u);
  const old = document.getElementById('dappFrame');
  // every visit gets a frame of its own, so its pages are the only history Back and Forward step through
  if (old && (old.getAttribute('src') !== u || (old.dataset.veil === '1') !== veil)) hideDappFrame();
  const lp = document.getElementById('dappLaunchpad'); if (lp) lp.style.display = 'none';
  hideSovereignBrowser();
  _dapp.url = u;
  // Wallet-level nav history (cross-origin iframes block contentWindow.history, so back/forward step THIS stack).
  if (!fromHistory && _dapp.history[_dapp.pos] !== u) {
    _dapp.history = _dapp.history.slice(0, _dapp.pos + 1);
    _dapp.history.push(u);
    _dapp.pos = _dapp.history.length - 1;
  }
  // a Veil frame may have moved on by a link inside the site, so a step through history always loads its page
  const f = dappFrameEl(); if (f) { f.style.display = 'block'; if (f.getAttribute('src') !== u) { _dapp.nav = null; const vp = browserViewportEl(); if (vp) vp.classList.add('loading'); f.setAttribute('src', u); } }
  const sov = document.getElementById('browserSovHome'); if (sov) sov.hidden = false;
  const badge = document.getElementById('browserConnBadge'); if (badge) badge.hidden = false;
  paintBrowserBar();
}
// What the address field shows for `url`. A desktop shows the address itself. A phone has room for a few words, and
// the address of an app this wallet serves is a loopback number that says nothing: there the field names the app
// (or the .mud site) until it is tapped, and shows the real address while it is being edited.
function browserTitleFor(url) {
  if (!url) return '';
  const app = LAUNCHPAD_APPS.find((a) => a.site && url.indexOf(sovUrl(a)) === 0);
  if (app) return app.name;
  const name = _veilOf(url);
  if (name) { const rest = url.slice(url.indexOf('/mud/' + name) + 5 + name.length); return name + '.mud' + (rest && rest !== '/' ? rest : ''); }
  return url;
}
// The toolbar says what it can do: Back is live whenever there is somewhere to go back TO (a page inside the open app,
// an earlier site, or the launchpad itself), Forward only when a step forward exists, Reload only with a page open.
function paintBrowserBar() {
  const open = !!_dapp.url;
  const nav = _dapp.nav;
  // the Sovereign page is the wallet's own page inside the Browser: Back leaves it for the launchpad too
  const sovHost = document.getElementById('pageSovereignHosting');
  const sovOpen = !open && !!sovHost && sovHost.style.display !== 'none';
  const set = (id, on) => { const b = document.getElementById(id); if (b) b.disabled = !on; };
  set('browserBack', open || sovOpen);
  set('browserForward', open && ((nav && nav.depth < nav.top) || _dapp.page.depth < _dapp.page.top || _dapp.pos < _dapp.history.length - 1));
  set('browserReload', open);
  const back = document.getElementById('browserBack');
  if (back) back.title = open && !((nav && nav.depth > 0) || _dapp.page.depth > 0 || _dapp.pos > 0) ? (_dapp.fromSovereign ? 'Back to Sovereign' : 'Back to the Launchpad') : 'Back';
  const bar = document.getElementById('browserUrl');
  if (bar && document.activeElement !== bar) {
    const phone = document.documentElement.classList.contains('m-phone');
    bar.value = open ? (phone ? browserTitleFor(_dapp.url) : _dapp.url) : (sovOpen ? (phone ? 'Sovereign' : 'sovereign://home') : '');
  }
}
function _dappAsk(dir) {
  const f = document.getElementById('dappFrame');
  if (!f || !f.contentWindow || !_dapp.url) return false;
  let origin;
  try { origin = new URL(f.getAttribute('src')).origin; } catch (e) { console.debug('[dapp-nav] no frame origin', e); return false; }
  if (!_isDappOrigin(origin)) return false;
  try { f.contentWindow.postMessage({ type: 'monerousd:nav', dir }, origin); return true; }
  catch (e) { console.debug('[dapp-nav] ask failed', e); return false; }
}
// The iframe lives in the Browser tab's own DOM, so switching tabs hides it with the view — no manual park needed.
function parkDapp() {}
function unparkDapp() {}
function syncDappBounds() {}
// Leaving an app takes its frame out of the page: the next app opens in a new one, with a history of its own (a frame
// that was only blanked kept the last app's pages behind the new one, so Back inside it stepped into a blank page).
function hideDappFrame() { const f = document.getElementById('dappFrame'); if (f) f.remove(); _dapp.nav = null; _dapp.page = { depth: 0, top: 0, len: window.history.length, step: 0, loaded: false }; }
function showLaunchpad() {
  _dapp.url = null; _dapp.fromSovereign = false;
  _dapp.history = []; _dapp.pos = -1;
  hideDappFrame();
  hideSovereignBrowser();   // leaving the Sovereign page → hide its host too, or #pageSovereignHosting stays stuck over the grid (the "blank box")
  const badge = document.getElementById('browserConnBadge'); if (badge) badge.hidden = true;
  const sov = document.getElementById('browserSovHome'); if (sov) sov.hidden = false;   // Sovereign is one tap away from anywhere in the Browser
  renderLaunchpad();
  paintBrowserBar();
}
// TESTNET TAP on the phone (owner 2026-09-21: "the testnet faucet app doesn't appear on iOS"): the tile's page is
// served by the node's sovereign host on 127.0.0.1:27752, which only the desktop runs (`serve-sites`). The phone's
// node runs in-process with no site host, so the tile called a dead port. On iOS the tile now asks the wallet's own
// node for the drip directly (`wallet_faucet_drip` → the node's testnet-only `/faucet/drip` door) and refreshes the
// balance — same door, same chain object, same settlement as the page.
async function tapFaucetNative(app) {
  const lp = document.getElementById('dappLaunchpad');
  const foot = lp ? lp.querySelector('.launchpad-footer') : null;
  const say = (t) => { if (foot) foot.textContent = t; };
  say('Testnet Tap · asking your node for 25 testnet USDm…');
  try {
    const r = await walletCore('wallet_faucet_drip', { amount_usdm: 25 });
    say('Testnet Tap · 25 USDm published as a chain credit (tx ' + String((r && r.tx_id) || '').slice(0, 12) + '…) — it lands with the next block.');
    setTimeout(renderBalance, 3000);
  } catch (e) {
    say('Testnet Tap · ' + (e && (e.message || e)));
  }
}
function openApp(app) {
  if (app.native) { openSovereignBrowser(); return; }   // Sovereign tile → the Sovereign page (pages/sovereign.js)
  if (app.id === 'faucet') {
    if (_netInfo && _netInfo.ios) { tapFaucetNative(app); return; }
    if (_netInfo === null) {
      // The descriptor loads with the first home-status poll; a tap before that asks the backend directly.
      walletCore('wallet_network_info')
        .then((i) => { _netInfo = learnSiteHost(i) || {}; if (_netInfo.ios) tapFaucetNative(app); else { hideSovereignBrowser(); loadDapp(appUrl(app)); } })
        .catch(() => { hideSovereignBrowser(); loadDapp(appUrl(app)); });
      return;
    }
  }
  hideSovereignBrowser();
  // BOTH networks embed in the wallet's own webview (old-wallet parity): sovereign mode → the private node
  // mirror; clearnet mode → the real subdomain. The shield in the toolbar toggles which.
  loadDapp(appUrl(app));
}
// ── SOVEREIGN, the MonerousD Veil browser and publisher (dist/pages/sovereign.js) ──────────────────────────────
// The Sovereign tile opens the Sovereign page mounted INSIDE #browserViewport — the wallet's own DOM, sized by the
// layout (no iframe, no floating webview). A site it opens goes through window.openSovereignSite → loadDapp, the
// wallet's own browser surface; every byte of it is served and checked by this wallet's own node.
function hideSovereignBrowser() {
  const host = document.getElementById('pageSovereignHosting');
  if (host) host.style.display = 'none';
}
function openSovereignBrowser() {
  hideDappFrame();                                              // take any open app's frame out so nothing sits over this page
  _dapp.url = null; _dapp.history = []; _dapp.pos = -1;
  const lp = document.getElementById('dappLaunchpad'); if (lp) lp.style.display = 'none';
  const vp = browserViewportEl(); if (!vp) return;
  let host = document.getElementById('pageSovereignHosting');
  if (!host) { host = document.createElement('div'); host.id = 'pageSovereignHosting'; host.className = 'sov-host'; vp.appendChild(host); }
  host.style.display = 'block';
  const sov = document.getElementById('browserSovHome'); if (sov) sov.hidden = false;
  paintBrowserBar();
  if (typeof window.initSovereignHostingPage === 'function') window.initSovereignHostingPage();
}
// The Sovereign page opens a site through window.openSovereignSite; window.navigateTo('about:blank') goes back to the
// launchpad. Both lead to the wallet's own browser surface.
window.openSovereignSite = function (url) {
  hideSovereignBrowser(); hideDappFrame();
  _dapp.history = []; _dapp.pos = -1; _dapp.fromSovereign = true;
  loadDapp(url);
};
window.navigateTo = function (url) {
  hideSovereignBrowser();
  if (!url || url === 'about:blank') { showLaunchpad(); return; }
  loadDapp(url);
};
function renderLaunchpad() {
  const vp = browserViewportEl(); if (!vp) return;
  let lp = document.getElementById('dappLaunchpad');
  if (!lp) {
    lp = document.createElement('div');
    lp.id = 'dappLaunchpad'; lp.className = 'dapp-launchpad';
    vp.insertBefore(lp, vp.firstChild);
  }
  lp.style.display = '';
  const modeCopy = _lpState.sovereign
    ? 'SOVEREIGN mode — every app opens from your OWN node (127.0.0.1:27752), private + censorship-proof, no VPS.'
    : 'Every listed app is audited and runs on MoneroUSD reserves. Your keys stay in this wallet — each action requires approval.';
  lp.innerHTML = sanitizeHtml(
    '<div class="launchpad-hero"><div class="launchpad-hero-left">' +
      '<div class="launchpad-brand"><span class="m-mini" data-usdm-logo></span>' +
        '<div><h1 class="launchpad-title">MoneroUSD Launchpad</h1>' +
        '<div class="launchpad-sub">' + (_lpState.sovereign ? 'Sovereign · served by your node' : 'Trusted dApps on the privacy chain') + '</div></div></div>' +
      '<p class="launchpad-copy">' + modeCopy + '</p>' +
    '</div></div>' +
    '<div class="launchpad-grid" id="launchpadGrid"></div>' +
    '<div class="launchpad-footer">' + (_lpState.sovereign
        ? 'Sovereign mode is ON — click the shield to switch back to clearnet domains.'
        : 'Click the shield in the toolbar to browse every site locally on your own node.') + '</div>' +
    '<div class="launchpad-web3" id="launchpadWeb3"></div>');
  paintWeb3Sites();
  const grid = lp.querySelector('#launchpadGrid');
  // Testnet-only apps (the faucet) appear ONLY while the wallet is on testnet — a faucet has no place on mainnet.
  LAUNCHPAD_APPS.filter((app) => !app.testnetOnly || state.net === 'testnet').forEach((app) => {
    const card = document.createElement('button');
    card.type = 'button';
    card.className = 'launchpad-card' + (app.native ? ' launchpad-card--native launchpad-card--sovereign' : '');
    card.dataset.appId = app.id;
    const sovPill = (app.native || _lpState.sovereign)
      ? '<span class="launchpad-sov-pill" title="Served locally on 127.0.0.1:27752">Sovereign</span>' : '';
    const cta = app.native ? 'Enter sovereign mode' : (_lpState.sovereign ? 'Open (local)' : 'Open');
    card.dataset.app = app.id;
    card.innerHTML = sanitizeHtml(
      '<div class="launchpad-card-head" style="position:relative">' +
        (app.id === 'letter' ? '<span class="launchpad-unread" data-app-badge="letter" style="display:none"></span>' : '') +
        '<img class="launchpad-card-logo" src="' + escapeHtml(app.logo || '') + '" alt="" width="40" height="40" />' +
        '<div class="launchpad-card-title">' + escapeHtml(app.name) +
          (app.verified ? '<span class="launchpad-verified" title="Verified dApp">&#10003;</span>' : '') + sovPill + '</div>' +
      '</div>' +
      '<div class="launchpad-card-blurb">' + escapeHtml(app.blurb) + '</div>' +
      '<div class="launchpad-card-tags">' + app.tags.map((t) => '<span class="launchpad-tag">' + escapeHtml(t) + '</span>').join('') + '</div>' +
      '<div class="launchpad-card-cta">' + escapeHtml(cta) + ' <span aria-hidden="true">&rarr;</span></div>');
    // DB-373: a logo image that does not load shows the app's initial — wired as a LISTENER, not an inline `onerror=`
    // attribute, because the wallet's CSP runs no inline script.
    const logoImg = card.querySelector('.launchpad-card-logo');
    if (logoImg) logoImg.addEventListener('error', () => {
      const initial = document.createElement('div');
      initial.className = 'launchpad-card-logo-fb';
      initial.textContent = (app.name || '?').charAt(0);
      logoImg.replaceWith(initial);
    }, { once: true });
    card.addEventListener('click', () => { if (app.id === 'letter') { _letterUnread = 0; _paintLetterBadge(); try { const pr = _tauriInvoke('wallet_letter_inbox'); if (pr && pr.then) pr.then((r) => _letterMarkAllSeen((r && r.messages) || [])).catch(() => {}); } catch (e) { void e; } } }, { capture: true });
    card.addEventListener('click', () => openApp(app));
    grid.appendChild(card);
  });
  // The launchpad brand mark ([data-usdm-logo]) is created here, AFTER the startup paintLogos() ran — paint the
  // MoneroUSD coin into it now so the header logo shows (it was rendering as an empty box otherwise).
  paintLogos();
}
// Entering the Browser tab: if an app is already loaded, bring its webview back on-screen; else show the grid.
function loadBrowser() {
  if (_dapp.url) {
    const lp = document.getElementById('dappLaunchpad'); if (lp) lp.style.display = 'none';
    requestAnimationFrame(syncDappBounds);
  } else {
    showLaunchpad();
  }
}
(function wireBrowser() {
  const bar = document.getElementById('browserUrl');
  const go = document.getElementById('browserGo');
  const home = document.getElementById('browserHome');
  const sovHome = document.getElementById('browserSovHome');
  const reload = document.getElementById('browserReload');
  const back = document.getElementById('browserBack');
  const forward = document.getElementById('browserForward');
  const navGo = () => { const u = normBrowserUrl(bar && bar.value); if (u) loadDapp(u); };
  if (go) go.addEventListener('click', navGo);
  if (bar) bar.addEventListener('keydown', (e) => { if (e.key === 'Enter') navGo(); });
  if (home) home.addEventListener('click', showLaunchpad);
  // The shield opens Sovereign, the Veil's search, from wherever the Browser is (its results are kept).
  if (sovHome) sovHome.addEventListener('click', () => {
    _dapp.url = null; _dapp.history = []; _dapp.pos = -1; hideDappFrame(); openSovereignBrowser();
    if (typeof window.sovereignHome === 'function') window.sovereignHome();   // the search home, its bar ready to type in
  });
  // Backspace steps Back, as in a browser, whenever the person is not typing (inside a Veil page its own script asks)
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Backspace' || e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || state.view !== 'browser') return;
    const t = e.target;
    if (t && (t.isContentEditable || /^(input|textarea|select)$/i.test(t.tagName))) return;
    if (back && !back.disabled) { e.preventDefault(); back.click(); }
  });
  // Reload: an app that reports its pages reloads the page it is ON (asked over the bridge, so no blank page is left in
  // its history). Any other page is re-fetched from its address (about:blank → src; cross-origin-safe).
  if (reload) reload.addEventListener('click', () => {
    if (!_dapp.url) return;
    if (_dapp.nav && _dappAsk('reload')) return;
    // the page again, in a frame of its own: blanking and refilling one frame left two pages in its history
    const u = _dapp.url; hideDappFrame(); loadDapp(u, true);
  });
  // Back, in the order a browser steps: a page back INSIDE the open app while it has one, then the site visited before
  // it, then the launchpad. Forward mirrors it. (The app's own pages live in a frame of another origin, so the wallet
  // asks the app to step: `monerousd:nav`, answered by the sites' lib/wallet-nav.js.)
  if (back) back.addEventListener('click', () => {
    if (_dapp.url && _dapp.nav && _dapp.nav.depth > 0 && _dappAsk('back')) return;
    // one page back inside the site the frame shows
    if (_dapp.url && _dapp.page.depth > 0) { _dapp.page.step = -1; window.history.back(); return; }
    if (_dapp.url && _dapp.pos > 0) { _dapp.pos--; loadDapp(_dapp.history[_dapp.pos], true); }
    else if (_dapp.url && _dapp.fromSovereign) { _dapp.url = null; hideDappFrame(); openSovereignBrowser(); }
    else showLaunchpad();
  });
  if (forward) forward.addEventListener('click', () => {
    if (_dapp.url && _dapp.nav && _dapp.nav.depth < _dapp.nav.top && _dappAsk('forward')) return;
    // one page forward inside the site, after a step back
    if (_dapp.url && _dapp.page.depth < _dapp.page.top) { _dapp.page.step = 1; window.history.forward(); return; }
    if (_dapp.url && _dapp.pos < _dapp.history.length - 1) { _dapp.pos++; loadDapp(_dapp.history[_dapp.pos], true); }
  });
  // The open app reports where it stands in its own pages; only the frame this wallet opened, on this node's origin.
  window.addEventListener('message', (ev) => {
    const d = ev.data;
    if (!d || d.type !== 'monerousd:navstate') return;
    const f = document.getElementById('dappFrame');
    if (!f || ev.source !== f.contentWindow || !_isDappOrigin(ev.origin) || !_dapp.url) return;
    const depth = Number(d.depth), top = Number(d.top);
    if (!Number.isInteger(depth) || !Number.isInteger(top) || depth < 0 || top < depth) return;
    _dapp.nav = { depth, top };
    if (typeof d.href === 'string' && d.href.length < 2048) {
      try { if (new URL(d.href).origin === ev.origin) _dapp.url = d.href; } catch (e) { console.debug('[dapp-nav] bad href', e); }
    }
    paintBrowserBar();
  });
  // the address field shows the real address while it is edited, and the app's name again when it is left (phone)
  if (bar) {
    bar.addEventListener('focus', () => { if (_dapp.url) { bar.value = _dapp.url; bar.select(); } });
    bar.addEventListener('blur', () => paintBrowserBar());
  }
  paintBrowserBar();
  // Keep the embedded webview aligned to #browserViewport as the window resizes.
  window.addEventListener('resize', () => { if (state.view === 'browser') syncDappBounds(); });
  // The embedded browser reports every navigation — mirror the REAL loaded URL into the address bar (MetaMask-style),
  // so the toolbar always shows the true site (https://ion.monerousd.org …), the actual origin.
  const T0 = window.__TAURI__;
  if (T0 && T0.event && T0.event.listen) {
    T0.event.listen('dapp:navigated', (evt) => {
      const u = evt && evt.payload; if (!u || !_dapp.url) return;
      _dapp.url = u;
      paintBrowserBar();
      const badge = document.getElementById('browserConnBadge'); if (badge) badge.hidden = false;
    });
  }
})();

const VIEW_LOADERS = { wallet: loadWallet, send: loadSend, receive: loadReceive, buy: loadBuy, activity: loadActivity, earn: loadEarn, borrow: loadBorrow, governance: loadGovernance, browser: loadBrowser, settings: loadSettings, merchant: loadMerchant };

// ⭐ §BR-4 — BORROW (R7 F8, ADOPTABLE A4): choose a size and how far Bitcoin may fall before the loan is liquidated; every cost
// and the liquidation price are shown in dollars before anything is sent; each loan shows how far Bitcoin is from its
// liquidation price, with a warning under 15 %.
let _borrowOpts = null;
let _borrowPoll = null;
async function loadBorrow() {
  // the loans list follows the chain while the page is open (a deposit minting, a close landing)
  // and the page opens by itself once the network has what borrowing needs (a Bitcoin price from the validators)
  if (!_borrowPoll) _borrowPoll = setInterval(() => { if (state.view === 'borrow') { mintPendingBorrows(); renderBorrowPositions(); if (!_borrowOpts) loadBorrow(); } }, 5000);
  const st = document.getElementById('borrowStatus');
  const sizeSel = document.getElementById('borrowSize');
  try {
    const o = await walletCore('wallet_borrow_options');
    _borrowOpts = o;
    document.getElementById('borrowPrice').textContent = 'BTC ' + usdText(Number(o.usd_per_btc));
    const sizes = [...new Set(o.options.map((x) => x.l))];
    sizeSel.innerHTML = sizes.map((l) => {
      const u = o.options.find((x) => x.l === l).usdm;
      return '<option value="' + l + '"' + (l === o.default.l ? ' selected' : '') + '>' + Number(u).toLocaleString() + ' USDm</option>';
    }).join('');
    // the standard sizes, one tap each, and the amount box showing the one that is chosen
    const chips = document.getElementById('borrowSizes');
    if (chips) {
      chips.innerHTML = sizes.map((l) => '<button type="button" class="chip bw-size" data-l="' + Number(l) + '">' +
        Number(o.options.find((x) => x.l === l).usdm).toLocaleString() + '</button>').join('');
      chips.querySelectorAll('.bw-size').forEach((b) => b.addEventListener('click', () => borrowPickSize(Number(b.dataset.l), true)));
    }
    const typed = document.getElementById('borrowAmount');
    if (typed && !(parseFloat(typed.value) > 0)) borrowPickSize(Number(o.default.l), true); else borrowTyped();
    document.getElementById('btnBorrow').disabled = false;
    st.textContent = '';
  } catch (e) {
    // no price on this network yet, or no wallet behind the page: said in words, and nothing looks like a dead box
    _borrowOpts = null;
    document.getElementById('btnBorrow').disabled = true;
    const chips = document.getElementById('borrowSizes');
    if (chips) chips.textContent = '';
    const note = document.getElementById('borrowSizeNote');
    if (note) note.textContent = '';
    st.textContent = (e && e.notInApp) ? 'Open the MoneroUSD app to borrow.'
      : 'Borrowing is not open on this network yet: ' + String(e && (e.message || e)) + '. This page opens by itself as soon as it is.';
  }
  renderBorrowPositions();
}
// The standard size nearest to what was typed (the smaller one on a tie).
function borrowNearestSize(amount) {
  if (!_borrowOpts) return null;
  const sizes = [...new Set(_borrowOpts.options.map((x) => x.l))].map((l) => ({ l, usdm: Number(_borrowOpts.options.find((x) => x.l === l).usdm) }));
  sizes.sort((a, b) => Math.abs(a.usdm - amount) - Math.abs(b.usdm - amount) || a.usdm - b.usdm);
  return sizes[0] || null;
}
// Choose a size: the wallet's record, the lit chip, and (when asked) the amount box.
function borrowPickSize(l, fill) {
  if (!_borrowOpts) return;
  const sel = document.getElementById('borrowSize');
  sel.value = String(l);
  const usdm = Number((_borrowOpts.options.find((x) => x.l === l) || {}).usdm || 0);
  for (const b of document.querySelectorAll('#borrowSizes .bw-size')) b.classList.toggle('active', Number(b.dataset.l) === l);
  const typed = document.getElementById('borrowAmount');
  if (fill && typed) typed.value = String(usdm);
  const asked = typed ? parseFloat(typed.value) : usdm;
  const note = document.getElementById('borrowSizeNote');
  if (note) note.textContent = asked > 0 && Math.abs(asked - usdm) > 1e-9
    ? 'Loans come in standard sizes, so no loan can be told from another. The nearest to ' + Number(asked).toLocaleString() + ' is ' + usdm.toLocaleString() + ' USDm; for more, open another loan.'
    : '';
  renderBorrowBands();
}
function borrowTyped() {
  const amount = parseFloat((document.getElementById('borrowAmount') || {}).value);
  if (!_borrowOpts) return;
  if (!(amount > 0)) { const note = document.getElementById('borrowSizeNote'); if (note) note.textContent = 'Enter how much USDm you want to borrow.'; return; }
  const near = borrowNearestSize(amount);
  if (near) borrowPickSize(near.l, false);
}
document.getElementById('borrowAmount')?.addEventListener('input', borrowTyped);
function borrowChoice() {
  if (!_borrowOpts) return null;
  const l = Number(document.getElementById('borrowSize').value);
  const k = Number(document.getElementById('borrowBand').value);
  return _borrowOpts.options.find((x) => x.l === l && x.k === k) || null;
}
function renderBorrowBands() {
  if (!_borrowOpts) return;
  const l = Number(document.getElementById('borrowSize').value);
  const bands = _borrowOpts.options.filter((x) => x.l === l);
  // the safety already chosen stays chosen when the amount changes
  const had = document.getElementById('borrowBand').value;
  const keep = had !== '' && bands.some((x) => x.k === Number(had)) ? Number(had) : _borrowOpts.default.k;
  document.getElementById('borrowBand').innerHTML = bands.map((x) =>
    '<option value="' + x.k + '"' + (x.k === keep ? ' selected' : '') + '>Liquidated below ' + usdText(x.liquidation_usd) +
    ' (Bitcoin −' + x.drop_pct.toFixed(0) + '%) · deposit ' + x.deposit_btc.toFixed(8) + ' BTC</option>').join('');
  renderBorrowQuote();
}
function renderBorrowQuote() {
  const x = borrowChoice();
  const q = document.getElementById('borrowQuote');
  if (!x) { q.textContent = ''; return; }
  q.textContent = 'You deposit ' + x.deposit_btc.toFixed(8) + ' BTC (' + usdText(x.collateral_usd) + ') and receive ' + Number(x.usdm).toLocaleString() +
    ' USDm. Interest is ' + _borrowOpts.rate_apr_pct + '% a year, paid when you repay. If Bitcoin falls below ' + usdText(x.liquidation_usd) +
    ' (' + x.drop_pct.toFixed(1) + '% below today) your Bitcoin repays the loan and you keep the USDm.';
}
document.getElementById('borrowSize')?.addEventListener('change', renderBorrowBands);
document.getElementById('borrowBand')?.addEventListener('change', renderBorrowQuote);
document.getElementById('btnBorrow')?.addEventListener('click', doBorrow);
async function doBorrow() {
  const st = document.getElementById('borrowStatus');
  const x = borrowChoice();
  if (!x) { st.textContent = 'Choose how much and how safe first.'; return; }
  const ok = await confirmCost({
    title: 'Borrow ' + Number(x.usdm).toLocaleString() + ' USDm against Bitcoin',
    confirmLabel: 'Get my deposit address',
    lines: [
      { label: 'You deposit', usd: x.collateral_usd, detail: x.deposit_btc.toFixed(8) + ' BTC, including the Bitcoin network fee that moves it into custody' },
      { label: 'You receive', usd: x.usdm, detail: Number(x.usdm).toLocaleString() + ' USDm' },
      { label: 'Interest', usd: x.usdm * _borrowOpts.rate_apr_pct / 100, cost: true, detail: _borrowOpts.rate_apr_pct + '% a year, charged only when you repay' },
      appFeeLine('Wallet fee (0.10%, once the deposit mints)', x.usdm * 0.001),
      { label: 'Liquidation price', usd: x.liquidation_usd, detail: 'Bitcoin ' + x.drop_pct.toFixed(1) + '% below today' },
    ],
    warning: 'If Bitcoin falls below ' + usdText(x.liquidation_usd) + ', your Bitcoin is used to repay this loan and you do not get it back — you keep the ' +
      Number(x.usdm).toLocaleString() + ' USDm. Send exactly the amount shown, on the Bitcoin network, to the address on the next screen only.',
  });
  if (!ok) { st.textContent = ''; return; }
  st.textContent = 'Opening your loan…';
  try {
    const r = await walletCore('wallet_borrow_open', { l: x.l, k: x.k });
    document.getElementById('borrowDeposit').innerHTML = '<div class="settings-row"><div><b>Send ' + Number(r.deposit_btc).toFixed(8) +
      ' BTC to</b></div><div class="mono selectable" id="borrowAddress">' + escapeHtml(r.deposit_address) + '</div>' +
      '<div class="muted">Your ' + Number(r.usdm).toLocaleString() + ' USDm arrive once the deposit confirms.</div></div>';
    st.textContent = '';
    startSwapPoll(r.swap_id);
    renderBorrowPositions();
  } catch (e) {
    st.textContent = 'The loan was not opened: ' + String(e && (e.message || e));
  }
}
// The honest auto-mint for a loan's deposit (the Buy page's `wallet_try_mint`): the node mints only once the real deposit has
// confirmed on Bitcoin, so asking while the deposit is pending is safe and asks again on the next tick.
let _borrowMinting = false;
async function mintPendingBorrows() {
  if (_borrowMinting) return;
  _borrowMinting = true;
  try {
    const p = await walletCore('wallet_borrow_positions');
    for (const x of (p.positions || [])) {
      if (['awaiting_reserve', 'awaiting_deposit', 'deposit_detected', 'gathering_quorum', 'published'].includes(x.status)) {
        await walletCore('wallet_try_mint', { swap_id: x.swap_id }).catch(() => null);
      }
    }
  } catch (_) {
  } finally {
    _borrowMinting = false;
  }
}
async function renderBorrowPositions() {
  const box = document.getElementById('borrowPositions');
  if (!box) return;
  let p;
  try { p = await walletCore('wallet_borrow_positions'); } catch (_) { return; }
  if (!p.positions || !p.positions.length) { box.innerHTML = '<div class="settings-empty">No loans yet.</div>'; return; }
  // A repaid loan ('closing': its repayment is relayed) says so from its own state, so the message survives every re-render
  // and a reload — it never owes anything and can no longer be liquidated.
  box.innerHTML = p.positions.map((x) => '<div class="settings-row borrow-pos" data-swap="' + escapeHtml(x.swap_id) + '">' +
    '<div><b>' + Number(x.usdm).toLocaleString() + ' USDm</b> · ' + escapeHtml(x.status) + ' · ' +
    (x.status === 'closing' ? 'repaid' : 'owes ' + Number(x.debt_usdm).toFixed(2) + ' USDm') + ' · ' +
    Number(x.collateral_btc).toFixed(8) + ' BTC</div>' +
    (x.status === 'closing' ? '' :
      '<div class="muted">Liquidated below ' + usdText(x.liquidation_usd) + ' — Bitcoin is ' + Number(x.drop_pct).toFixed(1) + '% above it</div>') +
    (x.warning ? '<div class="confirm-warning borrow-warning">⚠ Close to liquidation: Bitcoin is less than 15% above this loan\'s liquidation price. Repay now to keep your Bitcoin.</div>' : '') +
    (x.status === 'minted' ? '<input class="amt-input borrow-payout" placeholder="Bitcoin address for your collateral" />' +
      '<button class="btn btn-primary borrow-repay">Repay and get my Bitcoin back</button>' : '') +
    '<div class="send-status borrow-repay-status">' +
    (x.status === 'closing' ? 'Repaid — ' + Number(x.collateral_btc).toFixed(8) + ' BTC is on its way back over the next payout batches.' : '') +
    '</div></div>').join('');
  box.querySelectorAll('.borrow-repay').forEach((b) => b.addEventListener('click', () => doRepay(b.closest('.borrow-pos'), p)));
}
async function doRepay(row, p) {
  const id = row.dataset.swap;
  const x = p.positions.find((y) => y.swap_id === id);
  const st = row.querySelector('.borrow-repay-status');
  const addr = (row.querySelector('.borrow-payout').value || '').trim();
  if (!addr) { st.textContent = 'Enter the Bitcoin address your collateral returns to.'; return; }
  const ok = await confirmCost({
    title: 'Repay and get your Bitcoin back',
    confirmLabel: 'Repay',
    lines: [
      { label: 'You repay', usd: x.debt_usdm, cost: true, detail: Number(x.debt_usdm).toFixed(2) + ' USDm: the loan plus its interest' },
      feeLine(2),
      { label: 'Bitcoin returned', usd: x.collateral_btc * Number(p.usd_per_btc), detail: Number(x.collateral_btc).toFixed(8) + ' BTC to ' + addr },
    ],
    warning: 'Repaying burns ' + Number(x.debt_usdm).toFixed(2) + ' USDm. Your Bitcoin arrives in pieces over the next payout batches at the address above — check it: Bitcoin sent to a wrong address cannot be recovered.',
  });
  if (!ok) { st.textContent = ''; return; }
  st.textContent = 'Repaying…';
  try {
    const r = await walletCore('wallet_borrow_close', { swap_id: id, payout_to: addr });
    st.textContent = 'Repaid ' + Number(r.debt_usdm).toFixed(2) + ' USDm — ' + Number(r.collateral_btc).toFixed(8) + ' BTC is on its way back.';
    renderBorrowPositions();
  } catch (e) {
    st.textContent = 'Not repaid: ' + String(e && (e.message || e));
  }
}

// The view router — activate one nav item + one view, then load that view's live data.
function switchView(name) {
  if (!VIEW_LOADERS[name]) return;
  // Leaving the Browser tab: park the embedded dApp webview off-screen so it never floats over another view.
  if (state.view === 'browser' && name !== 'browser') parkDapp();
  state.view = name;
  for (const b of document.querySelectorAll('.nav-item')) b.classList.toggle('active', b.dataset.view === name);
  for (const v of document.querySelectorAll('.view')) v.classList.toggle('active', v.dataset.view === name);
  // Browser tab is FULL-BLEED (a real browser fills the whole content area, edge-to-edge). Drop the content
  // padding + 720px column cap only while it's active; every other view keeps the normal boxed layout.
  const contentEl = document.querySelector('.content');
  if (contentEl) contentEl.classList.toggle('content--browser', name === 'browser');
  VIEW_LOADERS[name]();
}
document.getElementById('nav').addEventListener('click', (e) => {
  const item = e.target.closest('.nav-item'); if (item) switchView(item.dataset.view);
});
// Mobile hamburger drawer — the bottom bar shows only Wallet · Buy/Sell · Browser; the drawer holds EVERY section
// (rebuilt from #nav each open so active-state + any new tab stay in sync) plus Logout.
(function wireMobileNav() {
  const btn = document.getElementById('mobileMenuBtn');
  const drawer = document.getElementById('mobileDrawer');
  const panel = document.getElementById('mobileDrawerPanel');
  if (!btn || !drawer || !panel) return;
  const closeDrawer = () => { drawer.hidden = true; };
  btn.addEventListener('click', () => {
    panel.innerHTML = '';
    document.querySelectorAll('#nav .nav-item').forEach((src) => {
      const b = document.createElement('button');
      b.className = 'mobile-drawer-item' + (src.classList.contains('active') ? ' active' : '');
      b.replaceChildren(...Array.from(src.childNodes, (n) => n.cloneNode(true)));
      b.addEventListener('click', () => { switchView(src.dataset.view); closeDrawer(); });
      panel.appendChild(b);
    });
    const logout = document.getElementById('btnLogout');
    if (logout) {
      const b = document.createElement('button');
      b.className = 'mobile-drawer-item';
      b.innerHTML = '<span class="nav-ic">⏻</span> Logout';
      b.addEventListener('click', () => { closeDrawer(); logout.click(); });
      panel.appendChild(b);
    }
    drawer.hidden = false;
  });
  drawer.addEventListener('click', (e) => { if (e.target === drawer) closeDrawer(); }); // tap backdrop to close
})();
// Top-bar network selector — surfaces the wallet's real Mainnet/Testnet control (the SAME state + node probe the
// welcome screen's toggle drives) on the mobile header, alongside the live block height.
(function wireTopbarNet() {
  const btn = document.getElementById('mtbNet');
  const menu = document.getElementById('mtbNetMenu');
  const label = document.getElementById('mtbNetLabel');
  if (!btn || !menu) return;
  const items = [].slice.call(menu.querySelectorAll('button[data-net]'));
  const reflect = () => {
    if (label) label.textContent = state.net;
    items.forEach((b) => b.classList.toggle('active', b.dataset.net === state.net));
  };
  reflect();
  const close = () => { menu.hidden = true; btn.setAttribute('aria-expanded', 'false'); };
  btn.addEventListener('click', (e) => {
    e.stopPropagation();
    menu.hidden = !menu.hidden;
    btn.setAttribute('aria-expanded', String(!menu.hidden));
  });
  items.forEach((b) => b.addEventListener('click', () => {
    const net = b.dataset.net; close();
    if (net === state.net || b.disabled || !NET_OPEN(net)) return;
    state.net = net;
    try { localStorage.setItem('monerousd.net', net); } catch (_) { /* private mode — session-only is fine */ }
    // Drive the SAME control the welcome screen uses: sync its toggle + re-probe the node on the chosen network.
    document.querySelectorAll('#netToggle button').forEach((t) => t.classList.toggle('active', t.dataset.net === net));
    reflect();
    if (typeof probeNode === 'function') probeNode();
    if (typeof homeStatusPoll === 'function') homeStatusPoll();
  }));
  document.addEventListener('click', (e) => { if (!menu.hidden && !menu.contains(e.target) && e.target !== btn) close(); });
})();
// In-content shortcuts (Receive chip on the balance card, "View all" on the activity peek).
document.querySelectorAll('[data-goto]').forEach((b) => b.addEventListener('click', () => {
  if (b.dataset.buymode) state.buyMode = b.dataset.buymode; // home Buy/Sell chips preselect the swap direction
  switchView(b.dataset.goto);
}));
// Pay / Request(POS) segmented toggle under the debit card (the merged Pay hub).
document.querySelectorAll('#segPay, #segRequest').forEach((b) => b.addEventListener('click', () => setSendMode(b.dataset.mode)));
document.getElementById('btnBuyQuote')?.addEventListener('click', doBuyQuote);
document.getElementById('btnAddMoney')?.addEventListener('click', addMoneyWithBitcoin);

// ⭐ ADOPTABLE A1 + §BR-6 — ADD MONEY WITH BITCOIN IN ONE TAP: no amount to type. The wallet opens one fresh address of its
// own Bitcoin vault; whatever arrives is mixed with other people's coins (Auto-OPSEC, on by default) and deposited as private
// USDm. Nothing is spent in the app, so the costs are shown in dollars beside the address, before the user sends anything.
async function addMoneyWithBitcoin() {
  state.buyMode = 'buy';
  state.buyAsset = 'BTC';
  switchView('buy');
  const rows = document.getElementById('buyRows');
  const costs = document.getElementById('addMoneyCosts');
  if (!state.autoOpsec) {
    if (rows) rows.innerHTML = '<div class="settings-empty">Auto-OPSEC is off: enter an amount above to get a deposit address. It will NOT be private.</div>';
    return;
  }
  if (rows) rows.innerHTML = '<div class="settings-empty">Opening your private Bitcoin address…</div>';
  try {
    const r = await walletCore('wallet_mix_start');
    state.mixPlanId = r.plan && r.plan.plan_id;
    renderMixPlans([r.plan]);
    startMixPoll();
  } catch (e) {
    if (rows) rows.innerHTML = '<div class="settings-empty">Could not open an address: ' + escapeHtml(String(e && (e.message || e))) + '</div>';
    return;
  }
  if (!costs) return;
  costs.classList.remove('hidden');
  const base = 'Send any amount of Bitcoin, from any wallet or exchange. <b>Wallet fee:</b> 0.10% of each deposit, once it mints. ' +
    '<b>Mixing:</b> free. Under 0.0001 BTC stays in your Bitcoin vault. Making it private takes a few minutes with this wallet open.';
  costs.innerHTML = base;
  try {
    const p = await walletCore('wallet_asset_price', { asset: 'BTC' });
    const q = await walletCore('wallet_mix_quote', { btc: 0.001 });
    const px = Number(p.usd);
    costs.innerHTML = base + ' <b>Example:</b> 0.001 BTC (' + usdText(0.001 * px) + ') gives ≈ ' + usdText(Number(q.usdm)) +
      ' of USDm; Bitcoin network fees ≈ ' + usdText(Number(q.bitcoin_fees_btc) * px) + ' (paid to Bitcoin miners).';
  } catch (_) {
    costs.innerHTML = base + ' Bitcoin network fees are shown in dollars as soon as your node prices Bitcoin.';
  }
}

async function openHome() {
  showScreen('screen-home');
  switchView('wallet');
  homeStatusPoll();
}

// Home status is a live mirror of the node too — poll the O(1) /get_info so the block height stays
// live in BOTH the sidebar footer and the Wallet view header.
let _homeStatusTimer = null;
let _lastPolledHeight = null; // last chain height the live poll saw — balance auto-re-renders when it advances
let _netInfo = null; // canonical network descriptor (net + live chain_id) — loaded once, mirrors the backend live
async function homeStatusPoll() {
  if (_homeStatusTimer) { clearTimeout(_homeStatusTimer); _homeStatusTimer = null; }
  const foot = document.getElementById('homeStatus');
  const conn = document.getElementById('homeConn');
  if (!foot) return;
  try {
    const info = await nodeRpc('/get_info');
    // Canonical GHOSTDAG height = selected-tip blue_score (see probeNode); `blocks` is only the in-memory DAG size.
    const h = info && (info.blue_score != null ? info.blue_score : (info.height != null ? info.height : info.blocks));
    if (h != null) {
      const txt = '● block ' + Number(h).toLocaleString();
      foot.textContent = txt; foot.style.color = 'var(--good)';
      // Live mirror of the canonical network descriptor: show which network this node is on. Loaded once
      // (net is per-session), and the door is open for a chain-parity warning once the canonical chain_id
      // is published (compare _netInfo.live_chain_id to the canonical → auto-surface a fork, never silent).
      if (_netInfo === null) { try { _netInfo = learnSiteHost(await walletCore('wallet_network_info')); } catch (_) { _netInfo = {}; } }
      // Chain-split auto-detector: green ✓ when the node is on THE canonical chain, red warning if it drifted
      // onto a fork/stale chain (surfaced, never silent). Neutral when unknown (unreachable / not-yet-pinned).
      const netLabel = (_netInfo && _netInfo.net)
        ? (' · ' + escapeHtml(_netInfo.net) + (_netInfo.on_canonical === false
            ? ' <span style="color:var(--bad,#e5484d)">⚠ off-canonical chain</span>'
            : (_netInfo.on_canonical === true ? ' <span style="color:var(--good)">✓</span>' : '')))
        : '';
      // Mirror the same live height + network onto the mobile top bar (right of the MoneroUSD brand).
      const mtbBlock = document.getElementById('mtbBlock');
      if (mtbBlock) mtbBlock.textContent = Number.isFinite(Number(h)) && Number(h) > 0 ? 'block ' + Number(h).toLocaleString() : 'on chain';
      const mtbNetLabel = document.getElementById('mtbNetLabel');
      if (mtbNetLabel) mtbNetLabel.textContent = (_netInfo && _netInfo.net) || state.net;
      if (conn) {
        // JOIN-MESH-OR-NOTHING mirror (same rule as probeNode): amber "Joining mesh…" until this node has
        // adopted/grafted from a live peer; green "Connected" only once it is actually on the mesh chain.
        if (info.mesh_joined === false) {
          conn.innerHTML = '● Joining mesh… · block <b>' + Number(h).toLocaleString() + '</b> · dialing peers' + netLabel;
          conn.style.color = 'var(--warn, #f5a623)';
        } else {
          conn.innerHTML = '● Connected · block <b>' + Number(h).toLocaleString() + '</b> · width ' + Number(info.dag_width ?? 32) + netLabel;
          conn.style.color = 'var(--good)';
        }
      }
      // AUTO-AGGREGATE, NO REFRESH: whenever the chain advances (a new block may carry a note received or a spend),
      // re-read + re-render the balance and AUTO-PERSIST the owned-note store. The total stays live on its own —
      // the user never clicks Refresh. Height-gated so an idle chain does no needless re-scan / disk write.
      if (h !== _lastPolledHeight) {
        _lastPolledHeight = h;
        if (document.getElementById('homeBalance')) renderBalance();
      }
    } else {
      foot.textContent = 'starting your node…'; foot.style.color = 'var(--text-3)';
      if (conn) conn.textContent = 'starting your node…';
    }
  } catch (_) {
    foot.textContent = 'starting your node…'; foot.style.color = 'var(--text-3)';
    if (conn) conn.textContent = 'starting your node…';
  }
  _homeStatusTimer = setTimeout(homeStatusPoll, 4000);
}

// Refresh = a SOUND full re-scan (decap every served note locally, ignore clues) that heals any owned-set drift,
// then re-render the Wallet view. This is the "recover my full balance" action — it reseeds the incremental scan so
// the balance + Send's spendable gate reflect the complete on-chain truth, not just the fast clue-accelerated delta.
const _btnRefresh = document.getElementById('btnRefresh');
if (_btnRefresh) _btnRefresh.addEventListener('click', async () => {
  const sub = document.getElementById('homeBalanceSub');
  if (sub) sub.textContent = 'Re-scanning all your notes…';
  try { await walletCore('wallet_full_rescan'); } catch (_) { /* fall through — loadWallet still does the delta read */ }
  loadWallet();
});

// Send: prove + broadcast a real confidential PQ transfer from the user's own node.
// ⛔⛔⛔ A SEND BUTTON MUST NEVER FAIL SILENTLY — user 2026-08-10: "the send button does nothing and fails
// silently with no error warning. There should be a loud error."
//
// `doSend` sets visible red text on every early exit, so a press that produces NOTHING means either the
// handler was never entered or it threw before reaching a status write. Both looked identical from the
// outside: the user presses Send, nothing happens, and there is no way to tell a rejected payment from a
// broken button. That ambiguity cost this session several readings in both directions.
//
// Wrap the invocation so ANY throw — including one before `doSend` writes its first status — is reported in
// the UI and the console. This changes no payment logic and relaxes no gate; it only guarantees the button
// always says what happened.
const _btnSend = document.getElementById('btnSend');
if (_btnSend) {
  _btnSend.addEventListener('click', async () => {
    const st = document.getElementById('sendStatus');
    try {
      if (st) { st.className = 'send-status'; st.textContent = '◌ Send pressed — preparing…'; }
      console.log('[send] button pressed');
      await doSend();
    } catch (e) {
      const msg = (e && (e.message || e)) || 'unknown error';
      console.error('[send] FAILED before completing:', e);
      if (st) { st.className = 'send-status err'; st.textContent = '✗ Send failed: ' + msg; }
    }
  });
} else {
  console.error('[send] ⛔ the Send button element is MISSING — no press can ever reach doSend');
}

// Stake: lock USDm into the stake pool to earn (broadcast-on-press, same WHIR carrier as Send).
const _btnStake = document.getElementById('btnStake');
if (_btnStake) _btnStake.addEventListener('click', doStake);
const _btnClaimReward = document.getElementById('btnClaimReward');
if (_btnClaimReward) _btnClaimReward.addEventListener('click', doClaim);
const _btnUnstake = document.getElementById('btnUnstake');
if (_btnUnstake) _btnUnstake.addEventListener('click', doUnstake);

// Bond: become a validator (broadcast-on-press, the WHIR bond carrier with the public-weight weld).
const _btnBond = document.getElementById('btnBond');
if (_btnBond) _btnBond.addEventListener('click', doBond);
const _btnBecomeValidator = document.getElementById('btnBecomeValidator');
if (_btnBecomeValidator) _btnBecomeValidator.addEventListener('click', doBecomeValidator);
const _keepAwakeToggle = document.getElementById('keepAwakeToggle');
if (_keepAwakeToggle) _keepAwakeToggle.addEventListener('click', toggleKeepAwake);

// Unbond: withdraw this wallet's validator bond weight (ML-DSA signed).
const _btnUnbond = document.getElementById('btnUnbond');
if (_btnUnbond) _btnUnbond.addEventListener('click', doUnbond);

// Governance: create a proposal (each proposal's Vote button is wired per-row in loadGovernance).
const _btnPropose = document.getElementById('btnPropose');
if (_btnPropose) _btnPropose.addEventListener('click', doPropose);

// USDm Pay: claim a @username handle mapped to this wallet's address.
const _btnClaimName = document.getElementById('btnClaimName');
if (_btnClaimName) _btnClaimName.addEventListener('click', doClaimName);

// Copy the receive address.
const _btnCopyAddr = document.getElementById('btnCopyAddr');
if (_btnCopyAddr) _btnCopyAddr.addEventListener('click', async () => {
  const addr = document.getElementById('homeAddress').textContent || '';
  try { await navigator.clipboard.writeText(addr); _btnCopyAddr.textContent = 'Copied ✓'; setTimeout(() => { _btnCopyAddr.textContent = 'Copy address'; }, 1200); } catch (_) {}
});

// POS: mint the tap-to-pay charge; the Cancel button returns the terminal to amount-entry (stops the monitor).
const _btnRequest = document.getElementById('btnRequest');
if (_btnRequest) _btnRequest.addEventListener('click', doRequest);

// ── Apple-Pay-style "Pay in person": the SAME #debitCard FLIP-moves (First-Last-Invert-Play) from its slot on the
// Pay page to center screen over a wallet-dimmed backdrop, shows the NFC "hold near reader" prompt, and the buyer
// just does Face ID + holds near the merchant's reader. No charge-code box — pure tap-to-pay. Cancel FLIPs it back. ──
let _cardHome = null; // { parent, next } — where #debitCard lives when it is NOT presented
let _presenting = false; // re-entrancy guard: ignore repeat "Pay in person" clicks while the card is already presented
let _tapPayToken = 0;     // supersedes an in-flight await-charge poll on cancel / new present
// `onDone` runs when the flight finishes. Use it for anything that PAINTS — see `presentCard`: turning on a
// backdrop-filter mid-flight is what made this animation stutter.
function _flip(el, mutate, ms, onDone) {
  const first = el.getBoundingClientRect();
  mutate(); // move the element to its new home in the DOM
  const last = el.getBoundingClientRect();
  const dx = first.left - last.left, dy = first.top - last.top;
  const sx = last.width ? first.width / last.width : 1, sy = last.height ? first.height / last.height : 1;
  el.style.transformOrigin = 'top left';
  el.style.transition = 'none';
  // Give the card its OWN compositor layer for the flight, so the browser animates it by moving a finished
  // texture instead of re-rasterizing the gradients, borders and shadows on every frame. Cleared in `done`
  // — a permanent will-change costs memory and defeats the point.
  el.style.willChange = 'transform';
  el.style.transform = 'translate(' + dx + 'px,' + dy + 'px) scale(' + sx + ',' + sy + ')'; // invert to the old spot
  el.getBoundingClientRect(); // force reflow to commit the inverted start
  const dur = ms || 440;
  el.style.transition = 'transform ' + dur + 'ms cubic-bezier(.34,.08,.2,1)';
  el.style.transform = ''; // play → animates from the old spot to the new one
  let finished = false;
  const done = () => {
    if (finished) return;
    finished = true;
    clearTimeout(guard);
    el.style.transition = ''; el.style.transformOrigin = ''; el.style.willChange = '';
    el.removeEventListener('transitionend', done);
    if (onDone) onDone();
  };
  // ⛔ transitionend DOES NOT FIRE when there is nothing to animate (the card already in place ⇒ dx/dy 0 and
  // scale 1). Without this guard `onDone` would never run, so the NFC panel would never appear and the tap
  // flow would hang with the card lifted — a dead screen, not a slow one. Always finish.
  const guard = setTimeout(done, dur + 90);
  el.addEventListener('transitionend', done);
}
function presentCard() {
  const card = document.getElementById('debitCard'), overlay = document.getElementById('payOverlay'), slot = document.getElementById('payCardSlot');
  if (!card || !overlay || !slot) return;
  _presenting = true;
  if (!_cardHome) _cardHome = { parent: card.parentNode, next: card.nextSibling };
  overlay.hidden = false;
  requestAnimationFrame(() => overlay.classList.add('show')); // fade the wallet-dimmed backdrop in
  // ⛔⛔⛔ THE PAINT WORK WAITS FOR THE CARD TO LAND. `dc-ready` reveals `.dc-nfc`, which carries a
  // `backdrop-filter: blur(3px)`, and adds a 70px shadow plus a 44px glow. Applying that at frame 0 meant the
  // browser re-computed a blur against a backdrop that was being SCALED on every one of the ~26 frames of the
  // lift, and repainted two large shadows with it — so a transform that should be pure compositor work became
  // per-frame rasterization, and the lift visibly stuttered. Deferring it costs nothing visually (the card is
  // still travelling; there is nothing to read yet) and makes the flight a texture move.
  // The guard matters: Cancel / Escape during the ~440ms flight runs `dismissCard`, which flies the card home
  // — and this callback would still fire afterwards and light the NFC panel up on a card sitting back in its
  // slot. Only reveal it if we are still presenting.
  _flip(card, () => { slot.appendChild(card); }, 440, () => {
    if (_presenting) card.classList.add('dc-ready');
  });
}
function dismissCard() {
  const card = document.getElementById('debitCard'), overlay = document.getElementById('payOverlay');
  if (!card || !overlay) return;
  _presenting = false;
  _tapPayToken++; // abort any in-flight await-charge poll
  overlay.classList.remove('show'); // fade the backdrop out
  if (_cardHome) {
    _flip(card, () => {
      card.classList.remove('dc-ready', 'dc-paid');
      if (_cardHome.next && _cardHome.next.parentNode === _cardHome.parent) _cardHome.parent.insertBefore(card, _cardHome.next);
      else _cardHome.parent.appendChild(card); // card seamlessly moves back to its place on the Pay page
    });
  }
  const nfcLabel = document.getElementById('dcNfcLabel'), nfcSub = document.getElementById('dcNfcSub');
  if (nfcLabel) nfcLabel.textContent = 'Hold near reader';
  if (nfcSub) nfcSub.textContent = 'Face ID ✓ · post-quantum';
  setTimeout(() => { overlay.hidden = true; }, 380);
}

// The buyer "held near the reader": the charge arrives ONLY over the REAL MoneroPay BLE radio
// (moneropay_ble_pay_nearby: scan → RSSI range-gate → ML-KEM handshake → open the sealed charge), then a REAL
// wallet_pos_pay broadcast (verify_pos_charge fail-closed → wallet_send WHIR carrier → /submit_pq_tx). There is NO
// same-device charge store and NO fallback — the tap completes over the radio or it fails honestly.
async function awaitAndPayCharge(setMsg) {
  const token = ++_tapPayToken;
  let charge = null, distCm = null;
  setMsg('', 'Hold near the reader…');
  try {
    const r = await walletCore('moneropay_ble_pay_nearby', { timeout_secs: 18 });
    if (token !== _tapPayToken) return;
    if (r && r.charge) { charge = r.charge; distCm = (r.distance_cm != null) ? Math.round(r.distance_cm) : null; }
  } catch (e) {
    // NO FALLBACK: surface the real reason the tap didn't reach a merchant over BLE (out of tap range / no merchant
    // advertising / Bluetooth off) and STOP — never a shortcut that reports paid without the radio carrying the charge.
    if (token !== _tapPayToken) return;
    setMsg('err', '' + ((e && e.message) || e));
    return;
  }
  if (token !== _tapPayToken) return;
  if (!charge) {
    setMsg('', 'No MoneroUSD reader in tap range — start a charge on a nearby wallet and hold them together. Or Cancel.');
    return;
  }
  setMsg('', '◌ Merchant found' + (distCm != null ? ' · ' + distCm + ' cm' : '') + ' — verifying…');
  let verified = null;
  try { verified = await walletCore('wallet_pos_verify_charge', { charge }); } // ML-DSA-65 charge check first, fail-closed
  catch (e) { setMsg('err', '⚠ ' + ((e && e.message) || e) + ' — charge check failed.'); return; }
  if (token !== _tapPayToken) return;
  // DB-319: the amount shown is the amount the merchant SIGNED, as the verify returned it — never the charge's own
  // unsigned float. wallet_pos_pay below sends exactly that signed amount, once (the radio call above never pays).
  const amt = Number(verified && verified.amount_usdm) || 0;
  if (!(await confirmCost({ title: 'Pay ' + usdText(amt) + ' in person', confirmLabel: 'Pay',
    lines: [{ label: 'You pay the merchant', usd: amt, detail: amt.toLocaleString(undefined, { minimumFractionDigits: 2 }) + ' USDm — the amount the merchant signed' }, feeLine()],
    warning: WARN_IRREVERSIBLE }))) { setMsg('', 'Payment cancelled — nothing was sent.'); return; }
  if (token !== _tapPayToken) return;
  setMsg('', '◌ Paying ' + amt.toLocaleString(undefined, { minimumFractionDigits: 2 }) + ' USDm…');
  try {
    const r = await walletCore('wallet_pos_pay', { charge }); // re-runs the gate + broadcasts the WHIR carrier
    if (token !== _tapPayToken) return;
    if (r && r.paid) {
      clearActiveCharge();
      const card = document.getElementById('debitCard'), nfcLabel = document.getElementById('dcNfcLabel'), nfcSub = document.getElementById('dcNfcSub');
      if (card) card.classList.add('dc-paid');
      if (nfcLabel) nfcLabel.textContent = '✓ Paid';
      if (nfcSub) nfcSub.textContent = amt.toLocaleString(undefined, { minimumFractionDigits: 2 }) + ' USDm' + (r.height ? ' · block ' + Number(r.height).toLocaleString() : '');
      setMsg('ok', '✓ Paid ' + amt.toLocaleString(undefined, { minimumFractionDigits: 2 }) + ' USDm' + (r.height ? ' · block ' + Number(r.height).toLocaleString() : ''));
      if (typeof renderBalance === 'function') renderBalance();
      setTimeout(() => { if (token === _tapPayToken) dismissCard(); }, 2400);
    } else { setMsg('err', 'Payment did not complete.'); }
  } catch (e) { setMsg('err', '' + ((e && e.message) || e)); }
}

// "Pay in person" pressed: present the card (Apple-Pay lift to center) + take Face ID, then wait-for-tap + settle.
// Fail-closed: a declined Face ID moves the card back, nothing withdraws.
async function doTapStart() {
  if (_presenting) return; // already presenting — ignore repeat taps so prompts never stack + brick the UI
  const startBtn = document.getElementById('btnTapStart');
  const nfcLabel = document.getElementById('dcNfcLabel'), nfcSub = document.getElementById('dcNfcSub');
  const card = document.getElementById('debitCard');
  const msg = document.getElementById('payMsg');
  const setMsg = (cls, txt) => { if (msg) { msg.className = 'pay-msg' + (cls ? ' ' + cls : ''); msg.textContent = txt || ''; } };
  if (startBtn) startBtn.disabled = true;
  setMsg('', '');
  if (card) card.classList.remove('dc-paid');
  presentCard();
  if (nfcLabel) nfcLabel.textContent = 'Authorizing…';
  if (nfcSub) nfcSub.textContent = 'Face ID · post-quantum';
  // ⛔ LET THE LIFT COMMIT BEFORE ANY AWAIT. Two rAFs is the yield that guarantees a COMMITTED frame:
  // the first fires before the upcoming paint, the second only after that paint has gone out. Once the
  // transform transition is committed it runs on the COMPOSITOR, so the card is already in motion by the
  // time the authorization prompt appears over it.
  //
  // This is belt-and-braces now, not the fix. The real defect was on the Rust side: `wallet_biometric_auth`
  // and `moneropay_ble_pay_nearby` were SYNCHRONOUS #[tauri::command]s, and a synchronous Tauri command
  // runs on the MAIN THREAD — the thread that renders this webview. The DOM was mutated and the thread
  // then froze before the browser painted a single frame, so nothing moved at all and the card SNAPPED
  // into place once the call returned. No amount of making the animation cheaper could have fixed that:
  // there was no animation, there was a freeze. Both commands are now `async fn` + `spawn_blocking`, so
  // the main thread stays free for the whole tap flow — through the prompt AND through the BLE scan,
  // which is where the user reported the lag.
  await new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r)));
  // ⛔ DB-373 — NO PROMPT HERE. The approval is the core's: `wallet_pos_pay` verifies the merchant's signed charge and
  // THEN asks Face ID / Touch ID with the VERIFIED amount and merchant — the user approves the charge itself, not "a
  // tap". A pre-tap prompt in this page gated only this page; any script reaching `invoke` paid unprompted.
  if (startBtn) startBtn.disabled = false;
  if (nfcLabel) nfcLabel.textContent = 'Hold near reader';
  if (nfcSub) nfcSub.textContent = 'You approve the amount next · post-quantum';
  awaitAndPayCharge(setMsg);
}
const _btnTapStart = document.getElementById('btnTapStart');
if (_btnTapStart) _btnTapStart.addEventListener('click', doTapStart);
const _btnPayCancel = document.getElementById('btnPayCancel');
if (_btnPayCancel) _btnPayCancel.addEventListener('click', () => dismissCard());
// Safety escapes so the present overlay can NEVER brick the app: click the dimmed backdrop (outside the card) or
// press Escape to slide the card back and release input. (The Cancel button + a cancelled Face ID also dismiss.)
const _payOverlayEl = document.getElementById('payOverlay');
if (_payOverlayEl) _payOverlayEl.addEventListener('click', (ev) => { if (ev.target === _payOverlayEl && _presenting) dismissCard(); });
document.addEventListener('keydown', (ev) => { if (ev.key === 'Escape' && _presenting) dismissCard(); });

// ── MERCHANT product catalog (POS) — merchant-local + persisted, so the POS runs autonomously. Add items + prices
// once; tap an item to add its price to the running sale; Charge sends the buyer the exact total (the confidential
// part is the ML-DSA-signed charge). Stored in localStorage — the merchant's own product list, not a chain asset.
const POS_CAT_KEY = 'musd.pos.catalog.v1';
let posCart = 0;
function loadPosCatalog() { try { const a = JSON.parse(localStorage.getItem(POS_CAT_KEY) || '[]'); return Array.isArray(a) ? a : []; } catch (_) { return []; } }
function savePosCatalog(list) { try { localStorage.setItem(POS_CAT_KEY, JSON.stringify(list)); } catch (_) {} }
function renderPosProducts() {
  const grid = document.getElementById('posProducts');
  if (!grid) return;
  const list = loadPosCatalog();
  grid.innerHTML = list.map((p, i) =>
    '<div class="pos-product" data-i="' + Number(i) + '" title="' + escapeHtml(p.name) + '"><span class="pp-del" data-del="' + Number(i) + '" title="Remove">×</span>' +
    (p.img ? '<img class="pp-img" src="' + escapeHtml(p.img) + '" alt="">' : '<span class="pp-img pp-img-ph" aria-hidden="true"></span>') +
    '<span class="pp-name">' + escapeHtml(p.name) + '</span>' +
    '<span class="pp-price">' + Number(p.price).toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' USDm</span></div>'
  ).join('');
  const empty = document.getElementById('posCatEmpty');
  if (empty) empty.hidden = list.length > 0;
}
function setPosCart(total) {
  posCart = Math.max(0, Math.round((Number(total) || 0) * 100) / 100);
  const cart = document.getElementById('posCart'), tot = document.getElementById('posCartTotal'), amt = document.getElementById('reqAmount');
  if (tot) tot.textContent = posCart.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 }) + ' USDm';
  if (cart) cart.hidden = posCart <= 0;
  if (amt) amt.value = posCart > 0 ? String(posCart) : '';
}
// Downscale a chosen image to a small JPEG thumbnail (data URL) so localStorage stays light even with many products.
function downscaleImage(file, max, cb) {
  try {
    const img = new Image(), url = URL.createObjectURL(file);
    img.onload = () => {
      let w = img.width || 1, h = img.height || 1;
      const s = Math.min(1, max / Math.max(w, h)); w = Math.max(1, Math.round(w * s)); h = Math.max(1, Math.round(h * s));
      const c = document.createElement('canvas'); c.width = w; c.height = h;
      const ctx = c.getContext('2d'); if (ctx) ctx.drawImage(img, 0, 0, w, h);
      let out = ''; try { out = c.toDataURL('image/jpeg', 0.82); } catch (_) { out = ''; }
      URL.revokeObjectURL(url); cb(out);
    };
    img.onerror = () => { URL.revokeObjectURL(url); cb(''); };
    img.src = url;
  } catch (_) { cb(''); }
}
function wirePosCatalog() {
  renderPosProducts();
  let pendingPhoto = ''; // thumbnail data URL for the product currently being added
  const prevImg = document.getElementById('posAddPhotoPreview'), plus = document.getElementById('posAddPhotoPlus');
  const resetPhoto = () => { pendingPhoto = ''; if (prevImg) { prevImg.src = ''; prevImg.hidden = true; } if (plus) plus.hidden = false; };
  const toggle = document.getElementById('btnPosAddToggle'), row = document.getElementById('posAddRow');
  if (toggle && row && !toggle.dataset.w) { toggle.dataset.w = '1'; toggle.addEventListener('click', () => { row.hidden = !row.hidden; const n = document.getElementById('posAddName'); if (!row.hidden && n) n.focus(); }); }
  // Photo picker: click the tile → open the hidden file input → downscale + preview the thumbnail.
  const photoBtn = document.getElementById('btnPosAddPhoto'), photoFile = document.getElementById('posAddPhotoFile');
  if (photoBtn && photoFile && !photoBtn.dataset.w) { photoBtn.dataset.w = '1';
    photoBtn.addEventListener('click', () => photoFile.click());
    photoFile.addEventListener('change', () => {
      const f = photoFile.files && photoFile.files[0]; if (!f) return;
      downscaleImage(f, 240, (dataUrl) => { pendingPhoto = dataUrl || ''; if (dataUrl && prevImg) { prevImg.src = dataUrl; prevImg.hidden = false; } if (dataUrl && plus) plus.hidden = true; });
      photoFile.value = '';
    });
  }
  const addBtn = document.getElementById('btnPosAdd');
  if (addBtn && !addBtn.dataset.w) { addBtn.dataset.w = '1'; addBtn.addEventListener('click', () => {
    const n = document.getElementById('posAddName'), pr = document.getElementById('posAddPrice');
    const name = ((n && n.value) || '').trim(), price = parseFloat(pr && pr.value);
    if (!name || !(price > 0)) { if (n) n.focus(); return; }
    const list = loadPosCatalog(); list.push({ name: name.slice(0, 40), price: Math.round(price * 100) / 100, img: pendingPhoto || '' });
    savePosCatalog(list);
    if (n) n.value = ''; if (pr) pr.value = ''; resetPhoto(); renderPosProducts(); if (n) n.focus();
  }); }
  const grid = document.getElementById('posProducts');
  if (grid && !grid.dataset.w) { grid.dataset.w = '1'; grid.addEventListener('click', (ev) => {
    const del = ev.target.closest('.pp-del');
    if (del) { const i = Number(del.getAttribute('data-del')); const list = loadPosCatalog(); if (i >= 0 && i < list.length) { list.splice(i, 1); savePosCatalog(list); renderPosProducts(); } ev.stopPropagation(); return; }
    const tile = ev.target.closest('.pos-product');
    if (tile) { const p = loadPosCatalog()[Number(tile.getAttribute('data-i'))]; if (p) setPosCart(posCart + Number(p.price)); }
  }); }
  const clr = document.getElementById('btnPosCartClear');
  if (clr && !clr.dataset.w) { clr.dataset.w = '1'; clr.addEventListener('click', () => setPosCart(0)); }
}
wirePosCatalog();
const _btnPosCancel = document.getElementById('btnPosCancel');
if (_btnPosCancel) _btnPosCancel.addEventListener('click', () => { posReset(); const a = document.getElementById('reqAmount'); if (a) a.focus(); });
// §17.6 (lane funds-brb33): what the balance says is still CONFIRMING (owned, its member leg not ready) and when it is ready —
// shown beside any refusal and on the Send button, so no press can fail on a note the chain has not folded yet.
function confirmingNote(b) {
  const c = Number((b && b.confirming_usdm) || 0);
  if (!(c > 0)) return '';
  return ' ' + c.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm is confirming — ' + String((b && b.pending_reason) || 'ready once the chain folds it') + '.';
}
let _sendGateBal = null;
async function gateSendOnSpendable() {
  const amtEl = document.getElementById('sendAmount');
  const btn = document.getElementById('btnSend');
  const st = document.getElementById('sendStatus');
  if (!amtEl || !btn) return;
  const amount = parseFloat(amtEl.value);
  if (!(amount > 0)) { btn.disabled = false; return; }
  try { _sendGateBal = await walletCore('wallet_balance'); } catch (_) { btn.disabled = false; return; }
  const sel = document.getElementById('sendAsset');
  if (sel && sel.value === 'SAT') { btn.disabled = false; return; }
  const spend = Number((_sendGateBal && _sendGateBal.usdm) || 0);
  const over = amount > spend + 1e-9;
  btn.disabled = over;
  if (st && over) { st.className = 'send-status'; st.textContent = spend.toLocaleString(undefined, { maximumFractionDigits: 8 }) + ' USDm spendable now.' + confirmingNote(_sendGateBal); }
  else if (st && st.className === 'send-status' && /spendable now/.test(st.textContent)) { st.textContent = ''; }
}
const _sendAmountEl = document.getElementById('sendAmount');
if (_sendAmountEl) _sendAmountEl.addEventListener('input', () => { gateSendOnSpendable(); });
const _sendTo = document.getElementById('sendTo');
if (_sendTo) _sendTo.addEventListener('input', () => {
  const u = parsePayUri(_sendTo.value);
  if (u) {
    _sendTo.value = u.address;
    const amtEl = document.getElementById('sendAmount');
    if (u.amount != null && !amtEl.value) amtEl.value = u.amount;
  }
});

// Settings: the SOUND authoritative "verify all funds" scan — decapsulates EVERY served note locally,
// clue-independent, so no corrupted or withheld detection clue (from a sender or a node) can hide a note you own.
// This is the completeness backstop for the fast clue-accelerated everyday balance; O(served), so it runs on press.
async function doVerifyFunds() {
  const btn = document.getElementById('btnVerifyFunds');
  const out = document.getElementById('verifyFundsOut');
  if (!btn || !out) return;
  if (btn.dataset.busy === '1') return; // re-entry guard while the scan is running
  const label = btn.textContent;
  btn.dataset.busy = '1'; btn.textContent = 'Scanning every note…';
  out.style.display = 'block';
  out.textContent = 'Decapsulating all served notes locally (clue-independent)…';
  try {
    const r = await walletCore('wallet_full_rescan');
    const usdm = (r && r.usdm != null) ? Number(r.usdm) : 0;
    const owned = (r && r.owned_notes != null) ? r.owned_notes : 0;
    const scanned = (r && r.scanned_notes != null) ? r.scanned_notes : 0;
    out.textContent = 'Authoritative balance: ' +
      usdm.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 8 }) + ' USDm\n' +
      owned + ' owned note(s) recovered · ' + scanned + ' served note(s) scanned · clue-independent';
  } catch (e) {
    out.textContent = 'Verify failed: ' + (e && e.message ? e.message : e);
  } finally {
    btn.dataset.busy = ''; btn.textContent = label;
  }
}
const _btnVerifyFunds = document.getElementById('btnVerifyFunds');
if (_btnVerifyFunds) _btnVerifyFunds.addEventListener('click', doVerifyFunds);

// --- Logout / Lock: the ONE real session-end. `wallet_lock` WIPES the in-process PQ keys in the
//     Rust core (WALLET + SCAN cleared, birth reset), so nothing sensitive survives in memory. Then
//     stop the home live-mirror poll and return to welcome — where the node-status poll resumes (the
//     node keeps running; the wallet auto-manages it — only YOUR keys leave). Both the sidebar
//     "Logout" and the Settings "Lock wallet" button call this ONE path. ---
async function logoutWallet() {
  { const bx = document.getElementById('viewSeedBox'); if (bx) { bx.classList.add('hidden'); bx.textContent = ''; } const bt = document.getElementById('btnViewSeed'); if (bt) bt.textContent = 'View recovery seed'; }
  try { await walletCore('wallet_lock'); } catch (_) {}
  if (_homeStatusTimer) { clearTimeout(_homeStatusTimer); _homeStatusTimer = null; }
  document.getElementById('homeBalance').textContent = '—';
  showScreen('screen-welcome');
  probeNode();
}
const _btnLogout = document.getElementById('btnLogout');
if (_btnLogout) _btnLogout.addEventListener('click', logoutWallet);
// ⭐ VIEW SEED (Settings): session-gated reveal of the persisted recovery phrase, for users who
// forgot/lost it. Two clicks (arm + confirm) so a stray tap never exposes it; select-all styling so
// it copies in one gesture; hidden again on Lock. cons: visible to anyone at the unlocked screen —
// the accepted device-possession model, and why Lock wallet clears it.
const _btnViewSeed = document.getElementById('btnViewSeed');
if (_btnViewSeed) _btnViewSeed.addEventListener('click', async () => {
  const box = document.getElementById('viewSeedBox');
  if (!box) return;
  if (!box.classList.contains('hidden')) { box.classList.add('hidden'); box.textContent = ''; _btnViewSeed.textContent = 'View recovery seed'; return; }
  if (_btnViewSeed.dataset.armed !== '1') { _btnViewSeed.dataset.armed = '1'; _btnViewSeed.textContent = 'Tap again to reveal (anyone at this screen will see it)'; setTimeout(() => { _btnViewSeed.dataset.armed = '0'; if (box.classList.contains('hidden')) _btnViewSeed.textContent = 'View recovery seed'; }, 5000); return; }
  _btnViewSeed.dataset.armed = '0';
  try {
    const r = await walletCore('wallet_view_seed');
    box.textContent = r.seed + (r.master_key ? '\n\nMaster key (restores the same wallet; a typo is refused by its checksum):\n' + r.master_key : '');
    box.classList.remove('hidden');
    _btnViewSeed.textContent = 'Hide recovery seed';
  } catch (e) { box.textContent = String(e); box.classList.remove('hidden'); }
});
const _btnLock = document.getElementById('btnLock');
if (_btnLock) _btnLock.addEventListener('click', logoutWallet);

// On launch, guarantee exactly one node is up — reuse a running one, else start one — then show
// live status. This is the auto-node-management the wallet owns ("the wallet IS a node"); node
// start is seconds by construction (RPC binds immediately; O(1) frontier startup).
async function initNode() {
  // Start the LIVE status poll immediately (t=0) so the welcome screen shows "Starting your node…/Connected"
  // from the first frame — never gated behind ensure_node. On iOS ensure_node returns fast now (non-blocking
  // Tor bring-up), so this ordering also keeps the UI responsive while the onion circuit warms up in the bg.
  probeNode();
  if (IN_TAURI) {
    const t0 = performance.now();
    try {
      const r = await walletCore('ensure_node');
      console.log('[node] ensure_node ' + Math.round(performance.now() - t0) + 'ms', r);
    } catch (e) {
      console.warn('[node] ensure_node failed:', e);
    }
    probeNode(); // re-probe once the node/onion path is (or is becoming) ready
  }
}
initNode();
