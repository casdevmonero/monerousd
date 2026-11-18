// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// lib/wallet-connect.js — CONNECT A WALLET TO THIS WEBSITE AND TRANSACT THROUGH IT (2026-11-10).
//
// user 2026-11-10: "users should be able to connect their wallet directly to the website. in the future itll be
// offered as a browser plugin wallet"; "the wallet should be able to connect and transact on ion.monerousd.org as
// well ... in the case that it goes down then the loopback must work without stopping the blockchain communication".
//
// WHAT TALKS TO THE CHAIN: THE WALLET, NEVER THIS SITE. This file carries a page's requests to the person's own
// MoneroUSD wallet on this computer. The wallet builds, proves and broadcasts every transaction through its own node,
// and reads every pool, token, NFT and price from that node. So the same pages work the same way whether they were
// served by ion.monerousd.org or by the person's own node (http://127.0.0.1:27752/ionswap-monerousd-org/, the route
// that stays up when the official host is down): only the page files come from a host.
//
// THREE WAYS A WALLET ANSWERS, ONE INTERFACE (`window.monerousd`, the provider the earlier extension exposed):
//   1. framed by the wallet's own browser: `lib/wallet-bridge.js` installed the provider already;
//   2. a browser plugin wallet: it injects the provider and fires `monerousd#initialized`;
//   3. the wallet app running on this computer: THIS file, through the wallet's connect door on the computer's own
//      loopback address (never the network). Two carriers reach that door:
//        a. the page's own request, where the browser lets a website reach this computer (Chrome, Edge, Firefox:
//           the browser asks its own permission question once);
//        b. a small LINK WINDOW the wallet itself serves, where the browser does not (Safari, Brave). The page talks
//           to that window and the window talks to the wallet; it stays open while the site is in use.
//
// WHAT A SITE GETS. A session for its own origin, after the person approves THIS site by name in the wallet. No
// address, and no balance until the person allows this site to see balances (it asks; the wallet decides). Every
// action that moves, lists, creates or publishes anything is shown by the wallet, with its cost in dollars, and
// approved there. The wallet lists the site under Browser, Websites, where one tap ends it.
//
// THE DOOR IS SHUT UNTIL THE PERSON CONNECTS A SITE, so a website cannot tell whether a wallet is installed by
// knocking. Connect asks the computer to open the wallet for this site (`monerousd://connect`), then knocks.
//
// LOCAL-STORAGE-REQUIRED: this tab's own session (one token and the carrier it used), kept in the TAB's session store
// so a reload stays linked; nothing is written that outlives the tab.
// bound: one entry of under 200 bytes per tab, removed on disconnect and by the browser when the tab closes.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet app's connect door
// (monerousd-wallet-v2, `web3_bridge`); that crossing is exercised with the real wallet, never inside this file.

const DOOR = 'http://127.0.0.1:27751'; // the wallet's connect door (the port the earlier desktop proxy used)
// these same pages, served by the person's own node: the folder is the site's own (a page names it in a meta tag)
const SITE_FOLDER = ((document.querySelector('meta[name="monerousd-site"]') || {}).content || 'ionswap-monerousd-org').replace(/[^a-z0-9-]/gi, '');
const LOCAL_SITE = 'http://127.0.0.1:27752/' + SITE_FOLDER + '/';
const KNOCK_MS = 1500; // how often Connect knocks while the wallet is being opened or the person is deciding
const GIVE_UP_MS = 150000; // two and a half minutes to open the wallet and approve
const OFFER_WINDOW_MS = 12000; // direct knocks unanswered this long: offer the link window too
const KEPT = 'monerousd.connect.session';

/// state: 'idle' | 'opening' (the computer was asked to open the wallet) | 'continue' (press Continue to open the link
/// window) | 'waiting' (approve in the wallet) | 'linked' | 'refused' | 'absent' (no wallet answered)
export const C = { state: 'idle', why: '', balances: false, via: '', offerWindow: false, localSite: LOCAL_SITE };
const watchers = new Set();
export const onChange = (fn) => { watchers.add(fn); return () => watchers.delete(fn); };
const set = (state, more) => { Object.assign(C, { state, why: '' }, more || {}); for (const fn of watchers) { try { fn(C); } catch (_) { /* a page that is gone */ } } };

let token = '';
let via = ''; // 'direct' | 'window'
let attempt = 0; // a newer Connect press ends an older one
let win = null; // the link window
let seq = 0;
const waitingOn = new Map(); // id → resolve, for answers that come back through the link window
const pause = (ms) => new Promise((r) => setTimeout(r, ms));
const ua = navigator.userAgent || '';
const onPhone = () => /Android|iPhone|iPad|iPod/i.test(ua);
const onThisComputer = () => /^http:$/.test(location.protocol) && /^(127\.0\.0\.1|localhost)$/.test(location.hostname);
const safari = () => /^((?!chrome|chromium|android|crios|fxios|edg|opr).)*safari/i.test(ua);
const brave = () => !!(navigator.brave && typeof navigator.brave.isBrave === 'function');
/// Does this browser stop a website's own request from reaching this computer? (A page already served by this
/// computer is never stopped.)
const needsWindow = () => !onThisComputer() && (safari() || brave());
const injected = () => !!(window.monerousd && typeof window.monerousd.rpc === 'function' && !window.monerousd.__loopback);

// ── the two carriers ──────────────────────────────────────────────────────────────────────────────────────────
async function direct(route, body, waitMs) {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), waitMs || 8000);
  try {
    const opts = {
      method: 'POST', mode: 'cors', cache: 'no-store', signal: ctl.signal,
      headers: Object.assign({ 'Content-Type': 'application/json' }, token ? { Authorization: 'Bearer ' + token } : {}),
      body: JSON.stringify(body || {}),
    };
    // browsers that ask the person before a website reaches this computer want the target named
    if (typeof Request !== 'undefined' && 'targetAddressSpace' in Request.prototype) opts.targetAddressSpace = 'loopback';
    const r = await fetch(DOOR + route, opts);
    return { status: r.status, body: await r.json().catch(() => ({})) };
  } finally { clearTimeout(t); }
}
window.addEventListener('message', (ev) => {
  if (ev.origin !== DOOR || !win || ev.source !== win) return;
  const d = ev.data;
  if (d && d.type === 'monerousd:door-res' && waitingOn.has(d.id)) { const done = waitingOn.get(d.id); waitingOn.delete(d.id); done({ status: d.status, body: d.body || {} }); }
  if (d && d.type === 'monerousd:door-ready' && waitingOn.has('ready')) { const done = waitingOn.get('ready'); waitingOn.delete('ready'); done(true); }
});
function throughWindow(route, body, waitMs) {
  return new Promise((resolve, reject) => {
    if (!win || win.closed) { reject(new Error('the link window is closed')); return; }
    const id = 'd' + (++seq);
    waitingOn.set(id, resolve);
    setTimeout(() => { if (waitingOn.has(id)) { waitingOn.delete(id); reject(new Error('the wallet did not answer')); } }, waitMs || 8000);
    win.postMessage({ type: 'monerousd:door', id, route, token, body: body || {} }, DOOR);
  });
}
async function door(route, body, waitMs) {
  const r = await (via === 'window' ? throughWindow(route, body, waitMs) : direct(route, body, waitMs));
  if (r.status === 0) throw new Error('the wallet is not answering');
  return r;
}
/// Open (or find again) the link window. Called from a press, so the browser allows it. Resolves true once the
/// wallet's own page inside it says it is ready.
async function openWindow() {
  const ready = new Promise((resolve) => { waitingOn.set('ready', resolve); setTimeout(() => { if (waitingOn.has('ready')) { waitingOn.delete('ready'); resolve(false); } }, 8000); });
  win = window.open(DOOR + '/bridge', 'monerousd-link', 'popup=yes,width=440,height=430');
  if (!win) { waitingOn.delete('ready'); return false; }
  return ready;
}

// ── the provider every page already talks to ──────────────────────────────────────────────────────────────────
function install() {
  const rpc = async (method, params, waitMs) => {
    let r;
    try { r = await door('/rpc', { method: String(method || ''), params: params || {} }, Math.max(15000, waitMs || 0) + 5000); }
    catch (e) { if (via === 'window' && (!win || win.closed)) forget('The link window was closed, so this site is no longer connected. Press Connect again.'); throw e; }
    if (r.status === 401) { forget('This site is no longer connected to your wallet. Press Connect again.'); throw new Error('This site is no longer connected to your wallet.'); }
    if (r.body && r.body.ok === true) return r.body.result;
    const err = new Error((r.body && r.body.error) || 'Your wallet did not answer.');
    if (r.body && r.body.hidden) err.hidden = r.body.hidden; // the person has not let this site see that
    throw err;
  };
  window.monerousd = {
    __walletBridge: true, __loopback: true, isMoneroUSD: true,
    rpc,
    connect: () => rpc('connect'),
    getNetwork: () => rpc('getNetwork'),
    getHeight: () => rpc('getHeight'),
    getBalance: (p) => rpc('getBalance', p),
    transfer: (p) => rpc('transfer', p, 600000),
    nodeRpc: (path, body) => rpc('nodeRpc', { path, body }),
    request: (path, body) => rpc('nodeRpc', { path, body }),
    qrSvg: (data) => rpc('qrSvg', { data: String(data || '') }),
  };
  try { window.dispatchEvent(new Event('monerousd#initialized')); } catch (_) { /* the pages also ask on their own */ }
}
function keep() { try { sessionStorage.setItem(KEPT, JSON.stringify({ token, via })); } catch (_) { /* a tab with no session store stays linked until it reloads */ } }
function forget(why) {
  token = '';
  try { sessionStorage.removeItem(KEPT); } catch (_) { /* nothing was kept */ }
  if (window.monerousd && window.monerousd.__loopback) { try { delete window.monerousd; } catch (_) { window.monerousd = undefined; } }
  set('idle', { balances: false, why: why || '' });
  try { window.dispatchEvent(new Event('monerousd#gone')); } catch (_) { /* nobody listening */ }
}

/// End this site's session (the wallet forgets it too).
export async function disconnect() {
  attempt++;
  if (token) { try { await door('/disconnect', {}, 4000); } catch (_) { /* the wallet may already be closed */ } }
  if (win && !win.closed) { try { win.close(); } catch (_) { /* not ours to close */ } }
  win = null;
  forget();
}

/// Ask the wallet for this site's one grant: 'balances' (balances, holdings and activity). The person decides in the
/// wallet. (Letters are never a website's: they are read and sent in the wallet.)
export async function allow(what) {
  if (injected()) return true; // an app in the wallet's own browser rests on the wallet's own consent
  if (C.state !== 'linked') return false;
  try {
    const r = await window.monerousd.rpc('grant', { what }, 600000);
    if (r && r.granted) { set('linked', what === 'balances' ? { balances: true, via } : { balances: C.balances, via }); return true; }
  } catch (_) { /* refused or timed out: it stays hidden */ }
  return false;
}
export const showBalances = () => allow('balances');

async function knock(mine, began) {
  let request = '';
  let opened = false;
  const openWallet = () => {
    if (opened) return;
    opened = true;
    // ask this computer, once, to open the wallet for this site; with no wallet installed nothing happens
    try { const f = document.createElement('iframe'); f.style.display = 'none'; f.src = 'monerousd://connect?origin=' + encodeURIComponent(location.origin); document.body.appendChild(f); setTimeout(() => f.remove(), 4000); } catch (_) { /* the knock below finds out */ }
  };
  while (mine === attempt && Date.now() - began < GIVE_UP_MS) {
    try {
      if (!request) {
        const r = await door('/connect', { app: document.title || location.hostname }, 4000);
        if (r.status === 200 && r.body && r.body.request) { request = r.body.request; set('waiting', { via }); }
        else if (r.status === 403) openWallet(); // the wallet is up and is not taking this site yet: the link arms it for this site
      } else {
        const r = await door('/session', { request }, 4000);
        const s = r.body && r.body.status;
        if (s === 'approved' && r.body.token) {
          token = r.body.token;
          keep();
          install();
          set('linked', { balances: !!r.body.balances, via });
          return true;
        }
        if (s === 'refused') { set('refused', { why: 'The connection was refused in the wallet.' }); return false; }
        if (s === 'expired' || r.status === 404) request = ''; // the wallet was restarted: ask again
      }
    } catch (_) {
      if (via === 'window' && (!win || win.closed)) { set('idle', { why: 'The link window was closed before the wallet answered. Press Connect again.' }); return false; }
      openWallet(); // nobody answered: the wallet is closed, or its door is
      if (via === 'direct' && !onThisComputer() && Date.now() - began > OFFER_WINDOW_MS && !C.offerWindow) set(C.state, { offerWindow: true, via });
    }
    await pause(KNOCK_MS);
  }
  if (mine === attempt) set('absent', { why: 'No MoneroUSD wallet answered on this computer. Open the wallet, choose Browser, then Connect a website, and press Connect again.' });
  return false;
}

/// Connect this site to the person's wallet. Call it from a press. Resolves true when linked.
export async function connect() {
  if (injected()) { set('linked', { balances: true, via: 'wallet' }); return true; } // framed or plugin: already answering
  if (C.state === 'linked') return true;
  if (onPhone()) {
    // a phone's browser hands this same page to the wallet's own browser, where the wallet is already answering
    set('opening', { via: 'phone' });
    location.href = 'monerousd://browse?url=' + encodeURIComponent(location.href);
    await pause(2500);
    set('absent', { why: 'The MoneroUSD wallet did not open. Install it on this phone, then press Connect again.' });
    return false;
  }
  const mine = ++attempt;
  // a tab that was linked before: try its kept session first
  let kept = null;
  try { kept = JSON.parse(sessionStorage.getItem(KEPT) || 'null'); } catch (_) { kept = null; }
  if (needsWindow() || (kept && kept.via === 'window')) {
    via = 'window';
    // the wallet must be open before its link window can load: ask the computer to open it, then the person continues
    try { const f = document.createElement('iframe'); f.style.display = 'none'; f.src = 'monerousd://connect?origin=' + encodeURIComponent(location.origin); document.body.appendChild(f); setTimeout(() => f.remove(), 4000); } catch (_) { /* Continue finds out */ }
    set('continue', { via });
    return false;
  }
  via = 'direct';
  set('opening', { via, offerWindow: false });
  return knock(mine, Date.now());
}

/// The second press, for the link window: opens it and finishes connecting. Also offered when direct knocks go
/// unanswered (a browser that blocks websites from reaching this computer without saying so).
export async function continueWithWindow() {
  const mine = ++attempt;
  via = 'window';
  set('opening', { via, offerWindow: false });
  if (!(await openWindow())) {
    if (win && !win.closed) { try { win.close(); } catch (_) { /* not ours */ } }
    win = null;
    set('absent', { why: 'The wallet\'s link window did not load: the wallet is not open yet, or the browser blocked the window. Open the MoneroUSD wallet, choose Browser, then Connect a website, and press Connect again.' });
    return false;
  }
  // a kept session is still good if the wallet still knows it
  let kept = null;
  try { kept = JSON.parse(sessionStorage.getItem(KEPT) || 'null'); } catch (_) { kept = null; }
  if (kept && kept.token) {
    token = kept.token;
    try { const r = await door('/rpc', { method: 'getNetwork', params: {} }, 5000); if (r.status === 200 && r.body && r.body.ok) { install(); set('linked', { via, balances: false }); probeBalances(); return true; } } catch (_) { /* fall through to a fresh request */ }
    token = '';
  }
  return knock(mine, Date.now());
}

// whether this site may see balances is the wallet's to say (the session's own answer to `connect`)
async function probeBalances() {
  try { const me = await window.monerousd.rpc('connect'); if (me && me.balances) set('linked', { balances: true, via }); } catch (_) { /* stays hidden */ }
}

// A tab that reloads keeps its session if the wallet still knows it (direct carrier only: a link window needs a press).
(async function resume() {
  if (injected() || onPhone()) return;
  let kept = null;
  try { kept = JSON.parse(sessionStorage.getItem(KEPT) || 'null'); } catch (_) { kept = null; }
  if (!kept || !kept.token || kept.via !== 'direct') return;
  token = kept.token; via = 'direct';
  try {
    const r = await direct('/rpc', { method: 'getNetwork', params: {} }, 4000);
    if (r.status === 200 && r.body && r.body.ok) { install(); set('linked', { via, balances: false }); probeBalances(); return; }
  } catch (_) { /* the wallet is closed: the session is over */ }
  forget();
})();
