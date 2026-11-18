// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// IonSwap — the app's entry (rewritten 2026-11-10 as ONE app on the wallet's real commands).
//
// A hash router over a handful of pages. Each page default-exports `render(view)`. No page holds a key, builds a proof
// or talks to a server of ours: every read and every action is asked of the person's own MoneroUSD wallet, whose node
// is the backend. The wallet answers a page it frames (lib/wallet-bridge.js) and a page in an ordinary browser that
// the person connected to it (lib/wallet-connect.js, the header's Connect button); the pages cannot tell the two apart.
//
// WHAT WAS HERE BEFORE: a router over pages written for a wallet API that no longer exists (wrapped mints, a pooled
// AMM, limit and mining pages, a network switcher that re-pointed fetches). Every one of those pages failed against
// the current wallet. They are gone; nothing here calls a method the wallet does not have.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. Its second party is the wallet that frames it; that crossing is
// exercised with the real wallet and real nodes, never inside this file.
import { S, learn, provider, ask, esc, walletGone } from './lib/native.js';
import { C, onChange, connect, continueWithWindow, disconnect, showBalances } from './lib/wallet-connect.js';

const V = 'v=54'; // bump on every change so a cached page module is never mixed with a new one

const pages = {
  swap: () => import(`./pages/swap.js?${V}`),
  tokens: () => import(`./pages/tokens.js?${V}`),
  token: () => import(`./pages/tokens.js?${V}`),
  create: () => import(`./pages/create.js?${V}`),
  nfts: () => import(`./pages/nfts.js?${V}`),
  market: () => import(`./pages/market.js?${V}`),
  studio: () => import(`./pages/studio.js?${V}`),
  pools: () => import(`./pages/pools.js?${V}`),
  activity: () => import(`./pages/activity.js?${V}`),
  privacy: () => import(`./pages/privacy.js?${V}`),
};
// links people may still hold from the old app
const moved = { trade: 'tokens', portfolio: 'tokens', 'pair-detail': 'tokens', 'dark-contracts': 'tokens', 'token-create': 'create', 'nft-marketplace': 'market', nft: 'nfts', liquidity: 'pools', incognito: 'privacy', orders: 'activity', mining: 'swap', rewards: 'swap', savings: 'swap' };
// which section's tab is lit for each page
const section = { swap: 'swap', tokens: 'tokens', token: 'tokens', create: 'tokens', nfts: 'nfts', market: 'nfts', studio: 'nfts', pools: 'pools', activity: 'activity', privacy: 'swap' };

const view = document.getElementById('view');
let turn = 0;

async function route() {
  let name = (location.hash.replace(/^#\/?/, '').split('?')[0] || 'swap').toLowerCase();
  if (moved[name]) { location.replace('#/' + moved[name]); return; }
  if (!pages[name]) name = 'swap';
  const mine = ++turn;
  document.querySelectorAll('#tabs a').forEach((a) => a.classList.toggle('active', a.getAttribute('href') === '#/' + section[name]));
  document.querySelectorAll('.ion-links a').forEach((a) => a.classList.toggle('active', a.getAttribute('href').split('?')[0] === '#/' + name));
  try {
    const mod = await pages[name]();
    if (mine !== turn) return; // the user already moved on
    view.replaceChildren();
    await mod.default(view, {});
  } catch (e) {
    if (mine !== turn) return;
    view.innerHTML = '<section class="ion page"><div class="note bad">This page could not open: ' + esc(String((e && e.message) || e)) + '</div></section>';
  }
  if (mine === turn) scrollTo({ top: 0 });
}

// who the app is talking to, said once in the header
function who() {
  const btn = document.getElementById('connect-btn');
  const net = document.getElementById('network-selector');
  const tor = document.getElementById('tor-badge');
  const pop = document.getElementById('network-popover');
  if (pop) pop.hidden = true;
  if (tor) { tor.textContent = S.wallet ? 'your own node' : 'no wallet'; tor.title = S.wallet ? 'Everything here is read from, and sent through, your own wallet and its node.' : 'Connect your MoneroUSD wallet: it reads the chain and sends every transaction through its own node.'; }
  if (btn) {
    const busy = C.state === 'opening' || C.state === 'waiting' || C.state === 'continue';
    btn.textContent = S.wallet ? 'Connected' : busy ? 'Connecting…' : 'Connect wallet';
    btn.title = S.wallet ? 'Your MoneroUSD wallet is answering this site. Press for its options.' : 'Connect your MoneroUSD wallet to this site.';
    btn.classList.toggle('primary', !S.wallet);
    btn.classList.toggle('on', S.wallet);
    btn.disabled = false;
  }
  if (net) {
    net.disabled = true; // the network is the wallet's: it is shown here, never switched from a page
    if (!S.wallet) { net.textContent = '—'; return; }
    ask('getNetwork', {}, 15000).then((n) => {
      const name = String((n && (n.network || n.name || n.chainId)) || '').toLowerCase();
      net.textContent = /main/.test(name) ? 'Mainnet' : 'Testnet';
      const strip = document.getElementById('network-strip');
      if (strip) { strip.hidden = /main/.test(name); strip.textContent = 'Testnet: coins here have no value.'; }
    }).catch(() => { net.textContent = '—'; });
  }
}

// the page is drawn once; it is drawn again only when the wallet goes from absent to present
let had = false;
async function meet() {
  if (provider()) await learn();
  who();
  if (S.wallet && !had) { had = true; return true; }
  return false;
}

// ── CONNECT A WALLET ────────────────────────────────────────────────────────────────────────────────────────────
// The header button and every "Connect wallet" button a page draws (`data-connect`) start the same thing: this site
// asks the person's own wallet to link (lib/wallet-connect.js). The panel says where that stands, in the wallet's own
// words, until the wallet answers. Linked, the button opens the session's options: balances and disconnect.
const panel = document.createElement('div');
panel.id = 'connect-panel';
panel.className = 'connect-panel';
panel.hidden = true;
document.body.appendChild(panel);
let panelOpen = false;
function drawPanel() {
  if (!panelOpen) { panel.hidden = true; return; }
  const local = location.protocol === 'http:' ? '' : '<p class="muted small">The same IonSwap is also served by your own node, and works when this site is down: <a href="' + esc(C.localSite) + '">' + esc(C.localSite) + '</a></p>';
  const win = C.offerWindow ? '<p class="muted small">If your wallet is open and nothing happens, your browser may be stopping this site from reaching it.</p><button type="button" class="btn" data-connect-window>Use the link window</button>' : '';
  let body = '';
  if (S.wallet && C.state === 'linked') {
    body = '<h3>Your wallet is connected</h3><p class="muted">Every read comes from your wallet\'s own node, and every action is approved in your wallet.</p>' +
      (C.via === 'wallet' ? '' : '<p>' + (C.balances ? 'This site can see your balances and holdings.' : 'Your balances are hidden from this site.') + '</p>' +
        (C.balances ? '' : '<button type="button" class="btn primary" data-connect-balances>Show my balances here</button>') +
        '<button type="button" class="btn" data-connect-end>Disconnect</button>');
  } else if (C.state === 'opening') {
    body = '<h3>Opening your MoneroUSD wallet</h3><p class="muted">Approve this site in the wallet when it asks. If the wallet does not come up, start it and choose Browser, then Connect a website.</p>' + win;
  } else if (C.state === 'continue') {
    body = '<h3>One more press</h3><p class="muted">Your wallet is opening. When it is up, press Continue: a small window served by your wallet will carry this site\'s requests to it. Keep that window open while you use the site.</p><button type="button" class="btn primary" data-connect-window>Continue</button>';
  } else if (C.state === 'waiting') {
    body = '<h3>Approve in your wallet</h3><p class="muted">Your wallet is showing this site\'s name. Nothing is shared and nothing moves until you approve there.</p>';
  } else {
    body = '<h3>Connect your wallet</h3><p class="muted">' + esc(C.why || 'Your MoneroUSD wallet signs and sends everything this site asks for, through its own node.') + '</p><button type="button" class="btn primary" data-connect-go>Connect wallet</button>' + local;
  }
  panel.innerHTML = '<div class="connect-card" role="dialog" aria-modal="true" aria-label="Wallet connection">' + body + '<button type="button" class="btn ghost" data-connect-close>Close</button></div>';
  panel.hidden = false;
}
async function startConnect() {
  panelOpen = true;
  drawPanel();
  const done = await connect();
  if (done) { panelOpen = false; drawPanel(); }
}
document.addEventListener('click', async (ev) => {
  const t = ev.target instanceof Element ? ev.target : null;
  if (!t) return;
  if (t === panel || t.closest('[data-connect-close]')) { panelOpen = false; drawPanel(); return; }
  if (t.closest('#connect-btn')) { if (S.wallet) { panelOpen = !panelOpen; drawPanel(); } else { startConnect(); } return; }
  if (t.closest('[data-connect-go]') || t.closest('[data-connect]')) { startConnect(); return; }
  if (t.closest('[data-connect-window]')) { if (await continueWithWindow()) { panelOpen = false; drawPanel(); } return; }
  if (t.closest('[data-connect-balances]')) { t.closest('[data-connect-balances]').disabled = true; await showBalances(); panelOpen = false; drawPanel(); route(); return; }
  if (t.closest('[data-connect-end]')) { await disconnect(); panelOpen = false; drawPanel(); }
});
onChange(async () => {
  // the wallet came or went: say so in the header and draw the page again from the wallet's answers (or without them)
  if (C.state === 'idle' && S.wallet) { walletGone(); had = false; who(); route(); }
  who();
  drawPanel();
});
window.addEventListener('hashchange', route);
window.addEventListener('monerousd#initialized', async () => { if (await meet()) route(); });

(async function boot() {
  await meet();
  route();
})();
