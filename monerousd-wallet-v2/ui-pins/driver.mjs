// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// THE UI PIN DRIVER (§PRODUCT, R7) — the browser half of `src-tauri/src/ui_pins.rs`. It serves the SHIPPED `dist/` at the
// app's own origin, installs `window.__TAURI__.core.invoke` before any app script runs, and forwards every invoke over
// stdout as one JSON line `{t:"invoke",id,cmd,args}`; the Rust side answers on stdin `{id,ok,value}` from the REAL core
// through the shipped command list. It ends with one line `{t:"result",ok,steps,...}`. No test logic lives behind
// invoke: the page sees exactly what the core answered.
//
// Beside each flow's steps the driver records (and fails on) every request the page makes outside its own origin and
// every uncaught page error.
//
// THE DRIVEN A2/A3 CENSUS: every click records the `role="dialog"` it landed in (its text and its aria-describedby
// warning), and a value-moving invoke takes the record of the click that caused it. A value-moving invoke whose click
// was not inside a dialog showing a dollar figure and a warning fails the flow.
//
// Env: UI_PIN_DIST (the dist dir), UI_PIN_FLOW (a FLOWS key), UI_PIN_PLAYWRIGHT (a playwright-core dir),
// UI_PIN_VALUE_MOVING (comma-separated value-moving commands, from ui_pins.rs), UI_PIN_PLANT (a planted defect in the
// served app.js: `no_confirm` skips the dialog, `no_dollars` drops the $ from every amount — the census must fail).

import { createRequire } from 'node:module';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.UI_PIN_PLAYWRIGHT);
const DIST = path.resolve(process.env.UI_PIN_DIST);
const FLOW = process.env.UI_PIN_FLOW;
// The origin the app is served at in the harness; every other origin is a stray request.
const ORIGIN = 'http://tauri.localhost';
const STEP_TIMEOUT_MS = 15000;
const VALUE = (process.env.UI_PIN_VALUE_MOVING || '').split(',').filter(Boolean);
const PLANT = process.env.UI_PIN_PLANT || '';
const PLANTS = {
  no_confirm: ['await confirmCost(', 'await Promise.resolve(true, '],
  no_dollars: ["return '$' + n.toLocaleString('en-US'", "return '' + n.toLocaleString('en-US'"],
};
const MIME = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml',
  '.png': 'image/png', '.json': 'application/json', '.woff2': 'font/woff2', '.ico': 'image/x-icon' };

function send(o) { process.stdout.write(JSON.stringify(o) + '\n'); }

let nextId = 1;
const pending = new Map();
const invoked = [];
// The app's own events (the core speaking to its page): handed to the listeners the wallet page registered.
let walletPage = null;
function deliverEvent(name, payload) {
  if (!walletPage) return;
  walletPage.evaluate(([n, p]) => { for (const cb of ((window.__uiPinListeners || {})[n] || [])) { try { cb({ event: n, payload: p }); } catch (e) { console.error(e); } } }, [name, payload]).catch(() => {});
}
readline.createInterface({ input: process.stdin }).on('line', (l) => {
  const m = JSON.parse(l);
  if (m.t === 'event') { deliverEvent(m.name, m.payload); return; }
  const p = pending.get(m.id);
  if (!p) return;
  pending.delete(m.id);
  if (m.ok) p.resolve(m.value); else p.reject(m.value);
});
// One invoke through the Rust side — the page's bridge and a flow's own "ask the core" both use it.
function invoke(cmd, args) {
  const id = nextId++;
  invoked.push(cmd);
  send({ t: 'invoke', id, cmd, args: args || {} });
  return new Promise((resolve, reject) => pending.set(id, { resolve, reject }));
}

const steps = [];
const valueInvokes = [];
function step(name, ok, detail) { steps.push({ name, ok: !!ok, detail: detail === undefined ? '' : String(detail) }); }

// Click and report whether the confirmation dialog appeared (never throws: a missing dialog is a step verdict).
async function dialogAfter(page, selector) {
  await page.click(selector);
  return page.waitForSelector('[role="dialog"]', { timeout: 3000 }).then(() => true, () => false);
}
async function dialogText(page) { return page.$eval('[role="dialog"]', (d) => d.innerText).catch(() => ''); }
async function answerDialog(page, yes) { if (await page.$('[role="dialog"]')) await page.click('[role="dialog"] [data-confirm="' + (yes ? 'yes' : 'no') + '"]'); }
async function reachedCore(cmd, ms = 5000) {
  for (const t = Date.now(); Date.now() - t < ms;) {
    if (valueInvokes.some((v) => v.cmd === cmd)) return true;
    await new Promise((r) => setTimeout(r, 50));
  }
  return false;
}
const oneLine = (t) => t.replace(/\s+/g, ' ').slice(0, 300);
// R7 LAYER 2: the flow's arguments (from the simulator) and a live event the harness forwards to it at once
const ARGS = JSON.parse(process.env.UI_PIN_ARGS || '{}');
// The wallet's own node serves its pages and the native coins' marks from its site host on this computer. When a flow
// names that host (`node_site`), the wallet page is told its address before any script runs (as the core's network
// descriptor tells it later), and a request the page makes to it is a request to the wallet's own node, not a stray:
// it goes through to that process. Any other origin is still a stray and fails the flow.
const SITE_HOST = ARGS.node_site ? new URL(ARGS.node_site).origin : '';
function emit(o) { send(Object.assign({ t: 'emit' }, o)); }

async function createWallet(page) {
  await page.goto(ORIGIN + '/index.html');
  await page.click('#btnCreate');
  await page.waitForSelector('#screen-create:not(.hidden)');
  await page.waitForSelector('#createSeed:not(.hidden)');
  await page.click('#btnContinueCreate');
  await page.waitForSelector('#screen-home:not(.hidden)');
}

// Each flow clicks what a user clicks and returns the facts the Rust pin checks against the core.
const FLOWS = {
  // A2 + A3 DRIVEN: sell, SAT send, bond and unbond pressed the way a user presses them. Each press opens the dialog
  // before the core is asked; the dialog shows the dollars; Cancel and Escape move nothing; Confirm reaches the core.
  async value_moving_presses(page) {
    await createWallet(page);
    step('home opens', true);
    // Sell 5 USDm for XMR (the one priced asset whose reference price needs no network call from the core). Stake is
    // not pressed: the core pauses it (DB-327) and the page disables the button, which is the right answer.
    await page.click('.nav-item[data-view="buy"]');
    await page.click('#buyModeSeg [data-mode="sell"]');
    await page.click('#sellAssetSeg [data-asset="XMR"]');
    await page.click('#sellDestSeg [data-dest="outside"]'); // a Monero cash-out pays an outside Monero address
    await page.fill('#sellAmount', '5');
    await page.fill('#sellPayoutAddr', '4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge');
    let shown = await dialogAfter(page, '#btnSellUsdm');
    const sellText = await dialogText(page);
    // no dialog: the Sell screen's own answer names why (a refused quote prints there)
    const sellWhy = shown ? '' : oneLine(await page.textContent('#sellRows').catch(() => '') || '');
    // A sale's dollars come from the chain's mark, read from the node. ARGS.priced: the flow runs on a chain that publishes
    // marks (harness::ui_layer2); without one the press must show no dollars it does not have and ask the core nothing.
    if (ARGS.priced) {
      step('Sell opens the confirmation before anything moves', shown && !valueInvokes.some((v) => v.cmd === 'wallet_cash_out'), sellWhy);
      step('the sell confirmation shows $5.00 and a warning', /\$5\.00/.test(sellText) && /cannot be undone/.test(sellText), oneLine(sellText));
      // §BR-14: the flat network fee is shown in dollars, to its third decimal, before anything moves
      step('the sell confirmation shows the $0.001 network fee', /Network fee/.test(sellText) && /\$0\.001/.test(sellText), oneLine(sellText));
      step('focus starts on Cancel', await page.evaluate(() => !!(document.activeElement && document.activeElement.dataset && document.activeElement.dataset.confirm === 'no')));
      await answerDialog(page, false);
      await page.waitForTimeout(300);
      step('Cancel moves nothing', !valueInvokes.some((v) => v.cmd === 'wallet_cash_out') && !(await page.$('[role="dialog"]')));
      shown = await dialogAfter(page, '#btnSellUsdm');
      await answerDialog(page, true);
      step('Confirm asks the core to cash out', shown && await reachedCore('wallet_cash_out'));
    } else {
      step('with no chain price, Sell opens no confirmation and asks the core nothing', !shown && !valueInvokes.some((v) => v.cmd === 'wallet_cash_out'), sellWhy);
      await answerDialog(page, false);
    }

    await page.click('.nav-item[data-view="send"]');
    await page.selectOption('#sendAsset', 'SAT');
    await page.fill('#sendTo', 'usdm1qpzry9x8gf2tvdw0s3jn54khce6mua7l');
    await page.fill('#sendAmount', '2');
    shown = await dialogAfter(page, '#btnSend');
    const satText = await dialogText(page);
    step('the SAT send confirmation says plainly it has no dollar price and shows the fee in dollars',
      shown && /No dollar price available/.test(satText) && /\$0\.00/.test(satText) && /cannot be undone/.test(satText), oneLine(satText));
    await answerDialog(page, true);
    step('Confirm asks the core to send SAT', shown && await reachedCore('wallet_send_sat'));

    await page.click('.nav-item[data-view="governance"]');
    await page.fill('#bondAmount', '1');
    shown = await dialogAfter(page, '#btnBond');
    const bondText = await dialogText(page);
    step('the bond confirmation names the lock and the slashing risk', shown && /locked/.test(bondText) && /slashing/.test(bondText), oneLine(bondText));
    await answerDialog(page, true);
    step('Confirm asks the core to bond', shown && await reachedCore('wallet_bond_sat'));

    shown = await dialogAfter(page, '#btnUnbond');
    await page.keyboard.press('Escape');
    await page.waitForTimeout(300);
    step('Escape on the unbond confirmation moves nothing', shown && !valueInvokes.some((v) => v.cmd === 'wallet_unbond') && !(await page.$('[role="dialog"]')));
    return { value_invokes: valueInvokes };
  },
  // R7 F3: the checksummed master key. Create a wallet, read its address and its master key from Settings → View recovery
  // seed, lock, then on the restore screen: a key with ONE mistyped character is refused by name and opens nothing; the
  // true key reopens the SAME address.
  async restore_master_key(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => { const t = document.getElementById('homeAddress').textContent.trim(); return t && t !== '—'; });
    const address = (await page.textContent('#homeAddress')).trim();
    await page.click('.nav-item[data-view="settings"]');
    await page.click('#btnViewSeed');
    await page.click('#btnViewSeed');
    await page.waitForSelector('#viewSeedBox:not(.hidden)');
    const box = await page.textContent('#viewSeedBox');
    const m = box.match(/[0-9a-f]{64}-[0-9a-f]{8}/);
    step('Settings shows a 64-hex master key with its 8-hex checksum', !!m, oneLine(box).slice(0, 80) + '…');
    const mk = m ? m[0] : '';
    await page.click('#btnLock');
    await page.waitForSelector('#screen-welcome:not(.hidden)');
    await page.click('#btnRestore');
    await page.waitForSelector('#screen-restore:not(.hidden)');
    const typo = mk ? (mk[10] === '0' ? mk.slice(0, 10) + '1' + mk.slice(11) : mk.slice(0, 10) + '0' + mk.slice(11)) : 'x';
    await page.fill('#restoreSeed', typo);
    await page.click('#btnDoRestore');
    await page.waitForFunction(() => /fail/i.test(document.getElementById('restoreMsg').textContent));
    const typoMsg = (await page.textContent('#restoreMsg')).trim();
    step('a master key with one mistyped character is refused by its checksum', /checksum/.test(typoMsg), oneLine(typoMsg));
    step('the refused key opened no wallet', await page.isVisible('#screen-restore') && !(await page.isVisible('#screen-home')));
    const t0 = Date.now();
    await page.fill('#restoreSeed', mk.toUpperCase());
    await page.click('#btnDoRestore');
    await page.waitForSelector('#screen-home:not(.hidden)');
    const restoreMs = Date.now() - t0;
    step('the true master key (any case) opens home in under 1 s', restoreMs < 1000, restoreMs + ' ms');
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => { const t = document.getElementById('homeAddress').textContent.trim(); return t && t !== '—'; });
    const back = (await page.textContent('#homeAddress')).trim();
    step('the restored wallet shows the SAME address', back === address, back.slice(0, 16) + '… vs ' + address.slice(0, 16) + '…');
    return { address_shown: back, address_before: address, restore_ms: restoreMs };
  },
  // R7 F2: restore from the 24 words — the phrase shown at creation, typed back after a lock, reopens the SAME wallet in
  // under a second; a phrase with one word changed opens nothing.
  async restore_phrase(page) {
    await page.goto(ORIGIN + '/index.html');
    await page.click('#btnCreate');
    await page.waitForSelector('#screen-create:not(.hidden)');
    await page.waitForSelector('#createSeed:not(.hidden)');
    const words = (await page.textContent('#createSeed')).trim().split(/\s+/).filter(Boolean);
    step('the phrase shown has 24 words', words.length === 24, words.length + ' words');
    await page.click('#btnContinueCreate');
    await page.waitForSelector('#screen-home:not(.hidden)');
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => { const t = document.getElementById('homeAddress').textContent.trim(); return t && t !== '—'; });
    const address = (await page.textContent('#homeAddress')).trim();
    await page.click('.nav-item[data-view="settings"]');
    await page.click('#btnLock');
    await page.waitForSelector('#screen-welcome:not(.hidden)');
    await page.click('#btnRestore');
    await page.waitForSelector('#screen-restore:not(.hidden)');
    const changed = words.slice();
    changed[5] = changed[5] === 'abandon' ? 'ability' : 'abandon';
    await page.fill('#restoreSeed', changed.join(' '));
    await page.click('#btnDoRestore');
    await page.waitForTimeout(800);
    const opened = await page.isVisible('#screen-home');
    const back1 = opened ? (await page.click('.nav-item[data-view="receive"]'), (await page.textContent('#homeAddress')).trim()) : '';
    step('a phrase with one word changed does not reopen this wallet', !opened || back1 !== address, opened ? 'opened another wallet' : 'refused');
    if (opened) {
      await page.click('.nav-item[data-view="settings"]');
      await page.click('#btnLock');
      await page.waitForSelector('#screen-welcome:not(.hidden)');
      await page.click('#btnRestore');
      await page.waitForSelector('#screen-restore:not(.hidden)');
    }
    const t0 = Date.now();
    await page.fill('#restoreSeed', words.join(' '));
    await page.click('#btnDoRestore');
    await page.waitForSelector('#screen-home:not(.hidden)');
    const restoreMs = Date.now() - t0;
    step('the true phrase opens home in under 1 s', restoreMs < 1000, restoreMs + ' ms');
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => { const t = document.getElementById('homeAddress').textContent.trim(); return t && t !== '—'; });
    const back = (await page.textContent('#homeAddress')).trim();
    step('the restored wallet shows the SAME address', back === address, back.slice(0, 16) + '… vs ' + address.slice(0, 16) + '…');
    return { address_shown: back, address_before: address, restore_ms: restoreMs };
  },
  // AUTO-OPSEC (user 2026-10-28): on by default; turning it off shows ONE warning that the transactions will not be
  // private, Cancel keeps it on, confirming turns it off in the CORE, and turning it back on asks nothing.
  async auto_opsec_toggle(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="settings"]');
    await page.waitForFunction(() => document.getElementById('settingsOpsecState').textContent.trim() === 'on');
    step('Auto-OPSEC is on by default', true);
    const opened = await dialogAfter(page, '#settingsOpsecToggle');
    const text = await dialogText(page);
    step('turning it off opens a warning that the transactions will not be private', opened && /NOT be private/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel keeps it on', (await page.textContent('#settingsOpsecState')).trim() === 'on');
    await dialogAfter(page, '#settingsOpsecToggle');
    await answerDialog(page, true);
    await page.waitForFunction(() => /off/.test(document.getElementById('settingsOpsecState').textContent));
    const coreOff = await invoke('wallet_auto_opsec');
    step('confirming turns it off in the core', coreOff && coreOff.on === false, JSON.stringify(coreOff));
    await page.click('#settingsOpsecToggle');
    await page.waitForTimeout(300);
    step('turning it back on asks nothing', !(await page.$('[role="dialog"]')));
    const coreOn = await invoke('wallet_auto_opsec');
    step('and the core is on again', coreOn && coreOn.on === true, JSON.stringify(coreOn));
    return { on_after: coreOn && coreOn.on };
  },
  // §BR-11 "BOND MY REWARDS": OFF by default; turning it on opens ONE confirmation naming the $0.00 cost and the 21-day
  // unbonding, Cancel keeps it off, and confirming sends the switch to the core.
  async bond_rewards_toggle(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="governance"]');
    await page.waitForFunction(() => document.getElementById('bondRewardsState').textContent.trim() === 'off');
    step('Bond my rewards is off by default', true);
    const opened = await dialogAfter(page, '#bondRewardsToggle');
    const text = await dialogText(page);
    step('turning it on opens a confirmation naming $0.00 and the 21-day unbonding', opened && /\$0\.00/.test(text) && /21 days/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel keeps it off', (await page.textContent('#bondRewardsState')).trim() === 'off');
    // Confirming sends `wallet_set_bond_rewards` — a value-moving command, which this harness records at the core's door
    // and does not run (the Rust pin asserts it arrived only after the dialog above was answered).
    const reopened = await dialogAfter(page, '#bondRewardsToggle');
    await answerDialog(page, true);
    await page.waitForTimeout(300);
    step('confirming sends the switch to the core through the same dialog', reopened);
    return { confirmed: reopened };
  },
  // §22 4 "Become a validator": ONE tap opens ONE confirmation naming the $0.00 fee, that the computer must stay online, the
  // 21-day exit and what each slash costs (delegators' SAT only for theft); Cancel sends nothing; confirming sends the one-tap
  // bond (value-moving: recorded at the core's door).
  async become_validator(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="governance"]');
    await page.waitForSelector('#btnBecomeValidator');
    const opened = await dialogAfter(page, '#btnBecomeValidator');
    const text = await dialogText(page);
    step('one tap opens one confirmation naming $0.00, staying online, the 21-day exit and what a slash costs',
      opened && /\$0\.00/.test(text) && /online/.test(text) && /21 days/.test(text) && /delegated/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel sends nothing', !valueInvokes.some((v) => v.cmd === 'wallet_become_validator') && !(await page.$('[role="dialog"]')));
    const again = await dialogAfter(page, '#btnBecomeValidator');
    await answerDialog(page, true);
    await page.waitForTimeout(300);
    step('confirming sends the one-tap bond through the same dialog', again && valueInvokes.some((v) => v.cmd === 'wallet_become_validator'));
    return { confirmed: again };
  },
  // §BR-8 "Take my rewards in Bitcoin": off by default; turning it on opens one confirmation naming the per-piece network fee
  // and the privacy delay; Cancel keeps it off; confirming sends the switch (value-moving: recorded at the core's door).
  async rewards_btc_toggle(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="governance"]');
    await page.waitForFunction(() => document.getElementById('rewardsBtcState').textContent.trim() === 'off');
    step('Take my rewards in Bitcoin is off by default', true);
    const opened = await dialogAfter(page, '#rewardsBtcToggle');
    const text = await dialogText(page);
    step('turning it on opens a confirmation naming the per-piece fee in dollars and the privacy delay', opened && /\$0\.00/.test(text) && /privacy delay/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel keeps it off', (await page.textContent('#rewardsBtcState')).trim() === 'off' && !valueInvokes.some((v) => v.cmd === 'wallet_set_rewards_in_btc'));
    const reopened = await dialogAfter(page, '#rewardsBtcToggle');
    await answerDialog(page, true);
    await page.waitForTimeout(300);
    step('confirming sends the switch to the core through the same dialog', reopened && valueInvokes.some((v) => v.cmd === 'wallet_set_rewards_in_btc'));
    return { confirmed: reopened };
  },
  // §BR-8 B8-b the remixer: off by default; turning it on opens one confirmation naming the per-round Bitcoin fee in dollars;
  // Cancel keeps it off; confirming sends the switch (value-moving: recorded at the core's door).
  async remix_toggle(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="governance"]');
    await page.waitForFunction(() => document.getElementById('remixState').textContent.trim() === 'off');
    step('remixing is off by default', true);
    const opened = await dialogAfter(page, '#remixToggle');
    const text = await dialogText(page);
    step('turning it on opens a confirmation naming the per-round fee in dollars', opened && /\$0\.30/.test(text) && /network fee/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel keeps it off', (await page.textContent('#remixState')).trim() === 'off' && !valueInvokes.some((v) => v.cmd === 'wallet_set_remix'));
    const reopened = await dialogAfter(page, '#remixToggle');
    await answerDialog(page, true);
    await page.waitForTimeout(300);
    step('confirming sends the switch to the core', reopened && valueInvokes.some((v) => v.cmd === 'wallet_set_remix'));
    return { confirmed: reopened };
  },
  // R7 F7 — A SWAP THROUGH THE WALLET (IonSwap's provider call): the confirmation names what the user pays and receives in
  // dollars and the 0.25 % wallet fee BEFORE anything is built; Cancel sends nothing; confirming sends the fill to the core.
  async swap_confirm(page) {
    await createWallet(page);
    const otherHex = 'ab'.repeat(24);
    const ask = (budget) => page.evaluate(([b, other]) => {
      window.__swapDone = null;
      _dappProviderCall('swapExecute', { assetA: USDM_ASSET_TAG_HEX, assetB: other, budget: b, minOut: 1 })
        .then(() => { window.__swapDone = 'ok'; }, (e) => { window.__swapDone = String(e && (e.message || e)); });
    }, [budget, otherHex]);
    await ask(250000000);
    await page.waitForSelector('[role="dialog"]', { timeout: 5000 }).catch(() => null);
    const text = await dialogText(page);
    step('the swap opens a confirmation naming $2.50 paid and the 0.25 % wallet fee', /\$2\.50/.test(text) && /0\.25%/.test(text) && /Wallet fee/.test(text), oneLine(text));
    const shownFee = parseFloat(((text.match(/Wallet fee[^$]*\$\s?([0-9.]+)/) || [])[1]) || 'NaN');
    step('the wallet fee is shown in dollars and never under what is charged (0.25 % of $2.50 = $0.00625)', shownFee >= 0.00625 && shownFee < 0.01, oneLine(text));
    await answerDialog(page, false);
    await page.waitForFunction(() => window.__swapDone !== null, null, { timeout: 5000 }).catch(() => null);
    const declined = await page.evaluate(() => window.__swapDone);
    step('Cancel sends nothing and the app is told the user declined', /USER_DECLINED/.test(String(declined)) && !valueInvokes.some((v) => v.cmd === 'dapp_provider_swap_execute'), String(declined));
    await ask(250000000);
    await page.waitForSelector('[role="dialog"]', { timeout: 5000 }).catch(() => null);
    await answerDialog(page, true);
    await page.waitForTimeout(300);
    step('confirming sends the swap to the core through the same dialog', valueInvokes.some((v) => v.cmd === 'dapp_provider_swap_execute'));
    return { declined };
  },
  // ⭐ R7 F13 — A DSOL CALL THROUGH THE WALLET shows the PUBLISHER FEE in dollars before confirming (§BR-12): the dialog names
  // the deployed fee the app handed over ($0.50; a second contract's $2.00 — the dollars follow the manifest, never a constant)
  // and the network fee; Cancel sends nothing and the app is told the user declined; confirming reaches the core's
  // `dapp_provider_dsol_call` through the same dialog. Driven through the provider call a launchpad app makes.
  async dsol_call_confirm(page) {
    await createWallet(page);
    const callFor = (feeAtomic, tag) => ({ cid: tag.repeat(32), manifest: { code_id: 'aa'.repeat(32), publisher_fee_atomic: feeAtomic, publisher_spk: 'bb'.repeat(32), deployer_id: 'cc'.repeat(32) },
      view_ek: 'dd'.repeat(1184), code: '01', entrypoint: 'main', argv: '', height_class: 14, storage: [], state_path: { mask: '00'.repeat(32), sibs: [] } });
    const ask = (call) => page.evaluate((c) => {
      window.__dsolDone = null;
      _dappProviderCall('dsolCall', { call: c }).then(() => { window.__dsolDone = 'ok'; }, (e) => { window.__dsolDone = String(e && (e.message || e)); });
    }, call);
    await ask(callFor(50000000, 'c1'));
    await page.waitForSelector('[role="dialog"]', { timeout: 5000 }).catch(() => null);
    let text = await dialogText(page);
    step('the call opens a confirmation naming the publisher fee in dollars ($0.50) and the network fee', /Publisher fee/.test(text) && /\$0\.50/.test(text) && /Network fee/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForFunction(() => window.__dsolDone !== null, null, { timeout: 5000 }).catch(() => null);
    const declined = await page.evaluate(() => window.__dsolDone);
    step('Cancel sends nothing and the app is told the user declined', /USER_DECLINED/.test(String(declined)) && !valueInvokes.some((v) => v.cmd === 'dapp_provider_dsol_call'), String(declined));
    await ask(callFor(200000000, 'c2'));
    await page.waitForSelector('[role="dialog"]', { timeout: 5000 }).catch(() => null);
    text = await dialogText(page);
    step('a second contract\'s dialog shows ITS fee ($2.00): the dollars follow the manifest', /\$2\.00/.test(text) && !/\$0\.50/.test(text), oneLine(text));
    await answerDialog(page, true);
    step('confirming sends the call to the core through the same dialog', await reachedCore('dapp_provider_dsol_call'));
    return { declined };
  },
  // ⭐ R7 F13 LAYER 2 — CALL A DEPLOYED CONTRACT FROM THE SHIPPED WALLET (live, against a simulated node): a new wallet reports
  // its address (the simulator funds it), waits for the credit on the home screen, then calls ARGS.call through the provider's
  // one dollar confirmation naming the publisher fee; the core's real answer (the call's tx hash) reaches the simulator, which
  // asserts the PEER node's contract-state root moved and the publisher's wallet holds the fee note.
  async live_dsol_call(page) {
    await page.goto(ORIGIN + '/index.html');
    await page.click('#btnCreate');
    await page.waitForSelector('#screen-create:not(.hidden)');
    await page.waitForSelector('#createSeed:not(.hidden)');
    const words = (await page.textContent('#createSeed')).trim().split(/\s+/).filter(Boolean);
    await page.click('#btnContinueCreate');
    await page.waitForSelector('#screen-home:not(.hidden)');
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const address = (await page.textContent('#homeAddress')).trim();
    emit({ address, phrase: words.join(' ') });
    await page.click('.nav-item[data-view="wallet"]');
    const funded = await page.waitForFunction(() => parseFloat(((document.getElementById('homeBalance') || {}).textContent || '').replace(/[^0-9.]/g, '')) > 0,
      null, { timeout: ARGS.wait_ms || 600000, polling: 1000 }).then(() => true, () => false);
    step('the credit shows on the home screen', funded, await page.textContent('#homeBalance'));
    if (!funded) return { address };
    await page.evaluate((c) => {
      window.__dsolDone = null;
      _dappProviderCall('dsolCall', { call: c }).then(() => { window.__dsolDone = 'ok'; }, (e) => { window.__dsolDone = String(e && (e.message || e)); });
    }, ARGS.call);
    const opened = await page.waitForSelector('[role="dialog"]', { timeout: 10000 }).then(() => true, () => false);
    const text = await dialogText(page);
    step('the call opens one confirmation naming the publisher fee in dollars', opened && /Publisher fee/.test(text) && /\$\s?\d/.test(text), oneLine(text));
    const shownFee = parseFloat(((text.match(/Publisher fee[^$]*\$\s?([0-9.]+)/) || [])[1]) || 'NaN');
    await answerDialog(page, true);
    const done = await page.waitForFunction(() => window.__dsolDone !== null, null, { timeout: ARGS.call_wait_ms || 900000, polling: 500 }).then(() => true, () => false);
    const result = await page.evaluate(() => window.__dsolDone);
    step('the core accepted the call and submitted it', done && result === 'ok', String(result));
    return { address, called: result === 'ok', shown_fee_usd: shownFee };
  },
  // ⭐ WEBSITE CONNECT, LIVE (real nodes, the real core, the real door, the shipped wallet page AND the shipped site):
  // a browser page of IonSwap served by a host with NO node behind it (what a static official host is) connects to this
  // wallet, reads the chain through the wallet's node, is refused balances until the wallet's user allows that site,
  // and creates a token the wallet prices, approves and sends. Then that host is stopped, and the same pages served by
  // the node's own site host connect and read the chain the same way. The check that spawned this flow funds the
  // wallet and asserts the created token on the PEER node.
  async live_web3_connect(page) {
    const http = await import('node:http');
    const SITES = path.resolve(ARGS.sites_dir);
    const DOOR = 'http://127.0.0.1:27751';
    const server = http.createServer(async (req, res) => {
      const u = new URL(req.url, 'http://x');
      const rel = path.normalize(decodeURIComponent(u.pathname.endsWith('/') ? u.pathname + 'index.html' : u.pathname));
      const file = path.join(SITES, rel);
      if (!file.startsWith(SITES + path.sep) || u.pathname.includes('/api/')) { res.writeHead(404); res.end(); return; }
      try { const body = await readFile(file); res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' }); res.end(body); }
      catch (_) { res.writeHead(404); res.end(); }
    });
    await new Promise((r) => server.listen(0, '127.0.0.1', r));
    const A = 'http://127.0.0.1:' + server.address().port; // the static-only host
    const B = ARGS.node_site || 'http://127.0.0.1:27752'; // the same pages, served by the node's own site host
    const siteCtx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
    siteCtx.setDefaultTimeout(STEP_TIMEOUT_MS);
    let site = await siteCtx.newPage();
    const siteErrors = [];
    site.on('pageerror', (e) => siteErrors.push(String(e && e.message || e)));
    const rpc = (method, params, ms) => site.evaluate(([m, p, w]) => window.monerousd.rpc(m, p || {}, w || 30000).then((r) => ({ ok: r }), (e) => ({ err: String(e.message || e), hidden: e.hidden || '' })), [method, params, ms]);
    const approveInWallet = async (must) => {
      const shown = await page.waitForSelector('[role="dialog"]', { timeout: 30000 }).then(() => true, () => false);
      const text = shown ? await dialogText(page) : '';
      const ok = shown && must.every((m) => (m instanceof RegExp ? m.test(text) : text.includes(m)));
      if (shown) await answerDialog(page, true);
      return { ok, text: oneLine(text) };
    };

    // 1. the wallet, funded by the check that runs this flow
    await createWallet(page);
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const address = (await page.textContent('#homeAddress')).trim();
    emit({ address });
    await page.click('.nav-item[data-view="wallet"]');
    const funded = await page.waitForFunction(() => parseFloat(((document.getElementById('homeBalance') || {}).textContent || '').replace(/[^0-9.]/g, '')) > 0,
      null, { timeout: ARGS.wait_ms || 600000, polling: 1000 }).then(() => true, () => false);
    step('the credit shows on the wallet\'s home screen', funded, await page.textContent('#homeBalance'));
    if (!funded) return { address };

    // 2. the site with no wallet: it offers Connect, shows no dead end, and the wallet's door does not answer it
    await site.goto(A + '/ionswap-monerousd-org/#/pools');
    await site.waitForSelector('#connect-btn');
    await site.waitForSelector('[data-connect]');
    const before = await site.evaluate(() => ({ btn: document.getElementById('connect-btn').textContent.trim(), text: document.body.innerText }));
    step('with no wallet the site offers Connect wallet and no dead end', /Connect wallet/.test(before.btn) && !/inside the MoneroUSD wallet|Open in the (MoneroUSD )?wallet|Open IonSwap/i.test(before.text), before.btn);
    const shut = await site.evaluate(async (door) => { try { await fetch(door + '/connect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' }); return 'answered'; } catch (_) { return 'no answer'; } }, DOOR);
    step('the wallet\'s door does not answer a site before its user opens it', shut === 'no answer', shut);

    // 3. the user opens the door, the site asks, the wallet names the site, the user approves
    await page.click('.nav-item[data-view="browser"]');
    await page.waitForSelector('#web3Arm');
    await page.click('#web3Arm');
    await page.waitForFunction(() => /Ready/.test((document.getElementById('web3Said') || {}).textContent || ''));
    await site.click('#connect-btn');
    const ask = await approveInWallet([A.replace('http://', ''), /cannot see your address or your balances/]);
    step('the wallet names the site and says what it cannot see, before anything is shared', ask.ok, ask.text);
    const linked = await site.waitForFunction(() => /Connected/.test(document.getElementById('connect-btn').textContent), null, { timeout: 60000 }).then(() => true, () => false);
    step('the site is connected after the approval', linked, (await site.textContent('#connect-btn')).trim());
    if (!linked) return { address };
    const tokenA = await site.evaluate(() => { try { return JSON.parse(sessionStorage.getItem('monerousd.connect.session')).token; } catch (_) { return ''; } });

    // 4. the chain is read THROUGH THE WALLET'S NODE: this host has no node and answers no /api route
    const assets = await rpc('nativeAssets');
    const names = assets.ok && Array.isArray(assets.ok.assets) ? assets.ok.assets.map((a) => a.sym + ':' + (a.usd || 0)) : [];
    step('the site reads the chain\'s assets and prices through the wallet\'s node', names.length >= 2, names.join(' ') || assets.err);
    const height = await rpc('getHeight');
    step('the site reads the chain\'s height through the wallet\'s node', !!height.ok, JSON.stringify(height).slice(0, 140));

    // 5. protections on by default: a session name and no address; no balance until the user allows THIS site
    const me = await rpc('connect');
    step('connecting hands the site a session name and no address', !!(me.ok && me.ok.session && me.ok.address === ''), JSON.stringify(me).slice(0, 160));
    const hid = await rpc('assets');
    step('balances are hidden from the site by default', hid.hidden === 'balances', JSON.stringify(hid).slice(0, 160));
    await site.click('#connect-btn');
    await site.click('[data-connect-balances]');
    const grant = await approveInWallet([/asks to see your balances/, A]);
    step('the wallet asks before a site sees balances, naming the site', grant.ok, grant.text);
    let held = { err: 'not read' };
    for (const t = Date.now(); Date.now() - t < 60000;) { held = await rpc('assets'); if (held.ok) break; await new Promise((r) => setTimeout(r, 1500)); }
    const holds = held.ok && Array.isArray(held.ok.assets) ? held.ok.assets.filter((a) => Number(a.atomic) > 0).length : 0;
    step('allowed, the site sees what the wallet holds', holds > 0, JSON.stringify(held).slice(0, 200));

    // 6. TRANSACT from the site: the page asks, the wallet prices it in dollars and asks, the core builds and sends it
    await site.goto(A + '/ionswap-monerousd-org/#/create');
    await site.waitForSelector('#crSym');
    await site.fill('#crSym', ARGS.symbol);
    await site.fill('#crName', 'Website Connect Check');
    await site.fill('#crSupply', '1000');
    const priced = await site.waitForFunction(() => { const b = document.getElementById('crGo'); return b && !b.disabled; }, null, { timeout: 60000 }).then(() => true, () => false);
    step('the site shows the chain\'s creation price, read through the wallet', priced, oneLine(await site.textContent('#crFacts')));
    let tag = '';
    if (priced) {
      await site.click('#crGo');
      const create = await approveInWallet([ARGS.symbol, /\$\s?\d/]);
      step('the wallet shows the creation and its price in dollars before anything moves', create.ok, create.text);
      const made = await site.waitForSelector('#crDone .cardtext', { timeout: ARGS.call_wait_ms || 900000 }).then(() => true, () => false);
      tag = made ? await site.evaluate(() => { const a = document.querySelector('#crBtns a'); return a ? String(a.getAttribute('href').split('t=')[1] || '') : ''; }) : '';
      step('the site shows the token the wallet created and sent', made && /^[0-9a-f]{48}$/.test(tag), tag || oneLine(await site.textContent('#crMsg').catch(() => '')));
      emit({ created: tag });
    }

    // 7. THE HOST GOES DOWN: the same pages, served by the node's own site host, connect and read the chain the same way
    await new Promise((r) => { server.close(r); if (server.closeAllConnections) server.closeAllConnections(); });
    const down = await site.goto(A + '/ionswap-monerousd-org/', { timeout: 6000 }).then(() => 'still up', () => 'down');
    step('the static host is down', down === 'down', down);
    // the person opens the node-served copy in a new tab (the old tab is showing the browser's own error page)
    await site.close().catch(() => {});
    site = await siteCtx.newPage();
    site.on('pageerror', (e) => siteErrors.push(String(e && e.message || e)));
    await page.click('#web3Arm');
    await page.waitForFunction(() => /Ready/.test((document.getElementById('web3Said') || {}).textContent || ''));
    await site.goto(B + '/ionswap-monerousd-org/#/swap');
    await site.waitForSelector('#connect-btn');
    await site.click('#connect-btn');
    const ask2 = await approveInWallet([B.replace('http://', '')]);
    const linked2 = await site.waitForFunction(() => /Connected/.test(document.getElementById('connect-btn').textContent), null, { timeout: 60000 }).then(() => true, () => false);
    const assets2 = linked2 ? await rpc('nativeAssets') : { err: 'not connected' };
    step('with that host down, the node-served copy connects to the same wallet and reads the chain', ask2.ok && linked2 && !!assets2.ok, ask2.text + ' | ' + JSON.stringify(assets2).slice(0, 120));
    // 8. one site's session is its own: the first site's token does nothing from the second site
    const stolen = await site.evaluate(async ([door, tok]) => { try { const r = await fetch(door + '/rpc', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: 'Bearer ' + tok }, body: JSON.stringify({ method: 'getHeight' }) }); return r.status; } catch (_) { return 0; } }, [DOOR, tokenA]);
    step('the first site\'s session token does nothing from another site', stolen === 401, String(stolen));
    step('the site pages raised no uncaught error', siteErrors.length === 0, siteErrors.join(' | '));
    await siteCtx.close();
    return { address, created: tag };
  },
  // §BR-3 17.3 DELEGATE SAT: a new wallet lists no delegation; Delegate with no amount is refused on screen; Delegate opens
  // ONE confirmation naming $0.00, the 21 days and the slash risk, Cancel sends nothing, confirming sends the delegation;
  // Undelegate all opens its own confirmation naming the 21 days.
  // ⭐ R7 F5 LAYER 2 — SEND FROM THE SHIPPED WALLET (live, against a simulated node): a new wallet reports its receive address
  // (the simulator funds it), waits until the home screen shows the credit, then pays ARGS.amount USDm to ARGS.to through the
  // Send screen's one dollar confirmation; the payment must be broadcast. The simulator then asserts the PEER node holds it.
  async live_send(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const address = (await page.textContent('#homeAddress')).trim();
    step('the receive screen shows this wallet\'s address', address.length > 40, address.slice(0, 24));
    emit({ address });
    await page.click('.nav-item[data-view="wallet"]');
    const funded = await page.waitForFunction(() => {
      const t = (document.getElementById('homeBalance') || {}).textContent || '';
      return parseFloat(t.replace(/[^0-9.]/g, '')) > 0;
    }, null, { timeout: ARGS.wait_ms || 600000, polling: 1000 }).then(() => true, () => false);
    step('the credit shows on the home screen', funded, await page.textContent('#homeBalance'));
    if (!funded) return { address };
    await page.click('.nav-item[data-view="send"]');
    await page.fill('#sendTo', String(ARGS.to || ''));
    await page.fill('#sendAmount', String(ARGS.amount || ''));
    const opened = await dialogAfter(page, '#btnSend');
    const text = await dialogText(page);
    step('Send opens one confirmation naming the dollars', opened && /\$\s?\d/.test(text), oneLine(text));
    await answerDialog(page, true);
    const broadcast = await page.waitForFunction(() => /Broadcast|Confirmed/.test((document.getElementById('sendStatus') || {}).textContent || ''), null, { timeout: 180000, polling: 500 })
      .then(() => true, () => false);
    step('the payment is broadcast', broadcast, oneLine(await page.textContent('#sendStatus')));
    return { address };
  },
  // ⭐ R7 F9 LAYER 2 — stake USDm from the shipped Earn screen: the confirmation names the dollars staked, the Earn screen
  // shows the stake once a block applies it and the holder yield IN DOLLARS a year beside the live APR, and Unstake opens
  // its own confirmation and returns the principal. The flow reports its 24 words and address (the simulator funds it,
  // then reads the stake back through the PEER node with the same words) and returns what the screen showed.
  async live_stake(page) {
    await page.goto(ORIGIN + '/index.html');
    await page.click('#btnCreate');
    await page.waitForSelector('#screen-create:not(.hidden)');
    await page.waitForSelector('#createSeed:not(.hidden)');
    const words = (await page.textContent('#createSeed')).trim().split(/\s+/).filter(Boolean);
    await page.click('#btnContinueCreate');
    await page.waitForSelector('#screen-home:not(.hidden)');
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const address = (await page.textContent('#homeAddress')).trim();
    emit({ address, phrase: words.join(' ') });
    await page.click('.nav-item[data-view="wallet"]');
    const funded = await page.waitForFunction(() => parseFloat(((document.getElementById('homeBalance') || {}).textContent || '').replace(/[^0-9.]/g, '')) > 0,
      null, { timeout: ARGS.wait_ms || 600000, polling: 1000 }).then(() => true, () => false);
    step('the credit shows on the home screen', funded, await page.textContent('#homeBalance'));
    if (!funded) return { address };
    await page.click('.nav-item[data-view="earn"]');
    await page.waitForFunction(() => !(document.getElementById('btnStake') || { disabled: true }).disabled, null, { timeout: 120000, polling: 1000 }).catch(() => {});
    const paused = await page.$eval('#btnStake', (b) => b.disabled).catch(() => true);
    step('Stake is enabled (the core is not paused)', !paused, await page.textContent('#stakeStatus').catch(() => ''));
    const amount = Number(ARGS.amount || 5);
    await page.fill('#stakeAmount', String(amount));
    const opened = await dialogAfter(page, '#btnStake');
    const text = await dialogText(page);
    step('Stake opens one confirmation naming the dollars staked', opened && /You stake/.test(text) && /\$\s?\d/.test(text), oneLine(text));
    await answerDialog(page, true);
    const staked = await page.waitForFunction(() => /✓ Staked/.test((document.getElementById('stakeStatus') || {}).textContent || ''), null, { timeout: 300000, polling: 1000 })
      .then(() => true, () => false);
    step('the stake is published', staked, oneLine(await page.textContent('#stakeStatus')));
    if (!staked) return { address };
    // "Your stake" reads the amount once the next block applies it; the page re-reads the core on its own timer.
    const shown = await page.waitForFunction((want) => {
      const t = (document.getElementById('earnStaked') || {}).textContent || '';
      return parseFloat(t.replace(/[^0-9.]/g, '')) >= want;
    }, amount, { timeout: ARGS.wait_ms || 600000, polling: 1000 }).then(() => true, () => false);
    step('Your stake shows the staked USDm', shown, await page.textContent('#earnStaked'));
    if (shown) emit({ staked: true }); // the simulator reads the stake through the PEER node now, while it stands
    const yieldUsd = (await page.textContent('#earnYieldUsd').catch(() => '')).trim();
    step('the holder yield is shown in dollars a year', /^\$\s?[\d,]+(\.\d+)?/.test(yieldUsd), yieldUsd + ' · live APR ' + (await page.textContent('#earnApr')).trim());
    // §17.6: the screen enables Unstake only once the core's own dry run says the stake can be spent now (the chain folded
    // it) — the flow waits for that, as the user would, and reports how long it took and what the screen said meanwhile.
    const tEnable = Date.now();
    const enabled = await page.waitForFunction(() => !(document.getElementById('btnUnstake') || { disabled: true }).disabled, null, { timeout: ARGS.wait_ms || 600000, polling: 1000 }).then(() => true, () => false);
    const pendingShown = (await page.textContent('#earnStakePending').catch(() => '')).trim();
    step('Unstake is enabled once the stake is ready to spend', enabled, 'after ' + Math.round((Date.now() - tEnable) / 1000) + ' s' + (pendingShown ? ' · pending line read: ' + oneLine(pendingShown) : ''));
    const unstakeOpened = await dialogAfter(page, '#btnUnstake');
    const unstakeText = await dialogText(page);
    step('Unstake opens its own confirmation', unstakeOpened && /Unstake/.test(unstakeText), oneLine(unstakeText));
    await answerDialog(page, true);
    // A stake just applied may not be provable yet ("its member leg is not ready"): the core refuses by name and nothing moves.
    // That is a "right now" refusal — the user presses again once the chain carries the path; so does the flow, until wait_ms.
    const settle = async () => page.waitForFunction(() => /✓ Unstaking|Failed:/.test((document.getElementById('claimStatus') || {}).textContent || ''), null, { timeout: 300000, polling: 1000 })
      .then(() => page.textContent('#claimStatus').catch(() => ''), () => '');
    let unstakeStatus = await settle();
    const until = Date.now() + (ARGS.wait_ms || 600000);
    let presses = 1;
    while (!/✓ Unstaking/.test(unstakeStatus) && /not ready|cannot be proved yet/.test(unstakeStatus) && Date.now() < until) {
      await page.waitForTimeout(5000);
      if (await dialogAfter(page, '#btnUnstake')) await answerDialog(page, true);
      presses += 1;
      unstakeStatus = await settle();
    }
    const unstaked = /✓ Unstaking/.test(unstakeStatus);
    step('the unstake is published and names the principal returned', unstaked, oneLine(unstakeStatus) + ' (after ' + presses + ' press' + (presses === 1 ? '' : 'es') + ')');
    return { address, amount, yield_usd: yieldUsd, presses };
  },
  // ⭐ R7 F12 LAYER 2 — the merchant half of tap-to-pay on the shipped Receive screen: the fee note names 0.5 %, Charge
  // mints a signed charge and shows the terminal with the signed amount; the flow reports the charge (the simulator's
  // payer wallet pays it over the tap protocol's payment path) and waits for the terminal to read "✓ Paid" from the chain.
  async live_pos_charge(page) {
    await page.goto(ORIGIN + '/index.html');
    await page.click('#btnCreate');
    await page.waitForSelector('#screen-create:not(.hidden)');
    await page.waitForSelector('#createSeed:not(.hidden)');
    const words = (await page.textContent('#createSeed')).trim().split(/\s+/).filter(Boolean);
    await page.click('#btnContinueCreate');
    await page.waitForSelector('#screen-home:not(.hidden)');
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const address = (await page.textContent('#homeAddress')).trim();
    const feeNote = (await page.textContent('#posFeeNote').catch(() => '')).trim();
    step('the POS screen names the merchant fee of 0.5 % before any charge', /0\.5\s?%/.test(feeNote), oneLine(feeNote));
    await page.click('.nav-item[data-view="send"]'); // the Pay / POS segment lives under the debit card on the Send screen
    await page.click('#segRequest'); // the POS segment opens the tap-to-pay terminal's entry
    await page.waitForFunction(() => (document.getElementById('requestPanel') || { style: {} }).style.display !== 'none', null, { timeout: 15000, polling: 200 });
    const amount = Number(ARGS.amount || 2.5);
    await page.fill('#reqAmount', String(amount));
    await page.click('#btnRequest');
    const terminal = await page.waitForFunction(() => (document.getElementById('posTerminal') || { style: {} }).style.display !== 'none', null, { timeout: 120000, polling: 500 })
      .then(() => true, () => false);
    step('Charge shows the tap-to-pay terminal', terminal, await page.textContent('#posStatus').catch(() => ''));
    const signed = (await page.textContent('#posAmount').catch(() => '')).trim();
    step('the terminal shows the amount the charge signed', parseFloat(signed.replace(/[^0-9.]/g, '')) === amount, signed);
    const charge = await page.evaluate(() => (typeof state !== 'undefined' && state.posCharge) || null);
    step('the page holds the signed charge it is advertising', !!(charge && charge.sig && charge.nonce), charge ? Object.keys(charge).join(',') : 'none');
    emit({ address, phrase: words.join(' '), charge });
    const paid = await page.waitForFunction(() => /✓ Paid/.test((document.getElementById('posStatus') || {}).textContent || ''), null, { timeout: ARGS.wait_ms || 600000, polling: 1000 })
      .then(() => true, () => false);
    step('the terminal reads the payment from the chain', paid, oneLine(await page.textContent('#posStatus').catch(() => '')));
    return { address, amount, status: (await page.textContent('#posStatus').catch(() => '')).trim() };
  },
  // ⭐ R7 F2 LAYER 2, run 1 — a new wallet in the shipped UI shows its 24 words; it reports them and its address (the
  // simulator funds it) and waits until the home screen shows the credit.
  async live_fund_report(page) {
    await page.goto(ORIGIN + '/index.html');
    await page.click('#btnCreate');
    await page.waitForSelector('#screen-create:not(.hidden)');
    await page.waitForSelector('#createSeed:not(.hidden)');
    const words = (await page.textContent('#createSeed')).trim().split(/\s+/).filter(Boolean);
    step('the phrase shown has 24 words', words.length === 24, words.length + ' words');
    await page.click('#btnContinueCreate');
    await page.waitForSelector('#screen-home:not(.hidden)');
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const address = (await page.textContent('#homeAddress')).trim();
    emit({ address, phrase: words.join(' ') });
    await page.click('.nav-item[data-view="wallet"]');
    const funded = await page.waitForFunction(() => parseFloat(((document.getElementById('homeBalance') || {}).textContent || '').replace(/[^0-9.]/g, '')) > 0,
      null, { timeout: ARGS.wait_ms || 600000, polling: 1000 }).then(() => true, () => false);
    step('the credit shows on the home screen', funded, await page.textContent('#homeBalance'));
    return { address };
  },
  // ⭐ R7 F2 LAYER 2, run 2 — a FRESH install restores ARGS.phrase: home opens in under 1 s, the same address returns, the
  // balance comes back and the history lists the credit — all read from the chain through the simulated node.
  async live_restore(page) {
    await page.goto(ORIGIN + '/index.html');
    await page.click('#btnRestore');
    await page.waitForSelector('#screen-restore:not(.hidden)');
    const t0 = Date.now();
    await page.fill('#restoreSeed', String(ARGS.phrase || ''));
    await page.click('#btnDoRestore');
    await page.waitForSelector('#screen-home:not(.hidden)');
    const restoreMs = Date.now() - t0;
    step('the 24 words open home in under 1 s', restoreMs < 1000, restoreMs + ' ms');
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const address = (await page.textContent('#homeAddress')).trim();
    step('the restored wallet shows the SAME address', address === ARGS.address, address.slice(0, 16) + '…');
    await page.click('.nav-item[data-view="wallet"]');
    const balance = await page.waitForFunction(() => parseFloat(((document.getElementById('homeBalance') || {}).textContent || '').replace(/[^0-9.]/g, '')) > 0,
      null, { timeout: ARGS.wait_ms || 600000, polling: 1000 }).then(() => true, () => false);
    step('the balance comes back from the chain', balance, await page.textContent('#homeBalance'));
    await page.click('.nav-item[data-view="activity"]');
    const history = await page.waitForFunction(() => {
      const l = document.getElementById('activityList');
      return l && l.querySelectorAll('.activity-row, [data-tx], li').length > 0 && !/Open to scan/.test(l.textContent);
    }, null, { timeout: 120000, polling: 1000 }).then(() => true, () => false);
    step('the history lists the credit', history, oneLine(await page.textContent('#activityList')));
    return { address, restore_ms: restoreMs };
  },
  // ⭐ R7 F6 LAYER 2 — CASH OUT TO BITCOIN FROM THE SHIPPED WALLET (live, against a simulated node priced by its validators):
  // a funded wallet opens Cash out; the privacy delay is on by default (Auto-OPSEC: each piece in a random batch within 24
  // hours); the quote and the one dollar confirmation say so; Cancel sends nothing; with Auto-OPSEC off the quote and the
  // dialog say "next batch, less private"; back on, confirming stages the pieces (§19.4) and the screen shows the plan's
  // honest progress (parts sent of total, hours left). The simulator then asserts the PEER holds every staged note.
  // ⭐ §BR-4 (R7 F8) — with no price on the chain the Borrow page says so and opens no dialog.
  async borrow_no_price(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="borrow"]');
    const said = await page.waitForFunction(() => /not available yet/.test((document.getElementById('borrowStatus') || {}).textContent || ''), null, { timeout: 30000 })
      .then(() => true, () => false);
    step('with no price the Borrow page says borrowing is not available yet', said, oneLine(await page.textContent('#borrowStatus')));
    await page.click('#btnBorrow');
    await page.waitForTimeout(300);
    step('Borrow with nothing to choose opens no dialog and sends nothing', !(await page.$('[role="dialog"]')) && !valueInvokes.some((v) => v.cmd === 'wallet_borrow_open'));
    return {};
  },
  // ⭐⭐ §BR-4 (R7 F8, A4) LIVE — borrow 10 USDm against Bitcoin from the shipped wallet, then repay it: the options are priced in
  // dollars, the confirmation names the liquidation price and that the Bitcoin is not returned if it is liquidated, Cancel
  // sends nothing; the deposit address appears (the simulator funds it); the loan shows as minted with its distance to
  // liquidation; Repay names the debt and the Bitcoin returned, and confirming relays the close.
  async live_borrow(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    emit({ address: (await page.textContent('#homeAddress')).trim() });
    await page.click('.nav-item[data-view="borrow"]');
    const priced = await page.waitForFunction(() => (document.getElementById('borrowSize') || {}).options && document.getElementById('borrowSize').options.length > 0, null, { timeout: ARGS.quote_ms || 600000, polling: 1000 })
      .then(() => true, () => false);
    step('the Borrow page offers sizes and safety bands priced in dollars', priced && /\$\s?\d/.test(await page.textContent('#borrowBand')), oneLine(await page.textContent('#borrowBand')));
    if (!priced) return {};
    await page.selectOption('#borrowSize', '0');
    await page.waitForTimeout(200);
    let opened = await dialogAfter(page, '#btnBorrow');
    let text = await dialogText(page);
    step('Borrow opens one confirmation in dollars naming the liquidation price and that the Bitcoin is not returned if liquidated',
      opened && /\$\s?\d/.test(text) && /Liquidation price/.test(text) && /do not get it back/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel sends nothing', !valueInvokes.some((v) => v.cmd === 'wallet_borrow_open'));
    await dialogAfter(page, '#btnBorrow');
    await answerDialog(page, true);
    const shown = await page.waitForFunction(() => /\S{40,}/.test(((document.getElementById('borrowAddress') || {}).textContent) || ''), null, { timeout: 120000, polling: 500 })
      .then(() => true, () => false);
    step('confirming shows the deposit address and the exact Bitcoin to send', shown,
      oneLine((await page.textContent('#borrowDeposit')) + ' | ' + (await page.textContent('#borrowStatus'))));
    if (!shown) return {};
    const btcText = await page.textContent('#borrowDeposit');
    const btc = parseFloat(((btcText.match(/Send ([0-9.]+) BTC/) || [])[1]) || '0');
    emit({ btc_address: (await page.textContent('#borrowAddress')).trim(), btc });
    const minted = await page.waitForFunction(() => /minted/.test((document.getElementById('borrowPositions') || {}).textContent || ''), null, { timeout: ARGS.wait_ms || 1800000, polling: 2000 })
      .then(() => true, () => false);
    step('the loan shows as open, with what it owes and how far Bitcoin is from its liquidation price', minted && /owes/.test(await page.textContent('#borrowPositions')) && /above it/.test(await page.textContent('#borrowPositions')),
      oneLine(await page.textContent('#borrowPositions')));
    if (!minted) return {};
    // the repayment needs one note covering the debt and the fee: the simulator's faucet credit is that note
    await page.waitForFunction(() => parseFloat(((document.getElementById('homeBalance') || {}).textContent || '').replace(/[^0-9.]/g, '')) > 11, null, { timeout: ARGS.wait_ms || 1800000, polling: 2000 }).catch(() => {});
    await page.fill('.borrow-payout', String(ARGS.payout || ''));
    opened = await dialogAfter(page, '.borrow-repay');
    text = await dialogText(page);
    step('Repay opens one confirmation naming the debt in dollars, the Bitcoin returned and the address warning',
      opened && /You repay/.test(text) && /Bitcoin returned/.test(text) && /cannot be recovered/.test(text), oneLine(text));
    await answerDialog(page, true);
    const repaid = await page.waitForFunction(() => /on its way back/.test(((document.querySelector('.borrow-repay-status') || {}).textContent) || ''), null, { timeout: ARGS.wait_ms || 1800000, polling: 1000 })
      .then(() => true, () => false);
    step('confirming relays the repayment and says the Bitcoin is on its way back', repaid, oneLine(((await page.$eval('#borrowPositions', (d) => d.innerText).catch(() => '')) || '')));
    return {};
  },
  async live_cash_out(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    emit({ address: (await page.textContent('#homeAddress')).trim() });
    await page.click('.nav-item[data-view="wallet"]');
    const funded = await page.waitForFunction(() => parseFloat(((document.getElementById('homeBalance') || {}).textContent || '').replace(/[^0-9.]/g, '')) > 0,
      null, { timeout: ARGS.wait_ms || 600000, polling: 1000 }).then(() => true, () => false);
    step('the credit shows on the home screen', funded, await page.textContent('#homeBalance'));
    if (!funded) return {};
    await page.click('.nav-item[data-view="buy"]');
    await page.click('#buyModeSeg [data-mode="sell"]');
    await page.waitForSelector('#sellForm:not(.hidden)');
    step('the privacy delay is on by default', /on/.test(await page.textContent('#sellOpsecState')) && /random batch within 24 hours/.test(await page.textContent('#sellOpsecHint')), oneLine(await page.textContent('#sellOpsecHint')));
    const quoteSays = async (re) => page.waitForFunction((src) => new RegExp(src).test((document.getElementById('sellReceiveCalc') || {}).textContent || ''), re.source, { timeout: ARGS.quote_ms || 120000, polling: 500 })
      .then(() => true, () => false);
    await page.fill('#sellAmount', String(ARGS.amount || ''));
    const priced = await quoteSays(/piece[\s\S]*random batches/);
    step('the quote names the pieces and the random batches before anything is asked', priced, oneLine(await page.textContent('#sellReceiveCalc')));
    let opened = await dialogAfter(page, '#btnSellUsdm');
    let text = await dialogText(page);
    step('Cash out opens one confirmation in dollars naming the random batches within 24 hours', opened && /\$\s?\d/.test(text) && /random batch within 24 hours/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel sends nothing', !valueInvokes.some((v) => v.cmd === 'wallet_cash_out'));
    await dialogAfter(page, '#sellOpsecToggle');
    text = await dialogText(page);
    step('turning Auto-OPSEC off warns that it will not be private', /NOT be private/.test(text), oneLine(text));
    await answerDialog(page, true);
    await page.waitForFunction(() => /off/.test(document.getElementById('sellOpsecState').textContent));
    await page.fill('#sellAmount', '');
    await page.fill('#sellAmount', String(ARGS.amount || ''));
    step('with it off the quote says next batch, less private', await quoteSays(/next batch \(less private\)/), oneLine(await page.textContent('#sellReceiveCalc')));
    opened = await dialogAfter(page, '#btnSellUsdm');
    text = await dialogText(page);
    step('and the confirmation warns the timing can be matched', opened && /Fast is on/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    await page.click('#sellOpsecToggle');
    await page.waitForFunction(() => /on/.test(document.getElementById('sellOpsecState').textContent));
    await page.fill('#sellAmount', '');
    await page.fill('#sellAmount', String(ARGS.amount || ''));
    await quoteSays(/random batches/);
    await dialogAfter(page, '#btnSellUsdm');
    await answerDialog(page, true);
    // at least one piece really staged (§19.4: "0 of 3 pieces set aside" would mean every piece failed)
    const burned = await page.waitForFunction(() => /[1-9]\d* of \d+ pieces set aside/.test((document.getElementById('sellRows') || {}).textContent || ''), null, { timeout: ARGS.burn_ms || 600000, polling: 1000 })
      .then(() => true, () => false);
    step('confirming stages the pieces for their private claims', burned, oneLine(await page.textContent('#sellRows')));
    const progress = await page.waitForFunction(() => /parts sent/.test((document.getElementById('cashOutPlans') || {}).textContent || '') && /h left/.test((document.getElementById('cashOutPlans') || {}).textContent || ''),
      null, { timeout: 60000, polling: 1000 }).then(() => true, () => false);
    const plans = oneLine(await page.textContent('#cashOutPlans'));
    step('the plan shows honest progress: parts sent of total and the hours left', progress, plans);
    step('no piece of the cash-out failed', !/⚠/.test(plans), plans);
    return {};
  },
  // ⭐ R7 F4 LAYER 2 — ADD MONEY WITH BITCOIN, PRIVATELY, FROM THE SHIPPED WALLET (live, against a simulated node and simulated
  // Bitcoin): Auto-OPSEC on by default sends a Bitcoin deposit through the entry mix; the one confirmation names the dollars,
  // the Bitcoin network fees and the minutes; Cancel starts nothing; confirming shows ONE vault address to send to; the
  // simulator funds it on Bitcoin (other people mix beside it); the screen reports the rounds honestly; the USDm arrives on the
  // home screen. The simulator then asserts the PEER serves the balance to a fresh restore of the same words.
  async live_add_btc(page) {
    await page.goto(ORIGIN + '/index.html');
    await page.click('#btnCreate');
    await page.waitForSelector('#screen-create:not(.hidden)');
    await page.waitForSelector('#createSeed:not(.hidden)');
    const words = (await page.textContent('#createSeed')).trim().split(/\s+/).filter(Boolean);
    await page.click('#btnContinueCreate');
    await page.waitForSelector('#screen-home:not(.hidden)');
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const usdmAddress = (await page.textContent('#homeAddress')).trim();
    await page.click('.nav-item[data-view="buy"]');
    await page.waitForSelector('#buyForm:not(.hidden)');
    await page.click('#buyUnitToggle');
    await page.fill('#buyAmount', String(ARGS.btc || ''));
    let opened = await dialogAfter(page, '#btnBuyQuote');
    let text = await dialogText(page);
    step('Auto-OPSEC on by default: the deposit is the private one, its confirmation names the dollars, the Bitcoin fees and the minutes',
      opened && /privately/.test(text) && /\$\s?\d/.test(text) && /Bitcoin network fees/.test(text) && /min/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel starts nothing', !invoked.includes('wallet_mix_start'));
    await dialogAfter(page, '#btnBuyQuote');
    await answerDialog(page, true);
    const shown = await page.waitForFunction(() => /\S{40,}/.test(((document.querySelector('#buyRows .mix-plan .mono') || {}).textContent) || ''), null, { timeout: 60000, polling: 500 })
      .then(() => true, () => false);
    const address = shown ? (await page.textContent('#buyRows .mix-plan .mono')).trim() : '';
    step('confirming shows one vault address to send Bitcoin to', shown, address.slice(0, 16));
    if (!shown) return {};
    emit({ btc_address: address, address: usdmAddress, phrase: words.join(' ') });
    const rounds = await page.waitForFunction(() => /[1-9]\d* step\(s\) done/.test(((document.querySelector('#buyRows .mix-plan') || {}).textContent) || ''), null, { timeout: ARGS.wait_ms || 900000, polling: 1000 })
      .then(() => true, () => false);
    step('the screen reports the mixing rounds as they finish', rounds, oneLine(((await page.$eval('#buyRows', (d) => d.innerText).catch(() => '')) || '')));
    await page.click('.nav-item[data-view="wallet"]');
    const funded = await page.waitForFunction(() => parseFloat(((document.getElementById('homeBalance') || {}).textContent || '').replace(/[^0-9.]/g, '')) > 0,
      null, { timeout: ARGS.wait_ms || 900000, polling: 1000 }).then(() => true, () => false);
    step('the USDm arrives on the home screen', funded, await page.textContent('#homeBalance'));
    return {};
  },
  // ⭐ ADOPTABLE A1 — GETTING USDm TAKES THREE TAPS OR FEWER FROM A FRESH INSTALL: every click is counted from the first page
  // load until a Bitcoin address that mints USDm is on screen; the address is the core's own open plan, and the costs are shown
  // in dollars (or said to be pending a price) beside it before anything is sent.
  // ⭐ §BR-15 R7 F16 — BUY SAT on the shipped Buy screen: "You get: SAT" offers USDm as a way to pay (and only then), the
  // receive line asks the core's book (the SAT market closed on a chain with no launch position says so, never a made-up
  // quote), the button reads "Buy SAT", and pressing it asks the core's book and opens no dialog while the market is closed —
  // nothing value-moving is sent. Leaving SAT takes USDm off the pay choices again.
  async buy_sat_screen(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="buy"]');
    await page.waitForSelector('#buyGetSat');
    step('Pay with USDm is hidden while buying USDm', await page.$eval('#buyPayUsdm', (b) => b.classList.contains('hidden')));
    await page.click('#buyGetSat');
    step('choosing SAT offers USDm as a way to pay', !(await page.$eval('#buyPayUsdm', (b) => b.classList.contains('hidden'))));
    step('the button reads Buy SAT', (await page.textContent('#btnBuyQuote')).trim() === 'Buy SAT');
    await page.click('#buyPayUsdm');
    await page.fill('#buyAmount', '25');
    await page.dispatchEvent('#buyAmount', 'input');
    const said = await page.waitForFunction(() => /SAT/.test((document.getElementById('buyReceiveCalc') || {}).textContent || ''), null, { timeout: 15000 })
      .then(() => true, () => false);
    const calc = oneLine(await page.textContent('#buyReceiveCalc'));
    step('the receive line answers from the core\'s book (a quote in SAT, or that the market is not open / not readable)', said && /SAT/.test(calc), calc);
    step('the core\'s book was asked', invoked.includes('wallet_defi_book'));
    await page.click('#btnBuyQuote');
    await page.waitForTimeout(800);
    const rows = oneLine(await page.textContent('#buyRows'));
    step('with the market closed the press opens no dialog and sends nothing', !(await page.$('[role="dialog"]')) && !valueInvokes.some((v) => v.cmd === 'wallet_buy_sat'), rows);
    await page.click('#buyGetSeg [data-get="USDM"]');
    step('leaving SAT takes USDm off the pay choices', await page.$eval('#buyPayUsdm', (b) => b.classList.contains('hidden')));
    return {};
  },
  async add_money_three_taps(page) {
    let taps = 0;
    const tap = async (sel) => { taps += 1; await page.click(sel); };
    await page.goto(ORIGIN + '/index.html');
    await tap('#btnCreate');
    await page.waitForSelector('#createSeed:not(.hidden)');
    const words = (await page.textContent('#createSeed')).trim().split(/\s+/).filter(Boolean);
    step('the first tap shows the 24 words to write down', words.length === 24, words.length + ' words');
    await tap('#btnContinueCreate');
    await page.waitForSelector('#screen-home:not(.hidden)');
    await tap('#btnAddMoney');
    const shown = await page.waitForFunction(() => /\S{40,}/.test(((document.querySelector('#buyRows .mix-plan .mono') || {}).textContent) || ''), null, { timeout: 30000, polling: 250 })
      .then(() => true, () => false);
    const address = shown ? (await page.textContent('#buyRows .mix-plan .mono')).trim() : '';
    step('a Bitcoin address that mints USDm is on screen after ' + taps + ' taps (three or fewer)', shown && taps <= 3, address.slice(0, 16));
    const plans = await invoke('wallet_mix_progress');
    const held = ((plans && plans.plans) || []).some((p) => p.receive_address === address);
    step('the address is the core\'s own open deposit plan', held, JSON.stringify(plans).slice(0, 200));
    const costs = (await page.textContent('#addMoneyCosts')) || '';
    step('the costs are shown beside it before anything is sent', /Wallet fee/.test(costs) && /0\.10%/.test(costs) && (/\$\s?\d/.test(costs) || /shown in dollars as soon as/.test(costs)), oneLine(costs));
    return { taps };
  },
  // ⭐ R7 F11 LAYER 2, the RECEIVER — a new wallet reports its address and waits until its own inbox (the wallet's own read,
  // `wallet_letter_inbox`) holds a letter; it reports what arrived and from whom.
  async live_letter_receiver(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const address = (await page.textContent('#homeAddress')).trim();
    emit({ receiver: address });
    let got = null;
    for (const t = Date.now(); Date.now() - t < (ARGS.wait_ms || 600000);) {
      const inbox = await invoke('wallet_letter_inbox').catch(() => null);
      const msgs = (inbox && (inbox.letters || inbox.messages || inbox.inbox)) || [];
      if (msgs.length) { got = msgs[0]; break; }
      await new Promise((r) => setTimeout(r, 2000));
    }
    step('a letter arrives in this wallet\'s own inbox', !!got, JSON.stringify(got).slice(0, 200));
    return { letter_from: got && got.from, letter_msg: got && got.msg };
  },
  // ⭐ R7 F11 LAYER 2, the SENDER — claims @ARGS.name on the Pay screen through its one dollar confirmation (the yearly fee
  // and the published-forever warning), publishes a profile, and sends a private letter to ARGS.to.
  async live_names_and_letter(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => /\S{40,}/.test((document.getElementById('homeAddress') || {}).textContent || ''), null, { timeout: 60000 });
    const address = (await page.textContent('#homeAddress')).trim();
    emit({ sender: address });
    await page.click('.nav-item[data-view="send"]');
    await page.fill('#nameInput', String(ARGS.name || ''));
    const opened = await dialogAfter(page, '#btnClaimName');
    const text = await dialogText(page);
    step('claiming a @username opens one confirmation naming its yearly fee in dollars and that it is published', opened && /\$\s?\d/.test(text) && /published/.test(text), oneLine(text));
    await answerDialog(page, true);
    const claimed = await page.waitForFunction(() => /is yours/.test((document.getElementById('nameStatus') || {}).textContent || ''), null, { timeout: 180000, polling: 500 })
      .then(() => true, () => false);
    step('the @username is claimed', claimed, oneLine(await page.textContent('#nameStatus')));
    const prof = await page.evaluate(() => _dappProviderCall('profileSet', { display: 'Ada', bio: 'pays in USDm', feeMicro: 0, avatar: '' }).then(() => 'ok', (e) => String(e && (e.message || e))));
    step('the profile publishes', prof === 'ok', prof);
    const sent = await page.evaluate((to) => _dappProviderCall('letterSend', { to, msg: 'hello from the shipped wallet' }).then((r) => JSON.stringify(r), (e) => 'ERR ' + String(e && (e.message || e))), String(ARGS.to || ''));
    step('a private letter is sealed and relayed', !/^ERR/.test(sent), sent.slice(0, 160));
    return { sender: address };
  },
  async delegate_sat(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="governance"]');
    await page.waitForSelector('#delegateCard');
    await page.waitForFunction(() => /no delegated SAT/.test(document.getElementById('delegateList').textContent));
    step('a new wallet lists no delegation', true);
    await page.click('#btnDelegate');
    await page.waitForTimeout(200);
    const noAmt = (await page.textContent('#delegateStatus')).trim();
    step('Delegate with no amount is refused on screen, with no dialog', /Enter a SAT amount/.test(noAmt) && !(await page.$('[role="dialog"]')), noAmt);
    await page.fill('#delegateAmount', '0.5');
    const opened = await dialogAfter(page, '#btnDelegate');
    const text = await dialogText(page);
    step('Delegate opens a confirmation naming $0.00, the 21 days and the slash risk', opened && /\$0\.00/.test(text) && /21 days/.test(text) && /slashed/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel sends nothing', !valueInvokes.some((v) => v.cmd === 'wallet_delegate_sat') && !(await page.$('[role="dialog"]')));
    const again = await dialogAfter(page, '#btnDelegate');
    await answerDialog(page, true);
    await page.waitForTimeout(300);
    step('confirming sends the delegation through the same dialog', again && valueInvokes.some((v) => v.cmd === 'wallet_delegate_sat'));
    const un = await dialogAfter(page, '#btnUndelegate');
    const unText = await dialogText(page);
    step('Undelegate all opens its own confirmation naming the 21 days', un && /21-day/.test(unText) && /\$0\.00/.test(unText), oneLine(unText));
    await answerDialog(page, true);
    await page.waitForTimeout(300);
    return { delegated: again, undelegated: un };
  },
  // §BR-3 17.6 STAKE USDm (R7 Earn): a new wallet's Stake is enabled with Claim and Unstake disabled (nothing staked); Stake
  // with no amount is refused on screen; Stake opens ONE confirmation naming the dollars, unstake-any-time and the fee pool,
  // Cancel sends nothing, confirming sends the stake.
  async stake_usdm(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="earn"]');
    await page.waitForFunction(() => { const b = document.getElementById('btnStake'); return b && !b.disabled; });
    const dis = await page.evaluate(() => [document.getElementById('btnClaimReward').disabled, document.getElementById('btnUnstake').disabled]);
    step('a new wallet can stake, and Claim and Unstake are disabled with nothing staked', dis[0] && dis[1], JSON.stringify(dis));
    await page.click('#btnStake');
    await page.waitForTimeout(200);
    const noAmt = (await page.textContent('#stakeStatus')).trim();
    step('Stake with no amount is refused on screen, with no dialog', /positive amount/.test(noAmt) && !(await page.$('[role="dialog"]')), noAmt);
    await page.fill('#stakeAmount', '5');
    const opened = await dialogAfter(page, '#btnStake');
    const text = await dialogText(page);
    step('Stake opens a confirmation naming $5.00, unstake any time and the fee pool', opened && /\$5\.00/.test(text) && /unstake/.test(text) && /network fees/.test(text), oneLine(text));
    await answerDialog(page, false);
    await page.waitForTimeout(300);
    step('Cancel sends nothing', !valueInvokes.some((v) => v.cmd === 'wallet_stake') && !(await page.$('[role="dialog"]')));
    const again = await dialogAfter(page, '#btnStake');
    await answerDialog(page, true);
    await page.waitForTimeout(300);
    step('confirming sends the stake through the same dialog', again && valueInvokes.some((v) => v.cmd === 'wallet_stake'));
    return { staked: again };
  },
  // R7 F12: the merchant sees the POS fee (0.5 %, beside the card networks' 2–3 %) before charging anyone.
  async pos_fee_shown(page) {
    await createWallet(page);
    const html = await page.evaluate(() => { const n = document.getElementById('posFeeNote'); const e = document.getElementById('posEntry');
      return { text: n ? n.textContent : '', inEntry: !!(n && e && e.contains(n)) }; });
    step('the POS fee note sits on the entry screen, before any charge', html.inEntry, JSON.stringify(html));
    step('it names the 0.5 % fee and the card networks\' 2–3 %', /0\.5%/.test(html.text) && /2–3%/.test(html.text), html.text);
    return html;
  },
  // R7 F14: the Updates card reads the core: up to date (no release three builders attest), never an install button.
  async update_card(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="settings"]');
    await page.waitForFunction(() => /Up to date|Update available|could not check/.test(document.getElementById('updateState').textContent));
    const state = (await page.textContent('#updateState')).trim();
    step('the Updates card shows the core\'s answer', /Up to date \(v\d/.test(state), state);
    step('with nothing attested there is nothing to install', await page.$eval('#btnVerifyRelease', (b) => b.classList.contains('hidden')));
    step('the card was filled by the core\'s own command', invoked.includes('wallet_update_status'));
    return { state };
  },
  // R7 F15: the miner card shows the miner pool's payout in plain language beside "Bond my rewards".
  async miner_pool_shown(page) {
    await createWallet(page);
    await page.click('.nav-item[data-view="governance"]');
    await page.waitForFunction(() => !/Miner pool: —$/.test(document.getElementById('minerPoolLine').textContent));
    const line = (await page.textContent('#minerPoolLine')).trim();
    step('the miner pool line names its payout in plain language (or says plainly the node has not answered)', /per block this quarter|no payout this quarter yet|node has not answered/.test(line), line);
    step('Bond my rewards sits on the same card, off by default', (await page.textContent('#bondRewardsState')).trim() === 'off');
    return { line };
  },
  async create_opens_home(page) {
    await page.goto(ORIGIN + '/index.html');
    await page.click('#btnCreate');
    await page.waitForSelector('#screen-create:not(.hidden)');
    const t0 = Date.now();
    await page.waitForSelector('#createSeed:not(.hidden)');
    const genMs = Date.now() - t0;
    const words = (await page.textContent('#createSeed')).trim().split(/\s+/).filter(Boolean);
    step('the phrase shown has 24 words', words.length === 24, words.length + ' words');
    step('the continue button appears only after the phrase', await page.isVisible('#btnContinueCreate'));
    await page.click('#btnContinueCreate');
    await page.waitForSelector('#screen-home:not(.hidden)');
    step('home opens', true);
    await page.click('.nav-item[data-view="receive"]');
    await page.waitForFunction(() => {
      const t = document.getElementById('homeAddress').textContent.trim();
      return t && t !== '—';
    });
    const address = (await page.textContent('#homeAddress')).trim();
    step('the Receive view shows an address', address.length > 0, address.length + ' chars');
    return { address_shown: address, generate_ms: genMs };
  },
};

const result = { t: 'result', flow: FLOW, ok: false, steps, stray_requests: [], page_errors: [] };
let browser;
try {
  if (!FLOWS[FLOW]) throw new Error('no such flow: ' + FLOW);
  browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1280, height: 860 } });
  ctx.setDefaultTimeout(STEP_TIMEOUT_MS);
  await ctx.route('**/*', async (route) => {
    const u = new URL(route.request().url());
    if (SITE_HOST && u.origin === SITE_HOST) return route.continue();
    if (u.origin !== ORIGIN) {
      result.stray_requests.push(u.href);
      return route.abort();
    }
    const rel = path.normalize(decodeURIComponent(u.pathname === '/' ? '/index.html' : u.pathname));
    const file = path.join(DIST, rel);
    if (!file.startsWith(DIST + path.sep)) return route.abort();
    try {
      let body = await readFile(file);
      if (PLANT && path.basename(file) === 'app.js') {
        const [from, to] = PLANTS[PLANT] || [];
        const src = body.toString('utf8');
        if (!from || !src.includes(from)) throw new Error('the plant ' + PLANT + ' found nothing to change');
        body = Buffer.from(src.split(from).join(to), 'utf8');
      }
      return route.fulfill({ status: 200, body, contentType: MIME[path.extname(file)] || 'application/octet-stream' });
    } catch (_) {
      return route.fulfill({ status: 404, body: '' });
    }
  });
  await ctx.exposeFunction('__uiPinInvoke', (cmd, args, dialog) => {
    if (VALUE.includes(cmd)) valueInvokes.push({ cmd, dialog });
    return invoke(cmd, args);
  });
  await ctx.addInitScript((value) => {
    // Every click records the dialog it landed in (or null); a value-moving invoke takes that record and clears it.
    window.__uiPinDialog = null;
    window.addEventListener('click', (ev) => {
      const d = ev.target && ev.target.closest ? ev.target.closest('[role="dialog"]') : null;
      const w = d && document.getElementById(d.getAttribute('aria-describedby') || '');
      window.__uiPinDialog = d ? { text: d.innerText, warning: w ? w.innerText : '' } : null;
    }, true);
    window.__uiPinListeners = {};
    window.__TAURI__ = { core: { invoke: (cmd, args) => {
      let d = null;
      if (value.includes(cmd)) { d = window.__uiPinDialog; window.__uiPinDialog = null; }
      return window.__uiPinInvoke(cmd, args === undefined ? {} : args, d);
    } },
    // the app's event channel: the page registers, the harness delivers what the core emits
    event: { listen: (name, cb) => { (window.__uiPinListeners[name] = window.__uiPinListeners[name] || []).push(cb); return Promise.resolve(() => {}); } } };
  }, VALUE);
  await ctx.addInitScript((host) => { if (host) window.__MONEROUSD_SITE_HOST__ = host; }, SITE_HOST);
  const page = await ctx.newPage();
  walletPage = page;
  page.on('pageerror', (e) => result.page_errors.push(String(e && e.message || e)));
  try {
    const facts = await FLOWS[FLOW](page);
    Object.assign(result, facts || {});
  } finally {
    const bare = valueInvokes.filter((v) => !(v.dialog && /\$\s?\d/.test(v.dialog.text) && v.dialog.warning.trim().length > 20));
    step('every value-moving invoke followed a click in a dialog showing dollars and a warning', bare.length === 0,
      bare.map((v) => v.cmd + (v.dialog ? ': ' + oneLine(v.dialog.text) : ': no dialog')).join(' | '));
  }
  step('the page made no request outside its own origin', result.stray_requests.length === 0, result.stray_requests.join(' '));
  step('no uncaught page error', result.page_errors.length === 0, result.page_errors.join(' | '));
  result.ok = steps.length > 0 && steps.every((s) => s.ok);
} catch (e) {
  step('the flow ran to its end', false, e && e.message || e);
  result.ok = false;
} finally {
  result.invoked = invoked;
  send(result);
  if (browser) await browser.close();
  process.exit(0);
}
