// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// MOTION (user 2026-11-10: "impressive moving features and eye catching design"). Two things a stylesheet cannot do
// alone, on the desktop and on a phone alike:
//
//   a balance COUNTS to its new value instead of jumping to it
//   the debit card TILTS toward the pointer or the finger, and its sheen follows
//
// Everything else that moves is in styles.css (transform and opacity only). This file changes no value the wallet
// shows: a count ends on the exact text the wallet wrote, and a person who asked their device for less motion gets
// that text at once and a card that stays flat.
//
// TWO-PARTY-REVIEWED: page presentation code, not a test; it builds no endpoint and moves no money.
'use strict';

(function () {
  const calm = window.matchMedia('(prefers-reduced-motion: reduce)');

  // A plain number as the wallet writes one: "1,234.56". Anything else ("—", a sentence) is not counted to.
  function numberIn(text) {
    const t = String(text).trim();
    return /^-?\d{1,3}(,\d{3})*(\.\d+)?$|^-?\d+(\.\d+)?$/.test(t) ? parseFloat(t.replace(/,/g, '')) : null;
  }

  function counting(el) {
    if (!el) return;
    let shown = numberIn(el.textContent);
    let frame = 0;
    const watch = new MutationObserver(() => {
      const text = el.textContent.trim();
      const to = numberIn(text);
      cancelAnimationFrame(frame);
      // not a number, the same number, an element with markup inside, or a person who wants stillness: nothing to do
      if (to === null || el.children.length || calm.matches || to === shown) { shown = to; return; }
      const decimals = (text.split('.')[1] || '').length;
      const from = shown === null ? 0 : shown;
      const began = performance.now();
      const lasts = 650;
      const write = (value) => { el.textContent = value; watch.takeRecords(); };
      const step = (now) => {
        const k = Math.min(1, (now - began) / lasts);
        const eased = 1 - Math.pow(1 - k, 3);
        shown = from + (to - from) * eased;
        if (k < 1) {
          write(shown.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals }));
          frame = requestAnimationFrame(step);
        } else {
          // the last frame is the wallet's own text, exactly
          shown = to;
          write(text);
        }
      };
      write(from.toLocaleString(undefined, { minimumFractionDigits: decimals, maximumFractionDigits: decimals }));
      frame = requestAnimationFrame(step);
    });
    watch.observe(el, { childList: true, characterData: true, subtree: true });
  }

  // The card leans toward where it is touched, a few degrees, and settles when let go. While it is presented for a
  // tap (lifted to the middle of the screen) it stays flat: that motion is the wallet's own.
  function tilting(card) {
    if (!card) return;
    const rest = () => { card.style.setProperty('--tilt-x', '0'); card.style.setProperty('--tilt-y', '0'); card.removeAttribute('data-tilting'); };
    const lean = (e) => {
      if (calm.matches || card.classList.contains('dc-ready') || card.classList.contains('dc-paid') || card.closest('.pay-overlay')) { rest(); return; }
      const r = card.getBoundingClientRect();
      if (!r.width || !r.height) return;
      const x = (e.clientX - r.left) / r.width - 0.5;
      const y = (e.clientY - r.top) / r.height - 0.5;
      card.style.setProperty('--tilt-x', (x * 12).toFixed(2));
      card.style.setProperty('--tilt-y', (-y * 9).toFixed(2));
      card.style.setProperty('--glow-x', ((x + 0.5) * 100).toFixed(1) + '%');
      card.style.setProperty('--glow-y', ((y + 0.5) * 100).toFixed(1) + '%');
      card.setAttribute('data-tilting', '');
    };
    card.addEventListener('pointermove', lean);
    card.addEventListener('pointerdown', lean);
    for (const end of ['pointerleave', 'pointerup', 'pointercancel']) card.addEventListener(end, rest);
  }

  document.addEventListener('DOMContentLoaded', () => {
    counting(document.getElementById('homeBalance'));
    counting(document.getElementById('dcBal'));
    tilting(document.getElementById('debitCard'));
  });
})();
