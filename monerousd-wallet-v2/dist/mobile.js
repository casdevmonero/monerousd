// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// THE PHONE LAYOUT. A phone gets its own design, not the desktop squeezed (user 2026-11-10). The rule, as the user
// set it the same day: a page fits the phone with NO DEAD SPACE, never moves sideways, and MAY scroll down, smoothly,
// the way MetaMask does ("allow scrolling down as well … it must be smooth … simply fit into the phone with no dead
// space"). So on a phone every page is:
//
//   title ⓘ            the page's name; ⓘ opens the page's help text, which is kept off the screen itself
//   [tab][tab][tab]     the page's sections. They stay at the top while the page scrolls, and a marker slides
//                       under the one in view
//   the page            one column that scrolls with the finger. A page shorter than the screen is stretched so its
//                       last block ends at the bottom bar: nothing is left blank
//
// Two kinds of page, told apart by the page itself:
//   - its sections are WAYS of doing one thing (Pay / POS, Buy / Sell / Trade): a tab SWITCHES what is shown
//   - its sections are parts of one page (Settings, Merchant): every part is on the page, and a tab SCROLLS to it
//
// Nothing here knows what a page does: it only decides which of the page's existing blocks are on screen. Every
// button, field and id is the desktop's own, so the two layouts can never drift apart in behaviour. A desktop window
// is never touched.
//
// TWO-PARTY-REVIEWED: page layout code, not a test; it builds no endpoint and moves no money.
'use strict';

(function () {
  const PHONE = window.matchMedia('(max-width: 720px)');

  // A page's sections on a phone: `sel` are selectors inside the page (":scope >" for a direct child), `show` runs when
  // the section opens (for pages whose own code switches panels). A page with any `show` is a page of ways: one
  // section at a time. A page not listed is cut at its own section headings.
  const SECTIONS = {
    wallet: [{ label: 'Wallet', all: true }],
    send: [
      // the card first, paying in person right under it, the @name, then the form (user 2026-11-10)
      { label: 'Pay', sel: ['#debitCard', '#btnTapStart', '#usernamePanel', '#payPanel'], show: () => window.setSendMode?.('pay') },
      { label: 'POS', sel: ['#requestPanel'], show: () => window.setSendMode?.('request') },
    ],
    buy: [
      { label: 'Buy', sel: [':scope > .card'], show: () => tap('#buyModeSeg [data-mode="buy"]') },
      { label: 'Sell', sel: [':scope > .card'], show: () => tap('#buyModeSeg [data-mode="sell"]') },
      { label: 'Trade SAT', sel: [':scope > .card'], show: () => tap('#buyModeSeg [data-mode="sat"]') },
      { label: 'History', sel: ['#swapHistory'], show: () => {} },
    ],
    earn: [{ label: 'Stake', sel: [':scope > .card.action-card'] }, { label: 'Overview', sel: ['#potCard', ':scope > .stat-hero', ':scope > .cta-link'] }],
    borrow: [{ label: 'Borrow', sel: [':scope > .card.action-card'] }, { label: 'My loans', sel: ['#borrowPositions'] }],
    governance: [
      { label: 'Validator', sel: [':scope > .stat-hero', '#becomeValidatorCard'] },
      { label: 'Delegate', sel: ['#delegateCard'] },
      { label: 'Votes', sel: ['#govVotesCard'] },
    ],
    settings: [
      { label: 'Wallet', sel: [':scope > section.card:nth-of-type(1)'] },
      { label: 'Updates', sel: ['#updateCard'] },
      { label: 'Devices', sel: [':scope > section.card:nth-of-type(3)'] },
      { label: 'Verify', sel: [':scope > section.card:nth-of-type(4)'] },
    ],
    merchant: [
      { label: 'New sale', sel: ['.mx-newsale'] },
      { label: 'Your sales', sel: ['.mx-sales', '.mx-tools'] },
      { label: 'Online shop', sel: ['.mx-online', '.mx-compare'] },
    ],
  };
  // Blocks a phone never shows because the tabs replace them.
  const NEVER = { send: [':scope > .seg'], buy: ['#buyModeSeg'], merchant: ['.mx-hero'] };

  function tap(sel) { const el = document.querySelector(sel); if (el && !el.classList.contains('active')) el.click(); }

  const state = new WeakMap(); // page -> { sections, active, switched }
  let watching = null;
  let queued = 0;

  const off = (el, yes) => { if (yes) el.setAttribute('data-m-off', ''); else el.removeAttribute('data-m-off'); };
  const own = (el) => el.classList.contains('view-head') || el.classList.contains('m-tabs');
  // shown as far as the PAGE's own code is concerned (this file's hiding does not count)
  const live = (el) => {
    const had = el.hasAttribute('data-m-off');
    if (had) el.removeAttribute('data-m-off');
    const shown = getComputedStyle(el).display !== 'none' && !el.hidden;
    if (had) el.setAttribute('data-m-off', '');
    return shown;
  };

  function sectionsOf(view) {
    const name = view.dataset.view;
    const kids = [...view.children].filter((c) => !own(c));
    const find = (sels) => sels.flatMap((s) => [...view.querySelectorAll(s)]);
    if (SECTIONS[name] && SECTIONS[name][0].all) return [{ label: SECTIONS[name][0].label, els: kids }];
    if (SECTIONS[name]) {
      const taken = new Set();
      const out = SECTIONS[name].filter((s) => !s.rest).map((s) => { const els = find(s.sel); els.forEach((e) => taken.add(e)); return { label: s.label, els, show: s.show }; });
      const rest = SECTIONS[name].find((s) => s.rest);
      if (rest) out.push({ label: rest.label, els: kids.filter((k) => !taken.has(k) && !k.classList.contains('panel-head')) });
      return out.filter((s) => s.show || s.els.length);
    }
    // cut at the page's own section headings
    const out = [{ label: 'Main', els: [] }];
    for (const k of kids) {
      if (k.classList.contains('panel-head')) out.push({ label: (k.textContent || '').trim().split(/\s+/).slice(0, 2).join(' ') || 'More', els: [] });
      else out[out.length - 1].els.push(k);
    }
    return out.filter((s) => s.els.length);
  }

  function build(view) {
    let tabs = view.querySelector(':scope > .m-tabs');
    if (!tabs) {
      tabs = document.createElement('div');
      tabs.className = 'm-tabs';
      const head = view.querySelector(':scope > .view-head');
      if (head) head.after(tabs); else view.prepend(tabs);
    }
    const head = view.querySelector(':scope > .view-head');
    if (head && !head.querySelector('.m-info')) {
      const info = document.createElement('button');
      info.type = 'button';
      info.className = 'm-info';
      info.textContent = 'i';
      info.setAttribute('aria-label', 'About this page');
      info.addEventListener('click', () => help(view));
      head.appendChild(info);
    }
    // the page scrolls: the tab in view is marked as the finger moves (one listener per page, never per layout)
    if (!view.__mSpy) {
      view.__mSpy = true;
      let frame = 0;
      view.addEventListener('scroll', () => {
        if (frame) return;
        frame = requestAnimationFrame(() => { frame = 0; spy(view); });
      }, { passive: true });
    }
    return tabs;
  }

  // The page's help text lives behind ⓘ on a phone, so the screen holds what is DONE there.
  function help(view) {
    const st = state.get(view);
    if (!st || !st.sections.length) return;
    const from = st.switched ? [st.sections[st.active]] : st.sections;
    const notes = from.flatMap((section) => section.els.flatMap((el) => [...el.querySelectorAll('.card-note:not([id]), .card-note.m-help, #posFeeNote, .mx-panel-head p, .mx-hero p')].concat(el.matches('.card-note:not([id])') ? [el] : [])));
    const sub = view.querySelector(':scope > .view-head .view-sub');
    const sheet = document.createElement('div');
    sheet.className = 'm-sheet';
    const card = document.createElement('div');
    card.className = 'm-sheet-card';
    const title = document.createElement('h3');
    const label = st.switched ? st.sections[st.active].label : 'Main';
    title.textContent = label === 'Main' ? (view.querySelector('h1') || {}).textContent || 'About' : label;
    card.appendChild(title);
    const lines = (sub && sub.textContent.trim() ? [sub.textContent.trim()] : []).concat(notes.map((n) => n.textContent.replace(/\s+/g, ' ').trim()).filter(Boolean));
    for (const text of [...new Set(lines)]) { const p = document.createElement('p'); p.textContent = text; card.appendChild(p); }
    if (!lines.length) { const p = document.createElement('p'); p.textContent = 'Everything this page does is on the screen.'; card.appendChild(p); }
    const done = document.createElement('button');
    done.type = 'button';
    done.className = 'btn btn-primary full';
    done.textContent = 'Done';
    card.appendChild(done);
    sheet.appendChild(card);
    const close = () => sheet.remove();
    done.addEventListener('click', close);
    sheet.addEventListener('click', (e) => { if (e.target === sheet) close(); });
    document.body.appendChild(sheet);
  }

  function clear(view) {
    for (const el of view.querySelectorAll('[data-m-off]')) el.removeAttribute('data-m-off');
    // a stretched block must be its own height again before anything is measured
    for (const el of view.querySelectorAll('[data-m-grow], [data-m-anchor]')) { el.removeAttribute('data-m-grow'); el.removeAttribute('data-m-anchor'); }
    const pager = view.querySelector(':scope > .m-pager');
    if (pager) pager.remove();
    view.style.removeProperty('--m-shrink');
  }

  // Where a block sits in the page's own scroll, whatever boxes it is nested in.
  const topOf = (view, el) => el.getBoundingClientRect().top - view.getBoundingClientRect().top + view.scrollTop;
  const firstShown = (section) => section.els.find((el) => el.offsetHeight > 0);
  // What stays at the top of the page while it scrolls: the tabs.
  const pinned = (view) => { const t = view.querySelector(':scope > .m-tabs'); return t && !t.hidden ? t.offsetHeight + 10 : 0; };

  // The marker under the tab in view slides to it.
  function mark(view) {
    const st = state.get(view);
    const tabs = view.querySelector(':scope > .m-tabs');
    if (!st || !tabs) return;
    [...tabs.children].forEach((b, i) => b.classList.toggle('active', i === st.active));
    const on = tabs.children[st.active];
    if (on) { tabs.style.setProperty('--m-mark-x', on.offsetLeft + 'px'); tabs.style.setProperty('--m-mark-w', on.offsetWidth + 'px'); }
  }

  // As the page scrolls: the part under the tabs is the tab that is lit, and the tabs cast a shadow once the page
  // has moved under them.
  function spy(view) {
    const st = state.get(view);
    if (!st) return;
    view.toggleAttribute('data-m-scrolled', view.scrollTop > 2);
    if (st.switched || st.sections.length < 2 || st.jumping) return;
    const line = view.scrollTop + pinned(view) + 12;
    let at = 0;
    st.sections.forEach((s, i) => { const el = firstShown(s); if (el && topOf(view, el) <= line) at = i; });
    // at the very end of the page the last part is the one in view, however short it is
    if (view.scrollTop + view.clientHeight >= view.scrollHeight - 2) at = st.sections.length - 1;
    if (at !== st.active) { st.active = at; mark(view); }
  }

  // A tab on a page of parts: glide to that part.
  function jump(view, i) {
    const st = state.get(view);
    const el = st && st.sections[i] && firstShown(st.sections[i]);
    if (!el) return;
    st.active = i;
    st.jumping = true;
    mark(view);
    const calm = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    view.scrollTo({ top: Math.max(0, topOf(view, el) - pinned(view)), behavior: calm ? 'auto' : 'smooth' });
    clearTimeout(st.landed);
    st.landed = setTimeout(() => { st.jumping = false; }, 700);
  }

  function lay(view) {
    if (!view || view.dataset.view === 'browser') return;
    const name = view.dataset.view;
    const st = state.get(view) || { active: 0 };
    state.set(view, st);
    const tabs = build(view);
    clear(view);
    for (const s of (NEVER[name] || [])) view.querySelectorAll(s).forEach((el) => el.setAttribute('data-m-never', ''));
    st.sections = sectionsOf(view);
    st.switched = st.sections.some((s) => s.show);
    if (st.active >= st.sections.length) st.active = 0;

    // the tabs: one per section. Built once per set of labels, so the marker glides instead of being redrawn.
    const labels = st.sections.map((s) => s.label).join('|');
    if (tabs.dataset.labels !== labels) {
      tabs.dataset.labels = labels;
      tabs.textContent = '';
      st.sections.forEach((s, i) => {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'm-tab';
        b.textContent = s.label;
        b.addEventListener('click', () => {
          const now = state.get(view);
          if (!now.switched) { jump(view, i); return; }
          now.active = i;
          const to = now.sections[i];
          if (to && to.show) to.show(view);
          view.scrollTop = 0;
          schedule();
        });
        tabs.appendChild(b);
      });
    }
    tabs.hidden = st.sections.length < 2;

    // a page of ways shows one way; a page of parts shows every part
    if (st.switched) {
      const mine = new Set(st.sections[st.active] ? st.sections[st.active].els : []);
      st.sections.forEach((s, i) => { if (i !== st.active) s.els.forEach((el) => { if (!mine.has(el)) off(el, true); }); });
    }
    // a way with nothing in it yet (a history before the first trade) says so: a blank screen is dead space
    let none = view.querySelector(':scope > .m-none');
    const bare = st.switched && st.sections[st.active] && !st.sections[st.active].els.some((el) => el.offsetHeight > 0);
    if (bare && !none) {
      none = document.createElement('div');
      none.className = 'm-none';
      none.textContent = 'Nothing here yet.';
      view.appendChild(none);
    } else if (!bare && none) none.remove();
    // the page's help text is one tap away behind ⓘ, not on the screen
    view.dataset.mRoomy = '0';
    compose(view);
    mark(view);
    spy(view);
  }

  // NO DEAD SPACE: a page shorter than the screen is stretched so its last block ends at the bottom bar, and that
  // block's main button sits at its foot, where a thumb is. A page longer than the screen is left alone: it scrolls.
  function compose(view) {
    if (view.scrollHeight > view.clientHeight + 1) return;
    const shown = [...view.children].filter((c) => !own(c) && c.offsetHeight > 0 && getComputedStyle(c).position !== 'absolute' && getComputedStyle(c).position !== 'fixed');
    // the last block that can take the room: usually the page's last, else the last card above a closing link or note
    const last = shown.slice().reverse().find((c) => c.matches('.card, section, .activity-list, .goods-list, .m-none'));
    if (!last) return;
    last.setAttribute('data-m-grow', '');
    const inside = [...last.children].filter((c) => c.offsetHeight > 0);
    const end = inside[inside.length - 1];
    const button = end && (end.matches('.btn-primary') ? end : (inside.length > 1 && inside[inside.length - 2].matches('.btn-primary') && end.matches('.card-note, .send-status') ? inside[inside.length - 2] : null));
    if (button) button.setAttribute('data-m-anchor', '');
  }

  // THE BOTTOM BAR: the four things a person does with money, and everything else one tap away under the menu.
  const ICON = {
    home: '<path d="M4 11.5 12 5l8 6.5V19a1 1 0 0 1-1 1h-4v-5h-6v5H5a1 1 0 0 1-1-1z"/>',
    pay: '<path d="M12 19V5"/><path d="m6 11 6-6 6 6"/>',
    get: '<path d="M12 5v14"/><path d="m6 13 6 6 6-6"/>',
    add: '<circle cx="12" cy="12" r="8.5"/><path d="M12 8v8M8 12h8"/>',
    swap: '<path d="M7 4v13"/><path d="m3.5 13.5 3.5 3.5 3.5-3.5"/><path d="M17 20V7"/><path d="m13.5 10.5 3.5-3.5 3.5 3.5"/>',
    apps: '<rect x="4" y="4" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="4" width="6.5" height="6.5" rx="1.5"/><rect x="4" y="13.5" width="6.5" height="6.5" rx="1.5"/><rect x="13.5" y="13.5" width="6.5" height="6.5" rx="1.5"/>',
  };
  const BAR = [['wallet', 'Wallet', 'home'], ['send', 'Pay', 'pay'], ['buy', 'Buy / Sell', 'swap'], ['receive', 'Receive', 'get'], ['browser', 'Browser', 'apps']];
  const svg = (name) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + ICON[name] + '</svg>';

  function go(name) { if (typeof window.switchView === 'function') window.switchView(name); }

  function bar() {
    let el = document.querySelector('.m-bar');
    if (!el) {
      el = document.createElement('nav');
      el.className = 'm-bar';
      el.setAttribute('aria-label', 'Main');
      for (const [name, label, icon] of BAR) {
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'm-bar-item';
        b.dataset.go = name;
        b.innerHTML = svg(icon);
        const text = document.createElement('span');
        text.textContent = label;
        b.appendChild(text);
        if (name === 'buy') b.classList.add('m-bar-main');
        b.addEventListener('click', () => go(name));
        el.appendChild(b);
      }
      document.body.appendChild(el);
    }
    const active = document.querySelector('.view.active');
    const at = active ? active.dataset.view : '';
    for (const b of el.children) b.classList.toggle('active', b.dataset.go === at);
    // the bar belongs to the wallet, not to the welcome or restore screens
    const nav = document.getElementById('nav');
    el.hidden = !(nav && nav.offsetParent !== null) && !(active && active.offsetParent !== null);
  }

  function run() {
    queued = 0;
    const view = document.querySelector('.view.active');
    if (watching) watching.disconnect();
    if (PHONE.matches) {
      document.documentElement.classList.add('m-phone');
      bar();
      try { lay(view); } catch (e) { console.error('[phone layout]', e); if (view) clear(view); }
    } else {
      document.documentElement.classList.remove('m-phone');
      document.querySelectorAll('.view').forEach(clear);
      document.querySelectorAll('[data-m-never]').forEach((el) => el.removeAttribute('data-m-never'));
    }
    // lay the page out again when ITS code adds, removes, shows or hides something
    const content = document.querySelector('.content');
    if (content && PHONE.matches) {
      watching = watching || new MutationObserver(changed);
      watching.observe(content, { childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'hidden', 'class', 'open'] });
    }
  }

  // a timer, not an animation frame: a page in the background gets no frames, and its layout must still be right
  function schedule() { if (!queued) queued = setTimeout(run, 16); }
  // text changing inside a block (a countdown, a status line) is not a change of what is on the page, and neither is
  // anything this file or the motion layer writes
  function changed(records) {
    const real = records.some((r) => {
      if (r.target.closest && r.target.closest('.m-tabs, .m-sheet, .m-none, .debit-card, .vx-plot')) return false;
      if (r.type === 'attributes' && r.attributeName === 'style' && r.target.classList && r.target.classList.contains('view')) return false;
      if (r.type !== 'childList') return true;
      return [...r.addedNodes, ...r.removedNodes].some((n) => n.nodeType === 1);
    });
    if (real) schedule();
  }

  // What the user is doing stays in view: a step that appears is scrolled to, gently.
  function follow(view, el) {
    if (!PHONE.matches || !view || !el || !el.scrollIntoView) return;
    const calm = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    el.scrollIntoView({ block: 'nearest', behavior: calm ? 'auto' : 'smooth' });
  }

  window.mobileLayout = { schedule, follow, open(viewName, label) {
    const view = document.querySelector('.view[data-view="' + viewName + '"]');
    const st = view && (state.get(view) || state.set(view, { active: 0 }).get(view));
    if (!st) return;
    const at = (st.sections || sectionsOf(view)).findIndex((s) => s.label === label);
    if (at >= 0) { st.active = at; view.scrollTop = 0; schedule(); }
  } };

  document.addEventListener('DOMContentLoaded', () => {
    if (typeof window.switchView === 'function') {
      const original = window.switchView;
      // a page always opens at its top
      window.switchView = function () {
        const r = original.apply(this, arguments);
        const view = document.querySelector('.view.active');
        if (view && PHONE.matches) view.scrollTop = 0;
        schedule();
        return r;
      };
    }
    PHONE.addEventListener('change', schedule);
    window.addEventListener('resize', schedule);
    window.addEventListener('orientationchange', schedule);
    schedule();
  });
})();
