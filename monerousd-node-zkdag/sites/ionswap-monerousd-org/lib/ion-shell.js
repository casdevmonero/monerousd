// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// IonSwap's shell (2026-11-10): the ion field behind the page, the moving mark under the open section, and the
// entrance of each page. Decoration only: nothing here decides or sends anything, and `prefers-reduced-motion`
// turns all of it off.
const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;

// the mark slides to the section that is open (app.js sets `.active` on the open section's link)
function markTab() {
  const tabs = document.getElementById('tabs');
  if (!tabs) return;
  const on = tabs.querySelector('a.active');
  const mark = tabs.querySelector('.ion-tab-mark');
  if (!mark) return;
  if (!on) { mark.style.opacity = '0'; return; }
  const box = tabs.getBoundingClientRect();
  const r = on.getBoundingClientRect();
  mark.style.opacity = '1';
  mark.style.setProperty('--w', r.width + 'px');
  mark.style.setProperty('--x', r.left - box.left + tabs.scrollLeft + 'px');
  // on a phone the sections scroll sideways: keep the open one in sight
  if (on.offsetLeft < tabs.scrollLeft || on.offsetLeft + on.offsetWidth > tabs.scrollLeft + tabs.clientWidth) {
    tabs.scrollTo({ left: Math.max(0, on.offsetLeft - 24), behavior: reduced ? 'auto' : 'smooth' });
  }
}
const tabs = document.getElementById('tabs');
if (tabs) new MutationObserver(markTab).observe(tabs, { attributes: true, subtree: true, attributeFilter: ['class'] });
addEventListener('resize', markTab);
addEventListener('load', markTab);

// each page rises in as the router fills the view
const view = document.getElementById('view');
if (view && !reduced) {
  new MutationObserver((list) => {
    for (const m of list) for (const n of m.addedNodes) if (n.nodeType === 1 && n.parentNode === view) n.classList.add('ion-enter');
  }).observe(view, { childList: true });
}

// the ion field: a slow drift of charged points, joined when they pass near each other
(function field() {
  const c = document.getElementById('field');
  if (!c || reduced || !c.getContext) return;
  const g = c.getContext('2d');
  let w = 0, h = 0, pts = [], raf = 0, scale = 1;
  const size = () => {
    scale = Math.min(2, devicePixelRatio || 1);
    w = c.width = Math.floor(innerWidth * scale);
    h = c.height = Math.floor(innerHeight * scale);
    const n = Math.min(64, Math.floor((innerWidth * innerHeight) / 24000));
    pts = Array.from({ length: n }, () => ({ x: Math.random() * w, y: Math.random() * h, a: Math.random() * 6.28, s: (0.15 + Math.random() * 0.35) * scale, r: (0.8 + Math.random() * 1.6) * scale, v: Math.random() < 0.3 }));
  };
  const step = (t) => {
    g.clearRect(0, 0, w, h);
    for (const p of pts) {
      p.a += Math.sin(t / 5200 + p.x / 310) * 0.012;
      p.x += Math.cos(p.a) * p.s;
      p.y += Math.sin(p.a) * p.s;
      if (p.x < -20) p.x = w + 20;
      if (p.x > w + 20) p.x = -20;
      if (p.y < -20) p.y = h + 20;
      if (p.y > h + 20) p.y = -20;
      g.beginPath();
      g.arc(p.x, p.y, p.r, 0, 6.28);
      g.fillStyle = p.v ? 'rgba(139,123,255,.5)' : 'rgba(255,138,61,.5)';
      g.fill();
    }
    const lim = (150 * scale) ** 2;
    g.lineWidth = 1;
    for (let i = 0; i < pts.length; i++) {
      for (let j = i + 1; j < pts.length; j++) {
        const dx = pts[i].x - pts[j].x, dy = pts[i].y - pts[j].y, q = dx * dx + dy * dy;
        if (q < lim) {
          g.strokeStyle = 'rgba(255,150,80,' + 0.1 * (1 - q / lim) + ')';
          g.beginPath();
          g.moveTo(pts[i].x, pts[i].y);
          g.lineTo(pts[j].x, pts[j].y);
          g.stroke();
        }
      }
    }
    raf = requestAnimationFrame(step);
  };
  size();
  addEventListener('resize', size);
  document.addEventListener('visibilitychange', () => {
    cancelAnimationFrame(raf);
    if (!document.hidden) raf = requestAnimationFrame(step);
  });
  raf = requestAnimationFrame(step);
})();
