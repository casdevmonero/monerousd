// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// Explorer motion — scroll reveals and the block-DAG backdrop, the same drawing monerousd.org's hero uses. The SPA
// draws its pages after this script runs, so pages call `USDM_ANIM.startDag(canvas)` for each canvas they render; a
// loop ends by itself when its canvas leaves the page. No trackers, no third-party calls.

(function () {
  var reduce = window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches;

  var io = null;
  function observeReveals() {
    var els = document.querySelectorAll('.rv:not(.in)');
    if (!('IntersectionObserver' in window) || reduce) { els.forEach(function (el) { el.classList.add('in'); }); return; }
    if (!io) {
      io = new IntersectionObserver(function (es) {
        es.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
      }, { rootMargin: '0px 0px -8% 0px' });
    }
    els.forEach(function (el) { io.observe(el); });
  }
  observeReveals();
  if ('MutationObserver' in window) {
    new MutationObserver(function () { observeReveals(); }).observe(document.body, { childList: true, subtree: true });
  }

  // Blocks appear in parallel lanes and link to the previous column, drifting left. `opts.live` brightens the newest
  // column for a moment each time `pulse()` is called (a block arrived).
  function startDag(cv, opts) {
    opts = opts || {};
    if (!cv || !cv.getContext) return { pulse: function () {} };
    var ctx = cv.getContext('2d'), W = 0, H = 0, dpr = Math.min(2, window.devicePixelRatio || 1);
    var step = opts.step || 118, speed = opts.speed || 0.026, cols = [], x0 = 0, last = performance.now(), flash = 0;
    function size() {
      W = cv.clientWidth || (cv.parentElement && cv.parentElement.clientWidth) || 800;
      H = cv.clientHeight || (cv.parentElement && cv.parentElement.clientHeight) || 400;
      cv.width = W * dpr; cv.height = H * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    function addCol(x) {
      var n = 1 + Math.floor(Math.random() * 3), c = [];
      for (var i = 0; i < n; i++) c.push({ x: x, y: H * (0.16 + 0.68 * (i + 0.5 + (Math.random() - 0.5) * 0.6) / n) });
      cols.push(c);
    }
    size();
    for (var x = 0; x < W + step * 4; x += step) addCol(x);
    window.addEventListener('resize', size);
    function frame(t) {
      if (!cv.isConnected) { window.removeEventListener('resize', size); return; }
      if (document.hidden) { last = t; requestAnimationFrame(frame); return; }
      var dt = Math.min(50, t - last); last = t;
      if (!reduce) x0 += dt * speed;
      flash = Math.max(0, flash - dt / 900);
      ctx.clearRect(0, 0, W, H);
      while (cols.length && cols[0][0].x - x0 < -step) cols.shift();
      while (cols.length && cols[cols.length - 1][0].x - x0 < W + step) addCol(cols[cols.length - 1][0].x + step);
      var fade = Math.min(280, W / 4);
      for (var i = 1; i < cols.length; i++) {
        for (var a = 0; a < cols[i].length; a++) for (var b = 0; b < cols[i - 1].length; b++) {
          var p = cols[i][a], q = cols[i - 1][b], px = p.x - x0, qx = q.x - x0;
          var al = Math.max(0, Math.min(1, px / fade, (W - px) / fade, qx / fade, (W - qx) / fade)) * 0.16;
          ctx.strokeStyle = 'rgba(255,122,0,' + al + ')'; ctx.lineWidth = 1;
          ctx.beginPath(); ctx.moveTo(qx + 14, q.y); ctx.lineTo(px - 14, p.y); ctx.stroke();
        }
      }
      var newest = -1;
      for (i = 0; i < cols.length; i++) if (cols[i][0].x - x0 < W - fade * 0.6) newest = i;
      for (i = 0; i < cols.length; i++) {
        for (a = 0; a < cols[i].length; a++) {
          var k = cols[i][a], fx = k.x - x0, e = Math.max(0, Math.min(1, fx / fade, (W - fx) / fade));
          var hot = (i === newest) ? flash : 0;
          ctx.globalAlpha = e * 0.9;
          ctx.shadowColor = 'rgba(255,102,0,' + (0.25 + hot * 0.6) + ')'; ctx.shadowBlur = 10 + hot * 18;
          ctx.fillStyle = hot > 0.05 ? 'rgba(255,122,0,' + (0.18 + hot * 0.5) + ')' : '#0f0f13';
          ctx.strokeStyle = 'rgba(255,122,0,' + (0.5 + hot * 0.5) + ')'; ctx.lineWidth = 1.2;
          ctx.beginPath();
          if (ctx.roundRect) ctx.roundRect(fx - 14, k.y - 10, 28, 20, 4); else ctx.rect(fx - 14, k.y - 10, 28, 20);
          ctx.fill(); ctx.stroke();
          ctx.shadowBlur = 0; ctx.globalAlpha = 1;
        }
      }
      requestAnimationFrame(frame);
    }
    requestAnimationFrame(frame);
    return { pulse: function () { flash = 1; } };
  }

  // Count a number up to its new value (tabular figures keep the width still).
  function countTo(el, to, fmt) {
    if (!el) return;
    fmt = fmt || function (n) { return Math.round(n).toLocaleString('en-US'); };
    var from = Number(el.dataset.v || 0);
    el.dataset.v = String(to);
    if (reduce || !isFinite(from) || from === to) { el.textContent = fmt(to); return; }
    var t0 = performance.now(), dur = 700;
    (function tick(t) {
      var f = Math.min(1, (t - t0) / dur), ease = 1 - Math.pow(1 - f, 3);
      el.textContent = fmt(from + (to - from) * ease);
      if (f < 1 && el.isConnected) requestAnimationFrame(tick);
    })(t0);
  }

  window.USDM_ANIM = { startDag: startDag, countTo: countTo, reduce: reduce };
})();
