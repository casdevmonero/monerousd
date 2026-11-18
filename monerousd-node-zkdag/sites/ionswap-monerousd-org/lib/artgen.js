// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// lib/artgen.js — one photo in, a collection out (2026-11-10).
//
// EVERYTHING HERE RUNS ON THIS DEVICE. The photo is drawn to a canvas in this page and never leaves it: no upload, no
// outside service, no model in the cloud. That is a privacy rule of the chain this app belongs to, and it is also why
// the generator is made of drawing code, not a remote image model.
//
// HOW A COLLECTION IS MADE. Every piece is the same photo seen four ways at once:
//   STYLE    how the photo itself is redrawn (duotone, poster, pixel, halftone, ink, neon, thermal, glitch, pop, hologram, gold)
//   PALETTE  the colours that style uses
//   FRAME    what surrounds it
//   EFFECT   what lies over it
// Each option belongs to a rarity tier. A collection is given a fixed share of each tier (so a few pieces really are
// rare), each piece gets one "feature" trait of its own tier and the rest from that tier or below, and no two pieces
// share all four traits. The optional description steers the choice: its words raise or exclude options.
//
// The numbers are drawn from a seeded generator, so a collection can be made again exactly from its seed.

export const SIZE = 512;
export const TIERS = ['Common', 'Uncommon', 'Rare', 'Epic', 'Legendary'];
export const TIER_COLOR = ['#9aa0ad', '#3ddc97', '#4da3ff', '#b57bff', '#ffb02e'];
// the share of a collection each tier gets (the rest is Common); at least one Legendary from ten pieces up
const TIER_SHARE = [0, 0.28, 0.14, 0.06, 0.02];

const PALETTES = [
  { name: 'Sunset', tier: 0, c: ['#1b0a2a', '#7a1f5c', '#ff5e62', '#ffd27d'], words: ['sunset', 'warm', 'orange', 'pink'] },
  { name: 'Ocean', tier: 0, c: ['#03131f', '#0b4f6c', '#20a4b8', '#c8f4ff'], words: ['ocean', 'sea', 'water', 'blue', 'teal'] },
  { name: 'Forest', tier: 0, c: ['#07140c', '#1e4d2b', '#6aa84f', '#e3f6c5'], words: ['forest', 'nature', 'green', 'jungle'] },
  { name: 'Mono', tier: 0, c: ['#050506', '#3a3a40', '#a6a6ad', '#fafafa'], words: ['mono', 'black', 'white', 'grey', 'gray', 'noir', 'minimal'] },
  { name: 'Candy', tier: 1, c: ['#3b1c4a', '#ff7eb6', '#ffd1e8', '#bdf7ff'], words: ['pastel', 'candy', 'cute', 'soft', 'kawaii'] },
  { name: 'Ember', tier: 1, c: ['#0d0202', '#7a1200', '#ff4d00', '#ffe08a'], words: ['fire', 'ember', 'lava', 'red', 'dark', 'moody'] },
  { name: 'Ice', tier: 1, c: ['#06101c', '#27507a', '#8ecbff', '#ffffff'], words: ['ice', 'frost', 'snow', 'cold', 'winter'] },
  { name: 'Royal', tier: 2, c: ['#0a0522', '#3d1a8f', '#8b7bff', '#f1e8ff'], words: ['royal', 'purple', 'violet', 'regal'] },
  { name: 'Acid', tier: 2, c: ['#05070a', '#00d68f', '#d8ff3c', '#ff2fd6'], words: ['acid', 'neon', 'cyber', 'cyberpunk', 'rave', 'toxic'] },
  { name: 'Vapor', tier: 3, c: ['#1a0b3b', '#ff5fd2', '#5ffbf1', '#fff5a8'], words: ['vapor', 'vaporwave', 'synth', 'synthwave', '80s', 'retro'] },
  { name: 'Gold', tier: 4, c: ['#1a0f00', '#8a5a00', '#ffc83d', '#fff6d0'], words: ['gold', 'golden', 'luxury', 'rich', 'treasure'] },
];
const STYLES = [
  { name: 'Portrait', tier: 0, words: ['photo', 'clean', 'natural', 'portrait', 'realistic'] },
  { name: 'Duotone', tier: 0, words: ['duotone', 'two tone', 'gradient'] },
  { name: 'Poster', tier: 0, words: ['poster', 'flat', 'bold', 'graphic'] },
  { name: 'Pixel', tier: 1, words: ['pixel', '8-bit', '8 bit', 'retro', 'arcade', 'game'] },
  { name: 'Halftone', tier: 1, words: ['halftone', 'comic', 'print', 'dots', 'newspaper'] },
  { name: 'Ink', tier: 1, words: ['ink', 'sketch', 'pencil', 'drawing', 'line art', 'manga'] },
  { name: 'Neon', tier: 2, words: ['neon', 'glow', 'cyber', 'cyberpunk', 'night'] },
  { name: 'Thermal', tier: 2, words: ['thermal', 'heat', 'infrared', 'predator'] },
  { name: 'Glitch', tier: 2, words: ['glitch', 'broken', 'vhs', 'digital', 'corrupt'] },
  { name: 'Pop', tier: 3, words: ['pop', 'pop art', 'warhol', 'quad'] },
  { name: 'Hologram', tier: 3, words: ['holo', 'hologram', 'holographic', 'iridescent', 'rainbow', 'foil'] },
  { name: 'Gilded', tier: 4, words: ['gilded', 'statue', 'metal', 'gold', 'golden'] },
];
const FRAMES = [
  { name: 'None', tier: 0, words: ['no frame', 'frameless', 'borderless'] },
  { name: 'Line', tier: 0, words: ['frame', 'border'] },
  { name: 'Corners', tier: 0, words: ['corner', 'viewfinder', 'camera'] },
  { name: 'Film', tier: 1, words: ['film', 'cinema', 'movie', 'analog'] },
  { name: 'Circle', tier: 1, words: ['circle', 'round', 'coin', 'medal'] },
  { name: 'Double', tier: 2, words: ['double', 'gallery', 'museum'] },
  { name: 'Hexagon', tier: 3, words: ['hex', 'hexagon', 'badge'] },
  { name: 'Ornate', tier: 4, words: ['ornate', 'baroque', 'luxury', 'royal'] },
];
const EFFECTS = [
  { name: 'None', tier: 0, words: ['plain', 'no effect'] },
  { name: 'Grain', tier: 0, words: ['grain', 'film', 'analog', 'vintage', 'old'] },
  { name: 'Vignette', tier: 0, words: ['vignette', 'moody', 'dark'] },
  { name: 'Scanlines', tier: 1, words: ['scanline', 'crt', 'tv', 'retro', 'vhs'] },
  { name: 'Stars', tier: 1, words: ['star', 'stars', 'space', 'night', 'cosmic'] },
  { name: 'Rain', tier: 2, words: ['rain', 'storm', 'matrix'] },
  { name: 'Halo', tier: 2, words: ['halo', 'angel', 'saint', 'glow'] },
  { name: 'Lightleak', tier: 3, words: ['light leak', 'flare', 'sun', 'dream', 'dreamy'] },
  { name: 'Aura', tier: 4, words: ['aura', 'energy', 'power', 'legendary', 'god'] },
];
export const TRAITS = { Style: STYLES, Palette: PALETTES, Frame: FRAMES, Effect: EFFECTS };

// ── numbers ─────────────────────────────────────────────────────────────────────────────────────────────────
export function seedNow() {
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return a[0] >>> 0;
}
function rng(seed) { // mulberry32
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = Math.imul(s ^ (s >>> 15), 1 | s);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const hex = (h) => [parseInt(h.slice(1, 3), 16), parseInt(h.slice(3, 5), 16), parseInt(h.slice(5, 7), 16)];
function ramp(stops) { // 256 colours along a palette
  const cs = stops.map(hex), out = new Uint8ClampedArray(768);
  for (let i = 0; i < 256; i++) {
    const t = (i / 255) * (cs.length - 1), k = Math.min(cs.length - 2, Math.floor(t)), f = t - k;
    for (let c = 0; c < 3; c++) out[i * 3 + c] = cs[k][c] + (cs[k + 1][c] - cs[k][c]) * f;
  }
  return out;
}
const lum = (d, i) => (d[i] * 54 + d[i + 1] * 183 + d[i + 2] * 19) >> 8;

// ── what the description asks for ───────────────────────────────────────────────────────────────────────────
// Returns a weight for every option: 1 by default, 8 when the description names it, 0 when it says "no <word>".
export function steer(text) {
  const t = ' ' + String(text || '').toLowerCase().replace(/[^a-z0-9 \-]/g, ' ').replace(/\s+/g, ' ') + ' ';
  const out = {};
  let asked = 0;
  for (const [kind, opts] of Object.entries(TRAITS)) {
    out[kind] = opts.map((o) => {
      let w = 1;
      for (const word of o.words.concat([o.name.toLowerCase()])) {
        if (t.includes(' no ' + word + ' ') || t.includes(' without ' + word + ' ')) return 0;
        if (t.includes(' ' + word + ' ') || t.includes(' ' + word + 's ')) { w = 8; asked++; }
      }
      return w;
    });
    // "no frame", "frameless", "no effects": the whole kind is switched off, leaving only its plain option
    const k = kind.toLowerCase();
    if (t.includes(' no ' + k + ' ') || t.includes(' no ' + k + 's ') || t.includes(' without ' + k + ' ') || t.includes(' ' + k + 'less ')) out[kind] = opts.map((o) => (o.name === 'None' ? 1 : 0));
    if (out[kind].every((w) => w === 0)) out[kind] = opts.map(() => 1); // never an empty choice
  }
  out.asked = asked;
  return out;
}

// ── the photo ───────────────────────────────────────────────────────────────────────────────────────────────
export async function loadPhoto(file) {
  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    img.decoding = 'async';
    await new Promise((ok, no) => { img.onload = ok; img.onerror = () => no(new Error('That file is not a picture this device can open.')); img.src = url; });
    const c = document.createElement('canvas');
    c.width = c.height = SIZE;
    const g = c.getContext('2d', { willReadFrequently: true });
    const s = Math.min(img.naturalWidth, img.naturalHeight); // centre square
    g.drawImage(img, (img.naturalWidth - s) / 2, (img.naturalHeight - s) / 2, s, s, 0, 0, SIZE, SIZE);
    return g.getImageData(0, 0, SIZE, SIZE);
  } finally { URL.revokeObjectURL(url); }
}

// ── styles: the photo redrawn ───────────────────────────────────────────────────────────────────────────────
function edges(src) { // Sobel magnitude, 0..255
  const w = SIZE, d = src.data, L = new Uint8Array(w * w), E = new Uint8Array(w * w);
  for (let i = 0, p = 0; i < d.length; i += 4, p++) L[p] = lum(d, i);
  for (let y = 1; y < w - 1; y++) for (let x = 1; x < w - 1; x++) {
    const p = y * w + x;
    const gx = L[p - w + 1] + 2 * L[p + 1] + L[p + w + 1] - L[p - w - 1] - 2 * L[p - 1] - L[p + w - 1];
    const gy = L[p + w - 1] + 2 * L[p + w] + L[p + w + 1] - L[p - w - 1] - 2 * L[p - w] - L[p - w + 1];
    E[p] = Math.min(255, Math.abs(gx) + Math.abs(gy) >> 1);
  }
  return E;
}
function styled(src, style, pal, r) {
  const w = SIZE, s = src.data, out = new ImageData(w, w), o = out.data, R = ramp(pal.c);
  const put = (i, c0, c1, c2) => { o[i] = c0; o[i + 1] = c1; o[i + 2] = c2; o[i + 3] = 255; };
  const mapped = (i, v) => put(i, R[v * 3], R[v * 3 + 1], R[v * 3 + 2]);
  switch (style.name) {
    case 'Portrait': { // the photo itself, graded: more contrast, shadows and highlights toned by the palette
      const k = 0.30 + r() * 0.16;
      for (let i = 0; i < s.length; i += 4) {
        const l = lum(s, i);
        for (let c = 0; c < 3; c++) { const v = (s[i + c] - 128) * 1.22 + 128; o[i + c] = v * (1 - k) + R[l * 3 + c] * k; }
        o[i + 3] = 255;
      }
      break;
    }
    case 'Duotone': for (let i = 0; i < s.length; i += 4) mapped(i, lum(s, i)); break;
    case 'Poster': { const n = 4 + Math.floor(r() * 2); for (let i = 0; i < s.length; i += 4) mapped(i, Math.min(255, Math.round((Math.floor((lum(s, i) / 256) * n) / (n - 1)) * 255))); break; }
    case 'Pixel': {
      const b = [8, 12, 16][Math.floor(r() * 3)];
      for (let y = 0; y < w; y += b) for (let x = 0; x < w; x += b) {
        const i0 = (Math.min(w - 1, y + (b >> 1)) * w + Math.min(w - 1, x + (b >> 1))) * 4;
        const v = Math.min(255, Math.round(Math.floor((lum(s, i0) / 256) * 6) / 5 * 255));
        for (let yy = y; yy < Math.min(w, y + b); yy++) for (let xx = x; xx < Math.min(w, x + b); xx++) mapped((yy * w + xx) * 4, v);
      }
      break;
    }
    case 'Halftone': {
      const b = 8, bg = hex(pal.c[3]), fg = hex(pal.c[0]), mid = hex(pal.c[1]);
      for (let i = 0; i < o.length; i += 4) put(i, bg[0], bg[1], bg[2]);
      for (let y = 0; y < w; y += b) for (let x = 0; x < w; x += b) {
        const l = lum(s, ((y + 4) * w + x + 4) * 4), rad = ((255 - l) / 255) * b * 0.72, col = l < 96 ? fg : mid;
        for (let yy = 0; yy < b; yy++) for (let xx = 0; xx < b; xx++) {
          const dx = xx - b / 2 + 0.5, dy = yy - b / 2 + 0.5;
          if (dx * dx + dy * dy <= rad * rad && y + yy < w && x + xx < w) put(((y + yy) * w + x + xx) * 4, col[0], col[1], col[2]);
        }
      }
      break;
    }
    case 'Ink': {
      const E = edges(src), paper = hex(pal.c[3]), ink = hex(pal.c[0]), wash = hex(pal.c[2]);
      for (let p = 0, i = 0; p < w * w; p++, i += 4) {
        const e = Math.min(1, E[p] / 70), shade = lum(s, i) < 90 ? 0.28 : 0;
        for (let c = 0; c < 3; c++) o[i + c] = (paper[c] * (1 - shade) + wash[c] * shade) * (1 - e) + ink[c] * e;
        o[i + 3] = 255;
      }
      break;
    }
    case 'Neon': {
      const E = edges(src), a = hex(pal.c[2]), b = hex(pal.c[3]), bg = hex(pal.c[0]);
      for (let p = 0, i = 0; p < w * w; p++, i += 4) {
        // a tube of light, not a hairline: the strongest edge among a pixel and its four neighbours
        const near = Math.max(E[p], E[p - 1] || 0, E[p + 1] || 0, E[p - w] || 0, E[p + w] || 0);
        const e = Math.min(1, near / 42), l = lum(s, i) / 255, k = (p % w) / w;
        for (let c = 0; c < 3; c++) o[i + c] = Math.min(255, bg[c] * 0.55 + s[i + c] * 0.24 * l + (a[c] * (1 - k) + b[c] * k) * e * 1.6);
        o[i + 3] = 255;
      }
      break;
    }
    case 'Thermal': { const T = ramp(['#00004a', '#3b00a8', '#d4006a', '#ff7a00', '#ffe600', '#ffffff']); for (let i = 0; i < s.length; i += 4) { const v = lum(s, i); put(i, T[v * 3], T[v * 3 + 1], T[v * 3 + 2]); } break; }
    case 'Glitch': {
      const sh = 6 + Math.floor(r() * 14);
      const rows = Array.from({ length: 9 }, () => ({ y: Math.floor(r() * w), h: 4 + Math.floor(r() * 26), dx: Math.floor((r() - 0.5) * 90) }));
      for (let y = 0; y < w; y++) {
        let dx = 0;
        for (const q of rows) if (y >= q.y && y < q.y + q.h) dx = q.dx;
        for (let x = 0; x < w; x++) {
          const i = (y * w + x) * 4, xr = (x + dx + sh + w) % w, xg = (x + dx + w) % w, xb = (x + dx - sh + 2 * w) % w;
          const v = Math.round(s[(y * w + xr) * 4] * 0.5 + R[lum(s, (y * w + xg) * 4) * 3] * 0.5);
          put(i, v, s[(y * w + xg) * 4 + 1], s[(y * w + xb) * 4 + 2]);
        }
      }
      break;
    }
    case 'Pop': { // four quadrants, four palettes
      const others = PALETTES.filter((p) => p !== pal), q = [pal, others[Math.floor(r() * others.length)], others[Math.floor(r() * others.length)], others[Math.floor(r() * others.length)]].map((p) => ramp(p.c)), h = w >> 1;
      for (let y = 0; y < w; y++) for (let x = 0; x < w; x++) {
        const Q = q[(y >= h ? 2 : 0) + (x >= h ? 1 : 0)], v = Math.min(255, Math.round(Math.floor((lum(s, (((y % h) * 2) * w + (x % h) * 2) * 4) / 256) * 4) / 3 * 255));
        put((y * w + x) * 4, Q[v * 3], Q[v * 3 + 1], Q[v * 3 + 2]);
      }
      break;
    }
    case 'Hologram': {
      for (let y = 0; y < w; y++) for (let x = 0; x < w; x++) {
        const i = (y * w + x) * 4, l = lum(s, i) / 255, hue = (l * 300 + x * 0.35 + y * 0.22) % 360, f = (n) => { const k = (n + hue / 60) % 6; return l * (1 - 0.55 * Math.max(0, Math.min(k, 4 - k, 1))); };
        put(i, 255 * f(5) * 0.85 + s[i] * 0.15, 255 * f(3) * 0.85 + s[i + 1] * 0.15, 255 * f(1) * 0.85 + s[i + 2] * 0.15);
        if (y % 4 === 0) { o[i] *= 0.82; o[i + 1] *= 0.82; o[i + 2] *= 0.82; }
      }
      break;
    }
    default: { // Gilded: a metal relief
      const G = ramp(['#1a0f00', '#6b4300', '#d99a1c', '#ffe9a6', '#fffdf0']);
      for (let y = 0; y < w; y++) for (let x = 0; x < w; x++) {
        const i = (y * w + x) * 4, j = (Math.min(w - 1, y + 2) * w + Math.min(w - 1, x + 2)) * 4;
        const v = Math.max(0, Math.min(255, lum(s, i) + (lum(s, i) - lum(s, j)) * 3));
        put(i, G[v * 3], G[v * 3 + 1], G[v * 3 + 2]);
      }
    }
  }
  return out;
}

// ── frame and effect, drawn over the styled photo ───────────────────────────────────────────────────────────
function decorate(g, frame, effect, pal, r) {
  const w = SIZE, a = pal.c[3], b = pal.c[2], dark = pal.c[0];
  const clip = (path) => { // keep the inside of `path`, fill the outside with the palette's dark
    g.save(); g.globalCompositeOperation = 'destination-in'; g.fill(path); g.restore();
    g.save(); g.globalCompositeOperation = 'destination-over'; g.fillStyle = dark; g.fillRect(0, 0, w, w); g.restore();
  };
  // effect first (it belongs to the picture), then the frame over it
  switch (effect.name) {
    case 'Grain': { const d = g.getImageData(0, 0, w, w); for (let i = 0; i < d.data.length; i += 4) { const n = (r() - 0.5) * 34; d.data[i] += n; d.data[i + 1] += n; d.data[i + 2] += n; } g.putImageData(d, 0, 0); break; }
    case 'Vignette': { const v = g.createRadialGradient(w / 2, w / 2, w * 0.3, w / 2, w / 2, w * 0.74); v.addColorStop(0, 'rgba(0,0,0,0)'); v.addColorStop(1, 'rgba(0,0,0,.72)'); g.fillStyle = v; g.fillRect(0, 0, w, w); break; }
    case 'Scanlines': g.fillStyle = 'rgba(0,0,0,.26)'; for (let y = 0; y < w; y += 4) g.fillRect(0, y, w, 2); break;
    case 'Stars': for (let k = 0; k < 70; k++) { const x = r() * w, y = r() * w, s = 0.6 + r() * 2.2; g.fillStyle = 'rgba(255,255,255,' + (0.4 + r() * 0.6) + ')'; g.beginPath(); g.arc(x, y, s, 0, 6.3); g.fill(); if (s > 2.2) { g.fillRect(x - 7, y - 0.5, 14, 1); g.fillRect(x - 0.5, y - 7, 1, 14); } } break;
    case 'Rain': g.strokeStyle = a; g.lineWidth = 1.2; for (let k = 0; k < 110; k++) { const x = r() * w, y = r() * w, l = 10 + r() * 26; g.globalAlpha = 0.18 + r() * 0.4; g.beginPath(); g.moveTo(x, y); g.lineTo(x - l * 0.25, y + l); g.stroke(); } g.globalAlpha = 1; break;
    case 'Halo': { g.save(); g.shadowColor = a; g.shadowBlur = 26; g.strokeStyle = a; g.lineWidth = 7; g.beginPath(); g.ellipse(w / 2, w * 0.16, w * 0.2, w * 0.045, 0, 0, 6.3); g.stroke(); g.restore(); break; }
    case 'Lightleak': { g.save(); g.globalCompositeOperation = 'screen'; for (let k = 0; k < 3; k++) { const x = r() * w, y = r() * w, v = g.createRadialGradient(x, y, 0, x, y, w * (0.35 + r() * 0.3)); v.addColorStop(0, k % 2 ? 'rgba(255,170,60,.75)' : 'rgba(255,70,140,.65)'); v.addColorStop(1, 'rgba(0,0,0,0)'); g.fillStyle = v; g.fillRect(0, 0, w, w); } g.restore(); break; }
    case 'Aura': { g.save(); g.globalCompositeOperation = 'screen'; for (let k = 0; k < 5; k++) { g.strokeStyle = k % 2 ? a : b; g.lineWidth = 10 - k * 1.5; g.shadowColor = g.strokeStyle; g.shadowBlur = 30; g.globalAlpha = 0.55 - k * 0.08; g.beginPath(); g.arc(w / 2, w / 2, w * (0.3 + k * 0.045) + r() * 6, r() * 6.3, r() * 6.3 + 4.4); g.stroke(); } g.restore(); break; }
    default:
  }
  const p = new Path2D();
  switch (frame.name) {
    case 'Line': g.strokeStyle = a; g.lineWidth = 6; g.strokeRect(13, 13, w - 26, w - 26); break;
    case 'Corners': g.strokeStyle = a; g.lineWidth = 6; for (const [x, y, sx, sy] of [[18, 18, 1, 1], [w - 18, 18, -1, 1], [18, w - 18, 1, -1], [w - 18, w - 18, -1, -1]]) { g.beginPath(); g.moveTo(x + 60 * sx, y); g.lineTo(x, y); g.lineTo(x, y + 60 * sy); g.stroke(); } break;
    case 'Film': g.fillStyle = '#050505'; g.fillRect(0, 0, w, 44); g.fillRect(0, w - 44, w, 44); g.fillStyle = a; for (let x = 14; x < w; x += 42) { g.fillRect(x, 13, 22, 18); g.fillRect(x, w - 31, 22, 18); } break;
    case 'Circle': p.arc(w / 2, w / 2, w * 0.46, 0, 6.3); clip(p); g.strokeStyle = a; g.lineWidth = 7; g.beginPath(); g.arc(w / 2, w / 2, w * 0.46, 0, 6.3); g.stroke(); break;
    case 'Double': g.strokeStyle = a; g.lineWidth = 10; g.strokeRect(9, 9, w - 18, w - 18); g.strokeStyle = b; g.lineWidth = 3; g.strokeRect(26, 26, w - 52, w - 52); break;
    case 'Hexagon': { for (let k = 0; k < 6; k++) { const t = Math.PI / 6 + k * Math.PI / 3, x = w / 2 + Math.cos(t) * w * 0.49, y = w / 2 + Math.sin(t) * w * 0.49; k ? p.lineTo(x, y) : p.moveTo(x, y); } p.closePath(); clip(p); g.strokeStyle = a; g.lineWidth = 8; g.stroke(p); break; }
    case 'Ornate': {
      const gold = g.createLinearGradient(0, 0, w, w); gold.addColorStop(0, '#fff3b0'); gold.addColorStop(0.35, '#d99a1c'); gold.addColorStop(0.6, '#fff8d8'); gold.addColorStop(1, '#9a6400');
      g.strokeStyle = gold; g.lineWidth = 22; g.strokeRect(11, 11, w - 22, w - 22); g.lineWidth = 3; g.strokeStyle = '#3a2400'; g.strokeRect(24, 24, w - 48, w - 48); g.strokeRect(2, 2, w - 4, w - 4);
      g.fillStyle = gold; for (const [x, y] of [[11, 11], [w - 11, 11], [11, w - 11], [w - 11, w - 11], [w / 2, 11], [w / 2, w - 11], [11, w / 2], [w - 11, w / 2]]) { g.beginPath(); g.arc(x, y, 15, 0, 6.3); g.fill(); g.stroke(); }
      break;
    }
    default:
  }
}

// ── picking traits ──────────────────────────────────────────────────────────────────────────────────────────
// An option the description ASKED for (weight above 1) is open to every piece whatever its tier: someone who asks for
// neon wants a neon collection, and rarity then comes from the other three traits. Everything else is open only to
// pieces of its tier or above, and rarer options are picked less often.
function pick(opts, weights, maxTier, r, must) {
  const pool = opts.map((o, i) => {
    const asked = weights[i] > 1;
    const open = must != null ? o.tier === must : o.tier <= maxTier || asked;
    return { o, w: open ? weights[i] * (asked ? 1 : 1 / (1 + o.tier)) : 0 };
  }).filter((x) => x.w > 0);
  if (!pool.length) return null;
  let t = r() * pool.reduce((s, x) => s + x.w, 0);
  for (const x of pool) { t -= x.w; if (t <= 0) return x.o; }
  return pool[pool.length - 1].o;
}
// The tier of every piece: a fixed share of each (so rare pieces really are few), highest tiers placed at random.
function tiersFor(n, r) {
  const out = new Array(n).fill(0);
  let at = 0;
  const order = Array.from({ length: n }, (_, i) => i).sort(() => r() - 0.5);
  for (let t = 4; t >= 1; t--) {
    let k = Math.round(n * TIER_SHARE[t]);
    if (t === 4 && n >= 10) k = Math.max(1, k);
    for (; k > 0 && at < n; k--) out[order[at++]] = t;
  }
  return out;
}
// Plan a collection: for each piece its four traits and its tier. No two pieces share all four.
export function plan(count, seed, description) {
  const r = rng(seed), W = steer(description), tiers = tiersFor(count, r), seen = new Set(), items = [];
  const kinds = Object.keys(TRAITS);
  for (let n = 0; n < count; n++) {
    let traits = null;
    for (let tries = 0; tries < 80 && !traits; tries++) {
      const tier = tiers[n];
      // one trait of exactly this piece's tier is its feature; the rest come from that tier or below
      const feature = kinds.filter((k) => TRAITS[k].some((o, i) => o.tier === tier && W[k][i] > 0)).sort(() => r() - 0.5)[0];
      const t = {};
      for (const k of kinds) t[k] = pick(TRAITS[k], W[k], tier, r, k === feature ? tier : null) || TRAITS[k][0];
      const key = kinds.map((k) => t[k].name).join('|');
      if (!seen.has(key) || tries === 79) { seen.add(key); traits = t; }
    }
    items.push({ n: n + 1, tier: tiers[n], traits, seed: (seed + n * 0x9e3779b1) >>> 0 });
  }
  // how many pieces carry each option, for "1 of N" on a piece's page
  const census = {};
  for (const it of items) for (const k of kinds) census[k + ':' + it.traits[k].name] = (census[k + ':' + it.traits[k].name] || 0) + 1;
  for (const it of items) it.share = Object.fromEntries(kinds.map((k) => [k, census[k + ':' + it.traits[k].name]]));
  return { items, asked: W.asked };
}

// ── drawing one piece, and its bytes ────────────────────────────────────────────────────────────────────────
export function draw(photo, item) {
  const r = rng(item.seed), c = document.createElement('canvas');
  c.width = c.height = SIZE;
  const g = c.getContext('2d', { willReadFrequently: true });
  g.putImageData(styled(photo, item.traits.Style, item.traits.Palette, r), 0, 0);
  decorate(g, item.traits.Frame, item.traits.Effect, item.traits.Palette, r);
  return c;
}
// The largest picture this app makes for an NFT and for a token's logo: just under what the chain keeps for each
// (24 KB and 8 KB), because the picture is written into the chain with the asset and every node keeps it.
export const NFT_ART_MOST = 23 * 1024;
export const TOKEN_ART_MOST = 7 * 1024 + 512;
// A canvas as picture bytes no larger than `most`: the best quality that fits.
export async function bytesOf(canvas, most = NFT_ART_MOST) {
  const blobOf = (type, q) => new Promise((ok) => canvas.toBlob(ok, type, q));
  for (const type of ['image/webp', 'image/jpeg']) {
    for (const q of [0.86, 0.76, 0.66, 0.55, 0.44, 0.34]) {
      const b = await blobOf(type, q);
      if (b && b.type === type && b.size <= most) return new Uint8Array(await b.arrayBuffer());
    }
  }
  // a picture too busy for the bound at full size: the same picture, smaller, until it fits
  for (const div of [2, 3, 4]) {
    const small = document.createElement('canvas');
    small.width = small.height = Math.round(SIZE / div);
    small.getContext('2d').drawImage(canvas, 0, 0, small.width, small.height);
    for (const q of [0.7, 0.5]) {
      const b = await new Promise((ok) => small.toBlob(ok, 'image/jpeg', q));
      if (b && b.size <= most) return new Uint8Array(await b.arrayBuffer());
    }
  }
  throw new Error('This picture could not be made small enough to keep on the chain. Try a simpler picture.');
}
// A file the person made themselves, as an NFT picture: the centre square, at the card's size.
export async function ownArt(file) {
  const c = document.createElement('canvas');
  c.width = c.height = SIZE;
  c.getContext('2d').putImageData(await loadPhoto(file), 0, 0);
  return c;
}
export const toHex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, '0')).join('');
export const fromHex = (h) => new Uint8Array((String(h).match(/.{2}/g) || []).map((x) => parseInt(x, 16)));
