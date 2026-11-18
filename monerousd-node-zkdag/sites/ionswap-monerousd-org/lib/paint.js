// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: BUSL-1.1 (see LICENSE in this directory; Apache-2.0 from 2029-12-01)
//
// lib/paint.js — A LIST THAT IS READ AGAIN REPAINTS IN PLACE (user 2026-11-12: "the activity cards keep flickering").
//
// MEASURED cause, in a browser, on the Activity page with seven cards: a card (`.ion .item`, `.ion .tile`) rises in
// from nothing when it is CREATED (ion-rise, 0.4 s). A page that reads its wallet again every few seconds wrote its
// whole list again each time, so all seven cards were created again and all seven rose again on every read, whether
// or not anything had changed. With `paint`: the same seven nodes stay, and no entry animation starts.
//
// `paint` is the ONE way a page redraws cards it reads again. Per card, by the HTML it is drawn from (so a page needs
// no ids for its cards):
//   * the same words as before  -> the card is not touched: nothing replays, a pressed link keeps its focus;
//   * words that changed        -> the card is replaced where it stands, with no entry animation (class `still`);
//   * a card that is new        -> it rises in, once.
// `cards` is one HTML string a card, each ONE element; `empty` is what the box shows when there are none.
//
// What is kept: the strings and nodes of one box, for as long as the box is on the page (a WeakMap: nothing is kept
// for a page the person left). Nothing is stored, sent or read from anywhere but the arguments.
//
// WHY ITS OWN FILE: a page module is fetched under a version (`app.js`'s `V`), a library is not. A new name added to a
// library a browser still holds an older copy of would stop every page that imports it from opening until that copy
// expired; a file with a new address has no older copy.
//
// TWO-PARTY-REVIEWED: a front-end module, not a test. It crosses to no second party: it only arranges elements.
const painted = new WeakMap();

export function paint(box, cards, empty) {
  const was = painted.get(box);
  // the box holds exactly what this function last put there, or it is painted from nothing (a first "Reading…" line,
  // a note another writer put there)
  const ours = !!was && was.nodes.length === box.childNodes.length && was.nodes.every((n, i) => box.childNodes[i] === n);
  if (!cards.length) {
    if (ours && was.empty === empty && !was.html.length) return;
    box.innerHTML = empty || '';
    painted.set(box, { html: [], nodes: Array.from(box.childNodes), empty });
    return;
  }
  const old = ours && was.html.length ? was : { html: [], nodes: [] };
  if (!old.nodes.length) box.replaceChildren(); // whatever stood there (a note, a first line) gives way to the cards
  // every earlier card that says the same words is kept as the node it already is
  const spare = new Map();
  old.html.forEach((h, i) => { if (!spare.has(h)) spare.set(h, []); spare.get(h).push(i); });
  const keptFrom = cards.map((h) => { const q = spare.get(h); return q && q.length ? q.shift() : -1; });
  const kept = new Set(keptFrom.filter((i) => i >= 0));
  const maker = document.createElement('template');
  const nodes = cards.map((h, j) => {
    if (keptFrom[j] >= 0) return old.nodes[keptFrom[j]];
    maker.innerHTML = h;
    const n = maker.content.childNodes.length === 1 ? maker.content.firstElementChild : null;
    // a card standing where an earlier card's words CHANGED is that card, updated: it does not rise in again
    if (n && j < old.nodes.length && !kept.has(j)) n.classList.add('still');
    return n;
  });
  if (nodes.some((n) => !n)) { // a string that is not exactly one element: drawn plainly, painted from nothing next time
    box.innerHTML = cards.join('');
    painted.delete(box);
    return;
  }
  old.nodes.forEach((n, i) => { if (!kept.has(i)) n.remove(); });
  nodes.forEach((n, j) => {
    if (box.childNodes[j] === n) return;
    // a kept card that changes place is moved without rising in again (a moved element replays its animation)
    if (keptFrom[j] >= 0) n.classList.add('still');
    box.insertBefore(n, box.childNodes[j] || null);
  });
  painted.set(box, { html: cards.slice(), nodes, empty });
}
