import { sanitizeHtml } from '../lib/sanitize.js';
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/* Side panel — host for the active activity's side content.
 * Page modules call `setSidePanelContent(html | node)` to populate.
 */

let panelEl = null;
let headerEl = null;
let contentEl = null;

export function mountSidePanel({ panel, header, content }) {
  panelEl = panel;
  headerEl = header;
  contentEl = content;
}

export function setSidePanelContent(content) {
  if (!contentEl) return;
  if (content instanceof Node) {
    contentEl.replaceChildren(content);
  } else {
    contentEl.innerHTML = sanitizeHtml(content);
  }
}

export function setSideHeader(text) {
  if (headerEl) headerEl.textContent = text;
}

export function getSideContentEl() {
  return contentEl;
}
