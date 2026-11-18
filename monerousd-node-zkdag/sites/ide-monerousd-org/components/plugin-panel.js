import { sanitizeHtml } from '../lib/sanitize.js';
// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

/* Plugin panel — context-aware right-side panel. ABI viewer / deployed list /
 * site preview iframe. Page modules drive content via setPluginPanelContent.
 */

let panelEl = null;
let headerEl = null;
let bodyEl = null;

export function mountPluginPanel({ panel, header, body }) {
  panelEl = panel;
  headerEl = header;
  bodyEl = body;
}

export function setPluginPanelContent(content) {
  if (!bodyEl) return;
  if (content instanceof Node) {
    bodyEl.replaceChildren(content);
  } else {
    bodyEl.innerHTML = sanitizeHtml(content);
  }
}

export function setPluginHeader(text) {
  if (headerEl) headerEl.textContent = text;
}

export function getPluginBodyEl() {
  return bodyEl;
}
