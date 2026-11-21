// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
// MonerousD pay panel for any website. No dependencies, no network calls except to the status address you give it.
//
//   <div class="musd-pay"
//        data-link="monerousd:pay?h=....onion&t=..."        the `link` your server got from the checkout helper
//        data-status="/my/order/123/status"                  a URL on YOUR site answering {"status": "...", "refund_code": null}
//        data-code="/my/order/123/code"                      optional: a URL on your site that takes POST {"code": "..."}
//        data-paid="/thanks"                                 optional: where to go once paid
//        data-protected></div>                               present when the order is a protected one
//   <script src="musd-pay.js" defer></script>
//
// Your site's status address asks the helper (GET /v1/orders/<id>/status with your key) and passes on `status` and
// `refund_code`. Your key never reaches this script, and this script is never what decides an order is paid.
//
// TWO-PARTY-REVIEWED: this file is a page widget, not a test, and builds no endpoint: it shows a link and repeats what
// the shop's own server says. The two-wallet payment it leads to is checked by scratchpad/net/goods.py on real nodes.
(function () {
  "use strict";
  var LINK = /^monerousd:pay\?h=[A-Za-z0-9.:_-]{1,128}&t=[A-Za-z0-9_-]{1,128}$/;
  var WORDS = { open: "waiting for payment", accepted: "waiting for payment", locked: "payment held safely", paid: "paid. Thank you.", cancelled: "cancelled", expired: "expired" };

  function el(tag, text, style) {
    var n = document.createElement(tag);
    if (text) n.textContent = text;
    if (style) n.setAttribute("style", style);
    return n;
  }

  function mount(box) {
    var link = box.getAttribute("data-link") || "";
    if (!LINK.exec(link)) { box.textContent = "MonerousD is not available for this order right now."; return; }
    var statusUrl = box.getAttribute("data-status"), codeUrl = box.getAttribute("data-code"), paidUrl = box.getAttribute("data-paid");
    var isProtected = box.hasAttribute("data-protected");
    box.setAttribute("style", "max-width:28rem;border:1px solid #d2d2d7;border-radius:14px;padding:1.5rem;font:16px/1.5 -apple-system,system-ui,sans-serif");
    box.appendChild(el("p", isProtected
      ? "Your payment is held in escrow until you confirm receipt. If your order is not delivered, it is refunded automatically."
      : "This payment is final the moment it lands, like cash."));
    var actions = el("div");
    actions.hidden = Boolean(statusUrl);
    box.appendChild(actions);
    var pay = el("a", "Pay with MonerousD", "display:block;text-align:center;background:#0071e3;color:#fff;text-decoration:none;border-radius:12px;padding:.9rem;font-weight:600");
    pay.setAttribute("href", link);
    actions.appendChild(pay);
    var copy = el("p", "Wallet on another device? Copy this into it:", "font-size:.85em;color:#6e6e73");
    copy.appendChild(el("br"));
    copy.appendChild(el("code", link, "word-break:break-all"));
    actions.appendChild(copy);
    var line = el("p", "Status: ");
    var status = el("strong", "checking…");
    line.appendChild(status);
    box.appendChild(line);
    var form = el("form");
    form.hidden = true;
    form.appendChild(el("p", "Received your order? Tap Confirm receipt in your wallet, or enter your release code here.", "font-size:.85em;color:#6e6e73"));
    var input = el("input", null, "width:100%;box-sizing:border-box;padding:.7rem;border:1px solid #d2d2d7;border-radius:10px");
    input.setAttribute("placeholder", "Handover code");
    input.setAttribute("autocomplete", "off");
    form.appendChild(input);
    var send = el("button", "I have my order", "margin-top:.8rem;width:100%;background:#0071e3;color:#fff;border:0;border-radius:12px;padding:.9rem;font-weight:600");
    send.setAttribute("type", "submit");
    form.appendChild(send);
    box.appendChild(form);
    var refund = el("p", "This order was cancelled. Your wallet claims the refund automatically; if it is closed, open it and enter this refund code on the Wallet page: ", "font-size:.85em");
    var refundCode = el("code", "", "word-break:break-all");
    refund.appendChild(refundCode);
    refund.hidden = true;
    box.appendChild(refund);
    var seenOpen = false;

    function show(j) {
      var open = j.status === "open" || j.status === "accepted";
      seenOpen = seenOpen || open;
      status.textContent = WORDS[j.status] || String(j.status || "checking…");
      actions.hidden = !open;
      form.hidden = !(codeUrl && j.status === "locked");
      if (j.refund_code) { refund.hidden = false; refundCode.textContent = j.refund_code; }
      if (seenOpen && j.status === "paid" && paidUrl) location.href = paidUrl;
    }

    function tick() {
      if (!statusUrl) return;
      fetch(statusUrl, { credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(show)
        .catch(function () {})
        .then(function () { setTimeout(tick, 4000); });
    }

    form.addEventListener("submit", function (e) {
      e.preventDefault();
      fetch(codeUrl, { method: "POST", credentials: "same-origin", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: input.value.trim() }) })
        .then(function (r) { return r.json(); })
        .then(function (j) { if (j.error) alert(j.error); else show(j); });
    });
    tick();
  }

  function start() { Array.prototype.forEach.call(document.querySelectorAll(".musd-pay"), mount); }
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", start); else start();
})();
