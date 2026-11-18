#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""MonerousD checkout helper: the one small program a shop runs to take MonerousD.

A shop's software (the WooCommerce plugin, the Shopify connector built in below, or any site's own code) talks to this
helper over plain HTTP on the shop's own machine. The helper talks to the shop's own MonerousD wallet, which runs beside
it and holds the keys. Nothing here holds a key, and no third party sits between the shop and its money.

Two ways to be paid, chosen per order:

  pay_now    an ordinary payment. Final the moment it lands. No dispute, no chargeback, nothing held.
  protected  the buyer's money is held in a vault until the buyer hands over a code (in person, at a counter, to a
             courier, or by tapping "I have it" in the wallet). If nothing is handed over by the deadline the money
             goes back to the buyer by itself. Nobody judges anything: money moves on a code or on the clock.

Who reaches the helper, and how:

  the shop's software   the /v1/orders calls, with the shop's key, on this machine
  the buyer's wallet    the /v1/pay/<token>/... calls, at the helper's Tor hidden address (a wallet never dials
                        anything else, so a buyer's network address never reaches a shop)
  the buyer's browser   the /pay/<token> page, wherever the shop chooses to show it

The helper keeps no file of orders. Every answer carries a signed `state` the shop stores with its own order and gives
back when it asks about that order after the helper restarted. The shop's order record is the record.

Python standard library only. Run:  musd_checkout.py --config checkout.json
"""
import argparse
import base64
import hashlib
import hmac
import html
import http.server
import json
import os
import secrets
import shutil
import subprocess
import threading
import time
import urllib.parse
import urllib.request

HOUR_MS = 3_600_000
ATOMIC_PER_USDM = 100_000_000
MAX_BODY = 64 * 1024
CHARGE_FRESH_MS = 60_000  # a charge is replaced once less than this much of its signed life is left


def atomic_of(amount):
    """A price as atomic units from a decimal string or number, exactly (never through a float)."""
    s = str(amount).strip()
    whole, _, frac = s.partition(".")
    if not whole.isdigit() or (frac and not frac.isdigit()) or len(frac) > 8 or len(whole) > 11:
        raise ValueError("the amount is not a positive price with at most 8 decimal places")
    value = int(whole) * ATOMIC_PER_USDM + int((frac + "0" * 8)[:8])
    if value <= 0:
        raise ValueError("the amount must be positive")
    return value


def usdm_text(atomic):
    return f"{atomic // ATOMIC_PER_USDM}.{atomic % ATOMIC_PER_USDM:08d}"


def dollars(atomic):
    """A price as a person reads it: two decimals unless the price really has more."""
    text = usdm_text(atomic).rstrip("0")
    whole, _, frac = text.partition(".")
    return f"{whole}.{frac.ljust(2, '0')}"


def mac(key: bytes, message: bytes) -> str:
    # SHA3 takes a key by prefix safely (no length extension), and one line of PHP or JavaScript checks it.
    return hashlib.sha3_256(key + message).hexdigest()


def compact(obj) -> str:
    return json.dumps(obj, separators=(",", ":"), sort_keys=True)


class Wallet:
    """The shop's own wallet process (`wallet-harness`), driven over its line protocol. One command at a time."""

    def __init__(self, command, env=None, seed_line=None):
        self.lock = threading.Lock()
        self.proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env, bufsize=1)
        if seed_line is not None:
            self.proc.stdin.write(seed_line.strip() + "\n")
            self.proc.stdin.flush()
        first = self._next_reply()
        if not first.get("ok"):
            raise RuntimeError("the wallet did not open: " + str(first.get("error", first)))

    def _next_reply(self):
        while True:
            line = self.proc.stdout.readline()
            if line == "":
                raise RuntimeError("the wallet process ended")
            line = line.strip()
            if line.startswith("{"):
                try:
                    return json.loads(line)
                except ValueError:
                    continue

    def call(self, *parts):
        """Run one wallet command. Returns its result, or raises with the wallet's own reason."""
        words = [str(p) for p in parts]
        if any((not w) or any(c.isspace() for c in w) for w in words):
            raise ValueError("a wallet argument is empty or holds a space")
        with self.lock:
            self.proc.stdin.write(" ".join(words) + "\n")
            self.proc.stdin.flush()
            reply = self._next_reply()
        if not reply.get("ok"):
            raise RuntimeError(str(reply.get("error", "the wallet refused")))
        return reply.get("result")


class Checkout:
    """Every order this helper knows, and the rules that move one."""

    PERSISTED = ("id", "reference", "title", "amount", "mode", "deadline_ms", "token", "status", "request", "funded", "refs", "refund_code")

    def __init__(self, cfg, wallet, post=None, clock=None):
        self.cfg = cfg
        self.wallet = wallet
        self.key = cfg["api_key"].encode()
        self.state_key = hashlib.sha3_256(b"state/" + self.key).digest()
        self.orders = {}
        self.lock = threading.RLock()
        self.post = post or self._post
        self.clock = clock or (lambda: int(time.time() * 1000))
        self.on_move = []  # connectors (Shopify) that hear every status change

    # ---- what the shop stores -------------------------------------------------------------------------------
    def state_of(self, o):
        body = base64.urlsafe_b64encode(compact({k: o.get(k) for k in self.PERSISTED}).encode()).decode()
        return body + "." + mac(self.state_key, body.encode())

    def order_from_state(self, state):
        body, _, tag = str(state).rpartition(".")
        if not body or not hmac.compare_digest(tag, mac(self.state_key, body.encode())):
            raise ValueError("that state was not written by this helper")
        o = json.loads(base64.urlsafe_b64decode(body.encode()))
        o["charge"] = None
        with self.lock:
            known = self.orders.setdefault(o["id"], o)
        # a seller's wallet recomputes its side from the two messages: nothing else was ever kept
        if known["mode"] == "protected" and known.get("request") and known.get("funded") and known["status"] in ("accepted", "locked"):
            try:
                self.wallet.call("purchase_funded", compact(known["request"]), compact(known["funded"]))
            except RuntimeError:
                pass
        return known

    # ---- the shop's calls -----------------------------------------------------------------------------------
    def create(self, reference, title, amount, mode="pay_now", deadline_hours=None):
        if mode not in ("pay_now", "protected"):
            raise ValueError("mode is pay_now or protected")
        title = " ".join(str(title).split())[:120] or "Order"
        now = self.clock()
        o = {
            "id": secrets.token_hex(16),
            "reference": str(reference)[:120],
            "title": title,
            "amount": atomic_of(amount),
            "mode": mode,
            "deadline_ms": 0,
            "token": secrets.token_urlsafe(24),
            "status": "open",
            "request": None,
            "funded": None,
            "refs": [],
            "refund_code": None,
            "charge": None,
        }
        if mode == "protected":
            hours = int(deadline_hours or self.cfg.get("protected_deadline_hours", 72))
            if hours < 2:
                raise ValueError("a protected order needs at least two hours before its deadline")
            o["deadline_ms"] = (now // HOUR_MS + hours + 1) * HOUR_MS
        else:
            minutes = int(self.cfg.get("pay_now_expiry_minutes", 60))
            o["deadline_ms"] = now + minutes * 60_000
            self.fresh_charge(o)
        with self.lock:
            self.orders[o["id"]] = o
        return self.view(o)

    def fresh_charge(self, o):
        """The signed charge the buyer's wallet pays: replaced when little of its signed life is left. Every charge an
        order ever showed is remembered by its nonce, because a payment names the charge it paid."""
        now = self.clock()
        charge = o.get("charge")
        if charge and int(charge.get("expiry_ms", 0)) - now >= CHARGE_FRESH_MS:
            return charge
        charge = self.wallet.call("poscharge", usdm_text(o["amount"]))
        if int(charge.get("amount_atomic", -1)) != o["amount"]:
            raise RuntimeError("the wallet signed a different amount than the order's price")
        o["charge"] = charge
        if charge["nonce"] not in o["refs"]:
            o["refs"].append(charge["nonce"])
        return charge

    def by_id(self, order_id):
        with self.lock:
            o = self.orders.get(order_id)
        if o is None:
            raise KeyError("no such order here: give its state to /v1/orders/import first")
        return o

    def by_token(self, token):
        with self.lock:
            for o in self.orders.values():
                if hmac.compare_digest(o["token"], token):
                    return o
        raise KeyError("no such order")

    def by_reference(self, reference):
        with self.lock:
            for o in self.orders.values():
                if o["reference"] == reference:
                    return o
        return None

    def link(self, o):
        return f"monerousd:pay?h={self.cfg['wallet_host']}&t={o['token']}"

    def view(self, o):
        base = self.cfg.get("public_url", "").rstrip("/")
        return {
            "order_id": o["id"],
            "reference": o["reference"],
            "status": o["status"],
            "mode": o["mode"],
            "amount": usdm_text(o["amount"]),
            "deadline_ms": o["deadline_ms"],
            "token": o["token"],
            "pay_url": f"{base}/pay/{o['token']}",
            "link": self.link(o),
            "refund_code": o.get("refund_code"),
            "state": self.state_of(o),
        }

    def offer(self, o):
        """What the buyer's wallet is shown before it pays: the shop's name, the item, the price, and how it is paid."""
        out = {
            "merchant": self.cfg.get("merchant_name", "Shop"),
            "title": o["title"],
            "amount": usdm_text(o["amount"]),
            "mode": o["mode"],
            "status": o["status"],
            "deadline_ms": o["deadline_ms"] if o["mode"] == "protected" else 0,
        }
        if o["mode"] == "pay_now" and o["status"] == "open":
            out["charge"] = self.fresh_charge(o)
        return out

    # ---- the buyer's wallet's calls (protected) -------------------------------------------------------------
    def request(self, o, request):
        if o["mode"] != "protected" or o["status"] not in ("open", "accepted"):
            raise ValueError("this order is not waiting for a protected payment")
        if not isinstance(request, dict) or request.get("amount") != o["amount"]:
            raise ValueError("the request's amount is not this order's price")
        if request.get("t_h") != o["deadline_ms"] // HOUR_MS:
            raise ValueError("the request's deadline is not this order's")
        if o["funded"] is not None and o["request"] != request:
            raise ValueError("this order is already being paid")
        accept = self.wallet.call("purchase_accept", usdm_text(o["amount"]), compact(request))
        o["request"], o["status"] = request, "accepted"
        return accept

    def funded(self, o, funded):
        if o["mode"] != "protected" or o["status"] not in ("accepted", "locked") or o["request"] is None:
            raise ValueError("this order is not waiting for a payment notice")
        if not isinstance(funded, dict) or funded.get("id") != o["request"].get("id"):
            raise ValueError("the payment notice is for another purchase")
        self.wallet.call("purchase_funded", compact(o["request"]), compact(funded))
        o["funded"] = funded
        return self.refresh(o)

    def code(self, o, code):
        """The buyer's handover code: the wallet checks it and takes the money. Paid only when the wallet says so.
        A code handed over after the deadline still pays, for as long as the buyer has not taken the money back."""
        held = o["status"] == "locked" or (o["status"] == "expired" and o["funded"] is not None)
        if o["mode"] != "protected" or not held:
            raise ValueError("this order is not waiting for a code")
        code = str(code).strip()
        if not code.startswith(o["request"]["id"] + ":"):
            raise ValueError("that code is for another order")
        self.wallet.call("purchase_release", code)
        self.move(o, "paid")
        return self.view(o)

    def cancel(self, o):
        """The shop calls the sale off. A protected order answers with the code that lets the buyer take the money
        back at once; the buyer's wallet picks it up from the order's status by itself."""
        if o["status"] in ("paid", "cancelled"):
            raise ValueError("this order is already finished")
        if o["mode"] == "protected" and o["request"] is not None:
            o["refund_code"] = self.wallet.call("purchase_refund_code", o["request"]["id"])["code"]
        self.move(o, "cancelled")
        return self.view(o)

    # ---- progress ------------------------------------------------------------------------------------------
    def refresh(self, o):
        """Ask the wallet where the order stands. The wallet's answer is the chain's, never the buyer's word."""
        if o["status"] in ("paid", "cancelled", "expired"):
            return self.view(o)
        now = self.clock()
        if o["mode"] == "pay_now":
            for nonce in list(o["refs"]):
                if (self.wallet.call("chargeawait", nonce, o["amount"]) or {}).get("paid"):
                    self.move(o, "paid")
                    return self.view(o)
            # a payment made on the last charge shown may still be on its way a little after the order closed
            if now >= o["deadline_ms"] + 10 * 60_000:
                self.move(o, "expired")
        elif o["funded"] is not None:
            st = self.wallet.call("purchase_status", o["request"]["id"])
            if st.get("locked") and o["status"] == "accepted":
                self.move(o, "locked")
            elif st.get("deadline_passed"):
                self.move(o, "expired")
        elif now >= o["deadline_ms"]:
            self.move(o, "expired")
        return self.view(o)

    def move(self, o, status):
        if o["status"] == status:
            return
        o["status"] = status
        for hear in self.on_move:
            threading.Thread(target=hear, args=(o,), daemon=True).start()
        self.notify(o)

    def notify(self, o):
        url = self.cfg.get("webhook_url")
        if not url:
            return
        body = compact({
            "event": "order." + o["status"],
            "order_id": o["id"],
            "reference": o["reference"],
            "amount": usdm_text(o["amount"]),
            "mode": o["mode"],
            "refund_code": o.get("refund_code"),
            "state": self.state_of(o),
            "sent_ms": self.clock(),
        }).encode()
        signature = mac(self.cfg.get("webhook_secret", self.cfg["api_key"]).encode(), body)
        threading.Thread(target=self.post, args=(url, body, signature), daemon=True).start()

    @staticmethod
    def _post(url, body, signature):
        for wait in (0, 5, 30, 120, 600):
            time.sleep(wait)
            try:
                req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json", "X-Musd-Signature": signature})
                with urllib.request.urlopen(req, timeout=15) as r:
                    if 200 <= r.status < 300:
                        return
            except OSError:
                continue

    def poll_once(self):
        with self.lock:
            live = [o for o in self.orders.values() if o["status"] in ("open", "accepted", "locked")]
        for o in live:
            try:
                self.refresh(o)
            except (RuntimeError, ValueError, KeyError):
                pass
        with self.lock:  # a finished order's record is the shop's; the helper forgets it an hour later
            now = self.clock()
            for oid in [k for k, o in self.orders.items() if o["status"] in ("paid", "cancelled", "expired") and now > o.setdefault("done_ms", now) + HOUR_MS]:
                del self.orders[oid]

    def poll_forever(self, every_s=10):
        while True:
            time.sleep(every_s)
            self.poll_once()


class Shopify:
    """The Shopify connector. Shopify hosts the shop, so nothing of ours runs inside it: the shop adds a manual payment
    method named "MonerousD" and one link on its order status page, pointing at this helper's /shopify/pay. The helper
    asks the shop's own Admin API for the order (the shop's token, from the config), shows the pay page, and marks the
    order paid when the wallet says the money arrived. The order's signed state is kept ON the Shopify order."""

    def __init__(self, cfg, checkout, ask=None):
        self.shop = cfg["shop"]
        self.token = cfg["admin_token"]
        self.version = cfg.get("api_version", "2025-01")
        self.mode = cfg.get("mode", "pay_now")
        self.gateway = cfg.get("gateway_name", "MonerousD").lower()
        self.checkout = checkout
        self.ask = ask or self._ask
        checkout.on_move.append(self.heard)

    def _ask(self, method, what, body=None):
        req = urllib.request.Request(
            f"https://{self.shop}/admin/api/{self.version}/{what}",
            data=None if body is None else compact(body).encode(),
            method=method,
            headers={"X-Shopify-Access-Token": self.token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read() or b"{}")

    def open_order(self, order_id, key):
        """The checkout order for a Shopify order, made once. `key` is the order's own secret (its token, or its whole
        order status address, which Shopify gives only to the buyer), so only the buyer can open its pay page."""
        if not str(order_id).isdigit():
            raise ValueError("that is not an order")
        reference = f"shopify:{order_id}"
        order = self.ask("GET", f"orders/{order_id}.json?fields=id,name,token,order_status_url,total_outstanding,currency,financial_status,payment_gateway_names,note_attributes").get("order") or {}
        secrets_of_order = [str(order.get(k)) for k in ("token", "order_status_url") if order.get(k)]
        if not order or not key or not any(hmac.compare_digest(s, str(key)) for s in secrets_of_order):
            raise KeyError("no such order")
        known = self.checkout.by_reference(reference)
        if known is not None:
            return known
        for attribute in order.get("note_attributes") or []:
            if attribute.get("name") == "musd_state":
                return self.checkout.order_from_state(attribute.get("value", ""))
        if order.get("currency") != "USD":
            raise ValueError("this shop's order is not priced in US dollars")
        if order.get("financial_status") not in ("pending", "partially_paid"):
            raise ValueError("this order is not waiting for a payment")
        if not any(self.gateway in str(g).lower() for g in order.get("payment_gateway_names") or []):
            raise ValueError("this order was not placed with the MonerousD payment method")
        view = self.checkout.create(reference, f"Order {order.get('name', order_id)}", order["total_outstanding"], self.mode)
        o = self.checkout.by_id(view["order_id"])
        self.keep_state(o)
        return o

    def keep_state(self, o):
        order_id = o["reference"].split(":", 1)[1]
        self.ask("PUT", f"orders/{order_id}.json", {"order": {"id": int(order_id), "note_attributes": [{"name": "musd_state", "value": self.checkout.state_of(o)}]}})

    def heard(self, o):
        if not o["reference"].startswith("shopify:"):
            return
        order_id = o["reference"].split(":", 1)[1]
        try:
            self.keep_state(o)
            if o["status"] == "paid":
                self.ask("POST", "graphql.json", {
                    "query": "mutation($input: OrderMarkAsPaidInput!) { orderMarkAsPaid(input: $input) { userErrors { message } } }",
                    "variables": {"input": {"id": f"gid://shopify/Order/{order_id}"}},
                })
            elif o["status"] == "locked":
                self.ask("PUT", f"orders/{order_id}.json", {"order": {"id": int(order_id), "tags": "MonerousD payment held: ship now"}})
        except (OSError, ValueError, KeyError):
            pass  # the next status change, or the next visit to the pay page, writes it again


PAY_PAGE = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="referrer" content="no-referrer"><title>Pay {merchant}</title><style>
body{{font:16px/1.5 -apple-system,system-ui,sans-serif;margin:0;background:#f5f5f7;color:#1d1d1f}}
main{{max-width:26rem;margin:3rem auto;background:#fff;border-radius:18px;padding:2rem;box-shadow:0 2px 20px rgba(0,0,0,.06)}}
h1{{font-size:1.25rem;margin:0 0 .25rem}} .amt{{font-size:2.2rem;font-weight:600;margin:.5rem 0}}
a.btn,button.btn{{display:block;width:100%;box-sizing:border-box;text-align:center;background:#0071e3;color:#fff;text-decoration:none;border:0;border-radius:12px;padding:.9rem;margin:1.2rem 0;font:inherit;font-weight:600;cursor:pointer}}
p.small{{color:#6e6e73;font-size:.9rem}} #st{{font-weight:600}} code{{word-break:break-all;font-size:.8rem}}
input{{width:100%;box-sizing:border-box;padding:.7rem;border:1px solid #d2d2d7;border-radius:10px;font:inherit}}
</style></head><body><main>
<h1>{merchant}</h1><div>{title}</div><div class="amt">${amount}</div>
<p>{promise}</p>
<a class="btn" id="pay" href="{link}">Pay with MonerousD</a>
<p class="small">Wallet on another device? Copy this into it:<br><code>{link}</code></p>
<p>Status: <span id="st"></span></p>
<form id="codeform" hidden><p class="small">Received your order? Tap Confirm receipt in your wallet, or enter your release code here.</p>
<input id="code" autocomplete="off" placeholder="Release code"><button class="btn" type="submit">Confirm receipt</button></form>
<p class="small" id="refund" hidden>The shop cancelled this order. Your wallet claims the refund automatically; if it is closed, open it and enter this refund code on the Wallet page:<br><code id="refundcode"></code></p>
</main><script>
const words={{open:"waiting for payment",accepted:"waiting for payment",locked:"payment held safely",paid:"paid. Thank you.",cancelled:"cancelled",expired:"expired"}};
const base={base_js}, back={return_js};
function show(j){{document.getElementById("st").textContent=words[j.status]||j.status;
document.getElementById("pay").hidden=!(j.status==="open"||j.status==="accepted");
document.getElementById("codeform").hidden=j.status!=="locked";
if(j.refund_code){{document.getElementById("refund").hidden=false;document.getElementById("refundcode").textContent=j.refund_code;}}
if(j.status==="paid"&&back)location.href=back;}}
async function tick(){{try{{show(await (await fetch(base+"/status")).json());}}catch(e){{}}setTimeout(tick,4000)}}
document.getElementById("codeform").addEventListener("submit",async e=>{{e.preventDefault();
const r=await fetch(base+"/code",{{method:"POST",headers:{{"Content-Type":"application/json"}},body:JSON.stringify({{code:document.getElementById("code").value}})}});
const j=await r.json();if(j.error)alert(j.error);else show(j);}});
show({{status:{status_js}}});tick();
</script></body></html>"""


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "musd-checkout/1"
    checkout: Checkout = None
    shopify: Shopify = None

    def log_message(self, *args):  # no request log: an address and a time are a customer's
        pass

    def _send(self, code, obj, content_type="application/json", headers=()):
        body = obj if isinstance(obj, bytes) else compact(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for name, value in headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > MAX_BODY:
            raise ValueError("the request is too large")
        body = json.loads(self.rfile.read(n) or b"{}")
        if not isinstance(body, dict):
            raise ValueError("the request is not an object")
        return body

    def _authorised(self):
        return hmac.compare_digest(self.headers.get("X-Checkout-Key", ""), self.checkout.cfg["api_key"])

    def do_GET(self):
        self._route("GET")

    def do_POST(self):
        self._route("POST")

    def _pay_page(self, o):
        c = self.checkout
        promise = (
            "Your payment is held in escrow until you confirm receipt. If your order is not delivered, it is refunded automatically."
            if o["mode"] == "protected"
            else "This payment is final the moment it lands, like cash."
        )
        page = PAY_PAGE.format(
            merchant=html.escape(c.cfg.get("merchant_name", "Shop")),
            title=html.escape(o["title"]),
            amount=html.escape(dollars(o["amount"])),
            promise=html.escape(promise),
            link=html.escape(c.link(o), quote=True),
            base_js=json.dumps(f"{c.cfg.get('public_url', '').rstrip('/')}/v1/pay/{o['token']}"),
            return_js=json.dumps(c.cfg.get("return_url", "")),
            status_js=json.dumps(o["status"]),
        )
        self._send(200, page.encode(), "text/html; charset=utf-8", [("Referrer-Policy", "no-referrer"), ("X-Frame-Options", "DENY")])

    def _route(self, method):
        c = self.checkout
        url = urllib.parse.urlparse(self.path)
        parts = [p for p in url.path.split("/") if p]
        query = urllib.parse.parse_qs(url.query)
        try:
            # ---- public: the buyer's browser and the buyer's wallet, by the order's own unguessable token
            if method == "GET" and len(parts) == 2 and parts[0] == "pay":
                return self._pay_page(c.by_token(parts[1]))
            if method == "GET" and len(parts) == 2 and parts[0] == "buy":
                # a price-list item: any page anywhere sells it with one ordinary link
                item = (c.cfg.get("products") or {}).get(parts[1])
                if item is None:
                    raise KeyError("no such item")
                view = c.create(f"item:{parts[1]}", item["title"], item["amount"], item.get("mode", "pay_now"), item.get("deadline_hours"))
                return self._send(303, {"pay_url": view["pay_url"]}, headers=[("Location", f"/pay/{view['token']}")])
            if method == "GET" and parts == ["shopify", "pay"] and self.shopify is not None:
                o = self.shopify.open_order(query.get("id", [""])[0], query.get("key", [""])[0])
                return self._send(303, {}, headers=[("Location", f"/pay/{o['token']}")])
            if len(parts) == 4 and parts[:2] == ["v1", "pay"]:
                o = c.by_token(parts[2])
                if method == "GET" and parts[3] == "offer":
                    return self._send(200, c.offer(o))
                if method == "GET" and parts[3] == "status":
                    return self._send(200, {"status": c.refresh(o)["status"], "refund_code": o.get("refund_code")})
                if method == "POST" and parts[3] == "request":
                    return self._send(200, {"accept": c.request(o, self._body().get("request"))})
                if method == "POST" and parts[3] == "funded":
                    return self._send(200, {"status": c.funded(o, self._body().get("funded"))["status"]})
                if method == "POST" and parts[3] == "code":
                    return self._send(200, {"status": c.code(o, self._body().get("code", ""))["status"]})
            # ---- the shop's own software, with the shop's key
            if parts[:2] == ["v1", "orders"]:
                if not self._authorised():
                    return self._send(401, {"error": "the checkout key is missing or wrong"})
                if method == "POST" and len(parts) == 2:
                    b = self._body()
                    return self._send(200, c.create(b.get("reference", ""), b.get("title", ""), b.get("amount"), b.get("mode", "pay_now"), b.get("deadline_hours")))
                if method == "POST" and len(parts) == 3 and parts[2] == "import":
                    return self._send(200, c.refresh(c.order_from_state(self._body().get("state", ""))))
                if len(parts) == 4:
                    o = c.by_id(parts[2])
                    if method == "GET" and parts[3] == "status":
                        return self._send(200, c.refresh(o))
                    if method == "POST" and parts[3] == "cancel":
                        return self._send(200, c.cancel(o))
                    if method == "POST" and parts[3] == "code":
                        return self._send(200, c.code(o, self._body().get("code", "")))
            return self._send(404, {"error": "no such page"})
        except KeyError as e:
            return self._send(404, {"error": str(e).strip("'\"")})
        except (ValueError, TypeError) as e:
            return self._send(400, {"error": str(e)})
        except RuntimeError as e:
            return self._send(409, {"error": str(e)})
        except OSError:
            return self._send(502, {"error": "the shop's own service could not be reached"})


def hidden_address(cfg, port):
    """The helper's Tor hidden address, which wallets dial. Named in the config, or made here by the `tor` program on
    this machine: its key lives in a folder beside the config, so the address is the same every time the helper starts."""
    if cfg.get("wallet_host"):
        return cfg["wallet_host"]
    tor = shutil.which("tor")
    if tor is None:
        raise SystemExit("no wallet_host in the config and no `tor` program on this machine: install Tor, or set wallet_host to this helper's hidden address")
    home = os.path.abspath(cfg.get("tor_dir", "musd-checkout-tor"))
    service = os.path.join(home, "service")
    os.makedirs(service, mode=0o700, exist_ok=True)
    os.chmod(home, 0o700)
    subprocess.Popen(
        [tor, "--quiet", "--SocksPort", "0", "--DataDirectory", os.path.join(home, "data"), "--HiddenServiceDir", service, "--HiddenServicePort", f"80 127.0.0.1:{port}"],
        stdin=subprocess.DEVNULL,
    )
    name = os.path.join(service, "hostname")
    for _ in range(120):
        if os.path.exists(name):
            with open(name, encoding="ascii") as f:
                return f.readline().strip()
        time.sleep(0.5)
    raise SystemExit("Tor did not publish a hidden address within a minute")


def serve(cfg, wallet):
    host, _, port = cfg.get("listen", "127.0.0.1:8787").rpartition(":")
    cfg["wallet_host"] = hidden_address(cfg, int(port))
    checkout = Checkout(cfg, wallet)
    Handler.checkout = checkout
    if cfg.get("shopify"):
        Handler.shopify = Shopify(cfg["shopify"], checkout)
    threading.Thread(target=checkout.poll_forever, daemon=True).start()
    httpd = http.server.ThreadingHTTPServer((host or "127.0.0.1", int(port)), Handler)
    print(f"MonerousD checkout helper on {host or '127.0.0.1'}:{port}; wallets reach it at {cfg['wallet_host']}", flush=True)
    httpd.serve_forever()


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--config", required=True, help="the JSON config file (see README.md)")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)
    if len(cfg.get("api_key", "")) < 24:
        raise SystemExit("api_key must be at least 24 characters: it is what lets your shop, and only your shop, create orders")
    # the recovery phrase is typed once at start and goes to the wallet's first input line; it is never written anywhere
    import getpass

    phrase = os.environ.get("MUSD_CHECKOUT_PHRASE") or getpass.getpass("Wallet recovery phrase (not shown, not stored): ")
    env = dict(os.environ, HARNESS_SEED_STDIN="1")
    env.pop("MUSD_CHECKOUT_PHRASE", None)
    serve(cfg, Wallet(cfg["wallet_command"], env=env, seed_line=phrase))


if __name__ == "__main__":
    main()
