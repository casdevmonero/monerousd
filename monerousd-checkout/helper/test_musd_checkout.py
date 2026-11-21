#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""Tests of the checkout helper's own rules, over real HTTP, against a stand-in wallet process.

TWO-PARTY-REVIEWED: the wallet here is a stand-in that speaks the real wallet's line protocol, so these tests judge
only the helper: what it refuses, what it tells the shop, and that it never calls an order paid before its wallet does.
Whether money really moves between a buyer's wallet and a shop's wallet on two nodes is the real-node check
`scratchpad/net/goods.py`, which runs this same helper against real `wallet-harness` and `usdmd-node` processes.

Run:  python3 test_musd_checkout.py
"""
import hashlib
import http.server
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import musd_checkout as mc  # noqa: E402

STAND_IN = r'''
import json, sys, secrets
paid, locked, deadline = set(), set(), set()
now_ms = None
def out(ok, op, v):
    print(json.dumps({"ok": ok, "op": op, **({"result": v} if ok else {"error": v})}), flush=True)
sys.stdin.readline()                      # the recovery phrase line
out(True, "open", {"address": "shop"})
for line in sys.stdin:
    w = line.split()
    if not w: continue
    op = w[0]
    if op == "poscharge":
        whole, _, frac = w[1].partition(".")
        out(True, op, {"amount_atomic": int(whole) * 10**8 + int((frac + "0" * 8)[:8]), "nonce": secrets.token_hex(16),
                       "expiry_ms": now_ms + 120000, "address": "shop", "pubkey": "00", "sig": "00"})
    elif op == "chargeawait":
        out(True, op, {"paid": w[1] in paid})
    elif op == "purchase_accept":
        r = json.loads(w[2]); out(True, op, {"kind": "accept", "id": r["id"], "seller_spk": "aa" * 32, "seller_salt": "bb" * 16, "lock2": "cc"})
    elif op == "purchase_funded":
        out(True, op, {"id": json.loads(w[1])["id"]})
    elif op == "purchase_status":
        out(True, op, {"locked": w[1] in locked, "deadline_passed": w[1] in deadline})
    elif op == "purchase_release":
        (out(True, op, {"taken": True}) if w[1].endswith(":good") else out(False, op, "that is not this purchase's code"))
    elif op == "purchase_refund_code":
        out(True, op, {"code": w[1] + ":refund"})
    elif op == "test_pay":      paid.add(w[1]); out(True, op, {})
    elif op == "test_lock":     locked.add(w[1]); out(True, op, {})
    elif op == "test_deadline": deadline.add(w[1]); out(True, op, {})
    elif op == "test_time":     now_ms = int(w[1]); out(True, op, {})
    else: out(False, op, "unknown command")
'''

KEY = "k" * 32
HOST = "b" * 56 + ".onion"


class WalletTestCase(unittest.TestCase):
    def setUp(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as script:
            self.addCleanup(os.unlink, script.name)
            script.write(STAND_IN)
        self.wallet = mc.Wallet([sys.executable, script.name], seed_line="phrase")
        self.addCleanup(self.wallet.proc.communicate)
        self.set_time(1_800_000_000_000)

    def set_time(self, now_ms):
        self.wallet.call("test_time", now_ms)
        self.now_ms = now_ms


class HelperTest(WalletTestCase):
    def setUp(self):
        super().setUp()
        self.hooks = []
        cfg = {"api_key": KEY, "merchant_name": "Corner Shop", "wallet_host": HOST, "webhook_url": "http://shop.invalid/hook",
               "webhook_secret": "s" * 32, "products": {"tea": {"title": "Green tea", "amount": "4.50"}}}
        self.checkout = mc.Checkout(cfg, self.wallet, post=lambda url, body, sig: self.hooks.append((url, body, sig)), clock=lambda: self.now_ms)

        class H(mc.Handler):
            checkout = self.checkout
            shopify = None

        self.H = H
        self.httpd = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.addCleanup(self.httpd.server_close)
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.shutdown)

    def call(self, method, path, body=None, key=None, raw=False):
        req = urllib.request.Request(self.base + path, method=method, data=None if body is None else json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", **({"X-Checkout-Key": key} if key else {})})
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                data = r.read()
                return r.status, (data if raw else json.loads(data))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    def new(self, **kw):
        code, v = self.call("POST", "/v1/orders", {"reference": "1001", "title": "Blue  mug", "amount": "12.50", **kw}, key=KEY)
        self.assertEqual(code, 200, v)
        return v

    def hooks_after(self, n):
        for _ in range(200):
            if len(self.hooks) >= n:
                break
            threading.Event().wait(0.01)
        return self.hooks

    def test_only_the_shops_key_creates_or_reads_an_order(self):
        for key in (None, "wrong" * 8):
            self.assertEqual(self.call("POST", "/v1/orders", {"title": "x", "amount": "1"}, key=key)[0], 401)
        v = self.new()
        self.assertEqual(self.call("GET", f"/v1/orders/{v['order_id']}/status")[0], 401)
        self.assertEqual(self.call("POST", f"/v1/orders/{v['order_id']}/cancel", {})[0], 401)

    def test_a_price_is_exact_or_refused(self):
        self.assertEqual(mc.atomic_of("12.5"), 1_250_000_000)
        self.assertEqual(mc.atomic_of(7), 700_000_000)
        self.assertEqual(mc.usdm_text(mc.atomic_of("0.00000001")), "0.00000001")
        self.assertEqual(mc.dollars(mc.atomic_of("12.5")), "12.50")
        for bad in ("0", "-1", "1e3", "1.123456789", "", "abc", None, "0.0"):
            code, _ = self.call("POST", "/v1/orders", {"title": "x", "amount": bad}, key=KEY)
            self.assertEqual(code, 400, bad)

    def test_a_plain_order_is_paid_only_when_the_wallet_saw_its_own_charge_paid(self):
        a, b = self.new(), self.new(reference="1002")
        self.assertEqual(a["link"], f"monerousd:pay?h={HOST}&t={a['token']}")
        offer_a = self.call("GET", f"/v1/pay/{a['token']}/offer")[1]
        offer_b = self.call("GET", f"/v1/pay/{b['token']}/offer")[1]
        self.assertEqual((offer_a["merchant"], offer_a["title"], offer_a["amount"]), ("Corner Shop", "Blue mug", "12.50000000"))
        self.assertNotEqual(offer_a["charge"]["nonce"], offer_b["charge"]["nonce"])
        self.assertEqual(self.call("GET", f"/v1/orders/{a['order_id']}/status", key=KEY)[1]["status"], "open")
        # the buyer of B pays: two open orders of ONE price, and only B is paid
        self.wallet.call("test_pay", offer_b["charge"]["nonce"])
        self.assertEqual(self.call("GET", f"/v1/pay/{b['token']}/status")[1]["status"], "paid")
        self.assertEqual(self.call("GET", f"/v1/orders/{a['order_id']}/status", key=KEY)[1]["status"], "open")
        url, body, sig = self.hooks_after(1)[0]
        self.assertEqual(sig, hashlib.sha3_256(b"s" * 32 + body).hexdigest())
        self.assertEqual((json.loads(body)["event"], json.loads(body)["reference"]), ("order.paid", "1002"))
        self.assertEqual(len(self.hooks), 1)

    def test_a_charge_is_renewed_and_a_payment_on_an_earlier_one_still_counts(self):
        a = self.new()
        offer_path = f"/v1/pay/{a['token']}/offer"
        first = self.call("GET", offer_path)[1]["charge"]["nonce"]
        self.assertEqual(self.call("GET", offer_path)[1]["charge"]["nonce"], first)
        self.set_time(self.now_ms + 90_000)  # most of the charge's signed two minutes are gone
        second = self.call("GET", offer_path)[1]["charge"]["nonce"]
        self.assertNotEqual(first, second)
        self.assertEqual(self.call("GET", offer_path)[1]["charge"]["nonce"], second)
        self.wallet.call("test_pay", first)
        self.assertEqual(self.call("GET", f"/v1/pay/{a['token']}/status")[1]["status"], "paid")

    def test_an_unpaid_plain_order_expires_and_a_finished_order_never_moves_again(self):
        a = self.new()
        nonce = self.call("GET", f"/v1/pay/{a['token']}/offer")[1]["charge"]["nonce"]
        self.set_time(self.now_ms + 71 * 60_000)
        self.assertEqual(self.call("GET", f"/v1/pay/{a['token']}/status")[1]["status"], "expired")
        self.wallet.call("test_pay", nonce)
        self.assertEqual(self.call("GET", f"/v1/pay/{a['token']}/status")[1]["status"], "expired")
        self.assertNotIn("charge", self.call("GET", f"/v1/pay/{a['token']}/offer")[1])

    def protected(self):
        v = self.new(mode="protected", deadline_hours=48)
        request = {"kind": "request", "id": "ab" * 16, "amount": 1_250_000_000, "t_h": v["deadline_ms"] // mc.HOUR_MS, "buyer_spk": "dd" * 32, "buyer_salt": "ee" * 16}
        return v, request

    def test_a_protected_order_walks_request_lock_code_and_is_paid_only_on_the_right_code(self):
        v, request = self.protected()
        t = v["token"]
        self.assertEqual(self.call("GET", f"/v1/pay/{t}/offer")[1]["deadline_ms"], v["deadline_ms"])
        for lie in ({**request, "amount": 1}, {**request, "t_h": request["t_h"] + 1}, "x", None):
            self.assertEqual(self.call("POST", f"/v1/pay/{t}/request", {"request": lie})[0], 400)
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/code", {"code": request["id"] + ":good"})[0], 400)  # nothing is locked yet
        code, said = self.call("POST", f"/v1/pay/{t}/request", {"request": request})
        self.assertEqual((code, said["accept"]["id"]), (200, request["id"]))
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/funded", {"funded": {"kind": "funded", "id": "ff" * 16, "lock1": "11"}})[0], 400)
        funded = {"kind": "funded", "id": request["id"], "lock1": "11"}
        # the buyer SAYS it paid; the shop's own wallet has not seen the money
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/funded", {"funded": funded})[1]["status"], "accepted")
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/code", {"code": request["id"] + ":good"})[0], 400)
        self.wallet.call("test_lock", request["id"])
        self.assertEqual(self.call("GET", f"/v1/orders/{v['order_id']}/status", key=KEY)[1]["status"], "locked")
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/code", {"code": "ff" * 16 + ":good"})[0], 400)
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/code", {"code": request["id"] + ":bad"})[0], 409)
        self.assertEqual(self.call("GET", f"/v1/pay/{t}/status")[1]["status"], "locked")
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/code", {"code": request["id"] + ":good"})[1]["status"], "paid")
        self.assertEqual([json.loads(b)["event"] for _, b, _ in self.hooks_after(2)], ["order.locked", "order.paid"])

    def test_a_cancelled_protected_order_gives_the_buyer_the_refund_code(self):
        v, request = self.protected()
        t = v["token"]
        self.call("POST", f"/v1/pay/{t}/request", {"request": request})
        self.call("POST", f"/v1/pay/{t}/funded", {"funded": {"kind": "funded", "id": request["id"], "lock1": "11"}})
        self.wallet.call("test_lock", request["id"])
        self.call("GET", f"/v1/pay/{t}/status")
        code, said = self.call("POST", f"/v1/orders/{v['order_id']}/cancel", {}, key=KEY)
        self.assertEqual((code, said["status"], said["refund_code"]), (200, "cancelled", request["id"] + ":refund"))
        self.assertEqual(self.call("GET", f"/v1/pay/{t}/status")[1], {"status": "cancelled", "refund_code": request["id"] + ":refund"})
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/code", {"code": request["id"] + ":good"})[0], 400)
        self.assertEqual(self.call("POST", f"/v1/orders/{v['order_id']}/cancel", {}, key=KEY)[0], 400)

    def test_a_protected_order_past_its_deadline_is_expired_not_paid(self):
        v, request = self.protected()
        t = v["token"]
        self.call("POST", f"/v1/pay/{t}/request", {"request": request})
        self.call("POST", f"/v1/pay/{t}/funded", {"funded": {"kind": "funded", "id": request["id"], "lock1": "11"}})
        self.wallet.call("test_lock", request["id"])
        self.wallet.call("test_deadline", request["id"])
        self.assertEqual(self.call("GET", f"/v1/pay/{t}/status")[1]["status"], "locked")  # locked first, as it was
        self.assertEqual(self.call("GET", f"/v1/pay/{t}/status")[1]["status"], "expired")
        # TWO-PARTY-REVIEWED: the helper's own rule against a stand-in wallet; the two real wallets are in scratchpad/net/goods.py.
        # The money is still in the vault until the buyer takes it back, so a late code is not turned away by the
        # helper: the wallet (and the chain behind it) decides.
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/code", {"code": request["id"] + ":bad"})[0], 409)
        self.assertEqual(self.call("GET", f"/v1/pay/{t}/status")[1]["status"], "expired")
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/code", {"code": request["id"] + ":good"})[1]["status"], "paid")

    def test_an_order_nobody_paid_into_cannot_be_paid_by_a_code_after_its_deadline(self):
        v, request = self.protected()
        t = v["token"]
        self.call("POST", f"/v1/pay/{t}/request", {"request": request})
        self.set_time(v["deadline_ms"] + 1)
        self.assertEqual(self.call("GET", f"/v1/pay/{t}/status")[1]["status"], "expired")
        self.assertEqual(self.call("POST", f"/v1/pay/{t}/code", {"code": request["id"] + ":good"})[0], 400)

    def test_the_shops_stored_state_brings_an_order_back_and_a_forged_state_does_not(self):
        v, request = self.protected()
        self.call("POST", f"/v1/pay/{v['token']}/request", {"request": request})
        state = self.call("GET", f"/v1/orders/{v['order_id']}/status", key=KEY)[1]["state"]
        self.checkout.orders.clear()  # the helper restarted
        self.assertEqual(self.call("GET", f"/v1/orders/{v['order_id']}/status", key=KEY)[0], 404)
        self.assertEqual(self.call("GET", f"/v1/pay/{v['token']}/offer")[0], 404)
        body, _, tag = state.rpartition(".")
        for forged in (body + "." + "0" * 64, "e30=." + tag, "", "nonsense"):
            self.assertEqual(self.call("POST", "/v1/orders/import", {"state": forged}, key=KEY)[0], 400)
        code, back = self.call("POST", "/v1/orders/import", {"state": state}, key=KEY)
        self.assertEqual((code, back["order_id"], back["status"], back["token"]), (200, v["order_id"], "accepted", v["token"]))
        self.assertEqual(self.call("GET", f"/v1/pay/{v['token']}/offer")[1]["title"], "Blue mug")

    def test_a_price_list_item_sells_from_one_link_and_the_pay_page_shows_only_the_order(self):
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *a, **k):
                return None

        try:
            urllib.request.build_opener(NoRedirect).open(self.base + "/buy/tea", timeout=10)
            self.fail("the item link did not redirect")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 303)
            where = e.headers["Location"]
        code, page = self.call("GET", where, raw=True)
        page = page.decode()
        self.assertEqual(code, 200)
        for want in ("Corner Shop", "Green tea", "$4.50", f"monerousd:pay?h={HOST}&amp;t="):
            self.assertIn(want, page)
        self.assertNotIn(KEY, page)
        self.assertEqual(self.call("GET", "/buy/coffee")[0], 404)
        self.assertEqual(self.call("GET", "/pay/" + "x" * 32)[0], 404)

    def test_a_title_cannot_carry_markup_into_the_pay_page(self):
        v = self.new(title='<script>alert(1)</script>"><img src=x>')
        page = self.call("GET", f"/pay/{v['token']}", raw=True)[1].decode()
        self.assertNotIn("<script>alert(1)", page)
        self.assertNotIn("<img src=x>", page)

    def test_product_link_decodes_one_path_segment_once(self):
        product_id = "Café + 10%20"
        self.checkout.cfg["products"][product_id] = {"title": "Coffee", "amount": "4.50"}
        path = "/buy/Caf%C3%A9%20+%2010%2520"
        code, page = self.call("GET", path, raw=True)
        self.assertEqual(code, 200)
        self.assertIn(b"Coffee", page)
        self.assertIsNotNone(self.checkout.by_reference("item:" + product_id))

    def test_hosted_page_renders_payment_actions_only_while_waiting(self):
        view = self.new()
        order = self.checkout.by_id(view["order_id"])
        for status in ("open", "accepted", "locked", "paid", "expired", "cancelled"):
            with self.subTest(status=status):
                order["status"] = status
                code, page = self.call("GET", "/pay/" + view["token"], raw=True)
                self.assertEqual(code, 200)
                self.assertEqual(b'<div id="payment-actions" hidden>' in page, status not in ("open", "accepted"))


class ShopifyTest(WalletTestCase):
    def setUp(self):
        super().setUp()
        self.checkout = mc.Checkout({"api_key": KEY, "wallet_host": HOST}, self.wallet, clock=lambda: self.now_ms)
        self.order = {"id": 77, "name": "#1077", "token": "tok77", "total_outstanding": "30.00", "currency": "USD",
                      "financial_status": "pending", "payment_gateway_names": ["MonerousD"], "tags": "gift, priority",
                      "note_attributes": [{"name": "Gift message", "value": "Happy birthday!"}]}
        self.state = None
        self.asked = []
        self.marked_paid = threading.Event()

        def ask(method, what, body=None):
            if method == "GET":
                return {"order": dict(self.order)}
            self.assertEqual((method, what), ("POST", "graphql.json"))
            query, variables = body["query"], body["variables"]
            if query.startswith("query"):
                self.assertIn('metafield(key: "musd_state")', query)
                self.assertEqual(variables["id"], "gid://shopify/Order/77")
                field = {"value": self.state} if self.state is not None else None
                return {"data": {"order": {"metafield": field}}}
            if "metafieldsSet(" in query:
                op = "metafieldsSet"
                field, = variables["fields"]
                self.assertEqual((field["ownerId"], field["key"], field.get("namespace")), ("gid://shopify/Order/77", "musd_state", None))
                self.state = field["value"]
            elif "tagsAdd(" in query:
                op = "tagsAdd"
                self.assertEqual(variables["id"], "gid://shopify/Order/77")
                self.order["tags"] = ", ".join(dict.fromkeys(self.order["tags"].split(", ") + variables["tags"]))
            else:
                op = "orderMarkAsPaid"
                self.assertIn("orderMarkAsPaid(", query)
                self.assertEqual(variables["input"]["id"], "gid://shopify/Order/77")
                self.order["financial_status"] = "paid"
            self.asked.append(op)
            if op == "orderMarkAsPaid":
                self.marked_paid.set()
            return {"data": {op: {"userErrors": []}}}

        self.shopify = mc.Shopify({"shop": "x.myshopify.com", "admin_token": "t"}, self.checkout, ask=ask)

    def test_only_the_buyers_own_pending_dollar_order_placed_with_monerousd_opens(self):
        for key in ("", "wrong"):
            with self.assertRaises(KeyError):
                self.shopify.open_order("77", key)
        with self.assertRaises(ValueError):
            self.shopify.open_order("77; drop", "tok77")
        for field, bad in (("currency", "EUR"), ("financial_status", "paid"), ("payment_gateway_names", ["Card"])):
            good, self.order[field] = self.order[field], bad
            with self.assertRaises(ValueError):
                self.shopify.open_order("77", "tok77")
            self.order[field] = good
        o = self.shopify.open_order("77", "tok77")
        self.assertEqual((o["amount"], o["reference"], o["title"]), (3_000_000_000, "shopify:77", "Order #1077"))
        self.assertIs(self.shopify.open_order("77", "tok77"), o)  # made once

    def test_the_order_is_marked_paid_only_after_the_wallet_says_so_and_its_state_rides_on_the_order(self):
        o = self.shopify.open_order("77", "tok77")
        self.assertEqual(self.asked, ["metafieldsSet"])
        self.assertEqual(self.order["note_attributes"], [{"name": "Gift message", "value": "Happy birthday!"}])
        self.checkout.orders.clear()  # the helper restarted: the order comes back from Shopify's own record
        again = self.shopify.open_order("77", "tok77")
        self.assertEqual((again["id"], again["refs"]), (o["id"], o["refs"]))
        self.assertEqual(self.asked, ["metafieldsSet"])
        self.wallet.call("test_pay", again["refs"][0])
        self.assertEqual(self.checkout.refresh(again)["status"], "paid")
        self.assertTrue(self.marked_paid.wait(2))
        self.shopify.open_order("77", "tok77")
        self.assertEqual(self.asked, ["metafieldsSet", "metafieldsSet", "orderMarkAsPaid"])

    def test_legacy_state_migrates_without_replacing_notes_or_tags(self):
        self.shopify.mode = "protected"
        o = self.shopify.open_order("77", "tok77")
        legacy = {"name": "musd_state", "value": self.state}
        self.order["note_attributes"].append(legacy)
        self.state = None
        self.checkout.orders.clear()
        restored = self.shopify.open_order("77", "tok77")
        self.assertEqual(restored["id"], o["id"])
        self.assertEqual(self.state, legacy["value"])
        restored["status"] = "locked"
        self.shopify.heard(restored)
        self.assertEqual(self.order["tags"], "gift, priority, MonerousD payment held: ship now")
        self.assertEqual(self.order["note_attributes"], [{"name": "Gift message", "value": "Happy birthday!"}, legacy])
        self.checkout.orders.clear()
        self.assertEqual(self.shopify.open_order("77", "tok77")["status"], "locked")
        self.assertEqual(self.asked, ["metafieldsSet", "metafieldsSet", "metafieldsSet", "tagsAdd"])

    def test_rejected_metafield_write_retries_the_same_checkout(self):
        ask = self.shopify.ask
        def reject_write(method, what, body=None):
            if body and "metafieldsSet(" in body["query"]:
                return {"data": {"metafieldsSet": {"userErrors": [{"message": "could not write"}]}}}
            return ask(method, what, body)
        self.shopify.ask = reject_write
        with self.assertRaises(OSError):
            self.shopify.open_order("77", "tok77")
        original = self.checkout.by_reference("shopify:77")
        self.shopify.ask = ask
        self.assertIs(self.shopify.open_order("77", "tok77"), original)
        self.assertEqual(self.state, self.checkout.state_of(original))

    def test_concurrent_paid_update_accepts_only_the_confirmed_order(self):
        o = self.shopify.open_order("77", "tok77")
        o["status"] = "paid"
        ask = self.shopify.ask
        gid = "gid://shopify/Order/77"
        paid_order = {"id": gid, "displayFinancialStatus": "PAID"}
        reply = {"data": {"orderMarkAsPaid": {"order": paid_order, "userErrors": [{"message": "Order cannot be marked as paid."}]}}}

        def other_request_paid_first(method, what, body=None):
            if body and "orderMarkAsPaid(" in body["query"]:
                self.assertIn("order { id displayFinancialStatus }", body["query"])
                return reply
            return ask(method, what, body)

        self.shopify.ask = other_request_paid_first
        self.assertIs(self.shopify.open_order("77", "tok77"), o)
        for reported_id, status in ((gid, "PENDING"), ("gid://shopify/Order/88", "PAID")):
            with self.subTest(reported_id=reported_id, status=status), self.assertRaises(OSError):
                paid_order.update(id=reported_id, displayFinancialStatus=status)
                self.shopify.open_order("77", "tok77")
        paid_order.update(id=gid, displayFinancialStatus="PAID")
        reply["errors"] = [{"message": "query failed"}]
        with self.assertRaises(OSError):
            self.shopify.open_order("77", "tok77")


if __name__ == "__main__":
    unittest.main(verbosity=2)
