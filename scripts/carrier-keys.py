#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""
carrier-keys.py — confirm a parcel carrier's published mail key and write it into the wallet's carrier list.

WHO RUNS THIS: the builders of a wallet release, by hand, once per carrier key. Nothing in the wallet or the node
ever runs it, and it holds no key of ours.

WHY IT EXISTS. The wallet accepts a carrier's signed "delivered" email as proof that a parcel arrived
(monerousd-wallet-v2/src-tauri/src/notice.rs). A key in the wallet's list
(monerousd-wallet-v2/src-tauri/src/carriers.json) lets an email it signed release a buyer's payment, so a wrong key
there is a way to take money. An entry is therefore written only when:

  1. THREE independent resolvers, asked over HTTPS, return the same published key for the carrier's own domain,
     byte for byte (one lying or poisoned resolver cannot place a key);
  2. the key is of the one kind the proof covers (2048-bit modulus, exponent 65537);
  3. the release's builders have read a LIVE notice from that carrier against the wording rule they state here
     (this script cannot do that part; it prints the reminder and the entry carries the wording they typed).

WHAT IT SENDS: one question per resolver, "the TXT record of <selector>._domainkey.<domain>". A carrier's public
domain name, nothing about any user, wallet or sale.

WHAT IT WRITES, AND THE WHOLE OF ITS COST. With --write, one entry in ONE SOURCE FILE of the repository
(carriers.json), at release time: about 620 bytes per listed key (512 hex characters of modulus plus its names).
Five carriers with two keys each is 10 x 620 B = 6.2 KB, compiled into the wallet once. cons: none on any node or
wallet at run time: nothing is written per block, per note, per sale or per user, and the file's size is a function
of how many carriers a release lists, never of the chain's history.

USE
  python3 scripts/carrier-keys.py --name "Carrier" --domain example.com --selector s1 \
      --delivered "Delivered" --delivered "Tracking Number" [--not-delivered "Out for Delivery"] [--write]
  python3 scripts/carrier-keys.py --self-test

Without --write the entry is printed and nothing is changed.

CLASSICAL-CRYPTO-EXEMPT: this tool READS an outside company's own published classical mail key so the wallet can
VERIFY that company's signature on its own data (user 2026-11-09: "we dont control external companies classical
crypto"). Nothing of ours is signed, keyed or secured by it.
"""
import argparse
import base64
import json
import os
import sys
import urllib.parse
import urllib.request

LIST = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "monerousd-wallet-v2", "src-tauri", "src", "carriers.json")

# Three resolvers run by three different operators, each asked over HTTPS for JSON.
RESOLVERS = [
    ("cloudflare", "https://cloudflare-dns.com/dns-query?name={name}&type=TXT"),
    ("google", "https://dns.google/resolve?name={name}&type=TXT"),
    ("quad9", "https://dns.quad9.net:5053/dns-query?name={name}&type=TXT"),
]

KEY_BYTES = 256  # the modulus size the notice proof covers
EXPONENT = 65537


def ask(url):
    """One resolver's TXT answer for the name, its quoted pieces joined: the record as published."""
    req = urllib.request.Request(url, headers={"accept": "application/dns-json", "user-agent": "carrier-keys"})
    with urllib.request.urlopen(req, timeout=20) as r:
        body = json.loads(r.read().decode("utf-8"))
    if body.get("Status") != 0:
        raise ValueError("the resolver answered status %r" % body.get("Status"))
    records = []
    for a in body.get("Answer", []):
        if a.get("type") != 16:
            continue
        text = a.get("data", "")
        # a TXT answer is one or more quoted strings; a long key is split across several
        pieces, cur, inside = [], "", False
        for ch in text:
            if ch == '"':
                if inside:
                    pieces.append(cur)
                    cur = ""
                inside = not inside
            elif inside:
                cur += ch
        records.append("".join(pieces) if pieces else text)
    return records


def tags(record):
    """The tag=value pairs of a published mail-key record (RFC 6376 §3.6.1)."""
    out = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = "".join(v.split())
    return out


def der_item(data, at):
    """One DER item at `at`: (tag, content, the position after it)."""
    tag = data[at]
    n = data[at + 1]
    at += 2
    if n & 0x80:
        count = n & 0x7F
        if count == 0 or count > 4:
            raise ValueError("a length this tool does not read")
        n = int.from_bytes(data[at:at + count], "big")
        at += count
    if at + n > len(data):
        raise ValueError("an item runs past the key's end")
    return tag, data[at:at + n], at + n


def key_numbers(p_value):
    """The modulus and exponent inside a published key (`p=`): a SubjectPublicKeyInfo holding the two integers."""
    der = base64.b64decode(p_value, validate=True)
    tag, outer, end = der_item(der, 0)
    if tag != 0x30 or end != len(der):
        raise ValueError("the key is not one sequence")
    tag, _algorithm, at = der_item(outer, 0)
    if tag != 0x30:
        raise ValueError("the key names no algorithm")
    tag, bits, at = der_item(outer, at)
    if tag != 0x03 or at != len(outer) or not bits or bits[0] != 0:
        raise ValueError("the key holds no bit string")
    tag, pair, end = der_item(bits[1:], 0)
    if tag != 0x30 or end != len(bits) - 1:
        raise ValueError("the key's numbers are not one sequence")
    tag, modulus, at = der_item(pair, 0)
    if tag != 0x02:
        raise ValueError("no modulus")
    tag, exponent, at = der_item(pair, at)
    if tag != 0x02 or at != len(pair):
        raise ValueError("no exponent")
    return int.from_bytes(modulus, "big"), int.from_bytes(exponent, "big")


def confirmed(domain, selector):
    """The key every resolver publishes for the name: (the p= value, the modulus as hex). Raises unless all agree."""
    name = urllib.parse.quote("%s._domainkey.%s" % (selector, domain))
    seen = {}
    for who, url in RESOLVERS:
        records = [r for r in ask(url.format(name=name)) if "p=" in r.replace(" ", "")]
        if len(records) != 1:
            raise ValueError("%s returned %d key records for %s (exactly one is required)" % (who, len(records), name))
        t = tags(records[0])
        kind = t.get("k", "rsa")  # CLASSICAL-CRYPTO-EXEMPT: the key type tag an OUTSIDE COMPANY's mail-key record states (RFC 6376); read, never used to sign
        if kind != "rsa":  # CLASSICAL-CRYPTO-EXEMPT: the one outside-company key type the notice proof verifies
            raise ValueError("%s: the key is of type %r, which the notice proof does not cover" % (who, kind))
        if not t.get("p"):
            raise ValueError("%s: the key was withdrawn (an empty p=)" % who)
        seen[who] = t["p"]
        print("  %-10s %s…%s (%d characters)" % (who, t["p"][:16], t["p"][-8:], len(t["p"])))
    if len(set(seen.values())) != 1:
        raise ValueError("the resolvers DISAGREE on the key; nothing is written")
    p = next(iter(seen.values()))
    modulus, exponent = key_numbers(p)
    if exponent != EXPONENT:
        raise ValueError("the key's exponent is %d; the notice proof covers %d only" % (exponent, EXPONENT))
    if modulus.bit_length() != 8 * KEY_BYTES or modulus % 2 == 0:
        raise ValueError("the key's modulus has %d bits; the notice proof covers %d-bit keys only" % (modulus.bit_length(), 8 * KEY_BYTES))
    return p, "%0*x" % (2 * KEY_BYTES, modulus)


def merge(listing, name, domain, selector, modulus_hex, delivered, not_delivered):
    """Put the key into the list: under the carrier of that name (made if new). An existing selector must match."""
    for c in listing["carriers"]:
        if c["name"] == name:
            carrier = c
            break
    else:
        carrier = {"name": name, "domains": [], "keys": [], "delivered": delivered, "not_delivered": not_delivered}
        listing["carriers"].append(carrier)
    if domain.lower() not in [d.lower() for d in carrier["domains"]]:
        carrier["domains"].append(domain.lower())
    for k in carrier["keys"]:
        if k["selector"] == selector:
            if k["modulus"].lower() != modulus_hex:
                raise ValueError("the list already holds ANOTHER key for selector %r; remove it by hand if the carrier rotated it" % selector)
            return False
    carrier["keys"].append({"selector": selector, "modulus": modulus_hex})
    carrier["delivered"] = delivered
    carrier["not_delivered"] = not_delivered
    return True


def self_test():
    """The key reader against a key made here: its numbers read back, and a damaged key is refused."""
    def item(tag, content):
        n = len(content)
        head = bytes([n]) if n < 0x80 else bytes([0x80 | len(n.to_bytes((n.bit_length() + 7) // 8, "big"))]) + n.to_bytes((n.bit_length() + 7) // 8, "big")
        return bytes([tag]) + head + content
    modulus = (1 << (8 * KEY_BYTES - 1)) | 0x1234567 | 1
    pair = item(0x30, item(0x02, b"\x00" + modulus.to_bytes(KEY_BYTES, "big")) + item(0x02, EXPONENT.to_bytes(3, "big")))
    # the algorithm identifier's own bytes are not read by this tool; any well-formed sequence stands in for it
    spki = item(0x30, item(0x30, item(0x06, b"\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01") + item(0x05, b"")) + item(0x03, b"\x00" + pair))
    p = base64.b64encode(spki).decode()
    assert key_numbers(p) == (modulus, EXPONENT), "the key's numbers do not read back"
    assert tags("v=DKIM1; k=x; p=" + p[:10] + " " + p[10:])["p"] == p, "a key split by blanks does not read whole"
    for cut in (1, 7, len(spki) // 2):
        try:
            key_numbers(base64.b64encode(spki[:-cut]).decode())
        except Exception:
            continue
        raise AssertionError("a key cut short by %d bytes was read" % cut)
    listing = {"carriers": []}
    assert merge(listing, "A", "a.example", "s1", "%0*x" % (2 * KEY_BYTES, modulus), ["Delivered"], [])
    assert not merge(listing, "A", "a.example", "s1", "%0*x" % (2 * KEY_BYTES, modulus), ["Delivered"], [])
    try:
        merge(listing, "A", "a.example", "s1", "%0*x" % (2 * KEY_BYTES, modulus + 2), ["Delivered"], [])
    except ValueError:
        pass
    else:
        raise AssertionError("another key was written over a listed selector")
    print("self-test passed")


def main():
    ap = argparse.ArgumentParser(description="Confirm a carrier's published mail key with three resolvers and add it to the wallet's carrier list.")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--name")
    ap.add_argument("--domain")
    ap.add_argument("--selector")
    ap.add_argument("--delivered", action="append", default=[], help="words every 'delivered' subject line of this carrier carries (repeat)")
    ap.add_argument("--not-delivered", action="append", default=[], help="words of the carrier's other notices (repeat)")
    ap.add_argument("--write", action="store_true", help="write the entry into carriers.json")
    a = ap.parse_args()
    if a.self_test:
        self_test()
        return 0
    if not (a.name and a.domain and a.selector and a.delivered):
        ap.error("--name, --domain, --selector and at least one --delivered are required")
    print("asking three resolvers for %s._domainkey.%s" % (a.selector, a.domain))
    try:
        _p, modulus_hex = confirmed(a.domain, a.selector)
    except Exception as e:  # nothing is written on any doubt
        print("NOT CONFIRMED: %s" % e)
        return 1
    print("CONFIRMED: all three agree; a %d-bit key with exponent %d" % (8 * KEY_BYTES, EXPONENT))
    entry = {"name": a.name, "domains": [a.domain.lower()], "keys": [{"selector": a.selector, "modulus": modulus_hex}], "delivered": a.delivered, "not_delivered": a.not_delivered}
    print(json.dumps(entry, indent=2))
    print("\nBEFORE A RELEASE CARRIES THIS KEY: open a real 'delivered' email from %s, check that its signature names\n"
          "selector %r under %s, and that its subject line carries every --delivered word and none of the\n"
          "--not-delivered words. A wording rule that also matches 'out for delivery' would pay a seller early." % (a.name, a.selector, a.domain))
    if not a.write:
        print("\n(nothing written; pass --write to add it to %s)" % os.path.normpath(LIST))
        return 0
    with open(LIST, "r", encoding="utf-8") as f:
        listing = json.load(f)
    try:
        added = merge(listing, a.name, a.domain, a.selector, modulus_hex, a.delivered, a.not_delivered)
    except ValueError as e:
        print("NOT WRITTEN: %s" % e)
        return 1
    if added:
        with open(LIST, "w", encoding="utf-8") as f:
            json.dump(listing, f, indent=2)
            f.write("\n")
        print("written to %s" % os.path.normpath(LIST))
    else:
        print("that key is already in the list; nothing changed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
