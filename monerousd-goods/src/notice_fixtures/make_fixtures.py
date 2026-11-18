#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""Makes the signed test notices that src/notice.rs checks.

A second, independent implementation: its own header and body canonicalization (RFC 6376 section 3.4),
OpenSSL's signature. The carrier is made up (parcels.example) and so are its subjects; no real carrier's
template is here. The private keys are made in a temp folder and never written beside the fixtures, so
running this again makes new keys and new fixtures.

Run: python3 make_fixtures.py
"""
import base64
import hashlib
import os
import re
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="notice-fixtures-")
DOMAIN, SELECTOR = "parcels.example", "k1"


def new_key(name):
    path = os.path.join(TMP, name + ".pem")
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", path], check=True, capture_output=True)  # CLASSICAL-CRYPTO-EXEMPT: a throwaway key standing in for an outside carrier's mail key, test fixtures only
    der = subprocess.run(["openssl", "pkey", "-in", path, "-pubout", "-outform", "DER"], check=True, capture_output=True).stdout
    with open(os.path.join(HERE, name + ".spki.der"), "wb") as f:
        f.write(der)
    return path


def sign(key, data):
    return subprocess.run(["openssl", "dgst", "-sha256", "-sign", key], input=data, check=True, capture_output=True).stdout


def relaxed_header(name, value):
    value = value.replace(b"\r\n", b"")
    value = re.sub(rb"[ \t]+", b" ", value).strip(b" \t")
    return name.lower().strip() + b":" + value + b"\r\n"


def relaxed_body(body):
    lines = [re.sub(rb"[ \t]+", b" ", l).rstrip(b" \t") for l in body.split(b"\r\n")]
    while lines and lines[-1] == b"":
        lines.pop()
    return b"".join(l + b"\r\n" for l in lines)


def simple_body(body):
    while body.endswith(b"\r\n"):
        body = body[:-2]
    return body + b"\r\n"


def make(name, key, headers, body, canon=("relaxed", "relaxed"), covered=("from", "to", "subject", "date"), t=1800000500, limit=False):
    hc, bc = canon
    cbody = relaxed_body(body) if bc == "relaxed" else simple_body(body)
    bh = base64.b64encode(hashlib.sha256(cbody).digest()).decode()
    tags = "v=1; a=rsa-sha256; c=%s/%s; d=%s; s=%s;" % (hc, bc, DOMAIN, SELECTOR)  # CLASSICAL-CRYPTO-EXEMPT: the tag an outside carrier's mail system writes, test fixtures only
    if t is not None:
        tags += " t=%d;" % t
    if limit:
        tags += " l=%d;" % len(cbody)
    tags += "\r\n h=%s;\r\n bh=%s;\r\n b=" % (":".join(covered), bh)
    tags = tags.encode()
    by_name = {n.lower(): (n, v) for n, v in headers}
    data = b""
    for want in covered:
        n, v = by_name[want]
        data += relaxed_header(n.encode(), v.encode()) if hc == "relaxed" else (n + ": " + v + "\r\n").encode()
    if hc == "relaxed":
        data += relaxed_header(b"DKIM-Signature", tags)[:-2]
    else:
        data += b"DKIM-Signature: " + tags
    b = base64.b64encode(sign(key, data)).decode()
    folded = "\r\n ".join(b[i:i + 64] for i in range(0, len(b), 64)).encode()
    msg = b"DKIM-Signature: " + tags + folded + b"\r\n"
    msg += b"".join((n + ": " + v + "\r\n").encode() for n, v in headers)
    msg += b"\r\n" + body
    with open(os.path.join(HERE, name), "wb") as f:
        f.write(msg)


def headers(subject, sender="Parcels Example <notify@parcels.example>"):
    return [
        ("From", sender),
        ("To", "orders@shop.example"),
        ("Subject", subject),
        ("Date", "Fri, 15 Jan 2027 09:30:00 -0500"),
        ("Message-ID", "<20270115143000.1@parcels.example>"),
        ("X-Mailer", "parcels-notify 4.2"),
    ]


key = new_key("carrier")
new_key("other")
delivered = "Parcels Example Delivery Notification, Tracking Number 1Z999AA10123456784"
body = b"Hello,\r\n\r\nYour parcel   was delivered. \r\nThank you.\t\r\n\r\n\r\n"

make("delivered.eml", key, headers(delivered), body)
make("returned.eml", key, headers("Parcels Example: Returned to Sender, Tracking Number 1Z999AA10123456784"),
     b"The parcel is being returned to the sender.\r\n", canon=("simple", "simple"), t=None)
make("encoded_subject.eml", key, headers("=?UTF-8?Q?Parcels_Example=C2=AE_Item_Delivered_9400111899223344556677?="), body)
make("with_length.eml", key, headers(delivered), body, limit=True)
make("subject_unsigned.eml", key, headers(delivered), body, covered=("from", "to", "date"))
make("from_elsewhere.eml", key, headers(delivered, sender="Parcels Example <notify@other.example>"), body)
print("fixtures written to", HERE)
