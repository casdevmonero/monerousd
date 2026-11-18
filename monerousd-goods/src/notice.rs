// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! A carrier's own signed delivery notice, checked, and the one fact read from it (spec section 16.2).
//!
//! A carrier signs its notification mail with its own mail key (DKIM, RFC 6376). [`verify`] checks that
//! signature against a pinned key and returns only what the carrier signed. [`read`] turns it into a
//! [`Fact`]: this carrier says this tracking number was delivered (or is coming back, or was lost).
//!
//! Three rules keep a shipper from shaping a fact:
//! - only the signed Subject is read, matched whole against the carrier's own template. Nothing a shipper
//!   can type (a reference, a memo, a name) is ever an input, and the body is hashed but never read;
//! - From, Subject and Date must each appear exactly once and be covered by the signature, so there is no
//!   second, unsigned copy to show instead;
//! - a signature that covers only a prefix of the body (the `l=` tag) is refused.
//!
//! This is the check the buyer's wallet runs on the notice the seller forwards (spec section 16.1 step 3).
//! The buyer learns nothing new from it: it is the notice about the buyer's own parcel.
//!
//! cons: none. Pure functions of the message bytes and a pinned key list. Nothing is stored, sent or logged.
//!
//! TWO-PARTY-REVIEWED: the second party here is the outside carrier, which signs with its own system. The
//! test notices are signed by an independent implementation (`notice_fixtures/make_fixtures.py`: its own
//! canonicalization, OpenSSL's signature) and checked by this one. Live notices from real carriers are
//! build step 0 of the spec and are not claimed here; no real carrier's template is in this file.

mod outside_sig;

use base64::Engine;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NoticeError {
    /// Not a mail message this code can take apart.
    Malformed,
    /// No signature from a domain on the key list.
    UnknownKey,
    /// A signature of a kind this code does not accept (another algorithm, a body-length limit).
    Unsupported,
    /// From, Subject or Date is missing, repeated, or not covered by the signature.
    Uncovered,
    BodyChanged,
    BadSignature,
    /// The From address is not at the signing domain.
    NotAligned,
    /// The signature carries no time and the Date cannot be read.
    Undated,
    /// The signed Subject is not one of the carrier's notices.
    NotANotice,
}

/// One mail key of one carrier: the domain it signs for, the selector, and the key as the carrier publishes it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarrierKey {
    pub domain: String,
    pub selector: String,
    pub spki_der: Vec<u8>,
}

/// What the carrier signed, and nothing else.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedMail {
    /// The signing domain (`d=`), lower case.
    pub domain: String,
    /// The Subject, unfolded and decoded.
    pub subject: String,
    /// When the carrier signed it (`t=`), or the signed Date, in seconds.
    pub signed_at_s: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status {
    Delivered,
    ReturnedToSender,
    Lost,
}

/// One notice of one carrier: the Subject is exactly `before`, a tracking number, `after`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    pub carrier: String,
    pub domain: String,
    pub status: Status,
    pub before: String,
    pub after: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fact {
    pub carrier: String,
    pub status: Status,
    pub tracking: String,
    pub signed_at_s: u64,
}

impl Fact {
    /// True when this fact is about the parcel the vault pinned, and the carrier signed it after the pin.
    /// The date matters: a carrier may reuse a tracking number months later (spec section 20 row 7).
    pub fn settles(&self, pinned_tracking: &str, pinned_at_s: u64) -> bool {
        self.tracking == pinned_tracking && self.signed_at_s > pinned_at_s
    }
}

struct Header {
    /// Lower case.
    name: String,
    /// The whole field as it came, folded lines and final CRLF included.
    raw: Vec<u8>,
}

fn is_wsp(b: u8) -> bool {
    b == b' ' || b == b'\t'
}

/// A saved message often has bare line feeds. The signature is over CRLF.
fn with_crlf(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len() + raw.len() / 40);
    for (i, &b) in raw.iter().enumerate() {
        if b == b'\n' && (i == 0 || raw[i - 1] != b'\r') {
            out.push(b'\r');
        }
        out.push(b);
    }
    out
}

fn split(msg: &[u8]) -> (&[u8], &[u8]) {
    match msg.windows(4).position(|w| w == b"\r\n\r\n") {
        Some(i) => (&msg[..i + 2], &msg[i + 4..]),
        None => (msg, &[]),
    }
}

fn headers(block: &[u8]) -> Result<Vec<Header>, NoticeError> {
    let mut out: Vec<Header> = Vec::new();
    let mut rest = block;
    while !rest.is_empty() {
        let end = rest.windows(2).position(|w| w == b"\r\n").map(|i| i + 2).ok_or(NoticeError::Malformed)?;
        let line = &rest[..end];
        rest = &rest[end..];
        if is_wsp(line[0]) {
            out.last_mut().ok_or(NoticeError::Malformed)?.raw.extend_from_slice(line);
        } else {
            let colon = line.iter().position(|&b| b == b':').ok_or(NoticeError::Malformed)?;
            let name = std::str::from_utf8(&line[..colon]).map_err(|_| NoticeError::Malformed)?;
            if name.is_empty() || name.bytes().any(|b| b <= b' ' || b >= 0x7f) {
                return Err(NoticeError::Malformed);
            }
            out.push(Header { name: name.to_ascii_lowercase(), raw: line.to_vec() });
        }
    }
    Ok(out)
}

fn value_of(raw: &[u8]) -> &[u8] {
    let colon = raw.iter().position(|&b| b == b':').unwrap_or(raw.len().saturating_sub(1));
    &raw[colon + 1..]
}

/// Unfold a field's value and trim it.
fn unfolded(raw: &[u8]) -> Result<String, NoticeError> {
    let v: Vec<u8> = value_of(raw).iter().copied().filter(|&b| b != b'\r' && b != b'\n').collect();
    Ok(String::from_utf8(v).map_err(|_| NoticeError::Malformed)?.trim().to_string())
}

#[derive(Clone, Copy, PartialEq)]
enum Canon {
    Simple,
    Relaxed,
}

fn canon_of(s: &str) -> Result<Canon, NoticeError> {
    match s {
        "simple" => Ok(Canon::Simple),
        "relaxed" => Ok(Canon::Relaxed),
        _ => Err(NoticeError::Unsupported),
    }
}

/// RFC 6376 section 3.4.2: the name in lower case, the value unfolded with each run of spaces as one space.
fn relaxed_header(raw: &[u8]) -> Vec<u8> {
    let colon = raw.iter().position(|&b| b == b':').unwrap_or(raw.len());
    let mut out: Vec<u8> = raw[..colon].iter().map(u8::to_ascii_lowercase).filter(|b| !is_wsp(*b)).collect();
    out.push(b':');
    let mut pending_space = false;
    let mut started = false;
    for &b in raw.get(colon + 1..).unwrap_or(&[]) {
        if b == b'\r' || b == b'\n' {
            continue;
        }
        if is_wsp(b) {
            pending_space = started;
            continue;
        }
        if pending_space {
            out.push(b' ');
            pending_space = false;
        }
        out.push(b);
        started = true;
    }
    out.extend_from_slice(b"\r\n");
    out
}

fn canon_header(raw: &[u8], mode: Canon) -> Vec<u8> {
    match mode {
        Canon::Simple => raw.to_vec(),
        Canon::Relaxed => relaxed_header(raw),
    }
}

/// RFC 6376 sections 3.4.3 and 3.4.4.
fn canon_body(body: &[u8], mode: Canon) -> Vec<u8> {
    match mode {
        Canon::Simple => {
            let mut end = body.len();
            while end >= 2 && &body[end - 2..end] == b"\r\n" {
                end -= 2;
            }
            let mut out = body[..end].to_vec();
            out.extend_from_slice(b"\r\n");
            out
        }
        Canon::Relaxed => {
            let mut lines: Vec<Vec<u8>> = Vec::new();
            let mut rest = body;
            loop {
                let (line, next) = match rest.windows(2).position(|w| w == b"\r\n") {
                    Some(i) => (&rest[..i], Some(&rest[i + 2..])),
                    None => (rest, None),
                };
                let mut out = Vec::with_capacity(line.len());
                let mut pending_space = false;
                for &b in line {
                    if is_wsp(b) {
                        pending_space = true;
                        continue;
                    }
                    if pending_space {
                        out.push(b' ');
                        pending_space = false;
                    }
                    out.push(b);
                }
                lines.push(out);
                match next {
                    Some(n) => rest = n,
                    None => break,
                }
            }
            while lines.last().map(|l| l.is_empty()).unwrap_or(false) {
                lines.pop();
            }
            let mut out = Vec::new();
            for l in lines {
                out.extend_from_slice(&l);
                out.extend_from_slice(b"\r\n");
            }
            out
        }
    }
}

/// The tags of a signature field. Every value has its folding and spaces removed. A repeated tag is refused.
fn tags(value: &[u8]) -> Result<Vec<(String, String)>, NoticeError> {
    let text = std::str::from_utf8(value).map_err(|_| NoticeError::Malformed)?;
    let mut out: Vec<(String, String)> = Vec::new();
    for part in text.split(';') {
        if part.trim().is_empty() {
            continue;
        }
        let (k, v) = part.split_once('=').ok_or(NoticeError::Malformed)?;
        let k = k.trim().to_string();
        let v: String = v.chars().filter(|c| !c.is_whitespace()).collect();
        if k.is_empty() || out.iter().any(|(seen, _)| *seen == k) {
            return Err(NoticeError::Malformed);
        }
        out.push((k, v));
    }
    Ok(out)
}

fn tag<'a>(list: &'a [(String, String)], key: &str) -> Option<&'a str> {
    list.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str())
}

/// The signature field with the value of its `b=` tag removed (RFC 6376 section 3.5), no final CRLF.
fn without_signature_value(raw: &[u8]) -> Vec<u8> {
    let trimmed = raw.strip_suffix(b"\r\n").unwrap_or(raw);
    let colon = trimmed.iter().position(|&b| b == b':').unwrap_or(trimmed.len());
    let mut out = trimmed[..(colon + 1).min(trimmed.len())].to_vec();
    let value = trimmed.get(colon + 1..).unwrap_or(&[]);
    let mut first = true;
    for part in value.split(|&b| b == b';') {
        if !first {
            out.push(b';');
        }
        first = false;
        let eq = part.iter().position(|&b| b == b'=');
        let key_is_b =
            eq.map(|i| part[..i].iter().copied().filter(|b| !b.is_ascii_whitespace()).eq(*b"b")).unwrap_or(false);
        match (key_is_b, eq) {
            (true, Some(i)) => out.extend_from_slice(&part[..=i]),
            _ => out.extend_from_slice(part),
        }
    }
    out
}

fn b64(text: &str) -> Result<Vec<u8>, NoticeError> {
    base64::engine::general_purpose::STANDARD.decode(text).map_err(|_| NoticeError::Malformed)
}

/// The domain of the one address in a From field.
fn from_domain(from: &str) -> Option<String> {
    let addr = match (from.rfind('<'), from.rfind('>')) {
        (Some(a), Some(b)) if a < b => &from[a + 1..b],
        (None, None) => from,
        _ => return None,
    };
    let (_, domain) = addr.trim().rsplit_once('@')?;
    let domain = domain.trim().to_ascii_lowercase();
    (!domain.is_empty() && domain.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')).then_some(domain)
}

/// Decode the encoded words of a Subject (RFC 2047): UTF-8, US-ASCII and ISO-8859-1, in Q or B.
fn decoded_words(subject: &str) -> Result<String, NoticeError> {
    let mut out = String::new();
    let mut rest = subject;
    let mut last_was_word = false;
    while let Some(start) = rest.find("=?") {
        let (before, word_on) = rest.split_at(start);
        let mut parts = word_on[2..].splitn(3, '?');
        let (charset, enc, tail) = match (parts.next(), parts.next(), parts.next()) {
            (Some(c), Some(e), Some(t)) => (c, e, t),
            _ => return Err(NoticeError::Malformed),
        };
        let end = tail.find("?=").ok_or(NoticeError::Malformed)?;
        let text = &tail[..end];
        // white space between two encoded words is not part of the text
        if !(last_was_word && before.chars().all(char::is_whitespace)) {
            out.push_str(before);
        }
        let bytes = match enc {
            "B" | "b" => b64(text)?,
            "Q" | "q" => {
                let raw = text.as_bytes();
                let mut v = Vec::with_capacity(raw.len());
                let mut i = 0;
                while i < raw.len() {
                    match raw[i] {
                        b'_' => v.push(b' '),
                        b'=' => {
                            let hex = raw.get(i + 1..i + 3).and_then(|h| std::str::from_utf8(h).ok());
                            v.push(hex.and_then(|h| u8::from_str_radix(h, 16).ok()).ok_or(NoticeError::Malformed)?);
                            i += 2;
                        }
                        b => v.push(b),
                    }
                    i += 1;
                }
                v
            }
            _ => return Err(NoticeError::Malformed),
        };
        match charset.to_ascii_lowercase().as_str() {
            "utf-8" | "us-ascii" => out.push_str(std::str::from_utf8(&bytes).map_err(|_| NoticeError::Malformed)?),
            "iso-8859-1" | "latin1" => out.extend(bytes.iter().map(|&b| char::from(b))),
            _ => return Err(NoticeError::Malformed),
        }
        rest = &tail[end + 2..];
        last_was_word = true;
    }
    out.push_str(rest);
    Ok(out)
}

/// Seconds since 1970 for an RFC 5322 date, e.g. `Tue, 10 Nov 2026 14:03:22 -0500`.
fn date_seconds(date: &str) -> Option<u64> {
    let date = date.split('(').next()?.trim();
    let date = date.rsplit_once(',').map(|(_, d)| d).unwrap_or(date);
    let mut it = date.split_whitespace();
    let day: i64 = it.next()?.parse().ok()?;
    let month = match it.next()?.to_ascii_lowercase().as_str() {
        "jan" => 1,
        "feb" => 2,
        "mar" => 3,
        "apr" => 4,
        "may" => 5,
        "jun" => 6,
        "jul" => 7,
        "aug" => 8,
        "sep" => 9,
        "oct" => 10,
        "nov" => 11,
        "dec" => 12,
        _ => return None,
    };
    let year: i64 = it.next()?.parse().ok()?;
    let mut clock = it.next()?.split(':');
    let (h, m): (i64, i64) = (clock.next()?.parse().ok()?, clock.next()?.parse().ok()?);
    let s: i64 = clock.next().map(|x| x.parse().ok()).unwrap_or(Some(0))?;
    let zone = it.next()?;
    let offset_min = match zone {
        "GMT" | "UT" | "UTC" | "Z" => 0,
        z if z.len() == 5 && (z.starts_with('+') || z.starts_with('-')) => {
            let hh: i64 = z[1..3].parse().ok()?;
            let mm: i64 = z[3..5].parse().ok()?;
            let total = hh * 60 + mm;
            if z.starts_with('-') { -total } else { total }
        }
        _ => return None,
    };
    if !(1..=31).contains(&day) || year < 1970 || h > 23 || m > 59 || s > 60 {
        return None;
    }
    // days from 1970-01-01 (Howard Hinnant's civil-from-days, run forward)
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = (month + 9) % 12;
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + m * 60 + s - offset_min * 60).ok()
}

fn check_one(sig: &Header, all: &[Header], body: &[u8], keys: &[CarrierKey]) -> Result<SignedMail, NoticeError> {
    let t = tags(value_of(&sig.raw))?;
    let need = |k: &str| tag(&t, k).ok_or(NoticeError::Malformed);
    let domain = need("d")?.to_ascii_lowercase();
    let selector = need("s")?;
    let key = keys
        .iter()
        .find(|k| k.domain.eq_ignore_ascii_case(&domain) && k.selector == selector)
        .ok_or(NoticeError::UnknownKey)?;
    let algorithm_ok = need("a")? == "rsa-sha256"; // CLASSICAL-CRYPTO-EXEMPT: the outside carrier's own mail signature scheme, verified only (user 2026-11-09)
    if need("v")? != "1" || !algorithm_ok || tag(&t, "l").is_some() {
        return Err(NoticeError::Unsupported);
    }
    let (header_mode, body_mode) = match tag(&t, "c").unwrap_or("simple/simple").split_once('/') {
        Some((h, b)) => (canon_of(h)?, canon_of(b)?),
        None => (canon_of(tag(&t, "c").unwrap_or("simple"))?, Canon::Simple),
    };
    let signed_names: Vec<String> = need("h")?.split(':').map(|n| n.to_ascii_lowercase()).collect();
    for required in ["from", "subject", "date"] {
        let present = all.iter().filter(|h| h.name == required).count();
        let covered = signed_names.iter().filter(|n| *n == required).count();
        if present != 1 || covered < 1 {
            return Err(NoticeError::Uncovered);
        }
    }
    if Sha256::digest(canon_body(body, body_mode)).as_slice() != b64(need("bh")?)?.as_slice() {
        return Err(NoticeError::BodyChanged);
    }
    // RFC 6376 section 5.4.2: each name takes the last instance not yet taken, from the bottom up
    let mut data = Vec::new();
    let mut taken = vec![false; all.len()];
    for name in &signed_names {
        if let Some(i) = (0..all.len()).rev().find(|&i| !taken[i] && all[i].name == *name) {
            taken[i] = true;
            data.extend_from_slice(&canon_header(&all[i].raw, header_mode));
        }
    }
    let mut own = without_signature_value(&sig.raw);
    if header_mode == Canon::Relaxed {
        own.extend_from_slice(b"\r\n");
        own = relaxed_header(&own);
        own.truncate(own.len() - 2);
    }
    data.extend_from_slice(&own);
    let digest: [u8; 32] = Sha256::digest(&data).into();
    if !outside_sig::valid(&key.spki_der, &digest, &b64(need("b")?)?) {
        return Err(NoticeError::BadSignature);
    }
    let field = |name: &str| all.iter().find(|h| h.name == name).map(|h| unfolded(&h.raw));
    let from = field("from").ok_or(NoticeError::Uncovered)??;
    let aligned = from_domain(&from)
        .map(|d| d == domain || d.ends_with(&format!(".{domain}")))
        .unwrap_or(false);
    if !aligned {
        return Err(NoticeError::NotAligned);
    }
    let signed_at_s = match tag(&t, "t") {
        Some(ts) => ts.parse::<u64>().map_err(|_| NoticeError::Malformed)?,
        None => date_seconds(&field("date").ok_or(NoticeError::Uncovered)??).ok_or(NoticeError::Undated)?,
    };
    let subject = decoded_words(&field("subject").ok_or(NoticeError::Uncovered)??)?;
    Ok(SignedMail { domain, subject, signed_at_s })
}

/// Check a raw message against the pinned keys. Returns what the carrier signed, or why not.
pub fn verify(raw: &[u8], keys: &[CarrierKey]) -> Result<SignedMail, NoticeError> {
    let msg = with_crlf(raw);
    let (head, body) = split(&msg);
    let all = headers(head)?;
    let mut last = NoticeError::UnknownKey;
    let mut any = false;
    for sig in all.iter().filter(|h| h.name == "dkim-signature") {
        any = true;
        match check_one(sig, &all, body, keys) {
            Ok(mail) => return Ok(mail),
            // a signature from a domain we hold no key for says nothing; keep the most telling refusal
            Err(NoticeError::UnknownKey) => {}
            Err(e) => last = e,
        }
    }
    Err(if any { last } else { NoticeError::UnknownKey })
}

fn is_tracking(s: &str) -> bool {
    (8..=34).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_digit() || b.is_ascii_uppercase())
}

/// Read the one fact from what the carrier signed. Exactly one of the carrier's templates must fit.
pub fn read(mail: &SignedMail, templates: &[Template]) -> Result<Fact, NoticeError> {
    let mut found: Option<Fact> = None;
    for t in templates.iter().filter(|t| t.domain.eq_ignore_ascii_case(&mail.domain)) {
        let middle = mail.subject.strip_prefix(t.before.as_str()).and_then(|r| r.strip_suffix(t.after.as_str()));
        if let Some(tracking) = middle.filter(|m| is_tracking(m)) {
            if found.is_some() {
                return Err(NoticeError::NotANotice);
            }
            found = Some(Fact {
                carrier: t.carrier.clone(),
                status: t.status,
                tracking: tracking.to_string(),
                signed_at_s: mail.signed_at_s,
            });
        }
    }
    found.ok_or(NoticeError::NotANotice)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Signed by notice_fixtures/make_fixtures.py: a made-up carrier, a key made there and thrown away.
    const KEY: &[u8] = include_bytes!("notice_fixtures/carrier.spki.der");
    const OTHER_KEY: &[u8] = include_bytes!("notice_fixtures/other.spki.der");
    const DELIVERED: &[u8] = include_bytes!("notice_fixtures/delivered.eml");
    const RETURNED: &[u8] = include_bytes!("notice_fixtures/returned.eml");
    const ENCODED: &[u8] = include_bytes!("notice_fixtures/encoded_subject.eml");
    const WITH_LENGTH: &[u8] = include_bytes!("notice_fixtures/with_length.eml");
    const SUBJECT_UNSIGNED: &[u8] = include_bytes!("notice_fixtures/subject_unsigned.eml");
    const FROM_ELSEWHERE: &[u8] = include_bytes!("notice_fixtures/from_elsewhere.eml");
    const PINNED: &str = "1Z999AA10123456784";
    const SIGNED_AT: u64 = 1_800_000_500;

    fn keys() -> Vec<CarrierKey> {
        vec![CarrierKey { domain: "parcels.example".into(), selector: "k1".into(), spki_der: KEY.to_vec() }]
    }

    fn templates() -> Vec<Template> {
        let t = |status, before: &str| Template {
            carrier: "Parcels Example".into(),
            domain: "parcels.example".into(),
            status,
            before: before.into(),
            after: String::new(),
        };
        vec![
            t(Status::Delivered, "Parcels Example Delivery Notification, Tracking Number "),
            t(Status::ReturnedToSender, "Parcels Example: Returned to Sender, Tracking Number "),
            t(Status::Delivered, "Parcels Example\u{00ae} Item Delivered "),
        ]
    }

    fn replace(msg: &[u8], from: &str, to: &str) -> Vec<u8> {
        let text = String::from_utf8(msg.to_vec()).unwrap();
        assert!(text.contains(from), "the fixture no longer holds {from:?}");
        text.replacen(from, to, 1).into_bytes()
    }

    #[test]
    fn a_notice_signed_elsewhere_verifies_here_and_gives_the_delivery() {
        let mail = verify(DELIVERED, &keys()).unwrap();
        assert_eq!(mail.domain, "parcels.example");
        assert_eq!(mail.signed_at_s, SIGNED_AT);
        let fact = read(&mail, &templates()).unwrap();
        assert_eq!((fact.status, fact.tracking.as_str()), (Status::Delivered, PINNED));
        assert!(fact.settles(PINNED, SIGNED_AT - 1));
    }

    #[test]
    fn a_saved_copy_with_bare_line_feeds_verifies_the_same() {
        let lf: Vec<u8> = String::from_utf8(DELIVERED.to_vec()).unwrap().replace("\r\n", "\n").into_bytes();
        assert_ne!(lf, DELIVERED);
        assert_eq!(verify(&lf, &keys()), verify(DELIVERED, &keys()));
    }

    #[test]
    fn the_simple_form_with_no_time_tag_verifies_and_is_dated_by_its_date() {
        let mail = verify(RETURNED, &keys()).unwrap();
        assert_eq!(mail.signed_at_s, date_seconds("Fri, 15 Jan 2027 09:30:00 -0500").unwrap());
        assert_eq!(mail.signed_at_s, 1_800_023_400);
        assert_eq!(read(&mail, &templates()).unwrap().status, Status::ReturnedToSender);
    }

    #[test]
    fn an_encoded_subject_is_decoded_before_it_is_matched() {
        let mail = verify(ENCODED, &keys()).unwrap();
        assert_eq!(mail.subject, "Parcels Example\u{00ae} Item Delivered 9400111899223344556677");
        assert_eq!(read(&mail, &templates()).unwrap().tracking, "9400111899223344556677");
    }

    #[test]
    fn one_changed_character_of_the_subject_or_the_body_is_refused() {
        let subject = replace(DELIVERED, "1Z999AA10123456784", "1Z999AA10123456785");
        assert_eq!(verify(&subject, &keys()), Err(NoticeError::BadSignature));
        let body = replace(DELIVERED, "was delivered", "was not delivered");
        assert_eq!(verify(&body, &keys()), Err(NoticeError::BodyChanged));
    }

    #[test]
    fn a_second_unsigned_subject_is_refused() {
        let doubled = replace(DELIVERED, "Subject:", "Subject: Parcels Example Delivery Notification, Tracking Number 1Z000AA00000000000\r\nSubject:");
        assert_eq!(verify(&doubled, &keys()), Err(NoticeError::Uncovered));
    }

    #[test]
    fn a_subject_the_signature_does_not_cover_is_refused() {
        assert_eq!(verify(SUBJECT_UNSIGNED, &keys()), Err(NoticeError::Uncovered));
    }

    #[test]
    fn a_signature_over_only_part_of_the_body_is_refused() {
        assert_eq!(verify(WITH_LENGTH, &keys()), Err(NoticeError::Unsupported));
    }

    #[test]
    fn a_from_address_at_another_domain_is_refused() {
        assert_eq!(verify(FROM_ELSEWHERE, &keys()), Err(NoticeError::NotAligned));
    }

    #[test]
    fn a_key_the_wallet_did_not_pin_proves_nothing() {
        assert_eq!(verify(DELIVERED, &[]), Err(NoticeError::UnknownKey));
        let mut wrong_selector = keys();
        wrong_selector[0].selector = "k2".into();
        assert_eq!(verify(DELIVERED, &wrong_selector), Err(NoticeError::UnknownKey));
        // the seller names its own key as the carrier's: the notice the real carrier signed fails under it
        let mut sellers_key = keys();
        sellers_key[0].spki_der = OTHER_KEY.to_vec();
        assert_eq!(verify(DELIVERED, &sellers_key), Err(NoticeError::BadSignature));
        let mut not_a_key = keys();
        not_a_key[0].spki_der.truncate(40);
        assert_eq!(verify(DELIVERED, &not_a_key), Err(NoticeError::BadSignature));
    }

    #[test]
    fn a_flipped_signature_bit_is_refused() {
        // flip one character inside the b= value (the fixture puts it on its own folded line)
        let text = String::from_utf8(DELIVERED.to_vec()).unwrap();
        let at = text.find("\r\n b=").unwrap() + 5 + 10;
        let mut bytes = text.into_bytes();
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        assert_eq!(verify(&bytes, &keys()), Err(NoticeError::BadSignature));
    }

    #[test]
    fn only_the_carriers_own_subject_makes_a_fact() {
        let mail = |subject: &str| SignedMail { domain: "parcels.example".into(), subject: subject.into(), signed_at_s: SIGNED_AT };
        let t = templates();
        for not_a_notice in [
            "Parcels Example Delivery Notification, Tracking Number ",
            "Parcels Example Delivery Notification, Tracking Number 1z999aa10123456784",
            "Parcels Example Delivery Notification, Tracking Number 1Z999AA1 0123456784",
            "Re: Parcels Example Delivery Notification, Tracking Number 1Z999AA10123456784",
            "Parcels Example Delivery Notification, Tracking Number 1Z999AA10123456784 (ref: Delivered)",
            "Your order shipped",
        ] {
            assert_eq!(read(&mail(not_a_notice), &t), Err(NoticeError::NotANotice), "{not_a_notice:?}");
        }
        // the same subject signed by another domain is not this carrier's notice
        let mut elsewhere = mail("Parcels Example Delivery Notification, Tracking Number 1Z999AA10123456784");
        elsewhere.domain = "parcels.example.evil.test".into();
        assert_eq!(read(&elsewhere, &t), Err(NoticeError::NotANotice));
    }

    #[test]
    fn a_notice_settles_only_the_pinned_parcel_and_only_after_the_pin() {
        let fact = read(&verify(DELIVERED, &keys()).unwrap(), &templates()).unwrap();
        assert!(fact.settles(PINNED, SIGNED_AT - 1));
        assert!(!fact.settles(PINNED, SIGNED_AT), "a notice signed at or before the pin is an old one");
        assert!(!fact.settles("1Z999AA10123456785", 0));
    }

    #[test]
    fn dates_are_read_in_their_own_zone() {
        assert_eq!(date_seconds("Thu, 01 Jan 1970 00:00:00 +0000"), Some(0));
        assert_eq!(date_seconds("1 Jan 1970 00:00 GMT"), Some(0));
        assert_eq!(date_seconds("Sat, 29 Feb 2020 12:00:00 +0100 (CET)"), Some(1_582_974_000));
        assert_eq!(date_seconds("Tue, 10 Nov 2026 14:03:22 -0500"), Some(1_794_337_402));
        assert_eq!(date_seconds("not a date"), None);
        assert_eq!(date_seconds("Tue, 10 Nov 2026 14:03:22"), None);
    }
}
