// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⭐ THE DOORSTEP (docs/GOODS-AND-SERVICES-LAYER-SPEC-20261109.md §16): a carrier's own signed delivery notice as
//! the fact neither side of a sale controls.
//!
//! THE SELLER'S WALLET reads the carrier's notification email (the file its mail program saves), finds the carrier's
//! mail signature, rebuilds the exact signed header lines the way the carrier's signer hashed them (RFC 6376), and
//! makes ONE proof: "the carrier's mail key signed lines that include this subject line and this date line"
//! (`usdm_decider`, THE NOTICE PROOF). Nothing else of the email leaves the seller's machine: not its mailbox, not
//! the message, not another header.
//!
//! THE BUYER'S WALLET checks that proof against the carrier's key IT holds (never one the seller names), then reads
//! the two lines itself: each must be a whole header line, the subject must be the carrier's own "delivered" wording
//! naming the tracking number this wallet pinned for the order, and the date must be after the pin. Then it confirms
//! receipt by itself, exactly as a tap on Confirm receipt would.
//!
//! THE SIGNATURE IS THE CARRIER'S, NEVER OURS. This wallet signs nothing with it and holds no key of its kind; the
//! one place the carrier's signature is checked is inside the proof (the prover crate's notice gate, where the
//! post-quantum pillar's carve-out for an outside company's own signature is marked line by line). Everything of this
//! wallet's own stays ML-KEM, ML-DSA, BLAKE3, Poseidon and WHIR.
//!
//! WHICH KEYS. `carriers.json` holds each accepted carrier's mail keys and its "delivered" wording. It is filled at
//! release time from the carriers' own published keys and is EMPTY in a build where none was confirmed: such a wallet
//! accepts no delivery proof and says so. A seller can never add a key.
//!
//! WHAT IS NOT COVERED, plainly: a buyer whose wallet never opens again, or was altered to refuse, is not made to
//! confirm by this proof (that would need the chain itself to check a carrier's signature inside every payment, or
//! to mark such a payment apart from the others; neither is acceptable). The seller's cover there is the buyer's
//! deposit. And a carrier that records a delivery wrongly is believed: its record is the fact.

use super::*;
use usdm_decider::whir_rec_block::{
    notice_padded, notice_signature_ok, prove_notice, verify_notice, NoticeStatement, NOTICE_BLOCK_BYTES, NOTICE_KEY_BYTES, NOTICE_MAX_BLOCKS, NOTICE_SIGNATURE_ALGORITHM,
};

/// One carrier: the mail domains it signs as, its keys, and the words its "delivered" subject line carries.
#[derive(serde::Deserialize, Clone, Debug)]
pub struct Carrier {
    pub name: String,
    pub domains: Vec<String>,
    pub keys: Vec<CarrierKey>,
    /// Every one of these appears in a "delivered" subject, as written.
    pub delivered: Vec<String>,
    /// None of these appears in one (the wording of the carrier's other notices).
    #[serde(default)]
    pub not_delivered: Vec<String>,
}

#[derive(serde::Deserialize, Clone, Debug)]
pub struct CarrierKey {
    pub selector: String,
    /// The key's modulus, 256 bytes of hex.
    pub modulus: String,
}

#[derive(serde::Deserialize)]
struct CarrierList {
    carriers: Vec<Carrier>,
}

/// The carriers this build accepts. Empty when the release confirmed none.
#[must_use]
pub fn carriers() -> Vec<Carrier> {
    serde_json::from_str::<CarrierList>(include_str!("carriers.json")).map(|l| l.carriers).unwrap_or_default()
}

/// The carrier and key a signature names, among `list`: the signing domain is the carrier's own or under it, and the
/// selector is one of its keys.
fn key_of<'a>(list: &'a [Carrier], domain: &str, selector: &str) -> Option<(&'a Carrier, Vec<u8>)> {
    let domain = domain.to_ascii_lowercase();
    let carrier = list.iter().find(|c| c.domains.iter().any(|d| domain == d.to_ascii_lowercase() || domain.ends_with(&format!(".{}", d.to_ascii_lowercase()))))?;
    let key = carrier.keys.iter().find(|k| k.selector == selector)?;
    let modulus = hex::decode(&key.modulus).ok().filter(|m| m.len() == NOTICE_KEY_BYTES)?;
    Some((carrier, modulus))
}

/// A notice as the seller's wallet read it.
#[derive(Clone, Debug)]
pub struct Read {
    pub domain: String,
    pub selector: String,
    /// The signed header lines, as the signer hashed them.
    pub signed: Vec<u8>,
    pub signature: Vec<u8>,
    /// Where the subject line and the date line sit in `signed`, each with the line end before it when it has one.
    pub subject: (usize, Vec<u8>),
    pub date: (usize, Vec<u8>),
}

fn b64(text: &str) -> Option<Vec<u8>> {
    veil_site::b64_decode(&text.chars().filter(|c| !c.is_whitespace()).collect::<String>())
}

/// One header field's signed form. `relaxed`: the name in lower case, the value unfolded with runs of blanks as one
/// space and none at its ends. Otherwise the field exactly as it stands. Without the line end.
fn canonical(name: &str, value: &str, relaxed: bool) -> String {
    if !relaxed {
        return format!("{name}:{value}");
    }
    let unfolded: String = value.replace("\r\n", "");
    let squeezed = unfolded.split([' ', '\t']).filter(|w| !w.is_empty()).collect::<Vec<_>>().join(" ");
    format!("{}:{}", name.trim_end_matches([' ', '\t']).to_ascii_lowercase(), squeezed)
}

/// SELLER: read a carrier's notice from the bytes of the saved email. Finds its mail signature, rebuilds the signed
/// lines, and places the subject and date lines in them. Nothing is checked against a key here.
pub fn read_notice(raw: &[u8]) -> Result<Read, String> {
    let text = String::from_utf8_lossy(raw).replace("\r\n", "\n").replace('\n', "\r\n");
    let head = text.split("\r\n\r\n").next().unwrap_or("");
    // the header fields, each as (name, value with its folding kept)
    let mut fields: Vec<(String, String)> = Vec::new();
    for line in head.split("\r\n") {
        if line.starts_with([' ', '\t']) {
            if let Some(last) = fields.last_mut() {
                last.1.push_str("\r\n");
                last.1.push_str(line);
            }
        } else if let Some((name, value)) = line.split_once(':') {
            fields.push((name.to_string(), value.to_string()));
        }
    }
    let is = |name: &str, want: &str| name.trim().eq_ignore_ascii_case(want);
    let tags_of = |value: &str| -> std::collections::HashMap<String, String> {
        value.replace("\r\n", "").split(';').filter_map(|t| t.split_once('=')).map(|(k, v)| (k.trim().to_ascii_lowercase(), v.trim().to_string())).collect()
    };
    let (sig_at, tags) = fields
        .iter()
        .enumerate()
        .filter(|(_, (name, _))| is(name, "dkim-signature"))
        .map(|(i, (_, value))| (i, tags_of(value)))
        .find(|(_, t)| t.get("a").map(String::as_str) == Some(NOTICE_SIGNATURE_ALGORITHM))
        .ok_or_else(|| "this email carries no mail signature this wallet can prove (the carrier must sign it)".to_string())?;
    let (Some(domain), Some(selector), Some(listed), Some(b)) = (tags.get("d"), tags.get("s"), tags.get("h"), tags.get("b")) else {
        return Err("this email's mail signature is incomplete".to_string());
    };
    let relaxed = tags.get("c").is_some_and(|c| c.split('/').next().unwrap_or("").trim().eq_ignore_ascii_case("relaxed"));
    // the signed fields: for each listed name, the last instance not yet used (RFC 6376 §5.4.2)
    let mut used = vec![false; fields.len()];
    let mut signed = String::new();
    let (mut subject, mut date) = (None, None);
    for want in listed.split(':').map(str::trim).filter(|w| !w.is_empty()) {
        let Some(i) = (0..fields.len()).rev().find(|i| !used[*i] && is(&fields[*i].0, want)) else { continue };
        used[i] = true;
        let line = format!("{}\r\n", canonical(&fields[i].0, &fields[i].1, relaxed));
        // a window opens at the line end before its line, so a reader sees the line is whole
        let from = signed.len().saturating_sub(2);
        let window = |signed: &str| (from, format!("{}{line}", &signed[from..]).into_bytes());
        if want.eq_ignore_ascii_case("subject") && subject.is_none() {
            subject = Some(window(&signed));
        }
        if want.eq_ignore_ascii_case("date") && date.is_none() {
            date = Some(window(&signed));
        }
        signed.push_str(&line);
    }
    // then the signature field itself, with its signature value emptied and no line end
    let own = &fields[sig_at];
    let mut emptied = String::new();
    for (n, part) in own.1.split(';').enumerate() {
        if n > 0 {
            emptied.push(';');
        }
        match part.split_once('=') {
            Some((k, _)) if k.trim() == "b" => {
                emptied.push_str(k);
                emptied.push('=');
            }
            _ => emptied.push_str(part),
        }
    }
    signed.push_str(&canonical(&own.0, &emptied, relaxed));
    let (Some(subject), Some(date)) = (subject, date) else {
        return Err("the carrier did not sign this email's subject and date, so it proves nothing".to_string());
    };
    let signature = b64(b).filter(|s| s.len() == NOTICE_KEY_BYTES).ok_or_else(|| "this email's mail signature is not one this wallet can prove (a 2048-bit key is needed)".to_string())?;
    Ok(Read { domain: domain.clone(), selector: selector.clone(), signed: signed.into_bytes(), signature, subject, date })
}

fn context_of(sale: &str) -> Digest4 {
    usdmd_node::spend_frontier::note_leaf_of(&blake3::derive_key("MonerousD 2026-11-10 delivery notice context v1", sale.as_bytes()))
}

/// What a seller sends a buyer about a delivered parcel: everything the proof's statement names.
#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct Shown {
    pub domain: String,
    pub selector: String,
    pub blocks: usize,
    /// (place, bytes as hex) of the subject line and of the date line.
    pub subject: (usize, String),
    pub date: (usize, String),
}

/// The two windows in the order they sit in the signed lines.
fn ordered(subject: (usize, Vec<u8>), date: (usize, Vec<u8>)) -> Vec<(usize, Vec<u8>)> {
    if subject.0 <= date.0 {
        vec![subject, date]
    } else {
        vec![date, subject]
    }
}

/// SELLER: prove a delivery for `sale` from a notice. Refused unless the notice's signature verifies under a key of
/// `list` (so the seller learns at once whether the buyer's wallet will take it).
pub fn prove(list: &[Carrier], sale: &str, notice: &Read) -> Result<(Shown, Vec<u8>), String> {
    let (carrier, modulus) = key_of(list, &notice.domain, &notice.selector)
        .ok_or_else(|| format!("this wallet holds no mail key for {} (selector {}), so its notices cannot be used as proof yet", notice.domain, notice.selector))?;
    let padded = notice_padded(&notice.signed);
    let blocks = padded.len() / NOTICE_BLOCK_BYTES;
    if blocks > NOTICE_MAX_BLOCKS {
        return Err("this notice's signed lines are longer than a proof covers".to_string());
    }
    if !notice_signature_ok(&modulus, &padded, &notice.signature) {
        return Err(format!("this email was not signed by {}'s mail key (or was altered since)", carrier.name));
    }
    let st = NoticeStatement { modulus, blocks, windows: ordered(notice.subject.clone(), notice.date.clone()), context: context_of(sale) };
    let proof = prove_notice(&st, &padded, &notice.signature).ok_or_else(|| "the delivery proof could not be made".to_string())?;
    let shown = Shown {
        domain: notice.domain.clone(),
        selector: notice.selector.clone(),
        blocks,
        subject: (notice.subject.0, hex::encode(&notice.subject.1)),
        date: (notice.date.0, hex::encode(&notice.date.1)),
    };
    Ok((shown, proof))
}

/// A whole header line named `name`, from a window: the text after the colon. The window must open at a line end (or
/// at the very start of the signed lines) and close with one, and hold no other line.
fn line_of(place: usize, window: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(window).ok()?;
    let line = match place {
        0 if !text.starts_with("\r\n") => text,
        _ => text.strip_prefix("\r\n")?,
    };
    let line = line.strip_suffix("\r\n")?;
    if line.contains('\r') || line.contains('\n') {
        return None;
    }
    let (field, value) = line.split_once(':')?;
    field.trim().eq_ignore_ascii_case(name).then(|| value.trim().to_string())
}

/// The moment an email date line states (RFC 5322: "Tue, 10 Nov 2026 14:03:22 +0000"), in unix seconds.
fn date_secs(value: &str) -> Option<u64> {
    let rest = value.split_once(',').map_or(value, |(_, r)| r);
    let mut parts = rest.split_whitespace();
    let day: i64 = parts.next()?.parse().ok()?;
    let month_word = parts.next()?.to_ascii_lowercase();
    let month = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"].iter().position(|m| month_word == *m)? as i64 + 1;
    let year: i64 = parts.next()?.parse().ok()?;
    let mut clock = parts.next()?.split(':');
    let (h, m): (i64, i64) = (clock.next()?.parse().ok()?, clock.next()?.parse().ok()?);
    let s: i64 = match clock.next() {
        Some(s) => s.parse().ok()?,
        None => 0,
    };
    let zone = parts.next()?;
    let offset = match zone.as_bytes().first()? {
        b'+' | b'-' if zone.len() == 5 => {
            let (zh, zm): (i64, i64) = (zone[1..3].parse().ok()?, zone[3..5].parse().ok()?);
            (zh * 3600 + zm * 60) * if zone.starts_with('-') { -1 } else { 1 }
        }
        _ if zone.eq_ignore_ascii_case("gmt") || zone.eq_ignore_ascii_case("ut") || zone.eq_ignore_ascii_case("utc") => 0,
        _ => return None,
    };
    if !(1970..=9999).contains(&year) || !(1..=31).contains(&day) || !(0..24).contains(&h) || !(0..60).contains(&m) || !(0..=60).contains(&s) {
        return None;
    }
    // days since 1970-01-01 (the civil-date count of Howard Hinnant's algorithm)
    let (y, mo) = if month <= 2 { (year - 1, month + 12) } else { (year, month) };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (mo - 3) + 2) / 5 + day - 1;
    let days = era * 146_097 + yoe * 365 + yoe / 4 - yoe / 100 + doy - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + m * 60 + s - offset).ok()
}

/// BUYER: does `proof` show that the carrier delivered the parcel `tracking`, in a notice dated after `pinned_secs`?
/// Every check is this wallet's own: the key is the one IT holds for the signing domain; the proof is for this sale;
/// the subject is a whole line in the carrier's "delivered" wording naming the pinned number; the date is a whole
/// line after the pin. `Ok(carrier name)` or the plain reason it is not taken.
pub fn check(list: &[Carrier], sale: &str, tracking: &str, pinned_secs: u64, shown: &Shown, proof: &[u8]) -> Result<String, String> {
    if list.is_empty() {
        return Err("this wallet holds no carrier's mail key, so it takes no delivery proof".to_string());
    }
    let (carrier, modulus) = key_of(list, &shown.domain, &shown.selector).ok_or_else(|| "the proof names a mail key this wallet does not hold for any carrier".to_string())?;
    let window = |w: &(usize, String)| -> Result<(usize, Vec<u8>), String> { Ok((w.0, hex::decode(&w.1).map_err(|_| "the proof is malformed".to_string())?)) };
    let (subject, date) = (window(&shown.subject)?, window(&shown.date)?);
    let st = NoticeStatement { modulus, blocks: shown.blocks, windows: ordered(subject.clone(), date.clone()), context: context_of(sale) };
    if !verify_notice(proof, &st) {
        return Err(format!("the delivery proof does not check out against {}'s mail key", carrier.name));
    }
    let said = line_of(subject.0, &subject.1, "subject").ok_or_else(|| "the proof does not show a whole subject line".to_string())?;
    let tracking = tracking.trim();
    let number_shown = said.split(|c: char| !c.is_ascii_alphanumeric()).any(|word| word.eq_ignore_ascii_case(tracking));
    if tracking.len() < 8 || !number_shown {
        return Err("the notice is not about the parcel pinned for this order".to_string());
    }
    if carrier.delivered.is_empty() || !carrier.delivered.iter().all(|w| said.contains(w.as_str())) || carrier.not_delivered.iter().any(|w| said.contains(w.as_str())) {
        return Err(format!("the notice is not {}'s delivered notice", carrier.name));
    }
    let when = line_of(date.0, &date.1, "date").and_then(|d| date_secs(&d)).ok_or_else(|| "the proof does not show a whole date line".to_string())?;
    if when <= pinned_secs {
        return Err("the notice is dated before this order's parcel was pinned".to_string());
    }
    Ok(carrier.name.clone())
}

/// A release builder's tool reads the same thing: the modulus inside a mail key record's `p=` value (the DER form
/// RFC 6376 §3.6.1 names), when it is a 2048-bit key with the usual exponent.
#[must_use]
pub fn modulus_of_record(p_value: &str) -> Option<Vec<u8>> {
    let der = b64(p_value)?;
    // the INTEGER of 257 bytes (a leading zero and the modulus) followed by the INTEGER 65537
    let tail = [0x02u8, 0x03, 0x01, 0x00, 0x01];
    let body = der.strip_suffix(&tail)?;
    let at = body.len().checked_sub(NOTICE_KEY_BYTES + 5)?;
    (body[at..at + 5] == [0x02, 0x82, 0x01, 0x01, 0x00]).then(|| body[at + 5..].to_vec())
}

// TWO-PARTY-REVIEWED: these tests are a seller's reading and proving against a buyer's own check, in one process,
// with a SELF-MADE key standing in for a carrier's (passed as the list; the shipped list is never altered). A real
// carrier's notice, a real parcel and two wallets on two nodes are the acceptance the spec names and are not claimed.
#[cfg(test)]
mod tests {
    use super::*;

    fn test_carrier() -> Vec<Carrier> {
        vec![Carrier {
            name: "Parcel Co".to_string(),
            domains: vec!["parcelco.example".to_string()],
            keys: vec![CarrierKey { selector: "test1".to_string(), modulus: include_str!("notice_test_modulus.hex").trim().to_string() }],
            delivered: vec!["Delivered".to_string()],
            not_delivered: vec!["Out for".to_string(), "will be".to_string()],
        }]
    }

    const TRACKING: &str = "1Z999AA10123456784";
    /// The fixture notice's date line, in unix seconds.
    const NOTICE_SECS: u64 = 1_794_319_402;

    #[test]
    fn a_saved_notice_is_read_the_way_its_signer_hashed_it_and_only_a_listed_key_makes_it_proof() {
        let read = read_notice(include_bytes!("notice_test_delivered.eml")).expect("the notice is read");
        assert_eq!((read.domain.as_str(), read.selector.as_str()), ("mail.parcelco.example", "test1"));
        let signed = String::from_utf8(read.signed.clone()).expect("text");
        assert!(signed.starts_with("from:Parcel Co <notify@parcelco.example>\r\n"), "{signed}");
        assert!(signed.contains("\r\nsubject:Parcel Co Update: Package Delivered, Tracking Number 1Z999AA10123456784\r\n"), "a folded subject is unfolded: {signed}");
        assert!(signed.ends_with("; b="), "the signature field is last, emptied, with no line end");
        // the signature the fixture carries verifies over exactly these bytes under the fixture's key
        let list = test_carrier();
        let (_, modulus) = key_of(&list, &read.domain, &read.selector).expect("the key is listed");
        assert!(notice_signature_ok(&modulus, &notice_padded(&read.signed), &read.signature), "the rebuilt lines are the lines that were signed");
        // the buyer's reading of the two windows
        assert_eq!(line_of(read.subject.0, &read.subject.1, "subject").as_deref(), Some("Parcel Co Update: Package Delivered, Tracking Number 1Z999AA10123456784"));
        assert_eq!(line_of(read.date.0, &read.date.1, "date").and_then(|d| date_secs(&d)), Some(NOTICE_SECS));
        // no listed key, no proof: an empty list (what this build ships)
        assert!(prove(&[], "sale-1", &read).is_err());
        assert!(carriers().is_empty(), "this build ships no carrier key; a wallet with none takes no delivery proof");
        let mut altered = read.clone();
        altered.signed[30] ^= 1;
        assert!(prove(&list, "sale-1", &altered).is_err_and(|e| e.contains("was not signed")), "an altered notice is refused before any proof is made");
    }

    #[test]
    fn a_buyer_takes_a_delivery_proof_only_for_its_own_pinned_parcel_after_the_pin() {
        let list = test_carrier();
        let read = read_notice(include_bytes!("notice_test_delivered.eml")).expect("the notice is read");
        let (shown, proof) = prove(&list, "sale-1", &read).expect("the seller proves");
        let pinned = NOTICE_SECS - 3 * 86_400;
        assert_eq!(check(&list, "sale-1", TRACKING, pinned, &shown, &proof).as_deref(), Ok("Parcel Co"));
        // every way it is not this order's delivery
        assert!(check(&list, "sale-2", TRACKING, pinned, &shown, &proof).is_err(), "⛔ a proof made for another sale was taken");
        assert!(check(&list, "sale-1", "1Z999AA10123456785", pinned, &shown, &proof).is_err(), "⛔ a notice about another parcel was taken");
        assert!(check(&list, "sale-1", TRACKING, NOTICE_SECS, &shown, &proof).is_err(), "⛔ a notice dated at or before the pin was taken");
        assert!(check(&[], "sale-1", TRACKING, pinned, &shown, &proof).is_err(), "⛔ a wallet with no carrier key took a proof");
        let mut other_words = list.clone();
        other_words[0].delivered = vec!["Shipped".to_string()];
        assert!(check(&other_words, "sale-1", TRACKING, pinned, &shown, &proof).is_err(), "⛔ a notice without the delivered wording was taken");
        let mut excluded = list.clone();
        excluded[0].not_delivered.push("Update".to_string());
        assert!(check(&excluded, "sale-1", TRACKING, pinned, &shown, &proof).is_err(), "⛔ a notice with another notice's wording was taken");
        // the seller cannot restate the windows: a subject that is not the proven bytes fails the proof itself
        let mut lie = shown.clone();
        lie.subject.1 = hex::encode(String::from_utf8(hex::decode(&shown.subject.1).expect("hex")).expect("text").replace("6784", "6785"));
        assert!(check(&list, "sale-1", "1Z999AA10123456785", pinned, &lie, &proof).is_err(), "⛔ a restated subject was taken");
        let mut bent = proof.clone();
        let mid = bent.len() / 2;
        bent[mid] ^= 1;
        assert!(check(&list, "sale-1", TRACKING, pinned, &shown, &bent).is_err());
    }

    #[test]
    fn only_a_whole_header_line_is_read_and_a_date_is_read_exactly() {
        assert_eq!(line_of(40, b"\r\nsubject:Delivered 1Z\r\n", "subject").as_deref(), Some("Delivered 1Z"));
        assert_eq!(line_of(0, b"subject:Delivered 1Z\r\n", "subject").as_deref(), Some("Delivered 1Z"), "the first signed line has no line end before it");
        // text that only looks like a subject: inside another field, cut short, or two lines
        assert!(line_of(40, b"x-ref:subject:Delivered 1Z\r\n", "subject").is_none());
        assert!(line_of(40, b"subject:Delivered 1Z\r\n", "subject").is_none(), "a window that does not open at a line end");
        assert!(line_of(40, b"\r\nsubject:Delivered 1Z", "subject").is_none());
        assert!(line_of(40, b"\r\nsubject:Delivered\r\nto:x\r\n", "subject").is_none());
        assert!(line_of(40, b"\r\nx-subject:Delivered 1Z\r\n", "subject").is_none());
        assert_eq!(date_secs("Tue, 10 Nov 2026 14:03:22 +0000"), Some(NOTICE_SECS));
        assert_eq!(date_secs("10 Nov 2026 09:03:22 -0500"), Some(NOTICE_SECS));
        assert_eq!(date_secs("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(date_secs("Tue, 29 Feb 2028 12:00:00 +0000"), Some(1_835_438_400));
        for bad in ["", "tomorrow", "Tue, 10 Nov 2026", "Tue, 10 Nov 2026 14:03:22", "Tue, 10 Foo 2026 14:03:22 +0000", "Tue, 10 Nov 2026 25:03:22 +0000", "Tue, 10 Nov 2026 14:03:22 PST"] {
            assert!(date_secs(bad).is_none(), "{bad} was read as a date");
        }
    }
}
