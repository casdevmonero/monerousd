// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The notice proof's pins: a company's mail key signed data whose bytes at the stated places are the stated bytes.
//!
//! CLASSICAL-CRYPTO-EXEMPT: these tests sign with a SELF-MADE 2048-bit key standing in for a carrier's mail key (no
//! carrier's key is here and none of ours is of this kind); what is under test is the VERIFY of an outside company's
//! signature, the pillar's stated carve-out.
//!
//! TWO-PARTY-REVIEWED: the prover's and the verifier's own verdicts on one statement, run on hostile statements and
//! hand-laid tables against the production verifier. A seller's wallet proving from a real carrier notice and a
//! buyer's wallet checking it against the carrier's published key is a real-node row and is not claimed here.

use super::*;
use crate::poseidon2_compress::lanes_of;

/// A self-made key: the modulus and the private exponent, hex. Made once from a fixed seed for these tests.
const TEST_N: &str = include_str!("test_modulus.hex");
const TEST_D: &str = include_str!("test_exponent.hex");
/// The signature of "abc" under that key, computed by an independent implementation.
const TEST_SIG_ABC: &str = include_str!("test_signature_abc.hex");
/// Another self-made key's modulus: "another company".
const OTHER_N: &str = include_str!("other_modulus.hex");
/// The bits of a key-sized number.
const KEY_BITS: usize = NOTICE_KEY_BYTES * u8::BITS as usize;

fn unhex(h: &str) -> Vec<u8> {
    let h = h.trim();
    (0..h.len() / 2).map(|i| u8::from_str_radix(&h[2 * i..2 * i + 2], 16).expect("hex")).collect()
}

fn be_of_limbs(limbs: &[u64; LIMBS]) -> Vec<u8> {
    let mut out = vec![0u8; NOTICE_KEY_BYTES];
    for i in 0..KEY_BITS {
        if (limbs[i / LIMB_BITS] >> (i % LIMB_BITS)) & 1 == 1 {
            out[NOTICE_KEY_BYTES - 1 - i / 8] |= 1 << (i % 8);
        }
    }
    out
}

/// Sign already-padded data with the test key: the padded hash to the private exponent, one exponent bit at a time.
fn sign(padded: &[u8]) -> Vec<u8> {
    let (n, d) = (limbs_of_be(&unhex(TEST_N)), unhex(TEST_D));
    let em = limbs_of_be(&padded_hash(&notice_hash_of_padded(padded).expect("whole blocks")));
    let mut r = [0u64; LIMBS];
    r[0] = 1;
    let exponent_bits = d.iter().flat_map(|byte| [7u8, 6, 5, 4, 3, 2, 1, 0].map(|bit| (byte >> bit) & 1 == 1));
    for set in exponent_bits {
        r = mul_divmod(&r, &r, &n).1;
        if set {
            r = mul_divmod(&r, &em, &n).1;
        }
    }
    be_of_limbs(&r)
}

/// The signed header lines of a made-up delivery notice, as a signer hashes them (relaxed canonical form).
fn notice(tracking: &str, day: &str) -> (Vec<u8>, String, String) {
    let subject = format!("subject:UPS Update: Package Delivered, Tracking Number {tracking}\r\n");
    let date = format!("date:{day}\r\n");
    let algo = "rsa-sha256"; // CLASSICAL-CRYPTO-EXEMPT: the algorithm name an outside company's mail signature states, as text in a made-up notice
    let lines = format!(
        "from:UPS <pkginfo@ups.com>\r\nto:orders+7f3a@cornershop.example\r\n{subject}{date}message-id:<771.20261110@ups.com>\r\nmime-version:1.0\r\n\
         dkim-signature:v=1; a={algo}; c=relaxed/relaxed; d=ups.com; s=test1; t=1794300000; h=from:to:subject:date:message-id:mime-version; bh=47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=; b="
    );
    (lines.into_bytes(), subject, date)
}

struct Case {
    st: NoticeStatement,
    padded: Vec<u8>,
    sig: Vec<u8>,
}

fn case(tracking: &str, day: &str) -> Case {
    let (data, subject, date) = notice(tracking, day);
    let padded = notice_padded(&data);
    let find = |needle: &str| data.windows(needle.len()).position(|w| w == needle.as_bytes()).expect("the line is in the data");
    // each window starts at the line end before its line, so the reader sees a whole header line
    let window = |line: &str| (find(line) - 2, format!("\r\n{line}").into_bytes());
    let st = NoticeStatement { modulus: unhex(TEST_N), blocks: padded.len() / NOTICE_BLOCK_BYTES, windows: vec![window(&subject), window(&date)], context: lanes_of(&[0xD0025, 2026]) };
    let sig = sign(&padded);
    Case { st, padded, sig }
}

fn standard() -> Case {
    case("1Z999AA10123456784", "Tue, 10 Nov 2026 14:03:22 +0000")
}

fn accepted(st: &NoticeStatement, cols: Vec<Vec<Fa4>>) -> bool {
    let st2 = st.clone();
    crate::committed_air::prove_air_blinded_chained_bytes(cols, move |g: Ea4| NoticeGate::of(&st2, g), &notice_bind(st)).is_some_and(|p| verify_notice(&p, st))
}

#[test]
fn the_hash_and_the_signature_check_agree_with_the_standards_own_answers() {
    let hex = |b: &[u8]| b.iter().map(|x| format!("{x:02x}")).collect::<String>();
    // FIPS 180-4's two worked examples
    assert_eq!(hex(&notice_hash_of_padded(&notice_padded(b"abc")).expect("one block")), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let two = notice_padded(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
    assert_eq!(two.len(), 128);
    assert_eq!(hex(&notice_hash_of_padded(&two).expect("two blocks")), "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    assert!(notice_hash_of_padded(&two[..100]).is_none());
    // a signature made by an independent implementation verifies here, and this file's own signing gives the same bytes
    let (n, abc) = (unhex(TEST_N), notice_padded(b"abc"));
    assert!(notice_signature_ok(&n, &abc, &unhex(TEST_SIG_ABC)));
    assert_eq!(hex(&sign(&abc)), TEST_SIG_ABC.trim());
    // … and for nothing else: other data, another key, a signature off by a bit
    assert!(!notice_signature_ok(&n, &notice_padded(b"abd"), &unhex(TEST_SIG_ABC)));
    assert!(!notice_signature_ok(&unhex(OTHER_N), &abc, &unhex(TEST_SIG_ABC)));
    let mut bent = unhex(TEST_SIG_ABC);
    bent[200] ^= 1;
    assert!(!notice_signature_ok(&n, &abc, &bent));
    // the limb form is the number: it reads back
    assert_eq!(be_of_limbs(&limbs_of_be(&n)), n);
}

#[test]
fn a_notice_proof_verifies_for_its_statement_and_for_no_other() {
    let c = standard();
    assert_eq!(c.st.blocks, 7, "the made-up notice's signed lines are seven blocks");
    let proof = prove_notice(&c.st, &c.padded, &c.sig).expect("the holder of the notice proves");
    assert!(verify_notice(&proof, &c.st), "the buyer's check passes");
    let other = |edit: &dyn Fn(&mut NoticeStatement)| {
        let mut st = c.st.clone();
        edit(&mut st);
        st
    };
    assert!(!verify_notice(&proof, &other(&|st| st.windows[0].1[40] ^= 1)), "⛔ a proof verified for another subject");
    assert!(!verify_notice(&proof, &other(&|st| st.windows[1].0 += 1)), "⛔ a proof verified for a window at another place");
    assert!(!verify_notice(&proof, &other(&|st| st.modulus = unhex(OTHER_N))), "⛔ a proof verified under another company's key");
    assert!(!verify_notice(&proof, &other(&|st| st.context = lanes_of(&[1]))), "⛔ a proof verified for another sale");
    assert!(!verify_notice(&proof, &other(&|st| st.blocks += 1)), "⛔ a proof verified for another length");
    assert!(
        !verify_notice(
            &proof,
            &other(&|st| {
                st.windows.pop();
            })
        ),
        "⛔ a proof verified for fewer windows"
    );
    assert!(!verify_notice(&[], &c.st) && !verify_notice(&proof[..proof.len() - 1], &c.st));
    // the honest prover makes no proof of a false statement
    let mut bent = c.sig.clone();
    bent[17] ^= 1;
    assert!(prove_notice(&c.st, &c.padded, &bent).is_none(), "a signature that does not verify");
    assert!(prove_notice(&other(&|st| st.windows[0].1[40] ^= 1), &c.padded, &c.sig).is_none(), "a window the data does not hold");
    assert!(prove_notice(&other(&|st| st.modulus = unhex(OTHER_N)), &c.padded, &c.sig).is_none(), "a key that did not sign it");
    // two lines one after the other share the line end between them: the standard case's two windows do, and agree
    assert_eq!(c.st.windows[0].0 + c.st.windows[0].1.len(), c.st.windows[1].0 + 2, "the date line follows the subject line");
    // statements that are not this class's: windows that disagree where they meet, a window past the data, an even
    // modulus
    assert!(!verify_notice(&proof, &other(&|st| st.windows[1].0 = st.windows[0].0 + 1)));
    assert!(prove_notice(&other(&|st| st.windows[1].0 = st.windows[0].0 + 1), &c.padded, &c.sig).is_none());
    assert!(!verify_notice(&proof, &other(&|st| st.windows[1].0 = st.blocks * NOTICE_BLOCK_BYTES)));
    assert!(!verify_notice(&proof, &other(&|st| st.modulus[NOTICE_KEY_BYTES - 1] &= 0xFE)));
}

/// A SELLER MUST NOT BE ABLE TO SHOW A DELIVERY THE CARRIER NEVER SIGNED. Each lie is a table laid by hand and proven
/// against the production gate; the production verifier must refuse it.
#[test]
fn every_lie_about_a_signed_notice_is_refused_by_the_gate() {
    let c = standard();
    assert!(accepted(&c.st, notice_cols(&c.st, &c.padded, &c.sig)), "CALIBRATION: the honest table verifies through the hand-laid path");
    // another notice the carrier really signed: another parcel's delivery
    let other = case("1Z999AA10123456785", "Mon, 09 Nov 2026 09:00:00 +0000");

    // 1. THE SUBJECT IS EDITED: the data says "Delivered … 6784" altered to another tracking number, under the true
    // signature. The hash is then another hash, and the signature is not for it.
    let mut edited = c.padded.clone();
    let at = c.st.windows[0].0 + c.st.windows[0].1.len() - 3;
    edited[at] = b'5';
    let mut lie = c.st.clone();
    lie.windows[0].1 = edited[lie.windows[0].0..lie.windows[0].0 + lie.windows[0].1.len()].to_vec();
    assert!(!accepted(&lie, notice_cols(&lie, &edited, &c.sig)), "⛔ an edited subject verified under the signature of the real one");
    // 2. THE OTHER NOTICE'S SIGNATURE under this notice's data
    assert!(!accepted(&c.st, notice_cols(&c.st, &c.padded, &other.sig)), "⛔ a signature of another notice verified");
    // 3. THE WINDOWS SAY ONE THING, THE SIGNED DATA ANOTHER: the other notice's data and signature (true together),
    // stated with this notice's subject
    assert!(!accepted(&c.st, notice_cols(&c.st, &other.padded, &other.sig)), "⛔ a window that is not the signed data's verified");
    // 4. THE KEPT HASH IS SWAPPED: this notice is hashed, the other notice's hash is laid in the kept column, and the
    // signature check is the other notice's (true for that hash)
    let mut cols = notice_cols(&c.st, &c.padded, &c.sig);
    let swap = notice_cols(&other.st, &other.padded, &other.sig);
    for col in SH_DIG..NOTICE_WIDTH {
        cols[col] = swap[col].clone();
    }
    assert!(!accepted(&c.st, cols), "⛔ a signature over another hash than the one the table computes verified");
    // 5. A KEY THAT DID NOT SIGN: the same table against another company's modulus
    let mut wrong_key = c.st.clone();
    wrong_key.modulus = unhex(OTHER_N);
    assert!(!accepted(&wrong_key, notice_cols(&c.st, &c.padded, &c.sig)), "⛔ a notice verified under a key that did not sign it");
    // 6. THE HASH IS TAKEN ONE BLOCK EARLY (a shorter message's hash): the statement says six blocks
    let mut short = c.st.clone();
    short.blocks -= 1;
    assert!(!accepted(&short, notice_cols(&short, &c.padded, &c.sig)), "⛔ a hash taken a block early verified");
    // 7. one cell of each kind nudged on the honest table
    let honest = notice_cols(&c.st, &c.padded, &c.sig);
    for (name, col, row) in [
        ("a working word's bit", SH_A + 40 * WORD + 5, 2usize),
        ("a schedule word's bit", SH_W + 20 * WORD + 9, 1),
        ("a round carry", SH_RC + 30 * 12 + 1, 3),
        ("the state after a block", SH_OUT + 3 * WORD + 7, 4),
        ("the chained state", SH_CVIN + 5, 2),
        ("the kept hash", SH_DIG + 9, 11),
        ("a step's first operand", RS_A + 3, 5),
        ("the signature riding the rows", RS_SIG + 100, 9),
        ("a quotient digit", RS_Q + 77 * LIMB_TRITS + 2, 6),
        ("a result digit", RS_R + 12 * LIMB_TRITS + 4, MUL_ROW),
        ("a carry digit", RS_C + 200 * CARRY_CELLS + 6, 3),
        ("a carry's top bit", RS_C + 300 * CARRY_CELLS + CARRY_TRITS, 4),
        ("the kept hash's top limb", SH_DIG + DIG_LIMBS - 1, MUL_ROW),
    ] {
        let mut cols = honest.clone();
        cols[col][row] += Fa4::ONE;
        assert!(!accepted(&c.st, cols), "⛔ {name}: a nudged cell verified");
    }
}

/// The blinded table the prover commits for a laid table: the data in the first half, fixed mix lanes in the second.
fn doubled(cols: &[Vec<Fa4>]) -> Vec<Vec<Fa4>> {
    cols.iter()
        .enumerate()
        .map(|(c, col)| {
            let mut out = col.clone();
            out.extend((0..col.len()).map(|r| Fa4::from_u64(((c as u64 + 1) * 0x9E37_79B9 + (r as u64 + 1) * 0x85EB_CA6B) % 0x7F00_0001)));
            out
        })
        .collect()
}

/// SOUND IS MEASURED: every law holds on the honest table, the base-field path gives the extension path's value, and
/// the degree and free-witness censuses pass on the wrapped gate over the doubled table the prover really commits.
#[test]
fn the_notice_gate_passes_the_censuses() {
    let c = standard();
    let cols = doubled(&notice_cols(&c.st, &c.padded, &c.sig));
    let nvars = cols[0].len().trailing_zeros() as usize;
    let inner = NoticeGate::of(&c.st, Ea4::from(Fa4::from_u64(0x9A7)));
    let g = crate::committed_air::Blinded { inner: inner.clone() };
    let n_rows = cols[0].len();
    for r in 0..n_rows / 2 {
        let oob = crate::air_zerocheck::OobLatch::new();
        let local: Vec<Ea4> = cols.iter().map(|col| Ea4::from(col[r])).collect();
        let next: Vec<Ea4> = cols.iter().map(|col| Ea4::from(col[(r + 1) % n_rows])).collect();
        let x: Vec<Ea4> = (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect();
        let at = |col: usize, _p: &[Ea4]| -> Ea4 { next[col] };
        let rs = crate::air_zerocheck::AirConstraint::residuals(&g, &crate::air_zerocheck::Row::new(&local, &oob), &at, &x);
        assert_eq!(rs.len(), law_count(), "the law count is the laws pushed");
        let bad: Vec<usize> = rs.iter().enumerate().filter(|(_, v)| **v != Ea4::ZERO).map(|(i, _)| i).take(12).collect();
        assert!(bad.is_empty(), "row {r}: residual(s) {bad:?} of {} are non-zero on the honest table", rs.len());
        // the base-field path is the same value on a base-field row
        let (base_row, base_next): (Vec<Fa4>, Vec<Fa4>) = (cols.iter().map(|col| col[r]).collect(), cols.iter().map(|col| col[(r + 1) % n_rows]).collect());
        let xb: Vec<Fa4> = (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Fa4::ONE } else { Fa4::ZERO }).collect();
        let via_base = crate::air_zerocheck::AirConstraint::eval_base(&inner, &crate::air_zerocheck::Row::new(&base_row, &oob), &|col| base_next[col], &xb);
        let via_ext = crate::air_zerocheck::AirConstraint::eval(&inner, &crate::air_zerocheck::Row::new(&local, &oob), &at, &x);
        assert_eq!(via_base, via_ext, "row {r}: the two paths agree");
    }
    // THE BATCHED VALUE IS THE LISTED LAWS' OWN: on rows of arbitrary cells at arbitrary points (where no law holds),
    // the one-product form of a step's coefficient laws gives exactly `Σ γ^k · law_k`, on both paths
    for r in n_rows / 2..n_rows / 2 + 4 {
        let oob = crate::air_zerocheck::OobLatch::new();
        let (base_row, base_next): (Vec<Fa4>, Vec<Fa4>) = (cols.iter().map(|col| col[r]).collect(), cols.iter().map(|col| col[(r + 1) % n_rows]).collect());
        let (local, next): (Vec<Ea4>, Vec<Ea4>) = (base_row.iter().map(|v| Ea4::from(*v)).collect(), base_next.iter().map(|v| Ea4::from(*v)).collect());
        let xb: Vec<Fa4> = (0..nvars).map(|k| Fa4::from_u64(3 + 5 * (r + k) as u64)).collect();
        let x: Vec<Ea4> = xb.iter().map(|v| Ea4::from(*v)).collect();
        let at = |col: usize, _p: &[Ea4]| -> Ea4 { next[col] };
        let listed = crate::air_zerocheck::AirConstraint::residuals(&inner, &crate::air_zerocheck::Row::new(&local, &oob), &at, &x);
        assert_eq!(listed.len(), law_count());
        assert!(listed.iter().filter(|v| **v != Ea4::ZERO).count() > law_count() / 2, "arbitrary cells break the laws");
        let folded = listed.iter().zip(&inner.gpow).fold(Ea4::ZERO, |acc, (law, g)| acc + *g * *law);
        let via_ext = crate::air_zerocheck::AirConstraint::eval(&inner, &crate::air_zerocheck::Row::new(&local, &oob), &at, &x);
        let via_base = crate::air_zerocheck::AirConstraint::eval_base(&inner, &crate::air_zerocheck::Row::new(&base_row, &oob), &|col| base_next[col], &xb);
        assert_eq!(via_ext, folded, "row {r}: the batched value is the listed laws'");
        assert_eq!(via_base, folded, "row {r}: and so is the base-field path's");
    }
    let shifted = crate::air_zerocheck::AirConstraint::shifted_cols(&g);
    crate::air_zerocheck::debug_degree_census(&cols, &g, nvars, false, &shifted);
    crate::air_zerocheck::debug_free_witness_census(&cols, &g, nvars, false, &shifted);
}

#[test]
fn the_notice_proof_is_measured() {
    let c = standard();
    let t0 = std::time::Instant::now();
    let proof = prove_notice(&c.st, &c.padded, &c.sig).expect("proves");
    let prove_ms = t0.elapsed().as_millis();
    let t1 = std::time::Instant::now();
    assert!(verify_notice(&proof, &c.st));
    eprintln!(
        "[notice-proof-cost] {} hashed blocks, {} rows x {NOTICE_WIDTH} columns, proof {} B, prove {prove_ms} ms, verify {} ms",
        c.st.blocks,
        c.st.laid(),
        proof.len(),
        t1.elapsed().as_millis()
    );
    // where the bytes are: the zerocheck (round sums, the opened row, the opened next-row cells) and the opening proof
    let bundle: crate::committed_air::ChainedAirBundle = postcard::from_bytes(&proof).expect("the proof is a chained carrier");
    let bytes_of = |values: &Vec<Ea4>| postcard::to_allocvec(values).expect("encodes").len();
    eprintln!(
        "[notice-proof-parts] zerocheck {} B (opened row {} values), next-row values and their bind {} B ({} columns), opening proof {} B",
        postcard::to_allocvec(&bundle.zc).expect("encodes").len(),
        bundle.zc.opened.len(),
        bytes_of(&bundle.next) + bytes_of(&bundle.bind_opened) + postcard::to_allocvec(&bundle.bind_rounds).expect("encodes").len(),
        bundle.next.len(),
        postcard::to_allocvec(&bundle.open).expect("encodes").len(),
    );
    assert!(proof.len() <= 1_800_000);
}

/// THE NEXT-ROW CLASS (2026-11-10): a prover that lies ONLY in the next-row openings. The statement names a key that
/// never signed and a subject the notice never carried; the table is the honest one for the real notice, so the
/// commitment, the opened row and the opening proof are all real. Through the notice's door, which binds the next-row
/// values to the commitment (the shift bind), it is refused. (The same lie through the door that takes next-row
/// openings from the wire verified: measured 2026-11-10, and held as a calibration in the income proof's pins.)
#[test]
fn a_prover_lying_in_the_next_row_openings_proves_no_notice() {
    let c = standard();
    let mut lie = c.st.clone();
    lie.modulus = unhex(OTHER_N);
    lie.windows[0].1[40] ^= 1;
    let st2 = lie.clone();
    let forged = crate::committed_air::forge_blinded_chained_for_tests(notice_cols(&c.st, &c.padded, &c.sig), move |g: Ea4| NoticeGate::of(&st2, g), &notice_bind(&lie))
        .expect("CALIBRATION: the gate reads the next row, so the adversary has an opening to move");
    assert!(!verify_notice(&forged, &lie), "⛔ a delivery no carrier signed VERIFIED: a next-row opening was moved and the door took it");
}

/// THE FIRST ROW'S CHAINED CELLS ARE PUBLIC: the standard start of the hash, and zeros where the kept hash, the
/// operand and the signature ride. The door opens no row in the clear; the gate keeps its first row free of secrets
/// all the same, so the row a next-row binding wraps around to never holds one.
#[test]
fn the_first_row_holds_nothing_secret_in_the_chained_columns() {
    let c = standard();
    let cols = notice_cols(&c.st, &c.padded, &c.sig);
    for col in shifted() {
        let cell = cols[col][0];
        let public = if (SH_CVIN..SH_CVIN + 16).contains(&col) {
            let (j, h) = ((col - SH_CVIN) / 2, (col - SH_CVIN) % 2);
            Fa4::from_u64(u64::from(SHA_IV[j] >> (h * HALF)) & 0xFFFF)
        } else {
            Fa4::ZERO
        };
        assert_eq!(cell, public, "⛔ column {col} of the first row is not a public constant");
    }
    // and the rows after it do carry them: the signature and the kept hash are not zero there
    assert!((RS_SIG..RS_SIG + LIMBS).any(|col| cols[col][LOAD_ROW] != Fa4::ZERO) && (SH_DIG..SH_DIG + DIG_LIMBS).any(|col| cols[col][LOAD_ROW] != Fa4::ZERO));
}
