// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! The content proof's pins: the key a delivery lock binds opens the sealed blocks to the leaves the offer names.
//!
//! TWO-PARTY-REVIEWED: the prover's and the verifier's own verdicts on one statement, run on hostile statements and
//! hand-laid tables against the production verifier. The two-wallet check (a seller's wallet seals and proves, a
//! buyer's wallet checks, pays, and reads the key from the seller's spend through its own node) is a real-node row
//! and is not claimed here.

use super::super::vault_gate::delivery_locks;
use super::*;
use crate::poseidon2_compress::lanes_of;

const KEY: VaultSecret = [0x00C0_FFEE, 0x7F00_0000, 3, 0x1234_5678];
const OTHER_KEY: VaultSecret = [0x00C0_FFEF, 0x7F00_0000, 3, 0x1234_5678];

struct Case {
    st: ContentStatement,
    /// The content, its blocks, its leaves and its root.
    bytes: Vec<u8>,
    leaves: Vec<Digest>,
    root: Digest,
}

fn content(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(7) ^ ((i >> 8) as u8)).collect()
}

const SALT: ListingSalt = [0x5A17, 11, 12, 13];

fn seller() -> Digest {
    NoteOwner::from_test_key(lanes_of(&[0xB0B, 4, 5, 6])).spk()
}

/// The statement a buyer writes for `listed` blocks of `len` bytes of content sealed under `key`.
fn case_of(len: usize, key: &VaultSecret, listed: &[u64]) -> Case {
    let bytes = content(len);
    let blocks = content_blocks(&bytes).expect("fits");
    let leaves: Vec<Digest> = blocks.iter().enumerate().map(|(j, b)| content_leaf(j as u64, b)).collect();
    let root = content_root(&leaves, len as u64);
    let seller_spk = seller();
    let rows = listed.iter().map(|j| ContentRow { index: *j, sealed: seal_block(&blocks[*j as usize], key, *j), leaf: leaves[*j as usize] }).collect();
    Case { st: ContentStatement { seller_spk, salt: SALT, locks: delivery_locks(&seller_spk, key, &SALT), rows, context: root }, bytes, leaves, root }
}

/// Every block of `len` bytes of content.
fn whole(len: usize) -> Case {
    let n = len.div_ceil(CONTENT_BLOCK_BYTES).max(1) as u64;
    case_of(len, &KEY, &(0..n).collect::<Vec<_>>())
}

/// Prove a hand-laid table as it stands and say whether the production verifier takes it for `st`.
fn accepted(st: &ContentStatement, cols: Vec<Vec<Fa4>>) -> bool {
    let st2 = st.clone();
    crate::committed_air::prove_air_blinded_bytes(cols, move |g: Ea4| ContentGate::of(&st2, g), &content_bind(st)).is_some_and(|p| verify_content(&p, st))
}

/// Re-lay row `r`'s keystream and leaf blocks under `key` at block `index`, leaving its lock block as laid.
fn relay_stream(cols: &mut [Vec<Fa4>], st: &ContentStatement, r: usize, key: &VaultSecret, index: u64) {
    let mut row = vec![Fa4::ZERO; CONTENT_WIDTH];
    let (left, right) = stream_inputs(key, index);
    crate::pow_pq_air::lay_perm_row_flat(&mut row, CG_KS_BLK, pose_state(&to_f(&left), &to_f(&right)));
    let block: DigestF = core::array::from_fn(|c| Fa4::from_u64(st.row(r).sealed[c]) - row[CG_KS_BLK + crate::pow_pq_air::PERM_OUT + c]);
    crate::pow_pq_air::lay_perm_row_flat(&mut row, CG_LEAF_BLK, pose_state(&to_f(&lanes_of(&[LEAF_DOMAIN, index])), &block));
    for c in CG_KS_BLK..CONTENT_WIDTH {
        cols[c][r] = row[c];
    }
}

#[test]
fn content_has_one_encoding_and_seals_and_opens_block_by_block() {
    for len in [0usize, 1, 29, 30, 31, 239, 240, 241, 1000] {
        let bytes = content(len);
        let blocks = content_blocks(&bytes).expect("fits");
        assert_eq!(blocks.len(), len.div_ceil(CONTENT_BLOCK_BYTES).max(1));
        assert!(blocks.iter().flatten().all(|l| *l < 1 << CONTENT_LANE_BITS));
        assert_eq!(content_bytes(&blocks, len as u64).as_deref(), Some(&bytes[..]), "{len} bytes come back");
        for (j, b) in blocks.iter().enumerate() {
            let sealed = seal_block(b, &KEY, j as u64);
            assert_eq!(open_block(&sealed, &KEY, j as u64), *b);
            assert_ne!(open_block(&sealed, &OTHER_KEY, j as u64), *b, "another key opens it to something else");
            assert_ne!(open_block(&sealed, &KEY, j as u64 + 1), *b, "and so does another block's stream");
        }
        // one content, one encoding: a wrong length, a lane past 30 bits and a set bit past the end are refused
        assert!(content_bytes(&blocks, len as u64 + CONTENT_BLOCK_BYTES as u64 + 1).is_none());
        let mut wide = blocks.clone();
        wide[0][0] |= 1 << CONTENT_LANE_BITS;
        assert!(content_bytes(&wide, len as u64).is_none());
        if len % CONTENT_BLOCK_BYTES != 0 {
            let mut padded = blocks.clone();
            let last = padded.len() - 1;
            padded[last][DIGEST_LANES - 1] |= 1 << (CONTENT_LANE_BITS - 1);
            assert!(content_bytes(&padded, len as u64).is_none(), "{len}: a bit past the content's end");
        }
    }
    // the largest lane a block holds plus the largest keystream lane wraps the field and still opens
    let full: Digest = [(1 << CONTENT_LANE_BITS) - 1; DIGEST_LANES];
    assert_eq!(open_block(&seal_block(&full, &KEY, 5), &KEY, 5), full);
}

#[test]
fn a_leaf_is_under_the_root_only_at_its_own_place() {
    let c = whole(1000);
    assert_eq!(c.leaves.len(), 34);
    for j in [0u64, 1, 17, 33] {
        let path = leaf_path(&c.leaves, j).expect("a listed block has a path");
        assert!(leaf_under_root(&c.leaves[j as usize], j, &path, 1000, &c.root));
        assert!(!leaf_under_root(&c.leaves[j as usize], j ^ 1, &path, 1000, &c.root), "⛔ a leaf verified at another block's place");
        assert!(!leaf_under_root(&c.leaves[(j as usize + 1) % 34], j, &path, 1000, &c.root), "⛔ another block's leaf verified");
        assert!(!leaf_under_root(&c.leaves[j as usize], j, &path, 999, &c.root), "⛔ the root does not bind the length");
        assert!(!leaf_under_root(&c.leaves[j as usize], j, &path[1..], 1000, &c.root), "⛔ a short path verified");
    }
    assert!(leaf_path(&c.leaves, 34).is_none());
    assert_ne!(content_root(&c.leaves[..33], 1000), c.root);
    // content of one block: its root is over that one leaf, and the path is empty
    let one = whole(12);
    assert!(leaf_under_root(&one.leaves[0], 0, &[], 12, &one.root));
    assert_eq!(content_bytes(&content_blocks(&one.bytes).expect("fits"), 12).expect("decodes"), one.bytes);
}

#[test]
fn a_content_proof_verifies_for_its_statement_and_for_no_other() {
    let c = whole(100);
    let proof = prove_content(&c.st, &KEY).expect("the seller proves");
    assert!(verify_content(&proof, &c.st), "the buyer's check passes");
    let mut other = c.st.clone();
    other.context = lanes_of(&[0x5A1E, 2027]);
    assert!(!verify_content(&proof, &other), "⛔ a proof verified for another sale");
    let mut other = c.st.clone();
    other.rows[1].sealed[3] ^= 1;
    assert!(!verify_content(&proof, &other), "⛔ a proof verified for other sealed lanes");
    let mut other = c.st.clone();
    other.rows[2].leaf[0] ^= 1;
    assert!(!verify_content(&proof, &other), "⛔ a proof verified for another leaf");
    let mut other = c.st.clone();
    other.rows.swap(0, 1);
    assert!(!verify_content(&proof, &other), "⛔ a proof verified for the rows in another order");
    let mut other = c.st.clone();
    other.locks = delivery_locks(&c.st.seller_spk, &OTHER_KEY, &c.st.salt);
    assert!(!verify_content(&proof, &other), "⛔ a proof verified for another key's lock");
    let mut other = c.st.clone();
    other.salt[0] ^= 1;
    assert!(!verify_content(&proof, &other), "⛔ a proof verified for another salt");
    let mut other = c.st.clone();
    other.seller_spk[1] ^= 1;
    assert!(!verify_content(&proof, &other), "⛔ a proof verified for another seller");
    let mut other = c.st.clone();
    other.rows.pop();
    assert!(!verify_content(&proof, &other), "⛔ a proof verified for a shorter list");
    assert!(!verify_content(&[], &c.st) && !verify_content(&proof[..proof.len() - 1], &c.st));
    // the honest prover makes no proof of a false statement
    assert!(prove_content(&c.st, &OTHER_KEY).is_none(), "a key that is not the lock's");
    let mut lie = c.st.clone();
    lie.rows[0].leaf = c.st.rows[1].leaf;
    assert!(prove_content(&lie, &KEY).is_none(), "a block that does not open to its listed leaf");
    let mut twice = c.st.clone();
    twice.rows.push(c.st.rows[0]);
    assert!(prove_content(&twice, &KEY).is_none() && !verify_content(&proof, &twice), "a block listed twice");
    let mut empty = c.st.clone();
    empty.rows.clear();
    assert!(prove_content(&empty, &KEY).is_none() && !verify_content(&proof, &empty));
}

/// A SELLER MUST NOT BE ABLE TO SHOW ONE KEY AND LOCK ANOTHER. Each lie is a table laid by hand and proven against
/// the production gate; the production verifier must refuse it.
#[test]
fn every_lie_about_sealed_content_is_refused_by_the_gate() {
    let c = whole(400);
    assert!(c.st.rows.len() == 14 && c.st.laid() == 16);
    // the calibration: the same machinery accepts the truth, so a refusal below is the gate's
    assert!(accepted(&c.st, content_cols(&c.st, &KEY)), "CALIBRATION: the honest table verifies through the hand-laid path");

    // 1. THE CONTENT IS SEALED UNDER ANOTHER KEY than the lock's. The leaves the seller lists are what that other key
    // opens the sealed blocks to, and the table is laid under it: true in every block but the lock's.
    let sealed_other = case_of(400, &OTHER_KEY, &(0..14).collect::<Vec<_>>());
    let lie = ContentStatement { locks: c.st.locks, ..sealed_other.st.clone() };
    assert!(!accepted(&lie, content_cols(&lie, &OTHER_KEY)), "⛔ content sealed under a key that is not the lock's verified");
    // 2. … the same, with the lock block laid under the lock's own key (two keys in one row)
    let mut cols = content_cols(&lie, &KEY);
    for r in 0..lie.laid() {
        relay_stream(&mut cols, &lie, r, &OTHER_KEY, lie.row(r).index);
    }
    assert!(!accepted(&lie, cols), "⛔ a row with one key in its lock and another in its stream verified");
    // 3. … on ONE row only: thirteen blocks really are the lock's key's, one is not
    let mut one = c.st.clone();
    one.rows[5] = sealed_other.st.rows[5];
    let mut cols = content_cols(&one, &KEY);
    relay_stream(&mut cols, &one, 5, &OTHER_KEY, 5);
    assert!(!accepted(&one, cols), "⛔ one block under another key verified");
    // 4. A LISTED LEAF THAT IS NOT THE BLOCK'S, the table laid truthfully (its leaf block says the real leaf)
    let mut lie = c.st.clone();
    lie.rows[3].leaf = c.st.rows[4].leaf;
    assert!(!accepted(&lie, content_cols(&lie, &KEY)), "⛔ a block that does not open to its listed leaf verified");
    // 5. ANOTHER BLOCK'S STREAM: block 3's sealed lanes opened with block 4's keystream, listed under the leaf that gives
    let mut lie = c.st.clone();
    lie.rows[3].leaf = content_leaf(3, &open_block(&c.st.rows[3].sealed, &KEY, 4));
    let mut cols = content_cols(&lie, &KEY);
    relay_stream(&mut cols, &lie, 3, &KEY, 4);
    // the leaf block re-laid at the listed index over the wrongly opened block, so only the stream's index is false
    let wrong: DigestF = core::array::from_fn(|k| Fa4::from_u64(lie.rows[3].sealed[k]) - cols[CG_KS_BLK + crate::pow_pq_air::PERM_OUT + k][3]);
    let mut row = vec![Fa4::ZERO; CONTENT_WIDTH];
    crate::pow_pq_air::lay_perm_row_flat(&mut row, CG_LEAF_BLK, pose_state(&to_f(&lanes_of(&[LEAF_DOMAIN, 3])), &wrong));
    for col in CG_LEAF_BLK..CONTENT_WIDTH {
        cols[col][3] = row[col];
    }
    assert!(!accepted(&lie, cols), "⛔ a block opened with another block's stream verified");
    // 6. A STREAM OF ANOTHER FAMILY: the keystream block's unused input lanes set
    let mut cols = content_cols(&c.st, &KEY);
    let (left, mut right) = stream_inputs(&KEY, 0);
    right[LOCK_LANES] = 1;
    let mut row = vec![Fa4::ZERO; CONTENT_WIDTH];
    crate::pow_pq_air::lay_perm_row_flat(&mut row, CG_KS_BLK, pose_state(&to_f(&left), &to_f(&right)));
    for col in CG_KS_BLK..CG_LEAF_BLK {
        cols[col][0] = row[col];
    }
    assert!(!accepted(&c.st, cols), "⛔ a keystream with a lane set past the key verified");
    // 7. every public lane is welded: nudge each cell the welds read, one at a time, on one row
    for (name, at) in [
        ("the lock's left input", CG_LOCK_BLK),
        ("the lock's key lanes", CG_LOCK_BLK + DIGEST_LANES),
        ("the lock's salt lanes", CG_LOCK_BLK + DIGEST_LANES + LOCK_LANES),
        ("the lock's output", CG_LOCK_BLK + crate::pow_pq_air::PERM_OUT),
        ("the lock's upper output", CG_LOCK_BLK + crate::pow_pq_air::PERM_OUT + LOCK_LANES),
        ("the stream's index", CG_KS_BLK + 1),
        ("the stream's key lanes", CG_KS_BLK + DIGEST_LANES),
        ("the leaf's index", CG_LEAF_BLK + 1),
        ("the opened block", CG_LEAF_BLK + DIGEST_LANES),
        ("the leaf", CG_LEAF_BLK + crate::pow_pq_air::PERM_OUT),
    ] {
        let mut cols = content_cols(&c.st, &KEY);
        cols[at][2] += Fa4::ONE;
        assert!(!accepted(&c.st, cols), "⛔ {name}: a nudged cell verified");
    }
    // 8. a row PAST the list restates the last listed block; laid as anything else it is refused
    let mut cols = content_cols(&c.st, &KEY);
    relay_stream(&mut cols, &c.st, 15, &KEY, 0);
    assert!(!accepted(&c.st, cols), "⛔ a padding row that is not the last listed block verified");
}

/// The blinded table the prover commits for a laid table: the data in the first half, fixed mix lanes in the second
/// (the prover draws these from the OS; a census needs a table it can reproduce).
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
/// the three censuses pass on the wrapped gate over the doubled table the prover really commits.
#[test]
fn the_content_gate_passes_the_three_censuses() {
    for c in [whole(12), whole(400)] {
        let laid = content_cols(&c.st, &KEY);
        let cols = doubled(&laid);
        let nvars = cols[0].len().trailing_zeros() as usize;
        let inner = ContentGate::of(&c.st, Ea4::from(Fa4::from_u64(0x9A7)));
        let g = crate::committed_air::Blinded { inner: inner.clone() };
        let never = |_: usize, _: &[Ea4]| -> Ea4 { panic!("a row-local gate read a shifted column") };
        for r in 0..cols[0].len() / 2 {
            let oob = crate::air_zerocheck::OobLatch::new();
            let local: Vec<Ea4> = cols.iter().map(|col| Ea4::from(col[r])).collect();
            let x: Vec<Ea4> = (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect();
            let rs = crate::air_zerocheck::AirConstraint::residuals(&g, &crate::air_zerocheck::Row::new(&local, &oob), &never, &x);
            let bad: Vec<usize> = rs.iter().enumerate().filter(|(_, v)| **v != Ea4::ZERO).map(|(i, _)| i).collect();
            assert!(bad.is_empty(), "row {r}: residual(s) {bad:?} of {} are non-zero on the honest table", rs.len());
            assert_eq!(rs.len(), inner.gpow.len(), "the γ-power table is as long as the law list");
            // the base-field path is the same value on a base-field row
            let base_row: Vec<Fa4> = cols.iter().map(|col| col[r]).collect();
            let xb: Vec<Fa4> = (0..nvars).map(|k| if (r >> (nvars - 1 - k)) & 1 == 1 { Fa4::ONE } else { Fa4::ZERO }).collect();
            let via_base = crate::air_zerocheck::AirConstraint::eval_base(&inner, &crate::air_zerocheck::Row::new(&base_row, &oob), &|_| Fa4::ZERO, &xb);
            let via_ext = crate::air_zerocheck::AirConstraint::eval(&inner, &crate::air_zerocheck::Row::new(&local, &oob), &never, &x);
            assert_eq!(via_base, via_ext, "row {r}: the two paths agree");
        }
        // off the hypercube the two paths agree too (a base-field point that is no row)
        let oob = crate::air_zerocheck::OobLatch::new();
        let base_row: Vec<Fa4> = (0..CONTENT_WIDTH).map(|c| Fa4::from_u64(c as u64 * 7919 + 13)).collect();
        let ext_row: Vec<Ea4> = base_row.iter().map(|v| Ea4::from(*v)).collect();
        let xb: Vec<Fa4> = (0..nvars).map(|k| Fa4::from_u64(k as u64 + 2)).collect();
        let xe: Vec<Ea4> = xb.iter().map(|v| Ea4::from(*v)).collect();
        assert_eq!(
            crate::air_zerocheck::AirConstraint::eval_base(&inner, &crate::air_zerocheck::Row::new(&base_row, &oob), &|_| Fa4::ZERO, &xb),
            crate::air_zerocheck::AirConstraint::eval(&inner, &crate::air_zerocheck::Row::new(&ext_row, &oob), &never, &xe)
        );
        let shifted = crate::air_zerocheck::AirConstraint::shifted_cols(&g);
        crate::air_zerocheck::debug_degree_census(&cols, &g, nvars, true, &shifted);
        crate::air_zerocheck::debug_free_witness_census(&cols, &g, nvars, true, &shifted);
        crate::air_zerocheck::debug_decorative_block_census(&cols, &g, nvars, true, &shifted);
    }
}

/// The public columns at a point: the fast path over a boolean suffix is the plain sum over every row.
#[test]
fn the_public_columns_are_the_tables_own_extension_at_every_point() {
    let c = whole(400);
    let g = ContentGate::of(&c.st, Ea4::from(Fa4::from_u64(3)));
    let n = g.data_vars;
    for mixed in 0..=n {
        // `mixed` leading coordinates off the hypercube, the rest bits
        let x: Vec<Fa4> = (0..n).map(|k| if k < mixed { Fa4::from_u64(k as u64 * 5 + 2) } else { Fa4::from_u64(((0b1011_0110 >> k) & 1) as u64) }).collect();
        let (shift, low, w) = row_weights(&x);
        assert_eq!(shift + mixed.max(n - shift), n.max(shift + mixed), "the suffix found is at least the bits laid");
        let fast: Fa4 = w.iter().enumerate().fold(Fa4::ZERO, |s, (h, wh)| s + *wh * g.table[(h << shift) | low][0]);
        let mut plain = Fa4::ZERO;
        for (r, row) in g.table.iter().enumerate() {
            let weight = (0..n).fold(Fa4::ONE, |p, k| p * if (r >> (n - 1 - k)) & 1 == 1 { x[k] } else { Fa4::ONE - x[k] });
            plain += weight * row[0];
        }
        assert_eq!(fast, plain, "{mixed} coordinates off the hypercube");
    }
}

#[test]
fn the_content_proof_is_measured() {
    for (len, name) in [(24usize, "a code"), (240, "a license file"), (960, "32 sampled blocks"), (7_680, "256 blocks"), (30_720, "1,024 blocks")] {
        let c = whole(len);
        let t0 = std::time::Instant::now();
        let proof = prove_content(&c.st, &KEY).expect("proves");
        let prove_ms = t0.elapsed().as_millis();
        let t1 = std::time::Instant::now();
        assert!(verify_content(&proof, &c.st));
        eprintln!(
            "[content-proof-cost] {name}: {} listed blocks, {} rows x {CONTENT_WIDTH} columns, proof {} B, prove {prove_ms} ms, verify {} ms",
            c.st.rows.len(),
            c.st.laid(),
            proof.len(),
            t1.elapsed().as_millis()
        );
        assert!(proof.len() <= 1_800_000);
    }
}
