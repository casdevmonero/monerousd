// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! D4's gates, each a lying prover the statement must refuse, beside the honest control.
//! TWO-PARTY-REVIEWED: the prover and an independently rebuilt verifier are the two parties here (the verifier rebuilds
//! the circuit from the public statement alone); a node's door refusing a call whose blob lies is the real-node check
//! `scratchpad/net/backend.py`.

use super::*;
use crate::poseidon2_compress::lanes_of;

/// The smallest call class whose blob has two entries: 2^10 / 496 = 2, a blob table of 2^11 rows.
const H: u8 = 10;

fn key(n: u64) -> Digest {
    compress(&lanes_of(&[0x6b65_79, n]), &lanes_of(&[n * 7 + 1]))
}
fn kc() -> Digest {
    lanes_of(&[0x6b63, 11, 22, 33, 44, 55, 66, 77])
}
fn tx() -> Digest {
    lanes_of(&[0x7478, 9, 8, 7])
}
fn salt(n: u64) -> Digest {
    lanes_of(&[0x73616c74, n])
}
fn text(b: &[u8]) -> (VmVal, Vec<u8>) {
    (VmVal::Str { digest: dsol_vm::str_digest(b), len: b.len() as u32 }, b.to_vec())
}
fn word(k: Digest, v: u64) -> Write {
    Write { key: k, val: VmVal::Word(v), bytes: Vec::new() }
}
fn string(k: Digest, b: &[u8]) -> Write {
    let (val, bytes) = text(b);
    Write { key: k, val, bytes }
}
/// A message long enough to fill several string slots (and not a whole number of blocks).
const NOTE: &[u8] = b"order #41: two lanterns, ship to the hut by the river; leave at the door. thanks!";
fn pre() -> dsol_vm::StorageTrie {
    let mut t = dsol_vm::StorageTrie::default();
    t.insert_checked(&key(1), VmVal::Word(5)).expect("insert");
    let (v, b) = text(b"hello there!");
    t.insert_checked(&key(2), v).expect("insert");
    t.contents.insert(dsol_vm::str_digest(&b), b);
    t
}
fn writes() -> Vec<Write> {
    // one update of a held word and one new string slot
    vec![word(key(1), 0xdead_beef_0042), string(key(9), NOTE)]
}
fn post_of(t: &dsol_vm::StorageTrie, ws: &[Write]) -> dsol_vm::StorageTrie {
    let mut t = t.clone();
    for w in ws {
        t.insert_checked(&w.key, w.val).expect("insert");
        if !w.bytes.is_empty() {
            t.contents.insert(dsol_vm::str_digest(&w.bytes), w.bytes.clone());
        }
    }
    t
}

#[test]
fn a_blob_decrypts_to_the_writes_and_a_pad_is_the_only_all_zero_entry() {
    let ws = writes();
    let w = entries_for_class(14);
    assert_eq!(w, (1 << 14) / (2 * STORAGE_DEPTH));
    let (blob, digest) = encrypt_blob(&kc(), &tx(), &salt(1), &ws, w).expect("fits");
    assert_eq!(blob.len(), w * ENTRY_BYTES, "every call of the class has one blob length");
    assert_eq!(blob_digest(&blob), Some(digest));
    assert_eq!(decrypt_blob(&kc(), &tx(), &salt(1), &blob), Some(ws.clone()), "the writes come back, in order, a string with its bytes");
    // the write-set a reader derives from two tries carries the string's bytes
    assert_eq!(writes_between(&pre(), &post_of(&pre(), &ws)), {
        let mut v = ws.clone();
        v.sort_by_key(|w| w.key);
        v
    });
    // a string past the stored bound, or whose bytes are not its digest's, never makes a blob
    let long = vec![b'x'; STR_STORED_MAX + 1];
    assert!(encrypt_blob(&kc(), &tx(), &salt(1), &[string(key(3), &long)], w).is_none());
    assert!(encrypt_blob(&kc(), &tx(), &salt(1), &[string(key(3), &long[..STR_STORED_MAX])], w).is_some(), "the bound itself fits");
    let mut liar = string(key(3), b"abc");
    liar.bytes = b"abd".to_vec();
    assert!(encrypt_blob(&kc(), &tx(), &salt(1), &[liar], w).is_none());
    // another key reads garbage, never the writes
    assert_ne!(decrypt_blob(&lanes_of(&[1]), &tx(), &salt(1), &blob), Some(ws.clone()));
    // the word 0 written to the key 0 is a write, not a PAD
    let zero = word([0; L], 0);
    assert_ne!(entry_of(&zero), [0u64; ENTRY_LANES]);
    assert_eq!(write_of(&entry_of(&zero)), Some(zero));
    // the three halves carry the key and the value; a string's bytes ride its slots (the blob round trip above)
    for w in &ws {
        let back = write_of(&entry_of(w)).expect("a write");
        assert_eq!((back.key, back.val), (w.key, w.val));
    }
    // a blob that is not whole entries, or carries a non-canonical lane, has no digest
    assert_eq!(blob_digest(&blob[..blob.len() - 1]), None);
    let mut bad = blob.clone();
    bad[..4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    assert_eq!(blob_digest(&bad), None);
}

#[test]
fn h1_two_proofs_of_one_call_never_share_a_keystream() {
    // the same call (one tx_hash), proven twice with different writes: with one salt the ciphertext difference IS the
    // plaintext difference (H1's leak); with a fresh salt per proof it is not
    let a = vec![word(key(1), 100)];
    let b = vec![word(key(1), 250)];
    // the halves follow the entry's string slots
    let ent = |bl: &[u8], i: usize| {
        let at = 4 * (STR_SLOTS * L + i);
        u64::from(u32::from_le_bytes(bl[at..at + 4].try_into().unwrap()))
    };
    let (ba, _) = encrypt_blob(&kc(), &tx(), &salt(1), &a, 2).unwrap();
    let (bb_same, _) = encrypt_blob(&kc(), &tx(), &salt(1), &b, 2).unwrap();
    let (bb_fresh, _) = encrypt_blob(&kc(), &tx(), &salt(2), &b, 2).unwrap();
    let (ea, eb) = (entry_of(&a[0]), entry_of(&b[0]));
    let lane = L + 1; // the value's low limb
    let pd = fsub(eb[lane], ea[lane]);
    assert_eq!(fsub(ent(&bb_same, lane), ent(&ba, lane)), pd, "CALIBRATION: one salt leaks the difference");
    assert_ne!(fsub(ent(&bb_fresh, lane), ent(&ba, lane)), pd, "⛔ a fresh salt still leaked the plaintext difference");
}

fn honest() -> (Vec<Vec<Fa4>>, BlobStatement) {
    build_trace(&kc(), &pre(), &tx(), &salt(1), &writes(), H).expect("the writes fit the class")
}

#[test]
fn the_laid_table_ends_on_the_post_state_and_the_blob_the_native_encryption_gives() {
    let (cols, stmt) = honest();
    assert_eq!(cols.len(), COLS);
    assert_eq!(cols[0].len(), 1 << blob_height_log2(H));
    assert_eq!(stmt.storage_post, post_of(&pre(), &writes()).root(), "the table's end root is the post-state");
    assert_eq!(stmt.storage_pre, pre().root());
    let (_, digest) = encrypt_blob(&kc(), &tx(), &salt(1), &writes(), stmt.entries).unwrap();
    assert_eq!(stmt.blob_digest, digest);
    assert_eq!(stmt.kc_commit, kc_commit(&kc()));
    // a write-set larger than the class holds is refused before any table is laid
    let many: Vec<Write> = (0..3).map(|n| word(key(20 + n), n)).collect();
    assert!(build_trace(&kc(), &pre(), &tx(), &salt(1), &many, H).is_none());
}

/// Prove `cols` against `stmt`; `true` only when a proof comes out AND an independently rebuilt verifier accepts it.
fn proves(cols: Vec<Vec<Fa4>>, stmt: &BlobStatement) -> bool {
    // A-F55: the door's own engine, the blinded chained door.
    match crate::committed_air::prove_air_blinded_chained_bytes(cols, make_constraint(stmt.clone()), &stmt.bind()) {
        Some(bytes) => crate::committed_air::verify_air_blinded_chained_bytes(
            &bytes,
            make_constraint(stmt.clone()),
            &stmt.bind(),
            (usize::from(stmt.height_log2), COLS),
        ),
        None => false,
    }
}

#[test]
fn an_honest_blob_proves_and_the_door_accepts_it_from_public_values_alone() {
    let (proof, stmt, blob) = prove_blob(&kc(), &pre(), &tx(), &salt(1), &writes(), H).expect("an honest blob proves");
    assert!(verify_blob(&proof, &stmt, &blob, H), "the door refused an honest blob");
    assert_eq!(decrypt_blob(&kc(), &tx(), &salt(1), &blob), Some(writes()));
    // the door's own checks, each refusing on a value it reads from the wire
    let mut cut = blob.clone();
    cut.truncate(blob.len() - ENTRY_BYTES);
    assert!(!verify_blob(&proof, &stmt, &cut, H), "⛔ a blob of another length passed");
    let mut garbage = blob.clone();
    let mid = blob.len() / 2;
    garbage[mid] ^= 1;
    assert!(!verify_blob(&proof, &stmt, &garbage, H), "⛔ A4: a garbage blob beside an honest storage_post passed");
    assert!(!verify_blob(&proof, &stmt, &blob, H + 1), "⛔ a blob of another class passed");
    eprintln!("[d4] proof {} B, blob {} B, table {} cols × 2^{}", proof.bytes.len(), blob.len(), COLS, stmt.height_log2);
}

/// ⛔⛔⛔ A-F55 (RED first) — THE DOOR REFUSES A STORAGE TRANSITION NO WRITE MADE, WHEN THE PROVER LIES IN THE ROW IT SENDS.
/// The honest call's blob and trace; the statement claims `storage_post = storage_pre` (the writes recorded nowhere), so
/// the door's own checks (class, length, blob digest) all pass and only the proof can refuse. The lying provers are the
/// crate's own: the direct engine's (zero zerocheck rounds, an opened row SOLVED to satisfy the gate at the rounds'
/// point, `whir_rec_block::forge_direct_light_decider_for_tests` — the DB-452 class, link 78 measured it accepted) and the
/// chained door's (`committed_air::forge_blinded_chained_for_tests`: one sent next-row value moved until the gate reads
/// zero). Whatever engine the door runs, neither may pass.
/// TWO-PARTY-REVIEWED: the two parties are the lying prover and the door's verifier, rebuilt from the public statement
/// alone (`verify_blob`); the node-to-node side of this door is the real-node check `scratchpad/net/backend.py`.
#[test]
fn af55_a_contract_storage_post_no_write_reached_is_refused_from_a_lying_prover() {
    let (proof, stmt, blob) = prove_blob(&kc(), &pre(), &tx(), &salt(1), &writes(), H).expect("an honest blob proves");
    assert!(verify_blob(&proof, &stmt, &blob, H), "CONTROL: the door accepts the honest call");
    let cols = build_trace(&kc(), &pre(), &tx(), &salt(1), &writes(), H).expect("the honest trace").0;
    let mut lie = stmt.clone();
    lie.storage_post = stmt.storage_pre;
    assert_ne!(lie.storage_post, stmt.storage_post, "CALIBRATION: the lie names another post state");
    assert!(!verify_blob(&proof, &lie, &blob, H), "CONTROL: the honest proof does not speak for the lie");
    let direct = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::whir_rec_block::forge_direct_light_decider_for_tests(cols.clone(), make_constraint(lie.clone()), &lie.bind())
    }))
    .ok()
    .flatten();
    let direct_passes = direct.as_ref().is_some_and(|b| verify_blob(&BlobProof { bytes: b.clone() }, &lie, &blob, H));
    eprintln!("[af55] the direct engine's solved-row liar: {} B, the door verifies={direct_passes}", direct.as_ref().map_or(0, Vec::len));
    assert!(!direct_passes, "⛔⛔⛔ A-F55: a contract's storage moved to a state no write reached — the door took a solved opened row");
    let chained = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        crate::committed_air::forge_blinded_chained_for_tests(cols.clone(), make_constraint(lie.clone()), &lie.bind())
    }))
    .ok()
    .flatten();
    let chained_passes = chained.as_ref().is_some_and(|b| verify_blob(&BlobProof { bytes: b.clone() }, &lie, &blob, H));
    eprintln!("[af55] the chained door's next-row liar: {} B, the door verifies={chained_passes}", chained.as_ref().map_or(0, Vec::len));
    assert!(!chained_passes, "⛔⛔⛔ A-F55: a contract's storage moved to a state no write reached — the door took a moved next-row value");
}

#[test]
fn a_lying_prover_is_refused_at_every_claim_of_the_statement() {
    let (cols, stmt) = honest();
    assert!(proves(cols.clone(), &stmt), "CONTROL: the honest table proves");
    let other = |f: &dyn Fn(&mut BlobStatement)| {
        let mut s = stmt.clone();
        f(&mut s);
        s
    };
    // the post-state the call's own proof states, with a blob of OTHER writes: the table's end root is not it
    let real_post = stmt.storage_post;
    let (lie_cols, _) = build_trace(&kc(), &pre(), &tx(), &salt(1), &[word(key(1), 7)], H).unwrap();
    assert!(!proves(lie_cols, &other(&|s| s.storage_post = real_post)), "⛔ another value for one write passed under the call's post-state");
    // a missing write: the first write only, claimed as the whole call
    let (short, _) = build_trace(&kc(), &pre(), &tx(), &salt(1), &writes()[..1], H).unwrap();
    assert!(!proves(short, &stmt), "⛔ a blob that leaves a write out passed");
    // another key than the deploy fixed
    assert!(!proves(cols.clone(), &other(&|s| s.kc_commit = kc_commit(&lanes_of(&[9])))), "⛔ a key the deploy never fixed passed");
    // another digest, salt, tx or pre-state than the table's
    assert!(!proves(cols.clone(), &other(&|s| s.blob_digest = lanes_of(&[1]))), "⛔ another blob digest passed");
    assert!(!proves(cols.clone(), &other(&|s| s.blob_salt = salt(9))), "⛔ another salt passed");
    assert!(!proves(cols.clone(), &other(&|s| s.tx_hash = lanes_of(&[4]))), "⛔ another call's tx passed");
    assert!(!proves(cols.clone(), &other(&|s| s.storage_pre = lanes_of(&[5]))), "⛔ another pre-state passed");
    // a PAD count that is not the class's
    assert!(!proves(cols.clone(), &other(&|s| s.entries = 1)), "⛔ a blob with another entry count passed");
    // a string written with its bytes withheld (no block absorbed): later calls could never re-supply it
    let (withheld, ws) = build_trace_lying(&kc(), &pre(), &tx(), &salt(1), &writes(), H, Lie::WithholdBytes).unwrap();
    assert_eq!(ws.storage_post, stmt.storage_post, "the lie keeps the call's post-state");
    assert!(!proves(withheld, &ws), "⛔ a string write whose bytes were withheld passed");
    // a string written under its true digest with other bytes in its slots
    let (other_bytes, os) = build_trace_lying(&kc(), &pre(), &tx(), &salt(1), &writes(), H, Lie::OtherBytes).unwrap();
    assert_eq!(os.storage_post, stmt.storage_post);
    assert!(!proves(other_bytes, &os), "⛔ a string write carrying other bytes passed");
}

#[test]
fn a_tampered_cell_of_the_table_is_refused() {
    let (cols, stmt) = honest();
    // the first write's first path row: a sibling, a direction bit, the old leaf, a key lane, a ciphertext input
    let first_po = (0..cols[0].len()).find(|r| cols[C_KIND + kind::PO][*r] == KoalaBear::ONE).expect("a path row");
    let first_sv = (0..cols[0].len()).find(|r| cols[C_KIND + kind::SV][*r] == KoalaBear::ONE).expect("a value row");
    let ab = (0..cols[0].len()).find(|r| cols[C_KIND + kind::AB1][*r] == KoalaBear::ONE).expect("an absorb row");
    let sba = (0..cols[0].len()).filter(|r| cols[C_KIND + kind::SBA][*r] == KoalaBear::ONE).collect::<Vec<_>>();
    assert_eq!(sba.len(), dsol_vm::str_blocks(NOTE.len()), "the string's blocks are each absorbed once");
    let ksp = (0..cols[0].len()).find(|r| cols[C_KIND + kind::KSP][*r] == KoalaBear::ONE).expect("an empty slot");
    let ks0_str = (0..cols[0].len()).filter(|r| cols[C_KIND + kind::KS0][*r] == KoalaBear::ONE).nth(1).expect("the string's halves");
    for (name, col, row) in [
        ("a sibling", C_SIB + 3, first_po + 20),
        ("a direction bit", C_BIT, first_po + 40),
        ("the old leaf", C_NO + 2, first_po),
        ("the entry's key", C_EK + 5, first_sv + 1),
        ("the entry's value", C_EV + 1, first_sv + 1),
        ("a ciphertext", 9, ab),
        ("the running root", C_ROOT + 1, first_po + 100),
        ("the key accumulator", C_KACC + 7, first_po + 30),
        ("a string block", C_BLK + 2, sba[1]),
        ("the sponge's capacity", C_CAP + 0, sba[0]),
        ("the string's digest", C_SDIG + 4, ks0_str),
        ("an empty slot's position", C_BS + 3, ksp),
    ] {
        let mut t = cols.clone();
        t[col][row] += KoalaBear::ONE;
        assert!(!proves(t, &stmt), "⛔ {name} changed at row {row} and the table still proved");
    }
}
