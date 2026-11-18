// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! OLI — the Oblivious Locator Index: SUB-SECOND COLD RESTORE without sacrificing privacy, PQ, or
//! trustlessness. The novel composition that removes the wallet-side O(chain) detection walk:
//!
//! 1. **Address-carried one-time locators.** A receive address (v2) embeds a fresh 16-byte locator
//!    `L_j = PRF(loc_sk, j)` — recipient-ENUMERABLE from the seed alone. The sender shapes `L_j` into a
//!    detection-clue-sized blob (`tag_clue_bytes`) and attaches it through the EXISTING per-note clue
//!    channel — zero consensus change, byte-indistinguishable from a real packed-LWE clue (both uniform;
//!    a tag blob simply tests non-pertinent for everyone). Collisions are impossible (the recipient owns
//!    the counter); unlinkability holds because distinct PRF outputs are computationally independent.
//! 2. **A serving-tier index, constant 256 entries per block.** At DA-record time every slot of the fixed
//!    cover shape gets an index key `K = H(clue-bytes)` — real notes from their attached clue, cover/
//!    unclued slots from a SECRET-seeded synth key — so the index leaks no real-count metadata (shape is
//!    the constant 256 regardless of activity). Consensus state is untouched: the index is rebuildable
//!    serving-tier data beside the DA store, exactly the placement the O(1) research verdict assigns.
//! 3. **LWE PIR lookup (single-server, post-quantum, trustless).** A restoring wallet enumerates its
//!    locators and probes the index through real lattice PIR (SimplePIR-class: hint = D·A once per epoch,
//!    per-query the server computes D·u and learns NOTHING about which locator was probed — LWE-hiding),
//!    always in a CONSTANT-shape wave of `WAVE_QUERIES` queries (dummies pad), so even query COUNT leaks
//!    nothing. Soundness is self-verified: a matched entry only yields balance after the wallet fetches
//!    the block and the ML-KEM decap + `note_cm` binding accept — a lying or garbling server can cause a
//!    MISS and nothing more. Lane A (this index) and Lane B (the wallet's existing clue/decap completeness
//!    scan) are two explicit, separately-invoked lanes: each works or fails on its own terms, fail-closed.
//!
//! Result: restore = O(owned) client work + constant-shape queries at ANY chain height. The unavoidable
//! linear pass (the PIR answer loop) runs on the UNTRUSTED serving node at memory-bandwidth constants,
//! amortized per epoch, sharded across nodes — never on the wallet, never in consensus state. The lookup
//! layer is swappable for a doubly-efficient PIR (polylog server) as those constructions mature.

/// Locator byte WIDTH — rides inside the v2 address. PRODUCTION-SCALE-REVIEWED: a serialization width, not a cover/block count.
use crate::fixed::FixedBytes;
pub const LOC_BYTES: usize = 16;
/// Index-key byte WIDTH — `K = keyed-blake3(clue-bytes)`. PRODUCTION-SCALE-REVIEWED: a serialization width, not a cover/block count.
pub const K_BYTES: usize = 16;
/// One index entry: fingerprint(7) ‖ the record's FOLD ORDINAL u64 LE (NOT-AN-ADDRESS, DB-223 Q2 §11 (a)) ‖ slot u8. PRODUCTION-SCALE-REVIEWED: the packed byte layout width, not a cover/block count.
pub const ENTRY_BYTES: usize = 16;
/// Slots per bucket (2-choice hashing, offline-built per epoch).
pub const BUCKET_SLOTS: usize = 8;
/// One bucket = 8 entries × 16 B = 128 bytes = 128 PIR cells (one byte per cell).
pub const BUCKET_BYTES: usize = BUCKET_SLOTS * ENTRY_BYTES;
/// PIR matrix rows in ONE SHARD — one bucket per column. This is the single most important number in
/// the design: the hint a client downloads is `S_ROWS × N_LWE × 4` bytes, so pinning rows pins the hint
/// at 512 KB **forever**, no matter how large the chain grows. Growth is absorbed by adding SHARDS, never
/// by growing a shard.
pub const S_ROWS: usize = BUCKET_BYTES; // 128 — one bucket per column
/// Buckets stacked per matrix column.
pub const BUCKETS_PER_COL: usize = S_ROWS / BUCKET_BYTES; // 1
/// Columns (= buckets) in one shard. Fixed, so a shard's table is a constant 256 KB.
pub const SHARD_BUCKETS: u64 = 2048;
/// Entry slots in one shard: 2048 buckets × 8 = 16,384. Fixed forever.
pub const SHARD_CAPACITY: usize = (SHARD_BUCKETS as usize) * BUCKET_SLOTS;
/// DB-107: the most entries one locator key can occupy — its two cuckoo buckets. More than this on one key
/// can never be placed by splitting shards (identical keys never separate).
pub const MAX_PER_KEY: usize = 2 * BUCKET_SLOTS;
/// DB-107: how many extra shard splits a build may spend on an overflow before it serves what fits.
pub const MAX_EXTRA_SPLITS: u32 = 6;
/// Target load factor per shard. The global shard count is chosen to hold the index near this, so a
/// shard has headroom for the 2-choice placement and never overflows in normal growth.
pub const SHARD_LOAD: f64 = 0.70;
/// Shards a restore touches per wave — a CONSTANT, padded with decoys. The observable pattern is always
/// exactly this many shard fetches, so the wave reveals neither how many notes a wallet owns nor which
/// of the fetched shards were the real ones.
pub const WAVE_SHARDS: usize = 16;
/// LWE dimension (SimplePIR parameterization: n=1024, q=2^32, σ≈6.4 → ~128-bit PQ).
pub const N_LWE: usize = 1024;
/// Cell modulus p (each matrix cell is one byte of INDEX-key material — never a value; the index
/// holds only key fingerprints and block positions, all value stays committed elsewhere).
pub const P_CELL: u64 = 256;
/// Scaling Δ = q/p = 2^24.
pub const DELTA: u32 = 1 << 24;
/// Constant-shape probe wave: EVERY restore sends exactly this many queries (dummies pad), so the
/// query count itself carries zero information about how many locators a wallet owns.
pub const WAVE_QUERIES: usize = 32;
// ⛔ RETIRED 2026-07-27 — `GAP_LIMIT` is DELETED, not merely unused.
//
// It said "a cold restore stops enumerating after this many consecutive unused locators", and its own comment
// pre-empted review by calling itself a protocol parameter. It was a BIP-44 gap limit in a system that bans
// windows: hand out 30 subaddresses, have only the 26th pay you, and that payment was invisible forever —
// silent fund loss, wrong balance, no error. Widening it only postpones the loss.
//
// Retired by CONSTRUCTION, not by a bigger number: a v3 address carries the owner-minted `(salt, hint)`, so
// `owns_tag` recognises a payment at ANY subaddress index in one step, and the wallet's next free index comes
// from the notes it has actually been paid at. There is nothing left to enumerate and no bound to exceed.
// ([[project_oli_gap_limit_fund_loss]] · [[feedback_no_windows_no_caps_cardinal]])
/// Blocks per index epoch. The index is rebuilt on an epoch boundary, not per block: a rebuild is a
/// whole-index pass while blocks land about every second. A restoring wallet covers the bounded tail
/// past the last boundary with its ordinary delta scan.
/// PRODUCTION-SCALE-REVIEWED: an epoch cadence in blocks, not a cover/block count.
pub const EPOCH_BLOCKS: u64 = 64;

/// ⭐ THE SERVED INDEX COVERS EVERY SERVED RECORD — the ONE frontier every reader keys the served index on (the build, the
/// published frontier the routes read lock-free, `/oli_params`). User 2026-11-03: "The cash layer must be ironclad."
/// MEASURED 2026-11-03 on a real pair (lane cashfirst, usdmd_journey_nativesend_99676): the frontier was floored to the last
/// `EPOCH_BLOCKS` boundary, so the index built at boot (0 tags) stayed served for the chain's first 64 records and, after that,
/// a note recorded since the last boundary was in NO served table — the faucet credit was carried and folded (tip 40 → 88)
/// and the payer read 0 for the whole run; the wallet's tail walk had been deleted on the premise the floor was gone. A
/// note its owner cannot locate is a note its owner cannot spend.
/// Why this is not the 2026-08-10 growth: the build reads the node's held DA tag rows (`oli_klog_entries`, bounded by the
/// ladder span), never an ordinal walk, and runs OFF the runtime lock, one builder at a time (`rpc_http::oli_index`), while the
/// previous index keeps serving — one bounded rebuild per new record, no term in chain length.
#[must_use]
pub fn served_index_frontier(served_records: u64) -> u64 {
    served_records
}

// ---------------------------------------------------------------------------------------------------
// Tag derivation — wallet side (recipient enumerates; sender shapes; node only ever hashes bytes).
// ---------------------------------------------------------------------------------------------------

/// DERIVE the wallet's locator secret FROM its existing root entropy (seed→key derivation, domain-
/// separated — reproducible BY DESIGN so a seed-only restore re-derives it; the root entropy itself is
/// CSPRNG-minted once at wallet creation elsewhere). Never leaves the wallet.
pub fn derive_loc_sk(entropy: &[u8; 32]) -> [u8; 32] {
    *blake3::Hasher::new_derive_key("MUSD/oli/loc-sk/v1")
        .update(entropy)
        .finalize()
        .as_bytes()
}

/// The j-th one-time locator for `domain` ("recv" for handed-out addresses, "chg" for own change notes).
/// PRF outputs — computationally unlinkable without `loc_sk`; enumerable with it.
pub fn locator_at(loc_sk: &[u8; 32], domain: &str, j: u64) -> [u8; LOC_BYTES] {
    let mut h = blake3::Hasher::new_keyed(loc_sk);
    h.update(b"MUSD/oli/locator/v1/");
    h.update(domain.as_bytes());
    h.update(&j.to_le_bytes());
    let mut out = [0u8; LOC_BYTES];
    out.copy_from_slice(&h.finalize().as_bytes()[..LOC_BYTES]);
    out
}

/// Shape a locator into a detection-clue-sized blob for the existing per-note clue channel. A real
/// packed-LWE clue is (a: uniform ring elements, c: a·s+e+Δm) — uniform-looking bytes; this XOF stream is
/// uniform bytes of the SAME length, so the two are byte-indistinguishable to any observer, and a tag
/// blob simply decodes to garbage (non-pertinent) under every clue secret. Reproducible from `L`, so the
/// RECIPIENT can recompute the exact bytes (and therefore the index key) from its seed alone.
pub fn tag_clue_bytes(loc: &[u8; LOC_BYTES]) -> Vec<u8> {
    let len = crate::omr::Clue::BYTES;
    let mut h = blake3::Hasher::new_derive_key("MUSD/oli/tag-clue/v1");
    h.update(loc);
    let mut out = vec![0u8; len];
    h.finalize_xof().fill(&mut out);
    out
}

/// ⭐ THE OWNER-RECOVERABLE ADDRESS HINT — what makes INFINITE subaddresses work with NO gap limit.
///
/// user 2026-07-27: *"the user should be able to generate an infinite amount of subaddresses and they all
/// work and aggregate funds forever. There should be no 20 address limit as that can cause funds loss."*
///
/// ⛔ THE PROBLEM THIS SOLVES. `locator_at` is a pure PRF of the index `j`, so given a tag on the wire an
/// owner could only ask "is this mine?" by GUESSING `j` — try 0, 1, 2 … and stop somewhere. That "stop
/// somewhere" is `GAP_LIMIT`, and it is silent fund loss: hand out 30 addresses, have only the 26th pay you,
/// and the payment is invisible forever. Widening the guess is not a fix, it only postpones the loss.
///
/// ⭐ THE FIX. The OWNER — who alone holds `loc_sk` — mints a HINT when it creates the address:
/// `hint = j ⊕ PRF(loc_sk, L)`. The address carries `(L, hint)`; a payer just copies both, learning nothing
/// (`hint` is `j` masked by a PRF output it cannot compute). The owner recovers `j` from any tag in ONE
/// step, at ANY index, with no enumeration and no bound.
///
/// The fact is WRITTEN DOWN when it happens (address creation) and LOOKED UP later — the same shape that
/// retired every other window here. ([[feedback_no_windows_no_caps_cardinal]])
pub fn address_index_hint(loc_sk: &[u8; 32], salt: &[u8; 8], j: u64) -> [u8; 8] {
    let mut h = blake3::Hasher::new_keyed(loc_sk);
    h.update(b"MUSD/oli/addr-index-mask/v1");
    h.update(salt);
    let mask = h.finalize();
    let mut out = [0u8; 8];
    for (i, b) in out.iter_mut().enumerate() {
        *b = j.to_le_bytes()[i] ^ mask.as_bytes()[i];
    }
    out
}

/// The per-address SALT that makes each hint independent. Minted by the owner from its own secret and the
/// index, so two addresses never share one — a fixed mask would make consecutive hints differ by a constant
/// and let an observer subtract two addresses to read the wallet's ordering.
pub fn address_salt(loc_sk: &[u8; 32], domain: &str, j: u64) -> [u8; 8] {
    let mut h = blake3::Hasher::new_keyed(loc_sk);
    h.update(b"MUSD/oli/addr-salt/v1");
    h.update(domain.as_bytes());
    h.update(&j.to_le_bytes());
    let mut out = [0u8; 8];
    out.copy_from_slice(&h.finalize().as_bytes()[..8]);
    out
}

/// ⭐ THE SELF-IDENTIFYING TAG — `salt ‖ hint ‖ XOF(L)`, recognised by its owner in ONE step at ANY index.
///
/// The v1 tag was `XOF(L)` alone: one-way, so an owner could only ask "is this mine?" by GUESSING the
/// subaddress index. That guess is `GAP_LIMIT`, and it is silent fund loss — hand out 30 subaddresses, have
/// only the 26th pay you, and the payment is invisible forever.
///
/// The payer copies `salt` and `hint` straight out of the v2 address and learns nothing: `hint` is the index
/// masked by a PRF only the owner can compute, and `salt` is uniform. Every byte of the blob is uniform, so
/// it stays byte-indistinguishable from a real packed-LWE clue exactly as before.
pub fn tag_clue_bytes_v2(loc: &[u8; LOC_BYTES], salt: &[u8; 8], hint: &[u8; 8]) -> Vec<u8> {
    let len = crate::omr::Clue::BYTES;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(salt);
    out.extend_from_slice(hint);
    let body = tag_clue_bytes(loc);
    out.extend_from_slice(&body[..len - 16]);
    out
}

/// ⭐⭐⭐ DB-273 §17 — THE ONE DIGEST OF AN OBJECT'S OWNER CLUE, the value every attested or signed statement of an
/// owner-named class binds. The encoding is canonical (`domain ‖ len(u32 LE) ‖ clue`), so two spellings never share
/// one attestation. It is what makes a relay that strips or replaces the credit's owner fail the quorum tally, where
/// before the copy settled the note UNFILED for its owner (DB-351's class, on the object path).
/// cons: none — 32 B more in a signed message; no linkage is added, because the carrying block's `oli_tags` already
/// pair this note's commitment with this very clue (`cm ‖ len ‖ clue`), and each clue is a fresh uniform
/// `tag_clue_bytes_v2` for its own index.
#[must_use]
pub fn owner_clue_digest(clue: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/owner-clue/v1");
    h.update(&(clue.len() as u32).to_le_bytes());
    h.update(clue);
    *h.finalize().as_bytes()
}

/// Is this detection blob a tag for one of OUR subaddresses? `Some((domain, j))` at ANY index, in one step.
///
/// ⛔ NO ENUMERATION, NO BOUND. This is the whole point: index 0 and index 10^9 cost exactly the same, so a
/// wallet may hand out infinitely many subaddresses and every one of them keeps working forever.
/// user 2026-07-27: *"the user should be able to generate an infinite amount of subaddresses and they all
/// work and aggregate funds forever. There should be no 20 address limit as that can cause funds loss."*
///
/// It is a TEST, not a decoder: anyone's bytes unmask to SOME number, so ownership is the RE-DERIVATION —
/// rebuild the locator from the recovered index and require the blob's own body to match it. Without that a
/// stranger's note reads as ours and the scan stops being O(owned).
///
/// DIGITAL-CASH-PRIVACY-REVIEWED: computed entirely LOCALLY from the wallet's own secret — it asks the
/// network nothing, so there is no which-item query and no observer learns that a test happened.
pub fn owns_tag(loc_sk: &[u8; 32], domains: &[&str], blob: &[u8]) -> Option<(String, u64)> {
    let len = crate::omr::Clue::BYTES;
    if blob.len() != len || len < 16 {
        return None;
    }
    let mut salt = [0u8; 8];
    salt.copy_from_slice(&blob[..8]);
    let mut hint = [0u8; 8];
    hint.copy_from_slice(&blob[8..16]);

    let mut h = blake3::Hasher::new_keyed(loc_sk);
    h.update(b"MUSD/oli/addr-index-mask/v1");
    h.update(&salt);
    let mask = h.finalize();
    let mut jb = [0u8; 8];
    for (i, b) in jb.iter_mut().enumerate() {
        *b = hint[i] ^ mask.as_bytes()[i];
    }
    let j = u64::from_le_bytes(jb);

    for d in domains {
        // The re-derivation IS the ownership proof — both the locator and the salt must be the ones this
        // wallet would have minted for index `j`.
        if address_salt(loc_sk, d, j) != salt {
            continue;
        }
        let loc = locator_at(loc_sk, d, j);
        if tag_clue_bytes(&loc)[..len - 16] == blob[16..] {
            return Some(((*d).to_string(), j));
        }
    }
    None
}

/// The index key of a note, from its clue-channel bytes: `K = keyed-blake3(clue)`. The node computes this
/// uniformly for EVERY note (real clue, tag blob, or synth) — it cannot tell the kinds apart.
pub fn index_key(clue_bytes: &[u8]) -> [u8; K_BYTES] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/oli/index-key/v1");
    h.update(clue_bytes);
    let mut out = [0u8; K_BYTES];
    out.copy_from_slice(&h.finalize().as_bytes()[..K_BYTES]);
    out
}

/// The blake3 derive-key context of [`filing_d_bytes_from_keys`] — one spelling, read by the node and the wallet.
pub const FILING_D_CONTEXT: &str = "MUSD/spend/filing-D/v1";

/// ⭐⭐⭐ DB-351 — THE ONE DEFINITION OF A SPEND'S FILING DIGEST `D`, the public input its carrier binds.
///
/// A payment's locator clues rode outside the transaction's id AND its proof, so a relay could race a stripped or
/// rewritten copy and the note settled unfiled — after DB-273 (C) a seed-only restore would never find it
/// (docs/DB-351 §1–2). `D` puts the filing under the carrier's authority. It binds what the chain FILES — each
/// output's `(cm, k)` with `k = index_key(clue)`, the pair a block's `oli_tags` carries — so EVERY verifier recomputes
/// it from bytes it already holds: the pool door and the wallet from the clue list, the graft door from the block's
/// own `oli_tags`. Zero wire bytes (§3a).
///
/// Over the outputs in ASCENDING cm byte order (the DB-350 set order — derivable without knowing which is out0):
/// `rec(cm) = cm ‖ 0x00` when the spend carries no clue for `cm`, else `cm ‖ 0x01 ‖ k`; then
/// `blake3::derive_key(FILING_D_CONTEXT, u8(n) ‖ rec…)`. `k_of` answers each output's filed key. A repeated output
/// cm, or more outputs than a `u8` counts, is refused (`None`): one output, one record.
/// cons: none — one derive over ≤ n × 49 bytes per spend; nothing is stored.
#[must_use]
pub fn filing_d_bytes_from_keys(
    outputs: &[[u8; 32]],
    k_of: impl Fn(&[u8; 32]) -> Option<[u8; K_BYTES]>,
) -> Option<[u8; 32]> {
    let n = u8::try_from(outputs.len()).ok()?;
    let mut sorted = outputs.to_vec();
    sorted.sort_unstable();
    if sorted.windows(2).any(|w| w[0] == w[1]) {
        return None;
    }
    let mut h = blake3::Hasher::new_derive_key(FILING_D_CONTEXT);
    h.update(&[n]);
    for cm in &sorted {
        h.update(cm);
        match k_of(cm) {
            Some(k) => {
                h.update(&[1u8]);
                h.update(&k);
            }
            None => {
                h.update(&[0u8]);
            }
        }
    }
    Some(*h.finalize().as_bytes())
}

/// [`filing_d_bytes_from_keys`] from a clue list as a transaction carries it — the pool door's and the wallet's form.
#[must_use]
pub fn filing_d_bytes_from_clues(outputs: &[[u8; 32]], clues: &[([u8; 32], Vec<u8>)]) -> Option<[u8; 32]> {
    filing_d_bytes_from_keys(outputs, |cm| clues.iter().find(|(c, _)| c == cm).map(|(_, clue)| index_key(clue)))
}

/// `D` as the carrier absorbs it: 8 lanes. `hash32_to_digest`, because these bytes were never a digest — they are
/// HASHED in, never decoded (see its doc for why the two must not be swapped).
#[must_use]
pub fn filing_d_digest(d_bytes: &[u8; 32]) -> usdm_decider::poseidon2_compress::Digest {
    usdm_decider::poseidon2_compress::hash32_to_digest(d_bytes)
}

/// ⭐ DB-351 — a spend's clue list in its ONE encoding, or `None`. The list parses whole (DB-330's one reader), its
/// records run in STRICTLY ascending cm order (so none repeats), and every cm is one of the spend's own outputs.
/// Anything else is a second spelling of the same transaction: the door refuses the SPEND, it never files a
/// filtered subset of it (a filtered list is exactly the relay rewrite DB-351 closes). An empty list is canonical.
#[must_use]
pub fn canonical_clue_records(outputs: &[[u8; 32]], list: &[u8]) -> Option<Vec<([u8; 32], Vec<u8>)>> {
    let records = parse_note_clue_records(list)?;
    if records.windows(2).any(|w| w[0].0 >= w[1].0) {
        return None;
    }
    if records.iter().any(|(cm, _)| !outputs.contains(cm)) {
        return None;
    }
    Some(records)
}

/// The key a network's served index derives its epoch seed from — a CHAIN property, `blake3(domain ‖ genesis
/// id)`, identical on every node of one network and chosen by none of them (the node's `oli_chain_key` is this
/// function; a node with no genesis keys on the domain tag alone). ONE derivation for the node and anything
/// that checks it (the `/oli_table` route pin reproduces the served epoch seed from `/get_info`'s `chain_id`).
/// DIGITAL-CASH-PRIVACY-REVIEWED: a function of the genesis id, which `/get_info` already serves to every caller.
pub fn chain_key(genesis: Option<&[u8; 32]>) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/oli/chain-key/v1");
    if let Some(g) = genesis {
        h.update(g);
    }
    *h.finalize().as_bytes()
}

/// The epoch PIR seed a node serves in `/oli_params` — a pure function of [`chain_key`]. A wallet that
/// derives the chain key from the genesis id VERIFIES it against the served seed before trusting it: a
/// derivation that does not reproduce the seed is a wrong chain or a wrong formula, never a guess to keep.
pub fn epoch_seed(chain_key: &[u8; 32]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(b"MUSD/oli/epoch-seed/v1");
    h.update(chain_key);
    *h.finalize().as_bytes()
}

/// The two candidate bucket indices for a key (2-choice hashing; derived from the key bytes alone —
/// no secret input, so sender and recipient compute the same choices independently).
pub fn bucket_choices(k: &[u8; K_BYTES], buckets: u64) -> (u64, u64) {
    let d = blake3::Hasher::new_derive_key("MUSD/oli/bucket/v1")
        .update(k)
        .finalize();
    let b = d.as_bytes();
    let h1 = u64::from_le_bytes(b[0..8].fixed()) % buckets;
    let h2 = u64::from_le_bytes(b[8..16].fixed()) % buckets;
    (h1, h2)
}

/// ⭐ DB-235 — an index entry's FINGERPRINT, SALTED BY THE ENTRY'S OWN POSITION: the first 7 bytes of
/// `blake3_derive("MUSD/oli/entry-fp/v2", K ‖ ordinal ‖ slot)` — `ordinal` the record's FOLD ORDINAL (NOT-AN-ADDRESS).
///
/// ⛔ The fingerprint used to be `K[0..7]` — the key's own prefix. Every note paid to one locator (a reused
/// address, or change inheriting its input's locator) carries the SAME key, so every one of its entries carried
/// the SAME fingerprint, and anyone reading the table — bucket by bucket through `/oli_answer` with un-noised
/// queries, or whole through `/oli_table` — could cluster all payments to one address without knowing it: a
/// linkage leak in the one structure built to find notes privately. Salting with `(ordinal, slot)`, which the entry
/// already carries, makes two payments to one address carry unrelated fingerprints; only a holder of `K` (the
/// recipient) can recompute them. Same 7 bytes, same 2^-56 per-entry false-positive rate, same entry width.
/// cons: none — `ENTRY_BYTES` stays 16, tables and hints are unchanged in size; a lookup costs one blake3 per
/// occupied slot of its two buckets (<= 16) instead of a byte compare.
pub fn entry_fingerprint(k: &[u8; K_BYTES], ordinal: u64, slot: u8) -> [u8; 7] {
    let mut h = blake3::Hasher::new_derive_key("MUSD/oli/entry-fp/v2");
    h.update(k);
    h.update(&ordinal.to_le_bytes());
    h.update(&[slot]);
    let mut fp = [0u8; 7];
    fp.copy_from_slice(&h.finalize().as_bytes()[0..7]);
    fp
}

/// One index entry's packed bytes: `entry_fingerprint(K, ordinal, slot)` (7) ‖ the record's FOLD ORDINAL (8, LE) ‖
/// slot (1) = `ENTRY_BYTES`. NOT-AN-ADDRESS (DB-223 Q2 §11 (a)): the ordinal is fetched by `by_ordinal` and resolved
/// to its record address node-side; the two are never one number.
///
/// The field stays a WHOLE u64: when it carried the ~10^17 record address, a narrower field returned `addr mod 2^n`
/// and every located note named a record that does not exist (measured live 2026-08-12 as "`/note_copath` entry
/// carried no usable block_root_hex"). An ordinal needs fewer bits today, but it is the same u64 space forever.
pub fn pack_entry(k: &[u8; K_BYTES], ordinal: u64, slot: u8) -> [u8; ENTRY_BYTES] {
    let mut e = [0u8; ENTRY_BYTES];
    e[0..7].copy_from_slice(&entry_fingerprint(k, ordinal, slot));
    e[7..15].copy_from_slice(&ordinal.to_le_bytes());
    e[15] = slot;
    e
}

/// The `(ordinal, slot)` an entry names WHEN IT BELONGS TO KEY `k` — its salted fingerprint recomputed from `k` and
/// the entry's own position. `None` for an empty slot or another key's entry. The one matching rule every reader
/// uses (`probe_candidates`, `table_lookup`, the tests), so no reader can compare against a stale format.
pub fn entry_for_key(e: &[u8], k: &[u8; K_BYTES]) -> Option<(u64, u8)> {
    let (fp, ordinal, slot) = unpack_entry(e)?;
    (entry_fingerprint(k, ordinal, slot) == fp).then_some((ordinal, slot))
}

/// Parse an entry back to (fp, fold ordinal, slot); `None` for an all-zero (empty) slot.
pub fn unpack_entry(e: &[u8]) -> Option<([u8; 7], u64, u8)> {
    if e.len() < ENTRY_BYTES || e.iter().all(|&b| b == 0) {
        return None;
    }
    let mut fp = [0u8; 7];
    fp.copy_from_slice(&e[0..7]);
    let ordinal = u64::from_le_bytes(e[7..15].fixed());
    Some((fp, ordinal, e[15]))
}

// ---------------------------------------------------------------------------------------------------
// Bucketed table — built OFFLINE per epoch from the full entry list (2-choice + bounded random-walk
// eviction). Sizing loop: an attempt that cannot place every entry within the kick bound returns None,
// and the builder retries with a 5% larger table until placement succeeds — a standard cuckoo-hash
// capacity search that always terminates; every entry lands, fail-closed otherwise.
// ---------------------------------------------------------------------------------------------------

// ---------------------------------------------------------------------------------------------------
// SHARDING — how restore stays sub-second at ANY chain size, for ANY number of users.
//
// A shard is a FIXED-size PIR database (SHARD_BUCKETS buckets, S_ROWS rows, 256 KB table + 512 KB hint).
// The chain growing does not grow a shard; it grows the NUMBER of shards. A key's shard is the top
// `shard_bits` of its index key, so when the index outgrows its shards every shard SPLITS IN TWO and
// each entry stays in the half its next prefix bit already selected — no entry ever moves to an
// unrelated shard, and nothing is rebuilt from scratch (extendible hashing).
//
// A restore therefore costs `WAVE_SHARDS × (one constant-size shard)` — a constant, independent of N.
// Because the entries a wallet needs are spread across shards by an unpredictable PRF, and the wave is
// padded with decoys to exactly WAVE_SHARDS, the fetch pattern is a constant-shape set that reveals
// neither the wallet's note count nor which fetches were real.
//
// This is also what makes MILLIONS of concurrent restores work: one restore costs a serving node one
// pass over a 256 KB shard, and different shards live on different nodes — capacity scales by adding
// nodes, never by making any single node bigger.
// ---------------------------------------------------------------------------------------------------

/// The number of shard-selecting prefix bits for an index holding `total_entries`: the smallest `b` such
/// that the average shard sits at or below `SHARD_LOAD`. Grows by ONE bit per doubling of the chain.
pub fn shard_bits_for(total_entries: usize) -> u32 {
    let per_shard_target = (SHARD_CAPACITY as f64) * SHARD_LOAD;
    let mut bits = 0u32;
    while (total_entries as f64) / ((1u64 << bits) as f64) > per_shard_target && bits < 40 {
        bits += 1;
    }
    bits
}

/// The shard a key belongs to: its top `shard_bits`. Taking the TOP bits is what makes growth cheap —
/// adding a bit splits each shard into the two halves its entries already sort into.
pub fn shard_of(k: &[u8; K_BYTES], shard_bits: u32) -> u64 {
    if shard_bits == 0 {
        return 0;
    }
    let lead = u64::from_be_bytes(k[0..8].fixed());
    lead >> (64 - shard_bits)
}

/// Build ONE shard's fixed-size table from the entries that belong to it. Returns `None` if the shard
/// cannot hold them — the signal to raise `shard_bits` and split, never to grow the shard.
pub fn build_shard(entries: &[([u8; K_BYTES], u64, u8)]) -> Option<Vec<u8>> {
    if entries.len() > SHARD_CAPACITY {
        return None;
    }
    try_build(entries, SHARD_BUCKETS)
}

/// Group an entry list into its shards at `shard_bits` (serving-tier epoch build).
pub fn partition_shards(
    entries: &[([u8; K_BYTES], u64, u8)],
    shard_bits: u32,
) -> std::collections::HashMap<u64, Vec<([u8; K_BYTES], u64, u8)>> {
    let mut out: std::collections::HashMap<u64, Vec<([u8; K_BYTES], u64, u8)>> =
        std::collections::HashMap::new();
    for e in entries {
        out.entry(shard_of(&e.0, shard_bits)).or_default().push(*e);
    }
    out
}

/// The NEXT constant-shape wave of whole-shard fetches for one restore pass — the ONE wave builder
/// (`oli_client::ShardTables` fetches exactly what this returns).
///
/// What a serving node observes of a restore's lookup is the SET OF SHARDS it fetches, so the set must not be
/// a function of the wallet's keys alone:
///   * an index of `WAVE_SHARDS` shards or fewer is fetched WHOLE in the first wave — every wallet sends the
///     same request, and the pass never fetches again;
///   * a larger index is fetched in waves of exactly `min(WAVE_SHARDS, unheld)` NEW shards — the still-needed
///     ones first, then decoys drawn by a keyed PRF of `(wave_secret, wave_index, counter)` among the unheld —
///     in ascending order, so the wire order carries nothing about which were needed.
///
/// ⛔ DB-228 (2026-09-26) — THE DECOYS ARE REPRODUCIBLE, NEVER FRESH PER PASS. The builder this replaces
/// rotated its decoys per sync, arguing that cross-sync linkage was the transport's job. But the wallet's scan
/// re-runs the lookup EVERY pass over one connection, so passes are linkable, and a rotating pad leaves the
/// needed shards as the only thing that recurs: intersecting two passes hands the node the wallet's shards.
/// It is the same channel the batched note fetch had — MEASURED there, two passes shared the 8 reals and only
/// 2 of 56 cover positions. A pad keyed on `(secret, wave index)` reproduces pass after pass and gives
/// intersection nothing.
/// cons: none — at most `size × 64 + min(total, 4096)` keyed hashes per wave (a local termination bound far
/// above what a wave needs; collisions only matter once nearly every shard is held, and an index small enough
/// for that is fetched whole by the first branch).
pub fn wave_shards(
    missing: &[u64],
    is_held: &dyn Fn(u64) -> bool,
    held: u64,
    shard_bits: u32,
    wave_secret: &[u8; 32],
    wave_index: u64,
) -> Vec<u64> {
    let total = 1u64 << shard_bits.min(40); // `shard_bits_for` never exceeds 40
    if total <= WAVE_SHARDS as u64 {
        return (0..total).filter(|s| !is_held(*s)).collect();
    }
    let size = (WAVE_SHARDS as u64).min(total.saturating_sub(held)) as usize;
    let mut wave: Vec<u64> = Vec::with_capacity(size);
    for s in missing {
        if wave.len() == size {
            break;
        }
        if *s < total && !is_held(*s) && !wave.contains(s) {
            wave.push(*s);
        }
    }
    let mut ctr: u64 = 0;
    let bound = (size as u64).saturating_mul(64).saturating_add(total.min(4096));
    while wave.len() < size && ctr < bound {
        let mut h = blake3::Hasher::new_keyed(wave_secret);
        h.update(b"MUSD/oli-client/decoy-shard/v1");
        h.update(&wave_index.to_le_bytes());
        h.update(&ctr.to_le_bytes());
        let mut b8 = [0u8; 8];
        b8.copy_from_slice(&h.finalize().as_bytes()[0..8]);
        let d = u64::from_le_bytes(b8) % total;
        if !is_held(d) && !wave.contains(&d) {
            wave.push(d);
        }
        ctr += 1;
    }
    wave.sort_unstable();
    wave
}

fn try_build(entries: &[([u8; K_BYTES], u64, u8)], buckets: u64) -> Option<Vec<u8>> {
    let mut table = vec![0u8; (buckets as usize) * BUCKET_BYTES];
    let mut occ: Vec<u8> = vec![0; buckets as usize]; // used slots per bucket
    // ⭐ DB-235 — THE KEY OF WHATEVER OCCUPIES EACH TABLE SLOT, so an evicted victim's own two bucket choices
    // re-derive from its key directly.
    //
    // ⛔ This recovered a victim's key from its fingerprint through an fp→key map, and read the fingerprint back
    // as `u64::from_le_bytes(cur[0..8])` — the 7 fingerprint bytes PLUS the low byte of the entry's ordinal — while
    // the map was keyed with that byte zeroed. So 255 of every 256 evictions missed the map, the attempt returned
    // `None`, and the caller SPLIT the shard: every eviction-needing shard cost a split, the index ran at about
    // half its designed load (twice the shards a restore fetches), and past `MAX_EXTRA_SPLITS` the build served
    // "what fits" and DROPPED the rest — notes their owners could no longer locate. Salted fingerprints (DB-235)
    // also make an fp→key map impossible by design; holding each slot's key is the correct shape either way.
    // cons: none — `buckets × BUCKET_SLOTS × K_BYTES` = 2048 × 8 × 16 B = 256 KB of transient build state per
    // shard, freed with the build; nothing is served or retained.
    let mut slot_key: Vec<[u8; K_BYTES]> = vec![[0u8; K_BYTES]; (buckets as usize) * BUCKET_SLOTS];
    // Reproducible walk seed — the epoch build must be identical on every node that builds it.
    let walk = blake3::Hasher::new_derive_key("MUSD/oli/build-walk/v1")
        .update(&buckets.to_le_bytes())
        .finalize();
    let wb = walk.as_bytes();
    for (i, (k, ordinal, slot)) in entries.iter().enumerate() {
        let mut cur = pack_entry(k, *ordinal, *slot);
        let mut cur_k = *k;
        let (mut b1, mut b2) = bucket_choices(k, buckets);
        let mut kicks = 0usize;
        loop {
            // Place in whichever choice has room (fewer-occupied first).
            let (first, second) = if occ[b1 as usize] <= occ[b2 as usize] {
                (b1, b2)
            } else {
                (b2, b1)
            };
            let mut placed = false;
            for b in [first, second] {
                let o = occ[b as usize] as usize;
                if o < BUCKET_SLOTS {
                    let at = (b as usize) * BUCKET_SLOTS + o;
                    table[at * ENTRY_BYTES..(at + 1) * ENTRY_BYTES].copy_from_slice(&cur);
                    slot_key[at] = cur_k;
                    occ[b as usize] += 1;
                    placed = true;
                    break;
                }
            }
            if placed {
                break;
            }
            // Both full → evict a pseudo-random victim from `first` and re-place it by ITS OWN two choices,
            // re-derived from the key held for its slot. Kicks are bounded; exceeding the bound returns None so
            // the sizing loop grows capacity.
            kicks += 1;
            if kicks > 64 {
                return None;
            }
            let vslot = (wb[(i + kicks) % 32] as usize) % BUCKET_SLOTS;
            let at = (first as usize) * BUCKET_SLOTS + vslot;
            let mut victim = [0u8; ENTRY_BYTES];
            victim.copy_from_slice(&table[at * ENTRY_BYTES..(at + 1) * ENTRY_BYTES]);
            let victim_k = slot_key[at];
            table[at * ENTRY_BYTES..(at + 1) * ENTRY_BYTES].copy_from_slice(&cur);
            slot_key[at] = cur_k;
            cur = victim;
            cur_k = victim_k;
            let (n1, n2) = bucket_choices(&cur_k, buckets);
            b1 = n1;
            b2 = n2;
        }
    }
    Some(table)
}

/// Look a key up directly in table bytes (the node's own sanity path + tests; wallets use PIR).
pub fn table_lookup(table: &[u8], buckets: u64, k: &[u8; K_BYTES]) -> Option<(u64, u8)> {
    let (b1, b2) = bucket_choices(k, buckets);
    for b in [b1, b2] {
        let off = (b as usize) * BUCKET_BYTES;
        for s in 0..BUCKET_SLOTS {
            if let Some(pos) = entry_for_key(&table[off + s * ENTRY_BYTES..off + (s + 1) * ENTRY_BYTES], k) {
                return Some(pos);
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------------------------------
// LWE PIR (SimplePIR-class): hint = D·A per epoch; query u = A·s + e + Δ·unit(col); ans = D·u.
// Post-quantum (plain LWE), single-server, trustless: the server learns NOTHING about the target
// column (LWE-hiding), and a wrong answer can only cause a self-verified miss, never a false accept.
// The matrix layout is column-major: column c = buckets [c·32, c·32+32), 4096 byte-cells tall.
// ---------------------------------------------------------------------------------------------------

/// Expand the A matrix row for column `c` (n u32s) from the epoch seed — common randomness every party
/// re-derives identically (standard PIR practice; it carries no trapdoor and no wallet data; the hiding
/// lives entirely in each query's fresh LWE secret + error).
fn a_row(epoch_seed: &[u8; 32], c: usize, out: &mut [u32; N_LWE]) {
    let mut h = blake3::Hasher::new_keyed(epoch_seed);
    h.update(b"MUSD/oli/A/v1");
    h.update(&(c as u64).to_le_bytes());
    let mut buf = [0u8; N_LWE * 4];
    h.finalize_xof().fill(&mut buf);
    for (i, w) in out.iter_mut().enumerate() {
        *w = u32::from_le_bytes(buf[i * 4..i * 4 + 4].fixed());
    }
}

/// Centered-binomial error sample with σ≈6.4 (η=82 → variance 41): Σ(a_i − b_i) over 82 coin pairs.
fn cbd_err(stream: &mut blake3::OutputReader) -> u32 {
    let mut bytes = [0u8; 21]; // 168 bits ≥ 164 needed
    stream.fill(&mut bytes);
    let mut acc: i32 = 0;
    let mut pairs = 0usize;
    'outer: for byte in bytes {
        for k in 0..4 {
            let a = (byte >> (2 * k)) & 1;
            let b = (byte >> (2 * k + 1)) & 1;
            acc += a as i32 - b as i32;
            pairs += 1;
            if pairs >= 82 {
                break 'outer;
            }
        }
    }
    acc as u32 // two's-complement wrap into Z_{2^32}
}

/// Worker-thread count for the serving-tier linear passes — bounded by available parallelism, capped so
/// a serving node never oversubscribes. One thread on a single core (the loops are correct either way).
fn worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, 16)
}

/// Server: build the per-epoch hint H = D·A (S_ROWS × N_LWE u32, LE bytes). Parallelized over columns
/// with `std::thread::scope` (each worker accumulates a private partial, folded at the end) — no external
/// dependency, and the fold is order-independent (integer add), so the hint is bitwise-identical to a
/// single-threaded build on every node.
pub fn build_hint(table: &[u8], buckets: u64, epoch_seed: &[u8; 32]) -> Vec<u8> {
    let t_cols = (buckets as usize) / BUCKETS_PER_COL;
    let hint = hint_words_for_columns(table, 0, t_cols, epoch_seed);
    let mut out = Vec::with_capacity(hint.len() * 4);
    for w in hint {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

/// ⭐ DB-223 Q2 §12d — THE ONE HINT LOOP, over the column range `[c0, c1)` of a column-major `S_ROWS`-row table, with
/// each column's A row taken at its ABSOLUTE index. A hint is `D·A`, a sum over columns, so the hint of a table that
/// grew from `c0` to `c1` columns is the old hint plus this range: the window index extends a cached hint one appended
/// column at a time instead of rebuilding it. `build_hint` is this over `[0, t_cols)`, so the OLI door's hint is
/// byte-identical to before. `S_ROWS × N_LWE` words; a table too short for `c1` columns yields the zero hint.
pub fn hint_words_for_columns(table: &[u8], c0: usize, c1: usize, epoch_seed: &[u8; 32]) -> Vec<u32> {
    let mut hint = vec![0u32; S_ROWS * N_LWE];
    if c1 <= c0 || table.len() < c1 * S_ROWS {
        return hint;
    }
    let span = c1 - c0;
    let nthreads = worker_threads().min(span.max(1));
    std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(nthreads);
        // one worker's stripe: columns tid, tid+nthreads, … (static stride assignment)
        let stripe = |tid: usize| {
            let mut acc = vec![0u32; S_ROWS * N_LWE];
            let mut arow = [0u32; N_LWE];
            // Static stride assignment: this worker owns columns c0+tid, c0+tid+nthreads, ….
            let mut c = c0 + tid;
            while c < c1 {
                a_row(epoch_seed, c, &mut arow);
                let col_base = c * S_ROWS; // byte offset of this column's cells
                for r in 0..S_ROWS {
                    let d = table[col_base + r] as u32;
                    if d == 0 {
                        continue;
                    }
                    let dst = &mut acc[r * N_LWE..(r + 1) * N_LWE];
                    for k in 0..N_LWE {
                        dst[k] = dst[k].wrapping_add(d.wrapping_mul(arow[k]));
                    }
                }
                c += nthreads;
            }
            acc
        };
        for tid in 0..nthreads {
            handles.push((tid, scope.spawn(move || stripe(tid))));
        }
        // a worker that panicked has its stripe computed inline: the same integer arithmetic, the same hint
        for (tid, h) in handles {
            let partial = crate::fixed::join_or_else(h, "oli hint worker", || stripe(tid));
            for (dst, v) in hint.iter_mut().zip(partial) {
                *dst = dst.wrapping_add(v);
            }
        }
    });
    hint
}

/// Expand the epoch's ENTIRE A matrix once (t_cols × N_LWE u32, row-major by column). A is fixed for
/// the whole epoch, so a client that caches this pays the PRF expansion ONCE and every later query is
/// pure arithmetic — the difference between a per-query cost that re-hashes megabytes and one that does
/// not. Measured: re-expanding per query dominated the client cost; this removes it.
pub fn expand_a(epoch_seed: &[u8; 32], t_cols: usize) -> Vec<u32> {
    let mut a = vec![0u32; t_cols * N_LWE];
    let nthreads = worker_threads().min(t_cols.max(1));
    let rows_per = t_cols.div_ceil(nthreads);
    std::thread::scope(|scope| {
        for (wi, chunk) in a.chunks_mut(rows_per * N_LWE).enumerate() {
            scope.spawn(move || {
                let c0 = wi * rows_per;
                let mut arow = [0u32; N_LWE];
                for (i, dst) in chunk.chunks_mut(N_LWE).enumerate() {
                    a_row(epoch_seed, c0 + i, &mut arow);
                    dst.copy_from_slice(&arow);
                }
            });
        }
    });
    a
}

/// Client: build one PIR query for `target_col` against a PRE-EXPANDED epoch A (see [`expand_a`]).
/// Returns (query u bytes t×4, secret s bytes n×4). The per-query LWE secret + error expand from
/// `rand32` — the CALLER supplies fresh CSPRNG bytes per query.
pub fn build_query_with_a(
    a: &[u32],
    target_col: usize,
    rand32: &[u8; 32],
) -> Option<(Vec<u8>, Vec<u8>)> {
    if a.len() % N_LWE != 0 {
        return None;
    }
    let t_cols = a.len() / N_LWE;
    let mut sh = blake3::Hasher::new_keyed(rand32);
    sh.update(b"MUSD/oli/secret/v1");
    let mut sbytes = vec![0u8; N_LWE * 4];
    sh.finalize_xof().fill(&mut sbytes);
    let s: Vec<u32> = sbytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.fixed()))
        .collect();
    let mut eh = blake3::Hasher::new_keyed(rand32);
    eh.update(b"MUSD/oli/err/v1");
    let mut estream = eh.finalize_xof();
    let mut ub = Vec::with_capacity(t_cols * 4);
    for c in 0..t_cols {
        let arow = &a[c * N_LWE..(c + 1) * N_LWE];
        let mut acc: u32 = 0;
        for k in 0..N_LWE {
            acc = acc.wrapping_add(arow[k].wrapping_mul(s[k]));
        }
        acc = acc.wrapping_add(cbd_err(&mut estream));
        if c == target_col {
            acc = acc.wrapping_add(DELTA);
        }
        ub.extend_from_slice(&acc.to_le_bytes());
    }
    Some((ub, sbytes))
}

/// Client: build one PIR query for `target_col`, expanding A inline. Equivalent to
/// `expand_a` + [`build_query_with_a`]; a client issuing more than one query per epoch should cache A
/// with [`expand_a`] instead. Returns (query u bytes t×4, secret s bytes n×4).
pub fn build_query(
    t_cols: usize,
    epoch_seed: &[u8; 32],
    target_col: usize,
    rand32: &[u8; 32],
) -> (Vec<u8>, Vec<u8>) {
    // Secret s ∈ Z_q^n expanded from the caller's fresh randomness.
    let mut sh = blake3::Hasher::new_keyed(rand32);
    sh.update(b"MUSD/oli/secret/v1");
    let mut sbytes = vec![0u8; N_LWE * 4];
    sh.finalize_xof().fill(&mut sbytes);
    let s: Vec<u32> = sbytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.fixed()))
        .collect();
    // Error stream (independent domain).
    let mut eh = blake3::Hasher::new_keyed(rand32);
    eh.update(b"MUSD/oli/err/v1");
    let mut estream = eh.finalize_xof();
    // u[c] = A_c·s + e_c (+ Δ at the target column).
    let mut u = vec![0u32; t_cols];
    let mut arow = [0u32; N_LWE];
    for (c, uc) in u.iter_mut().enumerate() {
        a_row(epoch_seed, c, &mut arow);
        let mut acc: u32 = 0;
        for k in 0..N_LWE {
            acc = acc.wrapping_add(arow[k].wrapping_mul(s[k]));
        }
        acc = acc.wrapping_add(cbd_err(&mut estream));
        if c == target_col {
            acc = acc.wrapping_add(DELTA);
        }
        *uc = acc;
    }
    let mut ub = Vec::with_capacity(t_cols * 4);
    for w in u {
        ub.extend_from_slice(&w.to_le_bytes());
    }
    (ub, sbytes)
}

/// Server core: answer a WHOLE BATCH of queries in ONE pass over the table. `queries` are the parsed
/// `u` vectors (each `t_cols` long); the result is one `S_ROWS` answer vector per query.
///
/// Two things make this the fast path, and both are load-bearing:
/// 1. **Column-major traversal.** Each column's `S_ROWS` cells are CONTIGUOUS, so the inner loop walks
///    memory linearly and every cache line is fully used. The natural-looking row-major form
///    (`table[c * S_ROWS + r]` in the inner loop) strides `S_ROWS` bytes per access and misses cache on
///    every load — measured at 787 MB/s, an order of magnitude off what the hardware can do.
/// 2. **Batching.** A column is loaded ONCE and multiplied into every query's accumulator, so the memory
///    traffic of a scan is amortized across the entire locator wave instead of being paid per query.
///    A restore's whole wave therefore costs about ONE table pass, not `WAVE_QUERIES` passes.
///
/// Each worker owns a stripe of columns and a private accumulator (`S_ROWS × queries`, a few tens of KB —
/// L2-resident); the partials fold with wrapping adds, which are associative, so the result is bitwise
/// identical to a single-threaded pass.
pub fn answer_columns(table: &[u8], t_cols: usize, queries: &[Vec<u32>]) -> Option<Vec<Vec<u32>>> {
    let k = queries.len();
    if k == 0 || queries.iter().any(|q| q.len() != t_cols) || table.len() < t_cols * S_ROWS {
        return None;
    }
    let nthreads = worker_threads().min(t_cols.max(1));
    let partials: Vec<Vec<u32>> = std::thread::scope(|scope| {
        let mut handles = Vec::with_capacity(nthreads);
        // one worker's stripe: columns tid, tid+nthreads, … (static stride assignment)
        let stripe = |tid: usize| {
            let mut acc = vec![0u32; S_ROWS * k];
            let mut c = tid;
            while c < t_cols {
                let col = &table[c * S_ROWS..(c + 1) * S_ROWS];
                for (j, q) in queries.iter().enumerate() {
                    let uc = q[c];
                    if uc == 0 {
                        continue;
                    }
                    let dst = &mut acc[j * S_ROWS..(j + 1) * S_ROWS];
                    for (a, d) in dst.iter_mut().zip(col.iter()) {
                        *a = a.wrapping_add((*d as u32).wrapping_mul(uc));
                    }
                }
                c += nthreads;
            }
            acc
        };
        for tid in 0..nthreads {
            handles.push((tid, scope.spawn(move || stripe(tid))));
        }
        handles
            .into_iter()
            // a worker that panicked has its stripe computed inline: the same integer arithmetic, the same answer
            .map(|(tid, h)| crate::fixed::join_or_else(h, "oli answer worker", || stripe(tid)))
            .collect()
    });
    let mut merged = vec![0u32; S_ROWS * k];
    for p in partials {
        for (dst, v) in merged.iter_mut().zip(p) {
            *dst = dst.wrapping_add(v);
        }
    }
    Some(merged.chunks(S_ROWS).map(|c| c.to_vec()).collect())
}

/// Server: answer a batch of serialized queries in ONE table pass — the shape a restore actually uses
/// (a constant-size wave of `WAVE_QUERIES`). Returns one serialized answer per query, in order.
pub fn answer_batch(table: &[u8], buckets: u64, queries: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
    let t_cols = (buckets as usize) / BUCKETS_PER_COL;
    let mut parsed = Vec::with_capacity(queries.len());
    for q in queries {
        if q.len() != t_cols * 4 {
            return None;
        }
        parsed.push(
            q.chunks_exact(4)
                .map(|c| u32::from_le_bytes(c.fixed()))
                .collect::<Vec<u32>>(),
        );
    }
    let answers = answer_columns(table, t_cols, &parsed)?;
    Some(
        answers
            .into_iter()
            .map(|a| {
                let mut out = Vec::with_capacity(S_ROWS * 4);
                for w in a {
                    out.extend_from_slice(&w.to_le_bytes());
                }
                out
            })
            .collect(),
    )
}

/// Server: answer = D·u (S_ROWS u32, LE bytes). One linear pass over the table at memory bandwidth —
/// the unavoidable linear cost, placed on the UNTRUSTED serving node exactly as the research verdict
/// assigns, and blind: `u` is LWE-hiding, so the pass reveals nothing about the target column.
pub fn answer_query(table: &[u8], buckets: u64, u_bytes: &[u8]) -> Option<Vec<u8>> {
    let t_cols = (buckets as usize) / BUCKETS_PER_COL;
    if u_bytes.len() != t_cols * 4 {
        return None;
    }
    let u: Vec<u32> = u_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.fixed()))
        .collect();
    let ans = answer_columns(table, t_cols, &[u])?.pop()?;
    let mut out = Vec::with_capacity(S_ROWS * 4);
    for w in ans {
        out.extend_from_slice(&w.to_le_bytes());
    }
    Some(out)
}

/// Client: recover one bucket's 128 bytes from an answer + the hint rows + the query secret.
/// `bucket_in_col` = which of the 32 stacked buckets in the queried column.
pub fn recover_bucket(
    ans_bytes: &[u8],
    hint_bytes: &[u8],
    s_bytes: &[u8],
    bucket_in_col: usize,
) -> Option<[u8; BUCKET_BYTES]> {
    if ans_bytes.len() != S_ROWS * 4
        || hint_bytes.len() != S_ROWS * N_LWE * 4
        || s_bytes.len() != N_LWE * 4
    {
        return None;
    }
    let s: Vec<u32> = s_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.fixed()))
        .collect();
    let mut out = [0u8; BUCKET_BYTES];
    let row0 = bucket_in_col * BUCKET_BYTES;
    for i in 0..BUCKET_BYTES {
        let r = row0 + i;
        let a = u32::from_le_bytes(ans_bytes[r * 4..r * 4 + 4].fixed());
        // hint[r]·s
        let hrow = &hint_bytes[r * N_LWE * 4..(r + 1) * N_LWE * 4];
        let mut hs: u32 = 0;
        for k in 0..N_LWE {
            let h = u32::from_le_bytes(hrow[k * 4..k * 4 + 4].fixed());
            hs = hs.wrapping_add(h.wrapping_mul(s[k]));
        }
        let noisy = a.wrapping_sub(hs); // = Σ D·e + Δ·D[r][target]
        let val = ((noisy.wrapping_add(DELTA / 2)) >> 24) as u64 % P_CELL; // round to nearest Δ multiple
        out[i] = val as u8;
    }
    Some(out)
}

/// The (column, bucket-within-column) coordinates of a key's TWO candidate buckets. A 2-choice lookup
/// is defined over both, so one locator always costs exactly two PIR queries — a constant shape that
/// reveals nothing about where (or whether) the key landed.
pub fn query_coords(k: &[u8; K_BYTES], buckets: u64) -> [(usize, usize); 2] {
    let (b1, b2) = bucket_choices(k, buckets);
    [
        (
            (b1 as usize) / BUCKETS_PER_COL,
            (b1 as usize) % BUCKETS_PER_COL,
        ),
        (
            (b2 as usize) / BUCKETS_PER_COL,
            (b2 as usize) % BUCKETS_PER_COL,
        ),
    ]
}

/// Client: the COMPLETE 2-choice lookup over a key's two recovered candidate buckets — EVERY entry
/// matching the key, from both buckets, in bucket then slot order.
///
/// All matches, not the first: a receive address hands out ONE locator, so if its owner reuses that
/// address every note paid to it shares an index key and lands in the same two buckets. Returning only
/// the first would make every payment after the first invisible at restore — the owner's money would sit
/// on-chain, unspendable and unseen. Two 8-slot buckets hold up to 16 such notes; beyond that the owner
/// must rotate to the next address, which is the normal one-address-per-payer practice anyway.
///
/// A key that is absent — or an answer a server garbled — yields an EMPTY list: a miss, never a forged hit.
pub fn probe_candidates(
    bucket_a: &[u8; BUCKET_BYTES],
    bucket_b: &[u8; BUCKET_BYTES],
    k: &[u8; K_BYTES],
) -> Vec<(u64, u8)> {
    let mut out = Vec::new();
    for bucket in [bucket_a, bucket_b] {
        for s in 0..BUCKET_SLOTS {
            if let Some(pos) = entry_for_key(&bucket[s * ENTRY_BYTES..(s + 1) * ENTRY_BYTES], k) {
                if !out.contains(&pos) {
                    out.push(pos);
                }
            }
        }
    }
    out
}

/// One bucket of a WHOLE shard table (`SHARD_BUCKETS` buckets of `BUCKET_BYTES`, the layout `try_build`
/// writes and `Index::shard_table` serves). `None` for a bucket index outside the table — never a
/// zero-filled stand-in, which would read as "no entry here" instead of "not a bucket of this table".
pub fn table_bucket(table: &[u8], b: u64) -> Option<[u8; BUCKET_BYTES]> {
    let off = usize::try_from(b).ok()?.checked_mul(BUCKET_BYTES)?;
    let s = table.get(off..off.checked_add(BUCKET_BYTES)?)?;
    let mut out = [0u8; BUCKET_BYTES];
    out.copy_from_slice(s);
    Some(out)
}

/// ⭐ DB-228 — the 2-choice lookup over a WHOLE shard table: the key's two candidate buckets sliced
/// straight out of the table and handed to the SAME [`probe_candidates`] the PIR path decodes into.
///
/// Holding the whole table is TRIVIAL PIR — the server learns which SHARD was fetched (exactly what the
/// LWE path's per-shard hint request already told it) and nothing about which bucket was read, and that
/// hiding is information-theoretic rather than computational. It is also the cheaper shape at this shard
/// size: the table is `SHARD_BUCKETS × BUCKET_BYTES` = 256 KB while the LWE hint alone is `S_ROWS × N_LWE ×
/// 4` = 512 KB, before a single 8 KB query is sent. Matching is byte-identical to the PIR path (same buckets,
/// same fingerprint test, every match returned), so what a wallet locates cannot differ between the two.
pub fn table_candidates(table: &[u8], k: &[u8; K_BYTES]) -> Vec<(u64, u8)> {
    let (b1, b2) = bucket_choices(k, SHARD_BUCKETS);
    match (table_bucket(table, b1), table_bucket(table, b2)) {
        (Some(a), Some(b)) => probe_candidates(&a, &b, k),
        _ => Vec::new(),
    }
}

/// ⭐ DB-228/DB-235 — the position of every entry in a shard table. Every entry is a real tagged note (the index
/// carries no chaff — DB-235), so this is the universe a restoring wallet draws its fetch cover from: the
/// universe its own real positions come from, named by record ADDRESS and true slot. Cover drawn anywhere else is
/// separable by the serving node, which knows every record's real slots and which records are idle (the wallet
/// pin `a_batched_note_fetch_hides_its_reals_in_one_coordinate_space_and_one_distribution`).
/// cons: none — one pass over a 256 KB table the caller already holds; nothing is retained here.
pub fn table_positions(table: &[u8]) -> Vec<(u64, u8)> {
    table
        .chunks_exact(ENTRY_BYTES)
        .filter_map(|e| unpack_entry(e).map(|(_, ordinal, slot)| (ordinal, slot)))
        .collect()
}

// ---------------------------------------------------------------------------------------------------
// Serving-tier persistence: an append-only K-log of REAL (clue-bearing) entries beside the DA store.
// Idle blocks append NOTHING (their synth entries regenerate from the secret at build time), so disk
// growth tracks real activity exactly like the DA shard itself. Rebuildable at any time; never consensus.
// ---------------------------------------------------------------------------------------------------

/// The FULL per-epoch entry list: exactly one entry per tagged real note in the klog, at its own
/// `(fold ordinal, slot)` (NOT-AN-ADDRESS, DB-223 Q2 §11 (a)), in canonical `(ordinal, slot)` order — nothing else.
///
/// ⛔ DB-235 — THE CHAFF IS DELETED. One chaff entry per real entry was keyed on the PUBLIC chain key, so any
/// reader recomputed and subtracted it: it hid nothing, doubled every table (so every shard a restore fetches),
/// and named slots that can be regenerated fill units — cover a wallet must never ask for. The index's count
/// still tracks the tagged notes it holds, exactly as before (the chaff was a constant multiple of them).
/// ⭐ ORDER: the entries are sorted, because cuckoo placement depends on insertion order; the klog arrived in
/// hash-map order, so two nodes indexing the same tags built differently-placed tables. Sorted, every node that
/// indexes the same tags serves byte-identical tables.
/// cons: none — O(tags log tags) per epoch build, off the lock, against the 2x-entries build it replaces.
pub fn epoch_entries(klog: &[(u64, u8, [u8; K_BYTES])]) -> Vec<([u8; K_BYTES], u64, u8)> {
    let mut out: Vec<([u8; K_BYTES], u64, u8)> = klog.iter().map(|(ordinal, slot, k)| (*k, *ordinal, *slot)).collect();
    out.sort_unstable_by(|a, b| (a.1, a.2, a.0).cmp(&(b.1, b.2, b.0)));
    out.dedup_by(|a, b| a.1 == b.1 && a.2 == b.2);
    out
}

// ---------------------------------------------------------------------------------------------------
// The served index — what a node holds and answers restores from.
// ---------------------------------------------------------------------------------------------------

/// One epoch's sharded locator index: a fixed-size table per shard plus the shard-bit width. Hints are
/// derived on demand (and cached by callers) because a hint is a pure function of a shard's table.
pub struct Index {
    /// Shard id → that shard's fixed-size table bytes. A shard absent from the map is EMPTY, and an
    /// empty shard still answers (as an all-zero table) so a probe of it is indistinguishable from a
    /// probe of a full one.
    pub shards: std::collections::HashMap<u64, Vec<u8>>,
    /// Prefix bits selecting a shard. A wallet needs this to know where its locators live.
    pub shard_bits: u32,
    /// The epoch's shared PIR randomness seed (A expansion).
    pub epoch_seed: [u8; 32],
}

impl Index {
    /// Build the whole epoch index: every block in `start_seq..end_seq` contributes its constant
    /// `notes_per_block` slots, partitioned into constant-size shards. If any shard overflows, the
    /// shard-bit width is raised and the partition retried — the split that keeps shards constant-size
    /// as the chain grows.
    pub fn build(
        klog: &[(u64, u8, [u8; K_BYTES])],
        da_secret: &[u8; 32],
        start_seq: u64,
        end_seq: u64,
        notes_per_block: usize,
        epoch_seed: [u8; 32],
    ) -> Index {
        // ⭐⭐⭐ P5 — HOLD ONE COPY OF THE EPOCH, AND NEVER RE-COPY IT PER SPLIT.
        //
        // The flat entry list used to stay ALIVE for the whole overflow loop, because `partition_shards`
        // BORROWED it on every iteration and copied every element into fresh per-shard vectors. So a build
        // that split k times materialized the epoch k+1 times, with the flat list, the buckets and the packed
        // shard tables all resident together at the peak. Serving-tier allocation executed on demand from an
        // RPC is the family that killed both nodes in the 2026-08-12 audit §1.1 (`rust_oom` in
        // `oli::epoch_entries → Index::build → oli_build_index_upto → rpc_http::oli_index`).
        //
        // ⚠️ SCOPE, STATED HONESTLY: the CHAIN-SIZED instance of that OOM is already gone, and this is not
        // what fixes it. `epoch_entries` no longer spans the sparse address range (the 6.9-exabyte
        // allocation), and the chaff width the node passes is 1, not the retired 256 — so the epoch is
        // O(REAL TAGS) either way. What this removes is the constant MULTIPLIER on top of that honest size.
        //
        // Partition ONCE, release the flat list before any table is packed, and re-split from the BUCKETS we
        // already hold rather than from a retained source. Placement is unchanged — the same `shard_of` over
        // the same key — so the served tables stay byte-identical.
        // ⛔ DB-235: `da_secret`, `start_seq`, `end_seq` and `notes_per_block` only ever sized and keyed the
        // deleted chaff. They stay in the signature solely until the two call sites (node.rs
        // `oli_build_index_upto`, rpc_http.rs `oli_index` — the consensus/RPC lanes' files) drop them in one edit.
        let _ = (da_secret, start_seq, end_seq, notes_per_block);
        let mut entries = epoch_entries(klog);
        // DB-107 (run 102l, 2026-09-19): ONE KEY CAN OCCUPY AT MOST ITS TWO BUCKETS. Every note paid to the
        // same address carries the same locator key, and the cuckoo table gives a key two buckets of
        // BUCKET_SLOTS — sixteen entries. The seventeenth kicked for 64 rounds, `try_build` refused the
        // shard, and the retry below split EVERY shard and tried again — identical keys never separate, so
        // the loop ran forever, doubling the table count each round (calloc + mmap were 95% of a stack
        // sample; the runtime lock was held throughout, so every RPC and the tick stalled: "tip has not
        // moved", INBOUND SILENCE, the pair forked). MEASURED: the burst pays one buyer from sixteen wallets
        // — 16 + the earlier payment + the mint = 18 entries on one key; the node hung on the first epoch
        // after the burst in runs 102j, 102k and 102l. A key keeps its NEWEST MAX_PER_KEY entries here;
        // the rest stay findable by the applied-notes trial decapsulation (DB-88) and the bucket lane — the
        // index is an accelerator, never the only door. The split loop is bounded below as well.
        {
            use std::collections::HashMap;
            let mut per_key: HashMap<[u8; K_BYTES], usize> = HashMap::new();
            for e in &entries {
                *per_key.entry(e.0).or_insert(0) += 1;
            }
            if per_key.values().any(|n| *n > MAX_PER_KEY) {
                // newest first per key: sort by (key, fold ordinal desc — a later fold is a newer note) and keep the
                // first MAX_PER_KEY of each key
                entries.sort_by(|a, b| a.0.cmp(&b.0).then(b.1.cmp(&a.1)).then(b.2.cmp(&a.2)));
                let mut kept: Vec<([u8; K_BYTES], u64, u8)> = Vec::with_capacity(entries.len());
                let mut run_key: Option<[u8; K_BYTES]> = None;
                let mut run_n = 0usize;
                let mut dropped = 0usize;
                for e in entries.into_iter() {
                    if run_key != Some(e.0) {
                        run_key = Some(e.0);
                        run_n = 0;
                    }
                    run_n += 1;
                    if run_n <= MAX_PER_KEY {
                        kept.push(e);
                    } else {
                        dropped += 1;
                    }
                }
                eprintln!(
                    "[oli-build] {dropped} entr(ies) beyond MAX_PER_KEY={MAX_PER_KEY} on one locator key left the \
                     index (the newest stay) — an address paid more than {MAX_PER_KEY} times is found by the \
                     applied-notes scan, never by this table alone (DB-107)"
                );
                entries = kept;
            }
        }
        let mut shard_bits = shard_bits_for(entries.len());
        let mut parts = partition_shards(&entries, shard_bits);
        drop(entries); // the flat copy is dead the moment it is bucketed — never held beside the tables
        let mut splits = 0u32;
        loop {
            let mut entries_len = 0usize;
            for (_sid, es) in &parts {
                entries_len += es.len();
            }
            let mut shards = std::collections::HashMap::with_capacity(parts.len());
            let mut overflowed = false;
            for (sid, es) in &parts {
                match build_shard(es) {
                    Some(t) => {
                        shards.insert(*sid, t);
                    }
                    None => {
                        overflowed = true;
                        break;
                    }
                }
            }
            if !overflowed {
                // ⭐ REPORT WHAT WAS ACTUALLY PLACED, NOT WHAT WAS HANDED IN.
                //
                // `[oli-build] indexed N tag(s)` prints the KLOG length — a figure taken BEFORE the entries
                // are filtered, partitioned and packed — so it read "1 tag" through every run in which the
                // wallet found nothing. The number that decides whether a payment is findable is how many
                // entries survived into the SERVED tables, and it had no instrument at all.
                // DIGITAL-CASH-PRIVACY-REVIEWED: BY CONSTRUCTION entry and shard COUNTS of this node's own
                // served index, plus the shard-bit width it already publishes in `/oli_params`. Never a tag,
                // key, note, amount or owner. Emitted once per index build, never per query or per block.
                eprintln!(
                    "[oli-placed] {} entr(ies) in -> {} shard table(s) at shard_bits={} — if this is 0 while \
                     [oli-build] reports tags, the entries were dropped between the klog and the served table.",
                    entries_len,
                    shards.len(),
                    shard_bits
                );
                return Index {
                    shards,
                    shard_bits,
                    epoch_seed,
                };
            }
            // DB-107: a split that cannot separate the colliding entries (a fingerprint clash of two different
            // keys, or a kick chain the walk cannot resolve) must not run forever — after MAX_EXTRA_SPLITS the
            // overflowing shards are built from the entries that FIT and the rest are logged out of the
            // index; the index is served, never a hung node.
            splits += 1;
            if splits > MAX_EXTRA_SPLITS {
                let mut shards = std::collections::HashMap::with_capacity(parts.len());
                let mut left_out = 0usize;
                for (sid, es) in &parts {
                    let mut keep = es.len();
                    let mut built = None;
                    while keep > 0 {
                        if let Some(t) = build_shard(&es[..keep]) {
                            built = Some(t);
                            break;
                        }
                        keep = keep * 3 / 4;
                    }
                    left_out += es.len() - keep;
                    if let Some(t) = built {
                        shards.insert(*sid, t);
                    }
                }
                eprintln!(
                    "[oli-build] ⛔ {left_out} entr(ies) could not be placed after {MAX_EXTRA_SPLITS} extra split(s) at \
                     shard_bits={shard_bits} — served without them (DB-107); they stay findable by the applied-notes scan"
                );
                return Index {
                    shards,
                    shard_bits,
                    epoch_seed,
                };
            }
            shard_bits += 1; // split every shard in two and retry — entries never move elsewhere
                             // Re-split from the buckets we ALREADY hold. The flat list was released above, so this never
                             // re-reads a retained source copy: the entries are moved out of the old buckets, re-placed at the
                             // wider width, and the old map dies with the iteration. Splits are logarithmic in the epoch size.
            let mut flat: Vec<([u8; K_BYTES], u64, u8)> = Vec::new();
            for (_sid, es) in parts {
                for e in es {
                    flat.push(e);
                }
            }
            parts = partition_shards(&flat, shard_bits);
        }
    }

    /// A shard's table bytes. An absent shard serves as an all-zero table of the same fixed size, so the
    /// response is byte-shaped identically whether or not that shard holds anything.
    pub fn shard_table(&self, sid: u64) -> std::borrow::Cow<'_, [u8]> {
        match self.shards.get(&sid) {
            Some(t) => std::borrow::Cow::Borrowed(t.as_slice()),
            None => std::borrow::Cow::Owned(vec![0u8; (SHARD_BUCKETS as usize) * BUCKET_BYTES]),
        }
    }

    /// The per-epoch hint for one shard (512 KB, fixed).
    pub fn shard_hint(&self, sid: u64) -> Vec<u8> {
        build_hint(&self.shard_table(sid), SHARD_BUCKETS, &self.epoch_seed)
    }

    /// Answer a batch of PIR queries against one shard — ONE pass over that shard's 256 KB table.
    pub fn answer(&self, sid: u64, queries: &[Vec<u8>]) -> Option<Vec<Vec<u8>>> {
        answer_batch(&self.shard_table(sid), SHARD_BUCKETS, queries)
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    /// DB-107 (run 102l, 2026-09-19): ONE ADDRESS PAID MANY TIMES MUST NOT HANG THE INDEX BUILD. Every note paid
    /// to the same address carries the same locator key; a key owns two cuckoo buckets (2 × BUCKET_SLOTS = 16
    /// entries), so the seventeenth entry could never be placed — and the build's overflow loop split every
    /// shard and retried FOREVER, doubling its tables each round, with the runtime lock held: every RPC and
    /// the tick of the node froze for minutes after the sixteen-wallet burst (runs 102j/102k/102l). The build
    /// now keeps the newest MAX_PER_KEY entries of such a key, terminates, and still answers for them; the
    /// rest are found by the applied-notes scan. Control: sixteen entries on one key all stay placed.
    #[test]
    fn a_key_paid_more_than_its_two_buckets_hold_builds_a_bounded_index_with_its_newest_entries() {
        let ent = |label: &[u8]| -> [u8; 32] { *blake3::hash(label).as_bytes() };
        let da_secret = ent(b"MUSD/oli/db107/da-secret");
        let epoch_seed = ent(b"MUSD/oli/db107/epoch");
        let k = index_key(b"MUSD/oli/db107/one-address-clue");
        // 40 payments to ONE address across 40 records: the same key, distinct (seq, slot)
        let klog: Vec<(u64, u8, [u8; K_BYTES])> = (0..40u64).map(|i| (1_000 + i, (i % 200) as u8, k)).collect();
        let t0 = std::time::Instant::now();
        let idx = Index::build(&klog, &da_secret, 0, 5_000, 1, epoch_seed);
        assert!(t0.elapsed() < std::time::Duration::from_secs(20), "the build terminates (it used to loop forever)");
        // the newest MAX_PER_KEY (16) of the 40 are the ones the table can hold and answers for
        let sid = shard_of(&k, idx.shard_bits);
        let table = idx.shard_table(sid);
        let (b1, b2) = bucket_choices(&k, SHARD_BUCKETS);
        let mut found: Vec<(u64, u8)> = Vec::new();
        for bucket in [b1 as usize, b2 as usize] {
            let off = bucket * BUCKET_BYTES;
            let b = &table[off..off + BUCKET_BYTES];
            for slot in 0..BUCKET_SLOTS {
                if let Some(pos) = entry_for_key(&b[slot * ENTRY_BYTES..(slot + 1) * ENTRY_BYTES], &k) {
                    found.push(pos);
                }
            }
        }
        found.sort();
        assert_eq!(found.len(), MAX_PER_KEY, "exactly the two buckets' worth of the key's entries are placed ({found:?})");
        assert!(
            found.iter().all(|(seq, _)| *seq >= 1_000 + 40 - MAX_PER_KEY as u64),
            "the NEWEST entries of the key stay (seqs {:?})",
            found.iter().map(|(s, _)| *s).collect::<Vec<_>>()
        );
        // CONTROL: a key with exactly MAX_PER_KEY entries keeps every one of them
        let k2 = index_key(b"MUSD/oli/db107/another-address-clue");
        let klog2: Vec<(u64, u8, [u8; K_BYTES])> = (0..MAX_PER_KEY as u64).map(|i| (2_000 + i, 3u8, k2)).collect();
        let idx2 = Index::build(&klog2, &da_secret, 0, 5_000, 1, epoch_seed);
        let sid2 = shard_of(&k2, idx2.shard_bits);
        let table2 = idx2.shard_table(sid2);
        let (c1, c2) = bucket_choices(&k2, SHARD_BUCKETS);
        let mut n2 = 0usize;
        for bucket in [c1 as usize, c2 as usize] {
            let b = &table2[bucket * BUCKET_BYTES..(bucket + 1) * BUCKET_BYTES];
            for slot in 0..BUCKET_SLOTS {
                if entry_for_key(&b[slot * ENTRY_BYTES..(slot + 1) * ENTRY_BYTES], &k2).is_some() {
                    n2 += 1;
                }
            }
        }
        assert_eq!(n2, MAX_PER_KEY, "a key that fits its two buckets keeps every entry");
    }

    /// ⭐⭐⭐ DB-351 — `D` BINDS EXACTLY WHAT THE CHAIN FILES, AND BOTH DOORS COMPUTE THE SAME ONE.
    ///
    /// TAMPER (each must MOVE D, i.e. a carrier proven under the honest D fails under the relay's): a rewritten clue
    /// byte, a stripped clue, a clue ADDED for an output that carried none, and a clue moved to the other output.
    /// PARITY: the graft door's form (keys read from a block's `oli_tags`) equals the pool door's form (keys derived
    /// from the pooled clue list) — one D, two readers. CALIBRATION: D is a function of the output SET (order-free), and
    /// a repeated output is refused rather than hashed twice.
    #[test]
    fn db351_the_filing_digest_binds_every_filed_byte_and_both_doors_agree() {
        let out_a = *blake3::hash(b"db351-out-a").as_bytes();
        let out_b = *blake3::hash(b"db351-out-b").as_bytes();
        let clue = vec![0x51u8; 608];
        let honest = vec![(out_a, clue.clone())];
        let d = filing_d_bytes_from_clues(&[out_a, out_b], &honest).expect("two distinct outputs");
        assert_eq!(
            filing_d_bytes_from_clues(&[out_b, out_a], &honest),
            Some(d),
            "CALIBRATION: D is a function of the output set, not of which output is out0"
        );
        let mut rewritten = clue.clone();
        rewritten[300] ^= 1;
        for (why, tampered) in [
            ("a rewritten clue byte", vec![(out_a, rewritten)]),
            ("a stripped clue", Vec::new()),
            ("a clue added for an output that carried none", vec![(out_a, clue.clone()), (out_b, clue.clone())]),
            ("a clue moved to the other output", vec![(out_b, clue.clone())]),
        ] {
            assert_ne!(
                filing_d_bytes_from_clues(&[out_a, out_b], &tampered),
                Some(d),
                "⛔ DB-351: {why} left D unchanged — a relay could rewrite it and the carrier would still verify"
            );
        }
        // The graft door reads the filed key straight from the block's `oli_tags`.
        let tags = [(out_a, index_key(&clue))];
        let from_block = filing_d_bytes_from_keys(&[out_a, out_b], |cm| {
            tags.iter().find(|(c, _)| c == cm).map(|(_, k)| *k)
        });
        assert_eq!(from_block, Some(d), "⛔ DB-351: the graft door and the pool door computed two different D");
        assert_eq!(filing_d_bytes_from_clues(&[out_a, out_a], &honest), None, "a repeated output is refused");
        assert_eq!(filing_d_digest(&d), usdm_decider::poseidon2_compress::hash32_to_digest(&d), "8 lanes, hashed in");
    }

    /// ⭐ DB-351 — THE ONE ENCODING OF A SPEND'S CLUE LIST. Refused: out of order, repeated, naming a note the spend
    /// does not create, malformed. Accepted: the ascending list of its own outputs, and the empty list. A refusal is of
    /// the whole spend — never a filtered subset filed in its place.
    #[test]
    fn db351_a_clue_list_in_any_other_spelling_is_refused_whole() {
        let lo = [0x10u8; 32];
        let hi = [0x20u8; 32];
        let foreign = [0x30u8; 32];
        let rec = |cm: [u8; 32], fill: u8| {
            let mut v = cm.to_vec();
            v.extend_from_slice(&96u16.to_le_bytes());
            v.extend_from_slice(&[fill; 96]);
            v
        };
        let outs = [hi, lo];
        let ascending = [rec(lo, 1), rec(hi, 2)].concat();
        assert_eq!(canonical_clue_records(&outs, &ascending).map(|r| r.len()), Some(2), "the canonical list parses");
        assert_eq!(canonical_clue_records(&outs, &[]).map(|r| r.len()), Some(0), "the empty list is canonical");
        for (why, list) in [
            ("descending", [rec(hi, 2), rec(lo, 1)].concat()),
            ("a repeated cm", [rec(lo, 1), rec(lo, 3)].concat()),
            ("a note this spend does not create", [rec(lo, 1), rec(foreign, 4)].concat()),
            ("a truncated record", ascending[..ascending.len() - 1].to_vec()),
        ] {
            assert!(canonical_clue_records(&outs, &list).is_none(), "⛔ DB-351: a list with {why} was accepted");
        }
    }

    use super::*;
    use crate::cover::BLOCK_FIXED_NOTE_COUNT;

    fn ent(label: &[u8]) -> [u8; 32] {
        *blake3::hash(label).as_bytes()
    }

    fn k_of(b: u8) -> [u8; K_BYTES] {
        let mut k = [b; K_BYTES];
        k[15] = b.wrapping_add(1);
        k
    }

    fn k_hash(i: u32) -> [u8; K_BYTES] {
        let mut k = [0u8; K_BYTES];
        k.copy_from_slice(&blake3::hash(&i.to_le_bytes()).as_bytes()[..K_BYTES]);
        k
    }

    /// ⭐⭐⭐ THE PUBLIC-TAG PRIVACY CARDINAL, PINNED (user 2026-08-14): "an address tag that is unlinkable
    /// and reusable and public — just a hash that means nothing to public observers and leaks 0 metadata."
    ///
    /// The OLI locator IS that tag, and this test pins the four properties the whole "records-on-DA indexed
    /// by public locator" architecture rests on. If any breaks, the public serving index would leak metadata:
    ///
    ///  1. PUBLIC + OWNER-RECOVERABLE: a locator is a deterministic function of the owner's secret key, the
    ///     domain and the index `j`, so the recipient regenerates its own locators from its seed to FIND its
    ///     notes — no server, no stored index (liveness-trustless).
    ///  2. INFORMATION-FREE TO OBSERVERS: without `loc_sk` the locator is unpredictable — a keyed hash — so a
    ///     node serving records by locator, or an observer watching the wire, learns nothing about the owner,
    ///     the amount, or any link. Revealing a locator in a query leaks 0 metadata BECAUSE it is meaningless.
    ///  3. UNLINKABLE ACROSS PAYMENTS: rotating `j` gives every payment a DISTINCT locator; an observer cannot
    ///     tell that two locators belong to one owner. (A reused `j` repeats by design so the owner can refind
    ///     — the unlinkability is a property of ROTATION, which the wallet does per payment.)
    ///  4. DOMAIN + KEY SEPARATION: a different owner key, or a different domain, yields an unrelated locator,
    ///     so no cross-owner and no cross-domain linkage.
    /// ⭐⭐⭐ THE WIRE-TIMING / QUERY-PATTERN METADATA LEAK, CLOSED BY CONSTRUCTION (user 2026-08-14: "come
    /// up with the solution for the wire-timing metadata leak. The bar is that monerousd is 100% private at
    /// every layer").
    ///
    /// THE LEAK: the public locator is information-free (proven in the sibling test), but a wallet still ASKS
    /// a node for records, and the SHAPE of that request could fingerprint the wallet even when each locator
    /// is meaningless.
    ///
    /// THE SOLUTION, already in the design and pinned here: every restore fetches a CONSTANT-shape wave.
    /// `wave_shards` pads the real shards with SECRET-KEYED decoys to EXACTLY `WAVE_SHARDS`, then SORTS so
    /// wire order carries nothing; each shard is a fixed-size PIR database (oblivious within the shard).
    ///
    /// Modelled as TWO endpoints: the OWNER (builds a wave from its real set) and a passive network OBSERVER
    /// — the adversary whose whole existence is this leak. The observer sees ONLY the wire bytes; the bar is
    /// that its view is IDENTICAL for two different owners, so it can never tell them apart. It OBSERVES the
    /// owner's effect (the wave) and fails to distinguish — that is the boundary, not a second serving node.
    ///
    /// cons: none. This is a test that PROVES a privacy property; it changes no production behaviour and
    /// makes nothing observable. The wave it exercises is a fixed `WAVE_SHARDS = 16` shards of fixed-size
    /// PIR — f(fixed constant), independent of chain height, note count or history — so it adds no growth
    /// and no metadata surface; it closes one.
    #[test]
    fn an_observer_cannot_distinguish_two_owners_constant_shape_waves() {
        let bits = 8u32; // 256 shards — comfortably larger than WAVE_SHARDS
        let total = 1u64 << bits;

        // THE SECOND ENDPOINT — the passive network OBSERVER (adversary). It receives a wave off the wire and
        // extracts every signal available to it: the count, whether it is sorted, and the value range. If
        // this tuple is the same for two different owners, the observer has learned NOTHING distinguishing.
        let observer_sees = |wave: &[u64]| -> (usize, bool, bool) {
            let count = wave.len();
            let sorted = wave.iter().zip(wave.iter().skip(1)).all(|(a, b)| a <= b);
            let in_range = wave.iter().all(|s| *s < total);
            (count, sorted, in_range)
        };

        // OWNER 1 and OWNER 2 — DIFFERENT real locator-shard sets, DIFFERENT wallet secrets.
        let owner1_real = vec![3u64, 40, 77];
        let owner2_real = vec![9u64, 12, 100, 201, 250];
        let secret1: [u8; 32] = ent(b"owner-1-wave-secret");
        let secret2: [u8; 32] = ent(b"owner-2-wave-secret");
        let wave1 = wave_shards(&owner1_real, &|_| false, 0, bits, &secret1, 0);
        let wave2 = wave_shards(&owner2_real, &|_| false, 0, bits, &secret2, 0);

        // ⭐ THE PRIVACY PROPERTY: the observer's view of the two owners is IDENTICAL — same count, same
        // sortedness, same range. The request shape is not a fingerprint (no count/volume/order leak).
        assert_eq!(
            observer_sees(&wave1),
            observer_sees(&wave2),
            "an observer must see the SAME wave shape for two different owners — else the request fingerprints"
        );

        // The owner still fetches its OWN shards (padding never displaces a real one, or a note is missed).
        for r in &owner1_real {
            assert!(
                wave1.contains(r),
                "every real shard must be in the wave, or the owner misses a note"
            );
        }
        // Count is the fixed constant regardless of how many reals the owner had (0..=WAVE_SHARDS).
        for real_n in [0usize, 1, 5, 12, 16] {
            let real: Vec<u64> = (0..real_n as u64).collect();
            assert_eq!(
                wave_shards(&real, &|_| false, 0, bits, &secret1, 0).len(),
                WAVE_SHARDS,
                "every wave is exactly WAVE_SHARDS — the count never reveals how many notes an owner has"
            );
        }
        // ⛔ DB-228 — the pad is REPRODUCIBLE for (secret, wave index), never fresh per pass. This asserted the
        // opposite ("decoys must rotate per sync"), arguing cross-sync linkage was the transport's job; but the
        // scan re-runs the lookup every pass over one connection, so passes ARE linkable, and a rotating pad
        // leaves the needed shards as the only thing that recurs — intersection returns them to the node
        // (MEASURED on the note fetch beside it: two passes shared the 8 reals and only 2 of 56 cover). A stable
        // pad gives intersection nothing; a different wallet secret still gives a different pad.
        assert_eq!(
            wave_shards(&owner1_real, &|_| false, 0, bits, &secret1, 0),
            wave_shards(&owner1_real, &|_| false, 0, bits, &secret1, 0),
            "the same pass state yields the same wave — nothing churns between passes to intersect"
        );
        assert_ne!(
            wave_shards(&owner1_real, &|_| false, 0, bits, &secret1, 0),
            wave_shards(&owner1_real, &|_| false, 0, bits, &secret2, 0),
            "the pad is keyed on the wallet secret, never a public function of the needed set"
        );
        // A later wave never re-fetches a held shard, and an index of WAVE_SHARDS shards or fewer is WHOLE.
        let held: std::collections::BTreeSet<u64> = wave1.iter().copied().collect();
        let next = wave_shards(&[3, 250], &|s| held.contains(&s), held.len() as u64, bits, &secret1, 1);
        assert_eq!(next.len(), WAVE_SHARDS, "the next wave is the same shape");
        assert!(next.iter().all(|s| !held.contains(s)) && next.contains(&250), "only unheld shards, needed first");
        assert_eq!(
            wave_shards(&[5], &|_| false, 0, 3, &secret1, 0),
            (0..8).collect::<Vec<u64>>(),
            "an 8-shard index is fetched whole, whatever is needed"
        );
    }

    #[test]
    fn the_public_locator_is_information_free_owner_recoverable_and_unlinkable() {
        let alice: [u8; 32] = ent(b"alice-loc-sk");
        let bob: [u8; 32] = ent(b"bob-loc-sk");
        let dom = "musd";

        // (1) OWNER-RECOVERABLE: deterministic for the owner — Alice regenerates the exact locator to find
        // her note. This is what lets a wallet fetch by locator with NO stored index.
        assert_eq!(
            locator_at(&alice, dom, 7),
            locator_at(&alice, dom, 7),
            "a locator must be a deterministic function of (key, domain, j) so the owner can refind it"
        );

        // (3) UNLINKABLE ACROSS PAYMENTS: rotating j → distinct locators, so an observer cannot group an
        // owner's payments. This is why a public tag leaks no linkage.
        let mut seen = std::collections::HashSet::new();
        for j in 0..64u64 {
            assert!(
                seen.insert(locator_at(&alice, dom, j)),
                "every rotated index must yield a DISTINCT public locator (no linkage across payments)"
            );
        }

        // (2) INFORMATION-FREE / (4) KEY + DOMAIN SEPARATION: without the owner's key — or under a different
        // owner, or a different domain — the locator is unrelated. An observer (or a serving node) holding
        // only the public locator learns nothing and cannot forge or link it.
        assert_ne!(
            locator_at(&alice, dom, 7),
            locator_at(&bob, dom, 7),
            "a different owner key must give an unrelated locator (no cross-owner linkage, unforgeable)"
        );
        assert_ne!(
            locator_at(&alice, dom, 7),
            locator_at(&alice, "other", 7),
            "a different domain must give an unrelated locator (no cross-domain linkage)"
        );

        // The public tag is exactly LOC_BYTES of keyed hash — a fixed, meaningless width, carrying no amount,
        // owner, count or timing. That fixed shape is what makes it safe to serve records by locator.
        assert_eq!(
            locator_at(&alice, dom, 0).len(),
            LOC_BYTES,
            "the public tag is a fixed-width opaque hash"
        );
    }

    #[test]
    fn a_subaddress_at_any_index_is_recognised_in_one_step_with_no_gap_limit() {
        // ⛔ THE FUND LOSS THIS RETIRES. The v1 tag was `XOF(L)` alone — one-way — so recognising one meant
        // GUESSING the subaddress index and stopping at `GAP_LIMIT`. Hand out 30 subaddresses, have only the
        // 26th pay you, and that payment was invisible FOREVER. Widening the guess only postpones the loss.
        //
        // user 2026-07-27: "the user should be able to generate an infinite amount of subaddresses and they
        // all work and aggregate funds forever. There should be no 20 address limit as that can cause funds
        // loss."
        let loc_sk = derive_loc_sk(blake3::hash(b"MUSD/oli/infinite-subaddr/owner").as_bytes());
        let mint = |d: &str, j: u64| -> Vec<u8> {
            let loc = locator_at(&loc_sk, d, j);
            let salt = address_salt(&loc_sk, d, j);
            tag_clue_bytes_v2(&loc, &salt, &address_index_hint(&loc_sk, &salt, j))
        };

        // Indices FAR past any gap that was ever written here, and past any that could be.
        for j in [
            0u64,
            1,
            16,
            17,
            25,
            1_000,
            1_000_000,
            u32::MAX as u64,
            u64::MAX - 1,
        ] {
            assert_eq!(
                owns_tag(&loc_sk, &["recv", "chg"], &mint("recv", j)),
                Some(("recv".to_string(), j)),
                "subaddress {j} must be recognised in ONE step — index 0 and index 10^9 cost the same"
            );
        }

        // The blob stays EXACTLY clue-shaped, or it is no longer byte-indistinguishable on the wire.
        assert_eq!(
            mint("recv", 25).len(),
            crate::omr::Clue::BYTES,
            "a tag must be clue-sized"
        );

        // Change addresses live in their own domain and must not be confused with receive addresses.
        let jc = 4_242_424_242u64;
        assert_eq!(
            owns_tag(&loc_sk, &["recv", "chg"], &mint("chg", jc)),
            Some(("chg".to_string(), jc))
        );
        assert_eq!(
            owns_tag(&loc_sk, &["recv"], &mint("chg", jc)),
            None,
            "a change tag must NOT read as a receive tag — domains are separate spaces"
        );

        // ⛔ IT IS A TEST, NOT A DECODER. Anyone's bytes unmask to SOME number; ownership is the
        // re-derivation. A STRANGER's tag must be rejected, or the prefilter becomes "keep everything" and
        // the scan stops being O(owned).
        let stranger_sk =
            derive_loc_sk(blake3::hash(b"MUSD/oli/infinite-subaddr/stranger").as_bytes());
        let sloc = locator_at(&stranger_sk, "recv", 7);
        let ssalt = address_salt(&stranger_sk, "recv", 7);
        let stag = tag_clue_bytes_v2(&sloc, &ssalt, &address_index_hint(&stranger_sk, &ssalt, 7));
        assert_eq!(
            owns_tag(&loc_sk, &["recv", "chg"], &stag),
            None,
            "a stranger's subaddress tag must NOT read as ours"
        );
        // ...and it must be rejected at EVERY index it could claim, not just the one it used.
        assert_eq!(owns_tag(&loc_sk, &["recv", "chg"], &stag[..]), None);

        // ⛔ A FORGED HINT ON OUR OWN LOCATOR MUST FAIL — without the re-derivation an attacker could pair
        // any locator with any hint and have it accepted.
        let mut forged = mint("recv", 25);
        forged[8] ^= 1;
        assert_eq!(
            owns_tag(&loc_sk, &["recv", "chg"], &forged),
            None,
            "a hint that does not unmask to the index this tag was minted for must be refused"
        );
        // ⛔ AND A SWAPPED BODY MUST FAIL — the body is what binds the tag to the locator.
        let mut swapped = mint("recv", 25);
        let other = mint("recv", 26);
        swapped[16..].copy_from_slice(&other[16..]);
        assert_eq!(
            owns_tag(&loc_sk, &["recv", "chg"], &swapped),
            None,
            "a tag whose body belongs to a different subaddress must be refused"
        );

        // ⛔ THE HINT LEAKS NOTHING. Consecutive subaddresses must not produce related hints, or an observer
        // subtracts two of a wallet's addresses and reads its ordering.
        let hs: Vec<[u8; 8]> = (0..3u64)
            .map(|j| {
                let salt = address_salt(&loc_sk, "recv", j);
                address_index_hint(&loc_sk, &salt, j)
            })
            .collect();
        assert!(
            hs[0] != hs[1] && hs[1] != hs[2] && hs[0] != hs[2],
            "consecutive hints must differ"
        );
        let d10: Vec<u8> = hs[1].iter().zip(hs[0].iter()).map(|(a, b)| a ^ b).collect();
        let d21: Vec<u8> = hs[2].iter().zip(hs[1].iter()).map(|(a, b)| a ^ b).collect();
        assert_ne!(
            d10, d21,
            "consecutive hints must not differ by a CONSTANT — that would let an observer subtract two \
             addresses and read the wallet's ordering"
        );
    }

    #[test]
    fn locator_enumeration_is_deterministic_and_domain_separated() {
        let sk = derive_loc_sk(&ent(b"MUSD/oli/test/entropy-a"));
        let a = locator_at(&sk, "recv", 3);
        let b = locator_at(&sk, "recv", 3);
        let c = locator_at(&sk, "chg", 3);
        let d = locator_at(&sk, "recv", 4);
        assert_eq!(
            a, b,
            "same (domain, j) reproduces — the seed-only enumeration anchor"
        );
        assert_ne!(a, c, "domains separate");
        assert_ne!(a, d, "indices separate");
        // Recipient K == node K over the sender-shaped clue bytes (the end-to-end tag agreement).
        let clue = tag_clue_bytes(&a);
        assert_eq!(
            clue.len(),
            crate::omr::Clue::BYTES,
            "tag blob wears the exact clue size"
        );
        assert_eq!(
            index_key(&clue),
            index_key(&tag_clue_bytes(&locator_at(&sk, "recv", 3)))
        );
    }

    #[test]
    fn tag_blob_is_a_valid_nonpertinent_clue_shape() {
        // Byte-indistinguishability floor: the blob PARSES as a Clue and tests non-pertinent for a real
        // clue secret — so tagged notes are invisible chaff to every other wallet's clue filter.
        let sk = derive_loc_sk(&ent(b"MUSD/oli/test/entropy-b"));
        let blob = tag_clue_bytes(&locator_at(&sk, "recv", 0));
        let clue = crate::omr::Clue::from_bytes(&blob).expect("tag blob parses as a clue");
        let (_pk, csk) = crate::omr::derive_clue_key(&ent(b"MUSD/oli/test/clue-key"));
        assert!(
            !crate::omr::is_pertinent(&csk, &clue),
            "tag blob is non-pertinent chaff to real keys"
        );
    }

    #[test]
    fn table_build_and_lookup_roundtrip_over_the_real_tags() {
        // Four real tags across three records (record 1 carries two). The epoch is exactly those tags — no chaff
        // (DB-235) — and every one resolves at its own (record, slot); an absent key resolves to nothing.
        let klog: Vec<(u64, u8, [u8; K_BYTES])> = vec![
            (0, 1, k_of(10)),
            (1, 0, k_of(20)),
            (1, 255, k_of(30)),
            (3, 128, k_of(40)),
        ];
        let entries = epoch_entries(&klog);
        assert_eq!(entries.len(), klog.len(), "one entry per real tag, nothing else");
        let table = build_shard(&entries).expect("entries fit one shard");
        for (k, seq, slot) in &entries {
            let (fseq, fslot) = table_lookup(&table, SHARD_BUCKETS, k).expect("every entry findable");
            assert_eq!((fseq, fslot), (*seq, *slot));
        }
        assert_eq!(table_lookup(&table, SHARD_BUCKETS, &k_of(99)), None, "absent key misses");
    }

    #[test]
    fn pir_roundtrip_recovers_the_exact_bucket_and_is_target_blind() {
        // Four production-shape blocks of entries (4 × 256), spanning multiple PIR columns.
        let entries: Vec<([u8; K_BYTES], u64, u8)> = (0..(4 * BLOCK_FIXED_NOTE_COUNT) as u32)
            .map(|i| {
                (
                    k_hash(i),
                    (i / BLOCK_FIXED_NOTE_COUNT as u32) as u64,
                    (i % BLOCK_FIXED_NOTE_COUNT as u32) as u8,
                )
            })
            .collect();
        let buckets = SHARD_BUCKETS;
        let table = build_shard(&entries).expect("entries fit one shard");
        let t_cols = (buckets as usize) / BUCKETS_PER_COL;
        let epoch_seed = ent(b"MUSD/oli/test/epoch-seed-a");
        let hint = build_hint(&table, buckets, &epoch_seed);
        // Probe a real key end to end through the PIR path — the FULL 2-choice lookup (both candidate
        // buckets, the constant two queries one locator always costs).
        let (k, kseq, kslot) = (&entries[137].0, entries[137].1, entries[137].2);
        let coords = query_coords(k, buckets);
        let rands = [
            ent(b"MUSD/oli/test/query-rand-a"),
            ent(b"MUSD/oli/test/query-rand-b"),
        ];
        let mut recovered: Vec<[u8; BUCKET_BYTES]> = Vec::with_capacity(2);
        let mut qlens: Vec<usize> = Vec::with_capacity(2);
        for (i, (col, in_col)) in coords.iter().enumerate() {
            let (u, s) = build_query(t_cols, &epoch_seed, *col, &rands[i]);
            qlens.push(u.len());
            let ans = answer_query(&table, buckets, &u).expect("well-formed query answers");
            recovered.push(recover_bucket(&ans, &hint, &s, *in_col).expect("recover"));
        }
        // Each recovered bucket is EXACTLY the table's bucket (LWE noise fully rounded away).
        let (b1, b2) = bucket_choices(k, buckets);
        for (bi, b) in [b1, b2].iter().enumerate() {
            let off = (*b as usize) * BUCKET_BYTES;
            assert_eq!(
                &recovered[bi][..],
                &table[off..off + BUCKET_BYTES],
                "PIR returns the true bucket bytes"
            );
        }
        assert_eq!(
            probe_candidates(&recovered[0], &recovered[1], k),
            vec![(kseq, kslot)],
            "the probed key resolves through the 2-choice lookup"
        );
        // TARGET-BLINDNESS shape: every query is the same length regardless of which column it targets,
        // and recovering with a DIFFERENT query's secret yields noise — the server, holding no secret at
        // all, is in a strictly worse position for EVERY query it answers.
        assert_eq!(
            qlens[0], qlens[1],
            "constant query shape regardless of target"
        );
        let (_u_other, s_other) = build_query(
            t_cols,
            &epoch_seed,
            coords[0].0,
            &ent(b"MUSD/oli/test/query-rand-c"),
        );
        let (u_real, s_real) = build_query(t_cols, &epoch_seed, coords[0].0, &rands[0]);
        let ans_real = answer_query(&table, buckets, &u_real).unwrap();
        let off1 = (b1 as usize) * BUCKET_BYTES;
        let honest = recover_bucket(&ans_real, &hint, &s_real, coords[0].1).unwrap();
        assert_eq!(
            &honest[..],
            &table[off1..off1 + BUCKET_BYTES],
            "the right secret recovers the bucket"
        );
        let garbled = recover_bucket(&ans_real, &hint, &s_other, coords[0].1).unwrap();
        assert_ne!(
            &garbled[..],
            &table[off1..off1 + BUCKET_BYTES],
            "without the right secret the answer is noise"
        );
    }

    #[test]
    fn tampered_answer_fails_closed_at_the_fingerprint_gate() {
        // ADVERSARIAL: a garbling server flips answer bytes — the recovered bucket then fails the fp
        // probe (an honest MISS, surfaced as such). It can never inject a false note: acceptance
        // downstream requires the wallet's own ML-KEM decap + note_cm binding, which no index answer
        // can forge. One production-shape block of entries.
        let entries: Vec<([u8; K_BYTES], u64, u8)> = (0..BLOCK_FIXED_NOTE_COUNT as u32)
            .map(|i| (k_hash(1_000_000 + i), 0u64, i as u8))
            .collect();
        let buckets = SHARD_BUCKETS;
        let table = build_shard(&entries).expect("entries fit one shard");
        let t_cols = (buckets as usize) / BUCKETS_PER_COL;
        let epoch_seed = ent(b"MUSD/oli/test/epoch-seed-b");
        let hint = build_hint(&table, buckets, &epoch_seed);
        let k = &entries[50].0;
        let coords = query_coords(k, buckets);
        let rands = [
            ent(b"MUSD/oli/test/tamper-rand-a"),
            ent(b"MUSD/oli/test/tamper-rand-b"),
        ];
        // Sanity FIRST: the HONEST answers do resolve this key — so the miss below is caused by the
        // tamper, not by a key that was never there (a test that cannot fail is no test).
        let mut honest: Vec<[u8; BUCKET_BYTES]> = Vec::with_capacity(2);
        let mut tampered: Vec<[u8; BUCKET_BYTES]> = Vec::with_capacity(2);
        for (i, (col, in_col)) in coords.iter().enumerate() {
            let (u, s) = build_query(t_cols, &epoch_seed, *col, &rands[i]);
            let ans = answer_query(&table, buckets, &u).unwrap();
            honest.push(recover_bucket(&ans, &hint, &s, *in_col).unwrap());
            // A garbling server: corrupt EXACTLY the answer rows this bucket decodes from.
            let mut bad = ans.clone();
            let row0 = *in_col * BUCKET_BYTES;
            for r in row0..row0 + BUCKET_BYTES {
                for byte in bad[r * 4..r * 4 + 4].iter_mut() {
                    *byte ^= 0xA5;
                }
            }
            tampered.push(recover_bucket(&bad, &hint, &s, *in_col).unwrap());
        }
        assert_eq!(
            probe_candidates(&honest[0], &honest[1], k),
            vec![(0u64, 50u8)],
            "control: the honest answers DO resolve this key"
        );
        assert!(
            probe_candidates(&tampered[0], &tampered[1], k).is_empty(),
            "tampered answer = miss, never a forged hit"
        );
    }

    #[test]
    fn a_recipient_finds_its_tagged_note_through_the_live_sharded_index_by_locator_alone() {
        // THE LIVE PATH, end to end, with nothing reconstructed: a SENDER shapes the recipient's locator
        // into the note's clue-channel tag; the node turns that tag into the slot's index key exactly as
        // `record_note_payload` does; the epoch index is built over the production 256-slot cover shape;
        // and the RECIPIENT — holding only its seed — re-derives the same locator, finds its shard, and
        // recovers (seq, slot) through the real PIR path. No note contents, no scan key, no server trust.
        let recipient_entropy = ent(b"MUSD/oli/live/recipient-seed");
        let loc_sk = derive_loc_sk(&recipient_entropy);
        let da_secret = ent(b"MUSD/oli/live/da-secret");
        let epoch_seed = ent(b"MUSD/oli/live/epoch");

        // SENDER: the recipient's address carries locator j=0; the sender attaches its tag to the note.
        let locator = locator_at(&loc_sk, "recv", 0);
        let tag = tag_clue_bytes(&locator);
        // NODE at record time: this slot's index key is the hash of whatever tag rode the clue channel.
        // A REAL-SHAPED canonical address (height<<8|sub, ~10^16) — deliberately ABOVE u32::MAX, so this
        // test goes RED if the entry's seq field ever truncates again. 1_234 fit in 32 bits and passed
        // straight through the truncation that killed live sends (`as u32` in epoch_entries/pack_entry).
        let (note_seq, note_slot) = (288_221_910_316_966_119u64, 77u8);
        let klog = vec![(note_seq, note_slot, index_key(&tag))];

        // NODE at epoch build: the full constant-shape index over every block's 256 slots.
        let idx = Index::build(
            &klog,
            &da_secret,
            0,
            2_000,
            BLOCK_FIXED_NOTE_COUNT,
            epoch_seed,
        );
        // ⛔ `2_000 * 256` ASSUMED THE RETIRED SWEEP — 512,000 entries for a span holding ONE real tag.
        // The epoch is now driven by the tags that exist, so this klog yields `1 + 256 - 1 = 256` entries and
        // `shard_bits_for(256)` is 0, not 6. Derive the floor from the same rule the generator follows, and
        // assert the width is AT LEAST that: `Index::build` only ever widens (the overflow loop splits and
        // retries), so a `>=` is the honest invariant and an `==` would be red the first time a shard packs
        // full. What actually matters is the probe below — that the recipient finds its note from its seed.
        // cons: none — test-only arithmetic over a 1-entry klog and the fixed 256-slot shape; no history term.
        let expected_entries = 1 + BLOCK_FIXED_NOTE_COUNT - 1;
        assert!(
            idx.shard_bits >= shard_bits_for(expected_entries),
            "shard width tracks the index size and only ever widens"
        );

        // RECIPIENT (seed only): re-derive the locator → key → shard, then probe through real PIR.
        let k = index_key(&tag_clue_bytes(&locator_at(&loc_sk, "recv", 0)));
        let sid = shard_of(&k, idx.shard_bits);
        let t_cols = (SHARD_BUCKETS as usize) / BUCKETS_PER_COL;
        let a = expand_a(&epoch_seed, t_cols);
        let hint = idx.shard_hint(sid);
        let coords = query_coords(&k, SHARD_BUCKETS);
        let mut qs = Vec::with_capacity(2);
        let mut ss = Vec::with_capacity(2);
        for (i, (col, _)) in coords.iter().enumerate() {
            let (u, s) = build_query_with_a(
                &a,
                *col,
                &ent(&[b"MUSD/oli/live/q".as_slice(), &[i as u8]].concat()),
            )
            .unwrap();
            qs.push(u);
            ss.push(s);
        }
        let answers = idx
            .answer(sid, &qs)
            .expect("the shard answers a well-formed batch");
        let b0 = recover_bucket(&answers[0], &hint, &ss[0], coords[0].1).unwrap();
        let b1 = recover_bucket(&answers[1], &hint, &ss[1], coords[1].1).unwrap();
        assert_eq!(
            probe_candidates(&b0, &b1, &k),
            vec![(note_seq, note_slot)],
            "the recipient locates its note's (block, slot) from its seed alone"
        );

        // A STRANGER holding a different seed learns nothing: its locators resolve to no entry.
        let stranger = derive_loc_sk(&ent(b"MUSD/oli/live/stranger-seed"));
        let sk_k = index_key(&tag_clue_bytes(&locator_at(&stranger, "recv", 0)));
        let s_sid = shard_of(&sk_k, idx.shard_bits);
        let s_hint = idx.shard_hint(s_sid);
        let s_coords = query_coords(&sk_k, SHARD_BUCKETS);
        let mut s_qs = Vec::with_capacity(2);
        let mut s_ss = Vec::with_capacity(2);
        for (i, (col, _)) in s_coords.iter().enumerate() {
            let (u, s) = build_query_with_a(
                &a,
                *col,
                &ent(&[b"MUSD/oli/live/sq".as_slice(), &[i as u8]].concat()),
            )
            .unwrap();
            s_qs.push(u);
            s_ss.push(s);
        }
        let s_ans = idx.answer(s_sid, &s_qs).unwrap();
        let sb0 = recover_bucket(&s_ans[0], &s_hint, &s_ss[0], s_coords[0].1).unwrap();
        let sb1 = recover_bucket(&s_ans[1], &s_hint, &s_ss[1], s_coords[1].1).unwrap();
        assert!(
            probe_candidates(&sb0, &sb1, &sk_k).is_empty(),
            "a stranger's locator finds nothing"
        );
    }

    #[test]
    fn epoch_entries_are_exactly_the_real_tags_in_canonical_order() {
        // The epoch is driven by the tags that EXIST — never by a numeric sweep over the sparse address space,
        // which found nothing and then tried to allocate 6.9 EXABYTES — and since DB-235 it is exactly those
        // tags: no chaff (public chaff hid nothing and doubled the index). The count therefore tracks the tagged
        // notes indexed, which it always did (chaff was a constant multiple of them).
        let tags: Vec<(u64, u8, [u8; K_BYTES])> = vec![(5, 7, k_of(3)), (2, 3, k_of(2)), (2, 0, k_of(1))];
        let entries = epoch_entries(&tags);
        assert_eq!(
            entries,
            vec![(k_of(1), 2, 0), (k_of(2), 2, 3), (k_of(3), 5, 7)],
            "every real tag at its own (record, slot), in canonical order — the order every node builds from"
        );
        let shuffled: Vec<(u64, u8, [u8; K_BYTES])> = vec![tags[2], tags[0], tags[1]];
        assert_eq!(epoch_entries(&shuffled), entries, "klog order never changes the epoch (byte-identical tables)");
        assert!(epoch_entries(&[]).is_empty(), "a span holding no tag contributes no entries");
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod bench {
    use super::*;
    use std::time::Instant;

    /// MEASURED restore cost across chain sizes spanning the LIVE chain to 1000x it — run with:
    /// `cargo test --release --lib oli::bench::measure -- --ignored --nocapture`
    ///
    /// This measures the REAL restore working set. A restore touches exactly `WAVE_SHARDS`
    /// constant-size shards (its locators' shards plus decoys), so those shards — not the whole chain —
    /// are what a restore pays for, and they are what is materialized here. The chain size only moves
    /// `shard_bits`; every per-restore column below must stay FLAT, which is the whole claim.
    #[test]
    #[ignore]
    fn measure_oli_restore_is_flat_in_chain_size() {
        let epoch_seed = *blake3::hash(b"MUSD/oli/bench/epoch").as_bytes();
        let da_secret = *blake3::hash(b"MUSD/oli/bench/da-secret").as_bytes();
        let t_cols = (SHARD_BUCKETS as usize) / BUCKETS_PER_COL;

        // A depends only on (epoch_seed, t_cols) — both FIXED — so ONE expansion serves every shard.
        let ta = Instant::now();
        let a = expand_a(&epoch_seed, t_cols);
        let t_a = ta.elapsed();

        // 33,529 blocks is the live testnet height; the rest scale it to 1000x.
        for blocks in [33_529u64, 335_290, 3_352_900, 33_529_000] {
            let n = (blocks as usize) * crate::cover::BLOCK_FIXED_NOTE_COUNT;
            let bits = shard_bits_for(n);
            let per_shard = ((SHARD_CAPACITY as f64) * SHARD_LOAD) as usize;

            // Materialize the wave's shards — a restore's true working set. Each is a full, realistically
            // loaded shard of secret-seeded synth entries (the constant cover shape).
            let t0 = Instant::now();
            let mut shards: Vec<Vec<u8>> = Vec::with_capacity(WAVE_SHARDS);
            let mut probe_keys: Vec<[u8; K_BYTES]> = Vec::with_capacity(WAVE_SHARDS);
            for sid in 0..WAVE_SHARDS as u64 {
                // Construct this shard's entries directly: a key lands in shard `sid` exactly when its
                // top `bits` are `sid`, so stamp that prefix over secret-seeded key material rather than
                // rejection-sampling for it (which would need ~2^bits draws per key).
                let mut es: Vec<([u8; K_BYTES], u64, u8)> = Vec::with_capacity(per_shard);
                for i in 0..per_shard as u64 {
                    let mut k = index_key(&[da_secret.as_slice(), &(sid * 1_000_000 + i).to_le_bytes()].concat());
                    if bits > 0 {
                        let lead = u64::from_be_bytes(k[0..8].try_into().unwrap());
                        let low_mask = if bits >= 64 { 0 } else { u64::MAX >> bits };
                        let stamped = (sid << (64 - bits)) | (lead & low_mask);
                        k[0..8].copy_from_slice(&stamped.to_be_bytes());
                    }
                    debug_assert_eq!(shard_of(&k, bits), sid);
                    es.push((k, (i % 4096) as u64, (i % 256) as u8));
                }
                probe_keys.push(es[per_shard / 2].0);
                shards.push(build_shard(&es).expect("a load-factor shard always places"));
            }
            let t_mat = t0.elapsed();

            // Per-epoch server work for the wave's shards (hints are shared, cacheable chain data).
            let t1 = Instant::now();
            let hints: Vec<Vec<u8>> = shards
                .iter()
                .map(|t| build_hint(t, SHARD_BUCKETS, &epoch_seed))
                .collect();
            let t_hint = t1.elapsed();

            // THE RESTORE: for each of WAVE_SHARDS shards, both candidate buckets of that shard's
            // locator — 2 queries per shard, answered in ONE pass over that shard.
            let t2 = Instant::now();
            let mut waves: Vec<Vec<Vec<u8>>> = Vec::with_capacity(WAVE_SHARDS);
            let mut secrets: Vec<Vec<Vec<u8>>> = Vec::with_capacity(WAVE_SHARDS);
            for (si, k) in probe_keys.iter().enumerate() {
                let coords = query_coords(k, SHARD_BUCKETS);
                let mut qs = Vec::with_capacity(2);
                let mut ss = Vec::with_capacity(2);
                for (qi, (col, _in_col)) in coords.iter().enumerate() {
                    let r = *blake3::hash(&((si * 2 + qi) as u64).to_le_bytes()).as_bytes();
                    let (u, s) = build_query_with_a(&a, *col, &r).unwrap();
                    qs.push(u);
                    ss.push(s);
                }
                waves.push(qs);
                secrets.push(ss);
            }
            let t_build = t2.elapsed();

            let t3 = Instant::now();
            let mut answers: Vec<Vec<Vec<u8>>> = Vec::with_capacity(WAVE_SHARDS);
            for (si, qs) in waves.iter().enumerate() {
                answers.push(answer_batch(&shards[si], SHARD_BUCKETS, qs).expect("batch answers"));
            }
            let t_ans = t3.elapsed();

            // Client recovery + the real 2-choice probe, proving the wave actually resolves its keys.
            let t4 = Instant::now();
            let mut hits = 0usize;
            for (si, k) in probe_keys.iter().enumerate() {
                let coords = query_coords(k, SHARD_BUCKETS);
                let b0 = recover_bucket(&answers[si][0], &hints[si], &secrets[si][0], coords[0].1)
                    .unwrap();
                let b1 = recover_bucket(&answers[si][1], &hints[si], &secrets[si][1], coords[1].1)
                    .unwrap();
                if !probe_candidates(&b0, &b1, k).is_empty() {
                    hits += 1;
                }
            }
            let t_rec = t4.elapsed();
            assert_eq!(
                hits, WAVE_SHARDS,
                "every probed key must resolve through the sharded PIR path"
            );

            let restore_ms =
                (t_build.as_secs_f64() + t_ans.as_secs_f64() + t_rec.as_secs_f64()) * 1e3;
            let hint_mb = hints.iter().map(|h| h.len()).sum::<usize>() as f64 / 1e6;
            let shard_mb = shards.iter().map(|t| t.len()).sum::<usize>() as f64 / 1e6;
            println!(
                "[oli] blocks={blocks:>10} notes={n:>12} shard_bits={bits:>2} shards={:>13}                  | per-shard: table={:>5.0}KB hint={:>5.0}KB                  | WAVE({WAVE_SHARDS} shards, {} queries): build={:>6.1}ms answer={:>6.1}ms recover={:>6.2}ms                  || RESTORE={:>6.1}ms (+expandA {:>4.0}ms once) | wave bytes: shards={:>4.1}MB hints={:>4.1}MB                  | [setup only: materialize={:>6.0}ms hints={:>6.0}ms]",
                1u64 << bits,
                shards[0].len() as f64 / 1e3,
                hints[0].len() as f64 / 1e3,
                WAVE_SHARDS * 2,
                t_build.as_secs_f64() * 1e3,
                t_ans.as_secs_f64() * 1e3,
                t_rec.as_secs_f64() * 1e3,
                restore_ms,
                t_a.as_secs_f64() * 1e3,
                shard_mb,
                hint_mb,
                t_mat.as_secs_f64() * 1e3,
                t_hint.as_secs_f64() * 1e3,
            );
        }
    }
    /// ⛔⛔⛔ THE RETRIEVAL ITSELF, WITH ONE KNOWN KEY AND NO CHAIN.
    ///
    /// MEASURED on the live pair, twice, on two fresh chains: every INPUT to a lookup was correct and the
    /// lookup still found nothing —
    ///   node:   [faucet]    clue attached form=v2 key=4abc6447
    ///   wallet: [oli-ask]   domain=recv first_key=4abc6447 shard=9
    ///   node:   [oli-build] indexed 1 tag(s), 0 unplaced      (shard_bits=5 -> 0x4a>>3 == 9)
    ///   wallet: [oli-yield] locate returned 0 position(s)
    /// Tag form, key bytes, domain, index range, placement and shard all agreed. Cutting the chaff from 256
    /// slots per record to 1 changed nothing, so the fault is not what is indexed nor how crowded it is.
    ///
    /// This isolates the two halves that must agree and nothing else: the bucket `build_shard` WRITES an
    /// entry into, and the bucket `query_coords` READS. If those disagree, every note ever paid is on chain
    /// and unfindable by its owner — the exact live symptom — and no amount of chain state can show it.
    #[test]
    fn an_entry_written_by_build_shard_is_read_back_at_the_coordinates_query_coords_names() {
        let mut k = [0u8; K_BYTES];
        k[0] = 0x4a; // the live key's leading byte, so this exercises the same shard arithmetic
        for (i, b) in k.iter_mut().enumerate().skip(1) {
            *b = (i as u8).wrapping_mul(37).wrapping_add(11);
        }
        let table = build_shard(&[(k, 7u64, 0u8)]).expect("one entry fits an empty shard");

        // Where the BUILDER put it.
        let (b1, b2) = bucket_choices(&k, SHARD_BUCKETS);
        let written = [b1, b2].iter().any(|b| {
            let off = (*b as usize) * BUCKET_BYTES;
            table[off..off + BUCKET_BYTES]
                .chunks_exact(ENTRY_BYTES)
                .any(|e| entry_for_key(e, &k).is_some())
        });
        assert!(
            written,
            "build_shard must place the entry in one of the key's two candidate buckets"
        );

        // Where the READER looks. `query_coords` returns (col, bucket_in_col) for the same two buckets, so
        // recomposing them must name those same buckets — this is the identity the PIR fetch relies on.
        for (col, in_col) in query_coords(&k, SHARD_BUCKETS) {
            let recomposed = (col * BUCKETS_PER_COL + in_col) as u64;
            assert!(
                recomposed == b1 || recomposed == b2,
                "query_coords named bucket {recomposed} (col {col}, in_col {in_col}) but the builder uses \
                 {b1} and {b2} — the reader and the writer disagree about where an entry lives, so every \
                 note is on chain and unfindable by its owner"
            );
        }

        // And the entry is actually READABLE from the coordinates the reader names.
        let found = query_coords(&k, SHARD_BUCKETS).iter().any(|(col, in_col)| {
            let off = (col * BUCKETS_PER_COL + in_col) * BUCKET_BYTES;
            table[off..off + BUCKET_BYTES]
                .chunks_exact(ENTRY_BYTES)
                .any(|e| entry_for_key(e, &k).is_some())
        });
        assert!(
            found,
            "the entry must be readable at the coordinates query_coords names"
        );
    }

    /// DB-228 — a WHOLE shard table locates exactly what the index holds for a key: every entry of that key,
    /// no other key's entry, and nothing for an absent key. `table_candidates` slices the two candidate
    /// buckets and runs the same `probe_candidates` the LWE path decodes into, so the two paths cannot
    /// disagree about what a wallet owns.
    #[test]
    fn db228_a_whole_shard_table_locates_every_entry_of_a_key_and_nothing_else() {
        fn ent(label: &[u8]) -> [u8; 32] {
            *blake3::hash(label).as_bytes()
        }
        let genesis = ent(b"MUSD/oli/db228/locate-genesis");
        let ck = chain_key(Some(&genesis));
        let reused = index_key(b"MUSD/oli/db228/one-address-paid-three-times");
        let mut klog: Vec<(u64, u8, [u8; K_BYTES])> = Vec::new();
        for i in 0..3u64 {
            klog.push((300_000_000_000_000_000u64 + i * 17, 0, reused));
        }
        for i in 0..200u64 {
            klog.push((310_000_000_000_000_000u64 + i * 29, (i % 2) as u8, index_key(&ent(&(5_000 + i).to_le_bytes()))));
        }
        let idx = Index::build(&klog, &ck, 0, u64::MAX, 1, epoch_seed(&ck));
        let table = idx.shard_table(shard_of(&reused, idx.shard_bits));
        let mut got = table_candidates(&table, &reused);
        got.sort_unstable();
        let mut want: Vec<(u64, u8)> = klog
            .iter()
            .filter(|(_, _, k)| *k == reused)
            .map(|(s, sl, _)| (*s, *sl))
            .collect();
        want.sort_unstable();
        assert_eq!(got, want, "every payment to one reused address is located — never only the first");
        // Identity with the bucket path: the same two buckets through `probe_candidates` directly.
        let (b1, b2) = bucket_choices(&reused, SHARD_BUCKETS);
        let direct = probe_candidates(
            &table_bucket(&table, b1).expect("in range"),
            &table_bucket(&table, b2).expect("in range"),
            &reused,
        );
        assert_eq!(direct.len(), want.len(), "the table path IS the bucket path");
        // An absent key locates nothing, and a bucket past the table is refused, never zero-filled.
        let absent = index_key(b"MUSD/oli/db228/never-paid");
        assert!(table_candidates(&idx.shard_table(shard_of(&absent, idx.shard_bits)), &absent).is_empty());
        assert!(table_bucket(&table, SHARD_BUCKETS).is_none(), "bucket index past the table is not a bucket");
    }

    /// ⛔ DB-235 PIN — TWO PAYMENTS TO ONE REUSED ADDRESS MUST NOT BE LINKABLE BY A TABLE READER.
    ///
    /// Every note paid to one locator carries the same index key `K`. A reader of the served table (anyone:
    /// `/oli_table` whole, or `/oli_answer` with un-noised queries) sees each entry's fingerprint; if two entries
    /// of one key share a fingerprint — or carry `K`'s own prefix — the reader clusters all payments to that
    /// address without ever knowing it. The owner, who holds `K`, must still find every one of them.
    #[test]
    fn db235_two_payments_to_one_address_are_unlinkable_in_a_served_table() {
        let reused = index_key(b"MUSD/oli/db235/one-address-paid-twice");
        let mut klog: Vec<(u64, u8, [u8; K_BYTES])> =
            vec![(301_000_000_000_000_001, 0, reused), (302_000_000_000_000_003, 1, reused)];
        for i in 0..200u64 {
            klog.push((310_000_000_000_000_000 + i * 7, (i % 2) as u8, index_key(&i.to_le_bytes())));
        }
        let idx = Index::build(&klog, &[3u8; 32], 0, u64::MAX, 1, [7u8; 32]);
        let table = idx.shard_table(shard_of(&reused, idx.shard_bits));
        let mut owner_sees = table_candidates(&table, &reused);
        owner_sees.sort_unstable();
        assert_eq!(
            owner_sees,
            vec![(301_000_000_000_000_001, 0), (302_000_000_000_000_003, 1)],
            "the owner (who holds K) finds BOTH payments to the reused address"
        );
        // The reader holds no key: all it has is each entry's bytes.
        let fps: Vec<[u8; 7]> = table
            .chunks_exact(ENTRY_BYTES)
            .filter_map(unpack_entry)
            .filter(|(_, seq, slot)| owner_sees.contains(&(*seq, *slot)))
            .map(|(fp, _, _)| fp)
            .collect();
        assert_eq!(fps.len(), 2, "both payments are in the served table");
        assert_ne!(
            fps[0], fps[1],
            "DB-235: two payments to ONE address carry the SAME fingerprint — any table reader links them"
        );
        assert!(
            fps.iter().all(|fp| fp[..] != reused[0..7]),
            "DB-235: an entry's fingerprint is its key's own prefix — the key, not the payment, is published"
        );
    }

    /// ⛔ DB-235 PIN — THE SERVED INDEX HOLDS EXACTLY THE REAL TAGS: nothing but an entry per tagged note, at
    /// its own position. Chaff derived from a public key hides nothing (anyone recomputes and subtracts it) and
    /// doubles every table and every shard a restore fetches.
    #[test]
    fn db235_the_served_index_holds_exactly_the_real_tags() {
        let mut klog: Vec<(u64, u8, [u8; K_BYTES])> = Vec::new();
        for i in 0..300u64 {
            klog.push((320_000_000_000_000_000 + i * 11, (i % 3) as u8, index_key(&(900 + i).to_le_bytes())));
        }
        let idx = Index::build(&klog, &[5u8; 32], 0, u64::MAX, 1, [9u8; 32]);
        let mut served: Vec<(u64, u8)> = Vec::new();
        for sid in 0..(1u64 << idx.shard_bits) {
            served.extend(idx.shard_table(sid).chunks_exact(ENTRY_BYTES).filter_map(unpack_entry).map(|(_, s, sl)| (s, sl)));
        }
        served.sort_unstable();
        let mut want: Vec<(u64, u8)> = klog.iter().map(|(s, sl, _)| (*s, *sl)).collect();
        want.sort_unstable();
        assert_eq!(
            served.len(),
            want.len(),
            "DB-235: the served index carries {} entries for {} real tags — the extra entries are chaff",
            served.len(),
            want.len()
        );
        assert_eq!(served, want, "every entry is a real tag at its own (record, slot), and every real tag is served");
    }

    /// ⛔ DB-235 PIN — A SHARD FILLED TO 90% OF CAPACITY BUILDS IN PLACE. A two-choice table of 8-slot buckets
    /// holds well past this load once evictions work; a builder whose evictions fail returns `None` here, and the
    /// index then splits every such shard (twice the shards a restore fetches) and, past `MAX_EXTRA_SPLITS`,
    /// drops entries — notes their owners can no longer locate.
    #[test]
    fn db235_a_shard_at_ninety_percent_load_builds_in_place_and_serves_every_entry() {
        let n = SHARD_CAPACITY * 9 / 10;
        let entries: Vec<([u8; K_BYTES], u64, u8)> = (0..n as u64)
            .map(|i| (index_key(&(7_000_000 + i).to_le_bytes()), 400_000_000_000_000_000 + i, (i % 251) as u8))
            .collect();
        let table = build_shard(&entries)
            .expect("DB-235: a shard at 90% load must build — a failed eviction splits the shard and drops entries");
        for (k, seq, slot) in &entries {
            assert_eq!(table_lookup(&table, SHARD_BUCKETS, k), Some((*seq, *slot)), "every entry is served");
        }
    }
}
// Moved here from `impl Node` (stage A of the node split): the codec reads and writes bytes only, so it lives with the clues it
// encodes; `Node::parse_note_clue_records` / `encode_note_clue_records` stay as one-line wrappers for their callers.
/// ⭐⭐⭐ DB-330 — THE ONE ENCODING OF A CLUE-RECORD LIST, READ WHOLE OR NOT AT ALL.
///
/// A list is `cm(32) ‖ len(u16 LE) ‖ clue`, repeated: the shape the wallet's `own_note_clue_record` writes.
/// Two readers used to parse it and they disagreed at the tail. `/submit_pq_tx` (rpc_http ~1435) kept the
/// records before a malformed one and dropped trailing bytes under 34; `stage_carried_note_clues` stopped at
/// the malformed record but kept what it had already filed. One reader now: any record running past the
/// list's end, or any trailing byte, makes the whole list `None`, and nothing from it is filed.
/// cons: none — a single pass over the list's own bytes; nothing stored.
#[must_use]
pub fn parse_note_clue_records(bytes: &[u8]) -> Option<Vec<([u8; 32], Vec<u8>)>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < bytes.len() {
        if off + 34 > bytes.len() {
            return None;
        }
        let mut cm = [0u8; 32];
        cm.copy_from_slice(&bytes[off..off + 32]);
        let len = u16::from_le_bytes([bytes[off + 32], bytes[off + 33]]) as usize;
        let end = off + 34 + len;
        if end > bytes.len() {
            return None;
        }
        out.push((cm, bytes[off + 34..end].to_vec()));
        off = end;
    }
    Some(out)
}

/// The writer paired with [`parse_note_clue_records`]. A clue longer than a `u16` length can state is
/// not written: the `as u16` casts this replaces would have TRUNCATED its length and corrupted the list.
#[must_use]
pub fn encode_note_clue_records(records: &[([u8; 32], Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (cm, clue) in records {
        let Ok(len) = u16::try_from(clue.len()) else {
            continue;
        };
        out.extend_from_slice(cm);
        out.extend_from_slice(&len.to_le_bytes());
        out.extend_from_slice(clue);
    }
    out
}

