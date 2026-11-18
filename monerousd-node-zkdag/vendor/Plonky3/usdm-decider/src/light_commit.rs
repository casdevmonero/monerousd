// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! ⭐⭐⭐ DB-452 — THE LIGHT DECIDER'S OPENINGS, BOUND TO A WHIR COMMITMENT (docs/DB-452-LIGHT-DECIDER-COMMITTED-OPENING.md).
//!
//! ⛔⛔⛔ THE HOLE, MEASURED 2026-10-21 (link 75, `db452_a_note_transition_stating_spends_no_carrier_proved_is_refused`):
//! the light decider recorded its claims on a `ZkPrefixProver` and finished with `prove_hvzk` — the WHIR claim-reduction
//! sumcheck with NO commit and NO query phase. `ZkVerifier::into_sumcheck` reconstructs each round's `c_1` from the running
//! target and returns the final target, which every caller dropped. Nothing any bundle carried was an evaluation of a
//! committed polynomial, so a producer sent its block-transition tie cell as ANY value and a forged note transition
//! verified: inflation.
//!
//! ⭐ THE SHAPE, BORROWED FROM THE COMMITTED CARRIER DOOR (`committed_air::prove/verify_air_committed_bytes_with`): the
//! tables are committed (Merkle root observed) BEFORE any challenge that depends on them is drawn, the commitment's OOD
//! answers follow, every claim is recorded on the layout, and one WHIR opening discharges all of them against the root.
//! The PCS is the money path's own `CarrierParams::LIVE` (Johnson bound, rate 1/4, 16 query-grind bits — H12 step 5).
//!
//! ⭐ NEXT-ROW OPENINGS (`AirZerocheckProof::shifted_opened`) — the SHIFT-BIND sumcheck (the HyperPlonk / Jolt shift
//! reduction): `Σ_y S(r,y)·F(y) = Σ_j λ^j·shifted_j`, `F = Σ_j λ^j·col_j`, `S(r,y) = eq(r, y−1 mod N)` on the cube; at the
//! sumcheck's own point ρ every column is opened through the commitment, and the verifier evaluates `S(r,ρ)` in closed
//! form. A row-LOCAL gate sends none (`is_row_local()` is read from the PUBLIC constraint, so there is one encoding).

use crate::air_zerocheck::{eq_z_hypercube, fold_one_var, lagrange_eval};
use crate::committed_air::{pcs_with, CarrierParams, Pcs};
use crate::hiding_decider::{Chl, Ea4, Fa4, Mmcs16};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_sumcheck::commit::CodewordRows;
use p3_sumcheck::layout::{Layout, PrefixProver, Table, TableShape, Verifier as LayoutVerifier};
use p3_whir::pcs::proof::WhirProof;
use p3_whir::pcs::verifier::WhirVerifier;
use serde::{Deserialize, Serialize};

/// The PCS every light-decider round opens under: the money path's `CarrierParams::LIVE` (Johnson bound, 100 bits
/// proven, rate 1/4, 16 query-grind bits) with the inverse rate growing by ONE per round instead of three.
///
/// ⛔ MEASURED 2026-10-21 (`db452_light_round_whir_schedule_by_stacked_arity`, night/link76-sched.log + -sched2.log;
/// `db452_grind_cost_by_bits`, night/link76-grind.log: one grind is 59 ms at 20 bits, 249 ms at 22, 1,012 ms at 24): a
/// light round's stacked arity is the WHOLE aggregate (the note transition: a 2^8 × 10,736 step table, a 2^14 × 196
/// sponge and a 2^11 × 196 chain = arity 23), and there `LIVE` derives fold grinds up to 35 bits — past KoalaBear's
/// one-word grind ceiling (the first pin run panicked after 81 s of grinding). The Johnson prox-gaps term `ρ^(−3/2)` is
/// what forces fold grinds in the deep rounds (H12 path B, 2026-10-04), and the grind is paid once per folded variable,
/// so it is the prove time: at arity 23, growth 3 / 2 / 1 → max grind 35 / 25 / 21 bits, est. grind 8,878 / 15.7 / 0.7 s,
/// queries 177 / 204 / 258. Growth 1 keeps every grind ≤ 22 bits through arity 24 (the two-adic limit). The schedule is
/// derived by `WhirConfig::new` for 100 bits in the same regime, so the security target is unchanged; the cost is the
/// extra queries (bytes, measured at the landing).
///
/// ⭐⭐ SPEED R4-G (2026-11-10) — AND EACH FOLD GRINDS AT THE CODE IT ACTS ON (`fold_grind_per_fold`,
/// `WhirConfig::with_fold_grinds_at_the_folded_code`). MEASURED on two real nodes (a stack sample of a proving node):
/// the fold grinds were 27 % of all proving work, and after the opening stopped recomputing its rows row by row, 40 %.
/// A block costs two light-decider proofs of 23 stacked variables; their fold grinds were 21,21,21,21 / 19×4 / 18×4 /
/// 16×4 bits = 11.8 million candidates an opening, and are 20,19,18,17 / 18,17,16,15 / 17,16,15,14 / 15,14,13,12 = 2.76
/// million. The shape (folds, rates, queries, bytes) is untouched; the 100 proven bits are scored per sub-round
/// (`committed_air::proven_bits`) and pinned on every light shape. A light round is verified natively only
/// (`LightCommitVerifier`), so no circuit's grind table is involved. CONSENSUS: a light-decider proof ground at the
/// per-fold figures is refused by a verifier that asks the group figures (pinned in `p3_whir`), so the prover and the
/// verifier change together — every block proof on the chain, from genesis.
///
/// ⭐⭐ SPEED R10 (2026-11-10) — AND THE ROUNDS ARE SIZED AT A WIDER JOHNSON SLACK (`regime: JohnsonBoundWide`,
/// `eta = sqrt(rho)/14` where `LIVE` reads `sqrt(rho)/20`; the SAME theorem — p3-whir's `SecurityAssumption` names the
/// statement as read in the paper). MEASURED after R4-G on two real nodes: grinding was still 20.8 % of a block's proof
/// CPU, and 2.80 M of an opening's 3.09 M grind candidates were the folds'. The fold's proximity-gap error grows as
/// `(m+½)^5` with `m = sqrt(rho)/(2 eta)`: at `m = 7` every folding sub-round needs 2.43 fewer bits than at 10 — the
/// first group grinds 17,16,15,14 — and each query buys 0.03 bit less, so the rounds ask 94, 60, 45, 35 + 29 queries
/// where they asked 91, 59, 44, 35 + 29. The target is the same 100 proven bits, scored term by term in the regime the
/// shape is built in (`committed_air::proven_bits::proven_regime`).
/// cons, quantified: five more queries an opening (about 4 KB, under 1 % of a block) for about three quarters of the
/// grind.
/// CONSENSUS, with R4-G: the query counts and the fold grinds of every light-decider proof change together.
pub const LIGHT_COMMIT_PARAMS: CarrierParams = CarrierParams {
    rate_growth: 1,
    max_fold_grind: crate::committed_air::ONE_WORD_GRIND_CEILING,
    fold_grind_per_fold: true,
    regime: p3_whir::parameters::SecurityAssumption::JohnsonBoundWide,
    ..CarrierParams::LIVE
};

/// The largest table arity a light round may declare — the committed door's own bound (`MAX_STATEABLE_NVARS`).
const LIGHT_MAX_NVARS: usize = crate::committed_air::MAX_STATEABLE_NVARS;

/// ⛔ A-F57 (2026-11-15) — THE LARGEST STACKED ARITY A LIGHT ROUND ADMITS, asked BEFORE any configuration is built.
/// `WhirConfig::new` ASSERTS `arity + start_rate − first_fold ≤ TWO_ADICITY` (`whir/src/parameters/whir.rs:168`): past it
/// the round panics, and on the verify path a round's shapes are a remote statement's. So [`LightCommitProver::commit`] and
/// [`LightCommitVerifier::begin`] refuse (`None`) a stacked arity past it, by name, for every light round at once.
/// KoalaBear's two-adicity is 24 and the light rounds start at rate 1/4 with a first fold of 4, so the bound is 26.
#[must_use]
pub fn light_arity_admissible(stacked: usize) -> bool {
    use p3_field::TwoAdicField;
    stacked + LIGHT_COMMIT_PARAMS.start_rate <= <Fa4 as TwoAdicField>::TWO_ADICITY + LIGHT_COMMIT_PARAMS.first_fold
}

/// ⭐ SPEED V2-R (lane speed5, 2026-11-17) — A LIGHT ROUND STARTS AT RATE 1/8 WHEREVER ITS ARITY ALLOWS IT, 1/4 ABOVE.
/// The parameters of one light round are a function of its STACKED ARITY, which both sides read from the statement's
/// shapes (the prover from its witness, the verifier from [`LayoutVerifier`] over the pinned shapes) — so they never
/// disagree, and a round has exactly one encoding.
///
/// WHY: the block's V2 root verifies the tree-ledger light proof IN-CIRCUIT (`usdm-agg::ledger_ssa`), and its rows are
/// the WHIR queries. MEASURED (`v2_light_round_schedule_by_start_rate`, every round scored ≥ 100.01 proven bits in the
/// regime it is built in): at 19 stacked variables the queries are 234 / 169 / 134 at start rates 2 / 3 / 4, at 23 they
/// are 263 / 194 / 156. Rate 1/8 is −28 % queries: fewer in-circuit rows (the ledger door from 35,523 rows toward a
/// 2^15 row class, half the ledger node's prove) and fewer bytes on the wire. Each query path is one level deeper.
/// WHY NOT EVERY ARITY: the codeword of a rate-1/8 round is 2^(stacked+3) points, and the PCS's two-adicity bounds it
/// (`stacked + start_rate ≤ TWO_ADICITY + first_fold`, 25 at 1/8 against 26 at 1/4). A round at 26 (the largest DSOL
/// call class still provable) keeps 1/4, so no statement that proves today stops proving.
/// cons, quantified: the commit of a 1/8 round encodes twice the codeword (its Reed–Solomon LDE and Merkle leaves ×2:
/// NOT MEASURED until the pin batch reports the tree-ledger commit ms); CONSENSUS/FORMAT: every light-decider proof at
/// stacked arity ≤ 25 changes encoding (prover and verifier together, from genesis).
/// SCALE: a constant per arity; nothing grows with nodes, items or height. AI RESISTANCE: (a) — every round is scored
/// ≥ 100 proven bits by `committed_air::proven_bits` at both rates (`production_shapes`), and the verifier checks it.
pub const LIGHT_FAST_START_RATE: usize = 3;

/// ⭐ V2-R2 (speed5, 2026-11-17) — the largest stacked arity a light round runs at rate 1/8. MEASURED (pin profile, this
/// machine): the fold band's step is a light round at 23 stacked variables, and at 1/8 its commit took 1,848–1,951 ms of a
/// 4,049–4,122 ms step (`nf_compact_air` db453_b, `MONEROUSD_PROVE_PROGRESS`) — the doubled codeword; the band is what
/// limits the chain's rate (P7, `[band-time]` 5.1–5.4 s a step on real nodes). A small round pays for its queries (rate 1/8
/// cuts them by about a third: the tree ledger at 19), a large one for its commit (1/4 halves it). So 1/8 up to this arity.
/// NETWORK UPGRADE (2026-11-17): the light rounds' rate split (main e14caff5 + 438d89ec) changes every light-decider proof's
/// encoding, so a node built before it does not interoperate with one built after (declared in the commit that says so).
pub const LIGHT_FAST_MAX_ARITY: usize = 20;

/// The parameters of a light round at `stacked` variables (see [`LIGHT_FAST_START_RATE`]).
#[must_use]
pub fn light_params(stacked: usize) -> CarrierParams {
    use p3_field::TwoAdicField;
    if stacked <= LIGHT_FAST_MAX_ARITY
        && stacked + LIGHT_FAST_START_RATE <= <Fa4 as TwoAdicField>::TWO_ADICITY + LIGHT_COMMIT_PARAMS.first_fold
    {
        CarrierParams { start_rate: LIGHT_FAST_START_RATE, ..LIGHT_COMMIT_PARAMS }
    } else {
        LIGHT_COMMIT_PARAMS
    }
}

/// One committed round of a light-decider proof: the Merkle root of the stacked tables, fixed before any challenge that
/// depends on them, and the WHIR opening that proves every claim the round recorded against it.
///
/// ⭐ R4 — ON THE WIRE THE TOP OF EVERY QUERY GROUP'S PATHS TRAVELS AS ONE CONSTANT-SIZE SLOT PER LEVEL. Every block
/// carries two light-decider proofs (the note and member ledgers), and on a real pair relaying them IS the block interval.
/// Within one query group (one WHIR round's queries, or the final queries) every query opens the SAME tree of 2^d leaves,
/// so at a level `l` there are only 2^(d−l) sibling positions while q paths each send one. [`SiblingSlots`] sends the
/// levels below `l0` per query and every level from `l0` up as ONE slot holding all 2^(d−l) positions — the positions no
/// query reads are zero digests — plus each query's position at `l0`. `l0` minimises the digests sent and is a function
/// of (q, d) alone, so EVERY proof of a shape has the same wire length. The decode restores each query's sibling list and
/// the UNCHANGED WHIR verifier checks every path; WHIR itself, its in-circuit verifier (`whir_program`) and every native
/// verify are untouched. Borrowed shape: a Merkle multiproof / batched decommitment (Winterfell's `BatchMerkleProof`,
/// Plonky2's merkle cap, Plonky3's own `open_batch_pruned`), applied at the encoding only.
///
/// ROOT-LAYER: the light round's serde is where its wire bytes are PRODUCED — every bundle (`AirBatchBusBundle`'s two
/// rounds) and every block that carries one encodes through it, so the paths shrink once for every producer and reader;
/// nothing downstream reads the old byte layout except through this decode.
/// MEASURED (2026-11-02): blocks from the 34th on are 1,512,985–1,520,265 B on four real T5 runs and a producer spaces
/// itself to the ~24 s it takes to pull one over Tor; the member ledger is 508,816 B of which sibling paths are 201,799 B
/// (`r4_the_member_ledger_proof_prints_its_bytes_by_part`, landed 970c70d). The first, variable-length form of this lever
/// cut it to 449,397 B and was REFUSED by `settlement_delta::tests::the_proof_is_byte_identical_however_many_spends_are_real`
/// — its length followed which paths merged; this form's length is fixed by (q, d).
/// MUST-STAY-GREEN: that constant-shape pin; every light_commit / member_ledger / slot_ledger / settlement_delta /
/// whir_rec_block / certificate_door pin; the node's frozen-consensus corpus replay (re-recorded as a NAMED format change).
///
/// §9.6 — a DECODE path for an existing door's object, not a new door: (1) PoW n/a; (2) the object's proof is verified by
/// the unchanged WHIR verifier on the restored paths; (3) no value path — a restored path that is not the tree's fails the
/// Merkle check; (4) replay n/a (the enclosing door's set); (5) work bound: q and d are the WHIR configuration's (the
/// proof's fixed shape), every slot and position is checked against (q, d) before it is read; (6) parity: the restored
/// object is exactly the old wire object. ONE ENCODING: `l0` is recomputed and must match, every slot length is fixed by
/// (q, d), a slot position no query reads must be the zero digest, and a wrong position or digest fails the path check —
/// so a proof has exactly one wire form that verifies.
/// cons: none on the wire (smaller, constant); encode/decode add one pass over the group's q·d siblings (µs).
#[derive(Clone)]
pub struct LightRound {
    pub commitment: <Mmcs16 as Mmcs<Fa4>>::Commitment,
    pub open: WhirProof<Fa4, Ea4, Mmcs16>,
}

/// One sibling digest of a light round's Merkle openings.
type Sibling = [Fa4; 8];
type LightQuery = p3_whir::pcs::proof::QueryOpening<Fa4, Ea4, <Mmcs16 as Mmcs<Fa4>>::Proof>;

/// One query group's top levels on the wire: `levels = d − l0`, each query's position at level `l0` (two bytes, little
/// endian), and the slots of levels `l0 .. d` in order, level `l` holding all 2^(d−l) sibling positions.
#[derive(Serialize, Deserialize)]
pub(crate) struct SiblingSlots {
    pub(crate) levels: u8,
    pub(crate) positions: Vec<u8>,
    pub(crate) slots: Vec<Sibling>,
}

#[derive(Serialize, Deserialize)]
struct LightRoundWire {
    commitment: <Mmcs16 as Mmcs<Fa4>>::Commitment,
    open: WhirProof<Fa4, Ea4, Mmcs16>,
    groups: Vec<SiblingSlots>,
}

/// Positions in the slots of levels `l0 .. d`: Σ 2^(d−l).
fn slot_len(d: usize, l0: usize) -> usize {
    (l0..d).map(|l| 1usize << (d - l)).sum()
}

/// The `l0` both sides use: the fewest digests (q·l0 per-query plus the slots), ties to the higher level. A function of
/// (q, d) alone.
fn slot_floor(q: usize, d: usize) -> usize {
    let mut best = d;
    for l0 in (0..d).rev() {
        if q * l0 + slot_len(d, l0) < q * best + slot_len(d, best) {
            best = l0;
        }
    }
    best
}

fn query_siblings_mut(q: &mut LightQuery) -> &mut Vec<Sibling> {
    match q {
        p3_whir::pcs::proof::QueryOpening::Base { proof, .. } | p3_whir::pcs::proof::QueryOpening::Extension { proof, .. } => {
            &mut proof.1
        }
    }
}

/// The query groups of one WHIR opening, in proof order: each round's queries, then the final queries.
fn query_groups_mut(open: &mut WhirProof<Fa4, Ea4, Mmcs16>) -> Vec<&mut Vec<LightQuery>> {
    let WhirProof { rounds, final_queries, .. } = open;
    rounds.iter_mut().map(|r| &mut r.queries).chain(core::iter::once(final_queries)).collect()
}

/// Encode: move every query's siblings from `l0` up into its group's slots.
fn slot_siblings(open: &mut WhirProof<Fa4, Ea4, Mmcs16>) -> Result<Vec<SiblingSlots>, &'static str> {
    let indices = open.query_indices.clone();
    let groups = query_groups_mut(open);
    if indices.len() != groups.len() {
        return Err("light round: the opening carries no query indices for its groups (only a prover's opening encodes)");
    }
    let mut out = Vec::with_capacity(groups.len());
    for (group, idx) in groups.into_iter().zip(indices) {
        if group.len() != idx.len() {
            return Err("light round: a query group's indices do not match its queries");
        }
        let q = group.len();
        let Some(d) = group.first_mut().map(|x| query_siblings_mut(x).len()) else {
            out.push(SiblingSlots { levels: 0, positions: Vec::new(), slots: Vec::new() });
            continue;
        };
        let l0 = slot_floor(q, d);
        if d - l0 > 16 || group.iter_mut().any(|x| query_siblings_mut(x).len() != d) {
            return Err("light round: a query group whose paths are not one tree's");
        }
        let offset = |l: usize| -> usize { slot_len(d, l0) - slot_len(d, l) };
        let mut slots = vec![[Fa4::ZERO; 8]; slot_len(d, l0)];
        let mut positions = Vec::with_capacity(2 * q);
        // O1-INFINITY-REVIEWED: q·(d − l0) steps — q and d are the WHIR configuration's query count and tree depth (the proof's fixed shape), independent of height, blocks or notes.
        for (x, &leaf) in group.iter_mut().zip(&idx) {
            let own = query_siblings_mut(x);
            for l in l0..d {
                slots[offset(l) + ((leaf >> l) ^ 1)] = own[l];
            }
            own.truncate(l0);
            positions.extend_from_slice(&((leaf >> l0) as u16).to_le_bytes());
        }
        out.push(SiblingSlots { levels: (d - l0) as u8, positions, slots });
    }
    Ok(out)
}

/// Decode: restore every query's sibling list, refusing every form [`slot_siblings`] would not have written.
fn unslot_siblings(open: &mut WhirProof<Fa4, Ea4, Mmcs16>, wire: Vec<SiblingSlots>) -> Result<(), &'static str> {
    let groups = query_groups_mut(open);
    if groups.len() != wire.len() {
        return Err("light round: the slots name another number of query groups");
    }
    let mut restored = Vec::with_capacity(groups.len());
    for (group, s) in groups.into_iter().zip(wire) {
        let q = group.len();
        let Some(l0) = group.first_mut().map(|x| query_siblings_mut(x).len()) else {
            if s.levels != 0 || !s.positions.is_empty() || !s.slots.is_empty() {
                return Err("light round: slots for a group with no queries");
            }
            restored.push(Vec::new());
            continue;
        };
        let d = l0 + s.levels as usize;
        if group.iter_mut().any(|x| query_siblings_mut(x).len() != l0) {
            return Err("light round: a query group whose own paths differ in length");
        }
        if d > 32 || slot_floor(q, d) != l0 || s.slots.len() != slot_len(d, l0) || s.positions.len() != 2 * q {
            return Err("light round: slots not of the one shape (q, d) fixes");
        }
        let offset = |l: usize| -> usize { slot_len(d, l0) - slot_len(d, l) };
        let mut read = vec![false; s.slots.len()];
        let mut idx = Vec::with_capacity(q);
        // O1-INFINITY-REVIEWED: q·(d − l0) steps over a shape checked above against the WHIR configuration's (q, d) — independent of height, blocks or notes.
        for (j, x) in group.iter_mut().enumerate() {
            let p = u16::from_le_bytes([s.positions[2 * j], s.positions[2 * j + 1]]) as usize;
            if p >> (d - l0) != 0 {
                return Err("light round: a position past its level");
            }
            let own = query_siblings_mut(x);
            for l in l0..d {
                let at = offset(l) + ((p >> (l - l0)) ^ 1);
                read[at] = true;
                own.push(s.slots[at]);
            }
            idx.push(p << l0);
        }
        if s.slots.iter().zip(&read).any(|(digest, &r)| !r && *digest != [Fa4::ZERO; 8]) {
            return Err("light round: a slot no query reads is not the zero digest");
        }
        restored.push(idx);
    }
    // Enough for a re-encode: the encoder reads only each index's bits from `l0` up.
    open.query_indices = restored;
    Ok(())
}

/// ⭐ SPEED C3a (lane speed4, 2026-11-12) — EVERY carrier's WHIR opening on the wire in the same constant-shape sibling
/// slots a light round uses, through `#[serde(with = "crate::light_commit::slotted_whir")]` on the bundle's `open` field
/// (`CommittedAirBundle`, `ChainedAirBundle`; the certificate's `SpartanCommittedProof` keeps its own form, since its
/// release-shape skeleton (`certificate_door::skeleton_whir`) is laid with no query positions). A payment carries four such openings (the spend,
/// its member path, its spend-or-decoy tag set, its membership), and their q·d per-query sibling paths were most of each
/// carrier's bytes; the light round's encoding sends a group's top levels once, as fixed slots.
///
/// It is the light round's encoder unchanged ([`slot_siblings`] / [`unslot_siblings`]), so the same rules hold: the length
/// is a function of (q, d) alone — never of which paths met, so never of a witness — `l0` is recomputed and must match, a
/// slot no query reads must be the zero digest, and a wrong slot fails the unchanged WHIR verifier's Merkle check. The
/// Fiat–Shamir transcript never absorbs a query opening, so every challenge (γ, z, ρ, the query indices) and every block
/// aggregate that replays a carrier's transcript (`transcript_of_committed_carrier`, `bound_step_row_committed`) is
/// byte-for-byte what it was; only the bytes a payment carries over Tor change. FORMAT (a transaction's wire form).
///
/// §9.6 — a DECODE path for an existing door's object, not a new door: the six answers are [`LightRound`]'s; (7) scale:
/// per carrier, a constant of the WHIR configuration; (8) protected by (a), the unchanged verifier on the restored paths.
/// cons: none on the wire (smaller, constant per class); one encode/decode pass over q·d siblings per carrier (µs).
pub(crate) mod slotted_whir {
    use super::{slot_siblings, unslot_siblings, Ea4, Fa4, Mmcs16, SiblingSlots, WhirProof};
    use serde::{Deserialize, Serialize};

    /// The wire form; `pub(crate)` so the C3a pin can lay a tampered one.
    #[derive(Serialize, Deserialize)]
    pub(crate) struct Wire {
        pub(crate) open: WhirProof<Fa4, Ea4, Mmcs16>,
        pub(crate) groups: Vec<SiblingSlots>,
    }

    pub fn serialize<S: serde::Serializer>(open: &WhirProof<Fa4, Ea4, Mmcs16>, s: S) -> Result<S::Ok, S::Error> {
        let mut open = open.clone();
        let groups = slot_siblings(&mut open).map_err(serde::ser::Error::custom)?;
        Wire { open, groups }.serialize(s)
    }

    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<WhirProof<Fa4, Ea4, Mmcs16>, D::Error> {
        let Wire { mut open, groups } = Wire::deserialize(d)?;
        unslot_siblings(&mut open, groups).map_err(serde::de::Error::custom)?;
        Ok(open)
    }
}

impl Serialize for LightRound {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut open = self.open.clone();
        let groups = slot_siblings(&mut open).map_err(serde::ser::Error::custom)?;
        LightRoundWire { commitment: self.commitment.clone(), open, groups }.serialize(s)
    }
}

impl<'de> Deserialize<'de> for LightRound {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let LightRoundWire { commitment, mut open, groups } = LightRoundWire::deserialize(d)?;
        unslot_siblings(&mut open, groups).map_err(serde::de::Error::custom)?;
        Ok(Self { commitment, open })
    }
}

/// The arity a table has INSIDE the stacked witness: `Witness::new_interleaved` zero-pads a table below the first fold.
fn stacked_arity(nvars: usize) -> usize {
    nvars.max(LIGHT_COMMIT_PARAMS.first_fold)
}

/// A table's point, lifted into its padded arity. The witness pads at the END of the evaluation vector, so the padding
/// variables are the leading (most-significant) ones and the original MLE at `r` is the padded MLE at `(0,…,0 ‖ r)`.
fn lift(point: &Point<Ea4>, nvars: usize) -> Point<Ea4> {
    let pad = stacked_arity(nvars) - nvars;
    if pad == 0 {
        return point.clone();
    }
    let mut v = vec![Ea4::ZERO; pad];
    v.extend(point.iter().copied());
    Point::new(v)
}

/// The prover side of one committed round.
pub struct LightCommitProver {
    layout: PrefixProver<Fa4, Ea4>,
    pcs: Pcs,
    merkle: <Mmcs16 as Mmcs<Fa4>>::ProverData<CodewordRows<Fa4>>,
    commitment: <Mmcs16 as Mmcs<Fa4>>::Commitment,
    open: WhirProof<Fa4, Ea4, Mmcs16>,
    nvars: Vec<usize>,
}

impl LightCommitProver {
    /// COMMIT `tables` (each a list of `2^nvars`-evaluation columns): the root is observed into `chl` here, then the
    /// commitment's OOD answers are drawn — the committed door's steps 2 and 2b, in that order. `None` fail-closed on a
    /// ragged, empty or over-wide table.
    #[must_use]
    pub fn commit(tables: Vec<Vec<Vec<Fa4>>>, chl: &mut Chl) -> Option<Self> {
        if tables.is_empty() {
            return None;
        }
        let mut nvars = Vec::with_capacity(tables.len());
        for cols in &tables {
            let h = cols.first().map(Vec::len).unwrap_or(0);
            if h == 0 || !h.is_power_of_two() || cols.iter().any(|c| c.len() != h) {
                return None;
            }
            let nv = h.trailing_zeros() as usize;
            if nv > LIGHT_MAX_NVARS {
                return None;
            }
            nvars.push(nv);
        }
        let tbls: Vec<Table<Fa4>> =
            tables.into_iter().map(|cols| Table::new(cols.into_iter().map(Poly::<Fa4>::new).collect())).collect();
        let t0 = std::time::Instant::now();
        let witness = PrefixProver::<Fa4, Ea4>::new_witness(tbls, LIGHT_COMMIT_PARAMS.first_fold);
        let stacked = witness.num_variables();
        if !light_arity_admissible(stacked) {
            return None; // A-F57: past the PCS's two-adicity a configuration asserts; refused here instead
        }
        let params = light_params(stacked);
        let pcs = pcs_with(stacked, params);
        let (mut layout, commitment, merkle) =
            PrefixProver::<Fa4, Ea4>::commit(&pcs.dft, &pcs.mmcs, chl, witness, params.first_fold, params.start_rate);
        let mut open = pcs.config.empty_proof();
        open.initial_ood_answers =
            (0..pcs.config.commitment_ood_samples).map(|_| layout.add_virtual_eval(chl)).collect();
        if std::env::var("MONEROUSD_PROVE_PROGRESS").is_ok() {
            eprintln!("[light-commit] {} table(s), stacked arity {stacked}: commit {} ms", nvars.len(), t0.elapsed().as_millis());
        }
        Some(Self { layout, pcs, merkle, commitment, open, nvars })
    }

    /// Open `cols` of table `t` at `point` (the table's own arity) — recorded as a claim the WHIR opening will prove,
    /// and absorbed exactly as the verifier's [`LightCommitVerifier::add_claim_at`] absorbs it.
    pub fn eval_at(&mut self, t: usize, cols: &[usize], point: &Point<Ea4>, chl: &mut Chl) -> Vec<Ea4> {
        let lifted = lift(point, self.nvars[t]);
        self.layout.eval_at(t, cols, &lifted, chl)
    }

    /// Discharge every recorded claim with ONE WHIR opening against the round's commitment.
    #[must_use]
    pub fn finish(self, chl: &mut Chl) -> LightRound {
        let Self { layout, pcs, merkle, commitment, mut open, .. } = self;
        let t0 = std::time::Instant::now();
        pcs.prove(&mut open, chl, layout, merkle);
        if std::env::var("MONEROUSD_PROVE_PROGRESS").is_ok() {
            // SPEED R4 (2026-11-10): the queried rows are derived one sub-coset at a time (`CodewordRows::prime_rows`); the
            // wording names the build, so a log line read later says which opening it timed.
            eprintln!("[light-commit] WHIR opening {} ms (queried rows by sub-coset)", t0.elapsed().as_millis());
        }
        LightRound { commitment, open }
    }
}

/// The verifier side of one committed round, built from the STATEMENT's shapes.
pub struct LightCommitVerifier<'a> {
    lv: LayoutVerifier<Fa4, Ea4>,
    pcs: Pcs,
    round: &'a LightRound,
    nvars: Vec<usize>,
}

impl<'a> LightCommitVerifier<'a> {
    /// Mirror [`LightCommitProver::commit`]: observe the root, refuse any mask commitment (this path has none — one
    /// encoding), and replay the OOD answers, whose count is a public function of the shapes. `shapes` are `(nvars,
    /// width)` as the statement pins them; the caller has already refused a carrier declaring others.
    #[must_use]
    pub fn begin(shapes: &[(usize, usize)], round: &'a LightRound, chl: &mut Chl) -> Option<Self> {
        if shapes.is_empty() || shapes.iter().any(|&(nv, w)| w == 0 || nv > LIGHT_MAX_NVARS) {
            return None;
        }
        let table_shapes: Vec<TableShape> =
            shapes.iter().map(|&(nv, w)| TableShape::new(stacked_arity(nv), w)).collect();
        let mut lv = LayoutVerifier::<Fa4, Ea4>::new(&table_shapes, PrefixProver::<Fa4, Ea4>::strategy());
        if !light_arity_admissible(lv.num_variables()) {
            return None; // A-F57: a statement past the PCS's two-adicity is refused, never a panic on a remote shape
        }
        let pcs = pcs_with(lv.num_variables(), light_params(lv.num_variables()));
        if !round.open.hvzk_mask_commits.is_empty()
            || round.open.initial_ood_answers.len() != pcs.config.commitment_ood_samples
        {
            return None;
        }
        chl.observe(round.commitment.clone());
        for &eval in &round.open.initial_ood_answers {
            lv.add_virtual_eval(eval, chl);
        }
        Some(Self { lv, pcs, round, nvars: shapes.iter().map(|&(nv, _)| nv).collect() })
    }

    /// Record the claim `cols of table t at point = vals` (the table's own arity); absorbs `vals`.
    pub fn add_claim_at(&mut self, t: usize, cols: &[usize], vals: &[Ea4], point: &Point<Ea4>, chl: &mut Chl) {
        let lifted = lift(point, self.nvars[t]);
        self.lv.add_claim_at(t, cols, vals, &lifted, chl);
    }

    /// The table arity the statement declared for `t` — the bound every point routed to it is built at.
    #[must_use]
    pub fn table_nvars(&self, t: usize) -> Option<usize> {
        self.nvars.get(t).copied()
    }

    /// The batching challenge, the batched claim, and the WHIR opening against the round's root. `true` iff every claim
    /// recorded on this round is an evaluation of the committed polynomial (up to the PCS's soundness error).
    #[must_use]
    pub fn finish(self, chl: &mut Chl) -> bool {
        let alpha: Ea4 = chl.sample_algebra_element();
        let constraint = self.lv.constraint(alpha);
        let mut claimed = Ea4::ZERO;
        constraint.combine_evals(&mut claimed);
        let v = WhirVerifier::new(&self.pcs.config, &self.pcs.mmcs, PrefixProver::<Fa4, Ea4>::variable_order());
        match v.verify(&self.round.open, chl, &self.round.commitment, constraint, claimed) {
            Ok(_) => true,
            Err(e) => {
                if std::env::var("MONEROUSD_CERT_LIGHT_DBG").is_ok() {
                    eprintln!("[light-commit] WHIR opening refused: {e:?}");
                }
                false
            }
        }
    }
}

/// The shift-bind proof for ONE row-shifted table: `nvars` degree-2 rounds (evals at 0, 1, 2) and every column opened at
/// the sumcheck's point ρ (bound to the round's commitment).
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct ShiftBindProof {
    pub round_evals: Vec<Vec<Ea4>>,
    pub opened: Vec<Ea4>,
}

fn absorb_ext(chl: &mut Chl, vals: &[Ea4]) {
    for e in vals {
        for &b in <Ea4 as BasedVectorSpace<Fa4>>::as_basis_coefficients_slice(e) {
            chl.observe(b);
        }
    }
}

/// `S(x, y)` — the multilinear extension of "y is the row after x" (cyclic, variable 0 the MOST significant bit, the
/// zerocheck's own convention). For each carry position `k`: every less-significant bit (j > k) is 1 in x and 0 in y, bit
/// k is 0 in x and 1 in y, every more-significant bit (j < k) agrees; plus the wrap `x = 1…1 → y = 0…0`. O(n).
#[must_use]
pub fn shift_mle(x: &[Ea4], y: &[Ea4]) -> Ea4 {
    let n = x.len();
    debug_assert_eq!(n, y.len());
    // suffix[k] = Π_{j ≥ k} x_j (1 − y_j); prefix[k] = Π_{j < k} eq(x_j, y_j)
    let mut suffix = vec![Ea4::ONE; n + 1];
    for j in (0..n).rev() {
        suffix[j] = suffix[j + 1] * x[j] * (Ea4::ONE - y[j]);
    }
    let mut acc = suffix[0]; // the wrap term
    let mut prefix = Ea4::ONE;
    for k in 0..n {
        acc += prefix * (Ea4::ONE - x[k]) * y[k] * suffix[k + 1];
        prefix *= x[k] * y[k] + (Ea4::ONE - x[k]) * (Ea4::ONE - y[k]);
    }
    acc
}

fn powers(lambda: Ea4, n: usize) -> Vec<Ea4> {
    let mut out = Vec::with_capacity(n);
    let mut p = Ea4::ONE;
    for _ in 0..n {
        out.push(p);
        p *= lambda;
    }
    out
}

/// PROVE that `shifted[k] = MLE(rot(cols[set[k]]))(r)` for every column of `set` (C2: the gate's public
/// `air_zerocheck::shifted_set`), reducing all of them to ONE opening of those columns of table `t` at a fresh point on
/// `prover`'s commitment. The caller has absorbed `shifted` already. Soundness is the same sumcheck over the set's terms:
/// `Σ_k λ^k shifted_k = Σ_y S(r,y)·Σ_k λ^k col_{set[k]}(y)`.
pub fn prove_shift_bind(
    cols: &[Vec<Fa4>],
    set: &[usize],
    r: &[Ea4],
    t: usize,
    prover: &mut LightCommitProver,
    chl: &mut Chl,
) -> ShiftBindProof {
    let n = r.len();
    let size = 1usize << n;
    let lambda: Ea4 = chl.sample_algebra_element();
    let lp = powers(lambda, set.len());
    let picked: Vec<&Vec<Fa4>> = set.iter().map(|&c| &cols[c]).collect();
    // ⭐ link 80 (2026-10-21): the λ-combination one row per worker — a row's value reads only that row, and the indexed
    // `collect` keeps row order, so `f` is the serial table value for value (`db452_g_…` pins the prove byte for byte on
    // one thread). MEASURED (`sample`, the 256-insert band slice): this serial loop was 145 of the prove's 8,961 samples.
    use rayon::prelude::*;
    let mut f: Vec<Ea4> = (0..size)
        .into_par_iter()
        .map(|i| picked.iter().zip(&lp).fold(Ea4::ZERO, |a, (c, &l)| a + l * Ea4::from(c[i])))
        .collect();
    let eq_r = eq_z_hypercube(r);
    // S(r, y) on the cube = eq(r, y − 1): the weight of row y is the eq weight of the row before it.
    let mut s: Vec<Ea4> = (0..size).map(|i| eq_r[(i + size - 1) % size]).collect();
    let mut round_evals = Vec::with_capacity(n);
    let mut rho = Vec::with_capacity(n);
    for _ in 0..n {
        let half = s.len() / 2;
        let mut h = [Ea4::ZERO; 3];
        for i in 0..half {
            let (s0, s1, f0, f1) = (s[i], s[i + half], f[i], f[i + half]);
            h[0] += s0 * f0;
            h[1] += s1 * f1;
            let (s2, f2) = (s1.double() - s0, f1.double() - f0);
            h[2] += s2 * f2;
        }
        absorb_ext(chl, &h);
        let c: Ea4 = chl.sample_algebra_element();
        s = fold_one_var(&s, c);
        f = fold_one_var(&f, c);
        round_evals.push(h.to_vec());
        rho.push(c);
    }
    let opened = prover.eval_at(t, set, &Point::new(rho), chl);
    ShiftBindProof { round_evals, opened }
}

/// VERIFY a [`ShiftBindProof`]: the round chain from `Σ_k λ^k shifted[k]`, the opening of `set`'s columns at ρ recorded
/// on `verifier` (proved by its WHIR opening), and `final == S(r, ρ)·Σ_k λ^k opened[k]`. `set` (C2: the gate's public
/// `shifted_set`) and `r` come from the statement.
#[must_use]
pub fn verify_shift_bind(
    proof: &ShiftBindProof,
    r: &[Ea4],
    shifted: &[Ea4],
    set: &[usize],
    t: usize,
    verifier: &mut LightCommitVerifier<'_>,
    chl: &mut Chl,
) -> bool {
    let n = r.len();
    let width = set.len();
    if width == 0 || shifted.len() != width || proof.opened.len() != width || proof.round_evals.len() != n {
        return false;
    }
    let lambda: Ea4 = chl.sample_algebra_element();
    let lp = powers(lambda, width);
    let mut claim = shifted.iter().zip(&lp).fold(Ea4::ZERO, |a, (&v, &l)| a + l * v);
    let mut rho = Vec::with_capacity(n);
    for h in &proof.round_evals {
        if h.len() != 3 || h[0] + h[1] != claim {
            return false;
        }
        absorb_ext(chl, h);
        let c: Ea4 = chl.sample_algebra_element();
        claim = lagrange_eval(h, c);
        rho.push(c);
    }
    verifier.add_claim_at(t, set, &proof.opened, &Point::new(rho.clone()), chl);
    let folded = proof.opened.iter().zip(&lp).fold(Ea4::ZERO, |a, (&v, &l)| a + l * v);
    claim == shift_mle(r, &rho) * folded
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air_zerocheck::mle_eval;
    use p3_field::PrimeCharacteristicRing;
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    fn chl() -> Chl {
        let mut rng = SmallRng::seed_from_u64(0xDB45_2);
        Chl::new(crate::hiding_decider::Perm16::new_from_rng_128(&mut rng))
    }

    /// ⭐⭐ SPEED R4-G (2026-11-10) — THE BLOCK PROOFS' FOLDS GRIND AT THE FOLDED CODE, AND EVERY SUB-ROUND STILL SCORES
    /// 100 BITS UNDER THE JOHNSON BOUND. A block costs two light-decider proofs of 23 stacked variables.
    /// (a) The SHAPE is the one `WhirConfig::new` derives — the group figure is still 21 bits, the rounds, rates and
    ///     queries are those of the same parameters without the per-fold grind — so no proof byte moves.
    /// (b) The first group grinds 20, 19, 18, 17; every later group one bit less per fold from one under its group
    ///     figure; in all, under a quarter of the candidates the group figures ask.
    /// (c) Every light shape (8 to 24 stacked variables) scores at least `COMMITTED_SECURITY` bits with each sub-round
    ///     scored at its own code and its own grind (`proven_bits::scored_bits`).
    /// (d) RED arm — the score is not vacuous: one sub-round ground ONE bit short of its figure scores under the target,
    ///     and the weakest term names that sub-round.
    /// (e) The carriers a circuit verifies keep `new`'s schedule: LIVE and both certificate carriers carry no per-fold list.
    /// TWO-PARTY-REVIEWED: a configuration is one function of (stacked variables, parameters) that the prover and the
    /// verifier each compute; this pins that function. The prover-against-verifier boundary of the schedule (a per-fold
    /// proof refused by a group-figure verifier, a tampered witness refused) is `p3_whir`'s
    /// `speed_r4g_fold_grinds_sized_at_the_folded_code_prove_verify_and_are_enforced`.
    #[test]
    fn speed_r4g_the_block_proofs_folds_grind_at_the_folded_code_and_every_sub_round_scores_100_bits() {
        use crate::committed_air::proven_bits::{proven_regime, scored_bits};
        use crate::committed_air::COMMITTED_SECURITY;
        use p3_whir::parameters::SecurityAssumption::{JohnsonBound, JohnsonBoundWide};
        let block = pcs_with(23, LIGHT_COMMIT_PARAMS).config;
        let plain = pcs_with(23, CarrierParams { fold_grind_per_fold: false, ..LIGHT_COMMIT_PARAMS }).config;
        // (a)
        assert!(block.fold_grinds.is_some() && plain.fold_grinds.is_none(), "CALIBRATION: the two configurations differ in the per-fold list only");
        // SPEED R10: the light rounds are sized at the wider Johnson slack — 18 where the reference slack asks 21, and
        // 94, 60, 45, 35 + 29 queries where it asks 91, 59, 44, 35 + 29 (the same rounds and rates; each count is
        // `queries(84 bits, rate)` and the round's own grind covers what the ceiling leaves, 15 or 16 bits).
        assert_eq!(proven_regime(&block), JohnsonBoundWide, "CALIBRATION: a light round is built in the wider Johnson regime");
        assert_eq!(block.starting_folding_pow_bits, 18, "CALIBRATION: the first group's figure at 23 variables");
        let reference = pcs_with(23, CarrierParams { regime: JohnsonBound, ..LIGHT_COMMIT_PARAMS }).config;
        assert_eq!(reference.starting_folding_pow_bits, 21, "CALIBRATION: the same group at the reference slack");
        let queries = |c: &p3_whir::parameters::WhirConfig<Ea4, Fa4, Chl>| c.round_parameters.iter().map(|r| r.num_queries).chain([c.final_queries]).collect::<Vec<_>>();
        assert_eq!(queries(&reference), vec![91, 59, 44, 35, 29], "CALIBRATION: the reference slack's queries");
        assert_eq!(queries(&block), vec![94, 60, 45, 35, 29], "⛔ the wider slack's queries are not the ones its slack asks");
        assert_eq!(
            block.round_parameters.iter().map(|r| (r.num_variables, r.log_inv_rate)).collect::<Vec<_>>(),
            reference.round_parameters.iter().map(|r| (r.num_variables, r.log_inv_rate)).collect::<Vec<_>>(),
            "⛔ the slack moved the rounds or the rates"
        );
        let shape = |c: &p3_whir::parameters::WhirConfig<Ea4, Fa4, Chl>| {
            (
                c.starting_folding_pow_bits,
                c.commitment_ood_samples,
                c.round_parameters.iter().map(|r| (r.num_queries, r.pow_bits, r.folding_pow_bits, r.ood_samples, r.num_variables, r.log_inv_rate)).collect::<Vec<_>>(),
                c.final_queries,
                c.final_pow_bits,
                c.final_sumcheck_rounds,
                c.final_folding_pow_bits,
            )
        };
        assert_eq!(shape(&block), shape(&plain), "⛔ the per-fold grind moved the shape — rounds, rates or queries differ, so proof bytes would");
        // (b)
        assert_eq!(block.starting_fold_grinds(), vec![17, 16, 15, 14], "⛔ the first group's folds do not grind at the folded code");
        assert_eq!(reference.starting_fold_grinds(), vec![20, 19, 18, 17], "CALIBRATION: the same folds at the reference slack");
        let candidates = |g: &[usize]| g.iter().map(|b| 1u64 << b).sum::<u64>();
        let all = |c: &p3_whir::parameters::WhirConfig<Ea4, Fa4, Chl>| {
            candidates(&c.starting_fold_grinds()) + (0..c.round_parameters.len()).map(|i| candidates(&c.round_fold_grinds(i))).sum::<u64>()
        };
        // Every later group: sub-round `s` is ground at the regime's own figure for the code with `s` fewer variables.
        // The bound is linear in the code length, so that is ABOUT one bit less per fold — and exactly so on a long
        // code. On a short one the wider regime's every-term bound (the theorem's `rho = k/n`, one less than the
        // dimension) rounds a fold UP one bit: MEASURED on the first run of this pin under R10, round 3 (2^7
        // coefficients at rate 1/64) grinds 11, 11, 10, 9 where "one bit less per fold" read 11, 10, 9, 8. So the pin
        // holds each fold to the regime's figure at ITS code, and to the band that figure can fall in: never less than
        // one bit per fold under the group's figure, never above it.
        let regime = block.params.soundness_type;
        for (i, rc) in block.round_parameters.iter().enumerate() {
            let folds = block.folding_factor(i + 1);
            let want: Vec<usize> = (1..=folds)
                .map(|s| regime.folding_pow_bits(block.params.security_level, <Ea4 as p3_field::Field>::bits(), rc.num_variables - s, rc.log_inv_rate).ceil() as usize)
                .collect();
            let got = block.round_fold_grinds(i);
            assert_eq!(got, want, "⛔ round {i}: a fold is not ground at the regime's figure for the code it acts on");
            for (s, g) in (1..=folds).zip(got.iter()) {
                assert!(
                    *g <= rc.folding_pow_bits && g + s >= rc.folding_pow_bits,
                    "⛔ round {i}, fold {s}: {g} bits is outside one bit per fold under the group's figure {}",
                    rc.folding_pow_bits
                );
            }
        }
        eprintln!(
            "[speed-r4g] 23 variables: first group {:?}, rounds {:?}; candidates per opening {} (group figures: {})",
            block.starting_fold_grinds(),
            (0..block.round_parameters.len()).map(|i| block.round_fold_grinds(i)).collect::<Vec<_>>(),
            all(&block),
            all(&plain)
        );
        assert!(4 * all(&block) < all(&plain), "⛔ the per-fold schedule grinds {} candidates against {}", all(&block), all(&plain));
        // (c) and (d)
        let target = COMMITTED_SECURITY as f64;
        // every arity a light round admits, at the rate `light_params` gives it (V2-R: 1/8 up to 25, 1/4 at 26)
        for v in (8..=26usize).filter(|&v| light_arity_admissible(v)) {
            let cfg = pcs_with(v, light_params(v)).config;
            let (bits, weakest) = scored_bits(&cfg, proven_regime(&cfg));
            assert!(bits >= target, "⛔⛔ {v} variables: {bits:.2} proven bits under the Johnson bound (weakest: {weakest}) — a fold is under-ground");
            // one bit short in the first sub-round that grinds at all
            let mut short = cfg.clone();
            let grinds = short.fold_grinds.as_mut().expect("a light round carries the per-fold list");
            if let Some(g) = grinds.starting.iter_mut().find(|g| **g > 0) {
                *g -= 1;
                let (bits, weakest) = scored_bits(&short, proven_regime(&short));
                assert!(
                    bits < target && weakest.starts_with("starting fold, sub-round"),
                    "⛔ {v} variables: a sub-round ground one bit short still scores {bits:.2} bits (weakest: {weakest}) — the score does not read the per-fold grind"
                );
            }
        }
        // (e)
        assert!(pcs_with(20, CarrierParams::LIVE).config.fold_grinds.is_none(), "⛔ a LIVE carrier carries a per-fold grind list its circuit verifier does not read");
        for (name, cfg) in crate::committed_air::proven_bits::production_shapes() {
            assert_eq!(cfg.fold_grinds.is_some(), name.starts_with("LIGHT_COMMIT_PARAMS"), "⛔ {name}: the per-fold grind is on the wrong carriers");
        }
    }

    /// INSTRUMENT (speed5, 2026-11-17, the ledger proof's size): the light round's WHIR schedule at the tree ledger's stacked
    /// arity (19) and the block ledger's older 23, at start rates 1/4 (today), 1/8 and 1/16 — every round's queries, their sum
    /// (each query opens a leaf and a Merkle path a round: the bytes' proxy), and the proven bits under the regime. A rate
    /// whose shape still scores at least `COMMITTED_SECURITY` with fewer queries is a smaller proof at the same security.
    #[test]
    fn v2_light_round_schedule_by_start_rate() {
        use crate::committed_air::proven_bits::{proven_regime, scored_bits};
        for v in [19usize, 23] {
            for sr in [2usize, 3, 4] {
                let p = CarrierParams { start_rate: sr, ..LIGHT_COMMIT_PARAMS };
                if !(v + p.start_rate <= 24 + p.first_fold) {
                    eprintln!("[v2-rate] nv {v} start_rate {sr}: past the two-adicity bound");
                    continue;
                }
                let cfg = pcs_with(v, p).config;
                let qs: Vec<usize> = cfg.round_parameters.iter().map(|r| r.num_queries).chain([cfg.final_queries]).collect();
                let (bits, weakest) = scored_bits(&cfg, proven_regime(&cfg));
                eprintln!(
                    "[v2-rate] nv {v} start_rate {sr} (rate 1/{}): rounds {} queries {qs:?} sum {} | proven {bits:.2} bits (weakest {weakest}) | start-fold grinds {:?}",
                    1usize << sr,
                    cfg.round_parameters.len(),
                    qs.iter().sum::<usize>(),
                    cfg.starting_fold_grinds()
                );
            }
        }
    }

    /// INSTRUMENT (DB-452 sizing): the WHIR schedule `pcs_with` derives for a light round at each stacked arity, per
    /// candidate parameter set — every grind must stay below the field's 31 bits, and the money path's config must be
    /// the one used wherever it can be.
    #[test]
    fn db452_light_round_whir_schedule_by_stacked_arity() {
        let cands: [(&str, CarrierParams); 5] = [
            ("LIVE", CarrierParams::LIVE),
            ("LIVE growth 2", CarrierParams { rate_growth: 2, ..CarrierParams::LIVE }),
            ("LIVE growth 1", CarrierParams { rate_growth: 1, ..CarrierParams::LIVE }),
            ("LIVE rate 1 growth 1", CarrierParams { start_rate: 1, rate_growth: 1, ..CarrierParams::LIVE }),
            ("LIVE rate 3 growth 1", CarrierParams { start_rate: 3, rate_growth: 1, ..CarrierParams::LIVE }),
        ];
        for nv in [18usize, 20, 21, 22, 23, 24] {
            for (name, p) in &cands {
                if nv + p.start_rate > 24 + p.first_fold {
                    continue;
                }
                let cfg = pcs_with(nv, *p).config;
                let rounds: Vec<(usize, usize, usize)> =
                    cfg.round_parameters.iter().map(|r| (r.num_queries, r.pow_bits, r.folding_pow_bits)).collect();
                let max = rounds
                    .iter()
                    .map(|r| r.1.max(r.2))
                    .chain([cfg.starting_folding_pow_bits, cfg.final_pow_bits, cfg.final_folding_pow_bits])
                    .max()
                    .unwrap_or(0);
                // grind seconds at the measured 1,012 ms per 24-bit grind (doubling per bit), once per folded variable;
                // queries summed as the byte proxy (each opens one leaf + one Merkle path per round).
                let g = |b: usize| if b == 0 { 0.0 } else { 1.012 * 2f64.powi(b as i32 - 24) };
                let grind_s = 4.0 * g(cfg.starting_folding_pow_bits)
                    + rounds.iter().map(|r| g(r.1) + 4.0 * g(r.2)).sum::<f64>()
                    + g(cfg.final_pow_bits);
                let q: usize = rounds.iter().map(|r| r.0).sum::<usize>() + cfg.final_queries;
                eprintln!(
                    "[db452-sched] nv {nv:>2} {name:<22} start-fold-grind {:>2} rounds (q, grind, fold-grind) {rounds:?} final q {} grind {} fold-grind {} | MAX {max} · est grind {grind_s:.1} s · queries {q}",
                    cfg.starting_folding_pow_bits, cfg.final_queries, cfg.final_pow_bits, cfg.final_folding_pow_bits
                );
            }
        }
    }

    /// INSTRUMENT (prove cost, 2026-11-03): the hash the light rounds spend half their CPU in, against the byte hash Plonky3's own
    /// non-recursive configuration would use. One thread: Poseidon2 width-16 permutations (scalar and NEON-packed, 32 B absorbed per
    /// permutation at rate 8) against blake3 over 64-byte blocks and over a 1 KiB row (its SIMD chunk path).
    #[test]
    #[ignore]
    fn prove_cost_poseidon2_against_blake3_on_this_machine() {
        use p3_field::{Field, PrimeCharacteristicRing};
        use p3_symmetric::Permutation;
        type P = <Fa4 as Field>::Packing;
        let mut rng = SmallRng::seed_from_u64(0xDB45_2);
        let perm = crate::hiding_decider::Perm16::new_from_rng_128(&mut rng);
        let n = 1u64 << 20;
        let t = std::time::Instant::now();
        let mut st = [Fa4::ZERO; 16];
        for i in 0..n {
            st[0] += Fa4::from_u64(i);
            perm.permute_mut(&mut st);
        }
        let scalar = n as f64 / t.elapsed().as_secs_f64();
        let t = std::time::Instant::now();
        let mut pst = [P::ZERO; 16];
        for _ in 0..n {
            pst[0] += P::ONE;
            perm.permute_mut(&mut pst);
        }
        let lanes = <P as p3_field::PackedValue>::WIDTH as f64;
        let packed = lanes * n as f64 / t.elapsed().as_secs_f64();
        let t = std::time::Instant::now();
        let mut b = [0u8; 64];
        for i in 0..4 * n {
            b[..8].copy_from_slice(&i.to_le_bytes());
            let h = blake3::hash(&b);
            b[8..40].copy_from_slice(h.as_bytes());
        }
        let b64 = 4.0 * n as f64 / t.elapsed().as_secs_f64();
        let row = vec![7u8; 1024];
        let t = std::time::Instant::now();
        let mut sink = 0u8;
        for _ in 0..n / 4 {
            sink ^= blake3::hash(&row).as_bytes()[0];
        }
        let b1k = (n / 4) as f64 / t.elapsed().as_secs_f64();
        eprintln!(
            "[hash-cost] Poseidon2-16 scalar {:.2} M perm/s = {:.0} MB/s absorbed · NEON {lanes}-lane {:.2} M perm/s = {:.0} MB/s · blake3 64 B {:.2} M/s = {:.0} MB/s · blake3 1 KiB {:.2} k/s = {:.0} MB/s (sink {sink}, {:?})",
            scalar / 1e6, scalar * 32.0 / 1e6, packed / 1e6, packed * 32.0 / 1e6, b64 / 1e6, b64 * 64.0 / 1e6, b1k / 1e3, b1k * 1024.0 / 1e6, st[0]
        );
    }

    /// INSTRUMENT (DB-452 prove cost): wall time of one Fiat–Shamir grind at each depth a light round's schedule uses.
    #[test]
    fn db452_grind_cost_by_bits() {
        use p3_challenger::GrindingChallenger;
        let mut ch = chl();
        for bits in [16usize, 20, 21, 22, 23, 24] {
            let t = std::time::Instant::now();
            let reps = 3;
            for i in 0..reps {
                ch.observe(Fa4::from_u64(i));
                let _ = ch.grind(bits);
            }
            eprintln!("[db452-grind] {bits} bits: {} ms per grind (mean of {reps})", t.elapsed().as_millis() / reps as u128);
        }
    }

    /// `shift_mle` agrees with its definition on the whole cube (`S(x,y) = 1` iff `y = x + 1 mod N`) and its MLE equals
    /// `MLE(rot(c))(r) = Σ_y S(r,y)·c(y)` at a random point.
    #[test]
    fn db452_shift_mle_is_the_next_row_relation_on_the_cube_and_off_it() {
        let n = 4usize;
        let size = 1usize << n;
        let bits = |i: usize| -> Vec<Ea4> { (0..n).map(|k| Ea4::from(Fa4::from_u64(((i >> (n - 1 - k)) & 1) as u64))).collect() };
        for i in 0..size {
            for j in 0..size {
                let want = if j == (i + 1) % size { Ea4::ONE } else { Ea4::ZERO };
                assert_eq!(shift_mle(&bits(i), &bits(j)), want, "S({i},{j})");
            }
        }
        let mut rng = SmallRng::seed_from_u64(7);
        let col: Vec<Fa4> = (0..size).map(|_| Fa4::from_u64(u64::from(rng.random::<u32>()))).collect();
        let rot: Vec<Fa4> = (0..size).map(|i| col[(i + 1) % size]).collect();
        let r: Vec<Ea4> = (0..n).map(|_| Ea4::from(Fa4::from_u64(u64::from(rng.random::<u32>())))).collect();
        let via_s = (0..size).fold(Ea4::ZERO, |a, y| a + shift_mle(&r, &bits(y)) * Ea4::from(col[y]));
        assert_eq!(via_s, mle_eval(&rot, &r));
    }

    /// The shift bind on a real committed round: honest ACCEPTS; a shifted value off by one REFUSES (round chain), an
    /// opening at ρ that is not the commitment's REFUSES (WHIR), and a table shorter than the first fold round-trips
    /// through the padded arity.
    /// R4 — THE CONSTANT-SIZE SIBLING SLOTS: a real round re-encodes SMALLER and to the SAME length whatever positions its
    /// queries drew (two tables, two transcripts), decodes to the byte-identical opening and verifies; and every form the
    /// encoder would not write is refused — at the decode (a non-zero digest in a slot no query reads, a position past its
    /// level, another `l0`, a slot or position short or long) or by the unchanged WHIR verifier (a read slot's digest
    /// altered, a position moved to another valid one).
    #[test]
    fn r4_a_light_round_sends_its_top_levels_as_constant_slots_and_every_other_form_is_refused() {
        let nv = 14usize;
        let round_of = |seed: u64| -> (LightRound, Vec<Ea4>) {
            let mut rng = SmallRng::seed_from_u64(seed);
            let cols: Vec<Vec<Fa4>> =
                (0..4).map(|_| (0..1usize << nv).map(|_| Fa4::from_u64(u64::from(rng.random::<u32>()))).collect()).collect();
            let mut pch = chl();
            let mut prover = LightCommitProver::commit(vec![cols], &mut pch).expect("commit");
            let pt = Point::new((0..nv).map(|_| pch.sample_algebra_element()).collect::<Vec<Ea4>>());
            let vals = prover.eval_at(0, &[0, 1, 2, 3], &pt, &mut pch);
            (prover.finish(&mut pch), vals)
        };
        let verify = |r: &LightRound, vals: &[Ea4]| -> bool {
            let mut vch = chl();
            let Some(mut v) = LightCommitVerifier::begin(&[(nv, 4)], r, &mut vch) else { return false };
            let p = Point::new((0..nv).map(|_| vch.sample_algebra_element()).collect::<Vec<Ea4>>());
            v.add_claim_at(0, &[0, 1, 2, 3], vals, &p, &mut vch);
            v.finish(&mut vch)
        };
        let (round, vals) = round_of(0x534c_4f54);
        let (other, other_vals) = round_of(0x534c_4f55);
        assert!(verify(&round, &vals) && verify(&other, &other_vals), "CONTROL: the honest rounds verify before any encoding");
        assert_ne!(round.open.query_indices, other.open.query_indices, "CONTROL: the two transcripts drew different positions");
        let plain = postcard::to_allocvec(&(&round.commitment, &round.open)).expect("the plain round encodes");
        let bytes = postcard::to_allocvec(&round).expect("the round encodes");
        let other_bytes = postcard::to_allocvec(&other).expect("the other round encodes");
        eprintln!("[light-wire] round: {} B with every path whole → {} B with slotted top levels", plain.len(), bytes.len());
        assert!(bytes.len() < plain.len(), "the slotted form is smaller than every path whole");
        assert_eq!(bytes.len(), other_bytes.len(), "⛔ the wire length depends on which positions the queries drew");
        let back: LightRound = postcard::from_bytes(&bytes).expect("the slotted form decodes");
        assert_eq!(
            postcard::to_allocvec(&(&back.commitment, &back.open)).expect("re-encodes"),
            plain,
            "the decode restores the identical opening"
        );
        assert!(verify(&back, &vals), "the decoded round verifies");
        assert_eq!(postcard::to_allocvec(&back).expect("re-encodes"), bytes, "a decoded round re-encodes to the same bytes");

        // Tampers on the wire form: decode it, or verify what it decodes to — both must refuse.
        let wire: LightRoundWire = postcard::from_bytes(&bytes).expect("the wire form decodes as itself");
        let refused = |w: &LightRoundWire| -> bool {
            let b = postcard::to_allocvec(w).expect("encodes");
            match postcard::from_bytes::<LightRound>(&b) {
                Err(_) => true,
                Ok(r) => !verify(&r, &vals),
            }
        };
        assert!(!refused(&wire), "CONTROL: the encoder's own form is accepted");
        let g = 0usize;
        let unread =
            wire.groups[g].slots.iter().position(|x| *x == [Fa4::ZERO; 8]).expect("a slot no query reads exists");
        let mut t = postcard::from_bytes::<LightRoundWire>(&bytes).unwrap();
        t.groups[g].slots[unread] = [Fa4::ONE; 8];
        assert!(refused(&t), "a non-zero digest in a slot no query reads");
        let read = wire.groups[g].slots.iter().position(|x| *x != [Fa4::ZERO; 8]).expect("a read slot");
        let mut t = postcard::from_bytes::<LightRoundWire>(&bytes).unwrap();
        t.groups[g].slots[read][0] += Fa4::ONE;
        assert!(refused(&t), "a read slot's digest altered");
        let mut t = postcard::from_bytes::<LightRoundWire>(&bytes).unwrap();
        let p0 = u16::from_le_bytes([t.groups[g].positions[0], t.groups[g].positions[1]]);
        t.groups[g].positions[..2].copy_from_slice(&(p0 ^ 1).to_le_bytes());
        assert!(refused(&t), "a position moved to another valid one");
        let mut t = postcard::from_bytes::<LightRoundWire>(&bytes).unwrap();
        t.groups[g].positions[..2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(refused(&t), "a position past its level");
        let mut t = postcard::from_bytes::<LightRoundWire>(&bytes).unwrap();
        t.groups[g].levels += 1;
        assert!(refused(&t), "another l0 than (q, d) fixes");
        let mut t = postcard::from_bytes::<LightRoundWire>(&bytes).unwrap();
        t.groups[g].slots.push([Fa4::ZERO; 8]);
        assert!(refused(&t), "one slot too many");
        let mut t = postcard::from_bytes::<LightRoundWire>(&bytes).unwrap();
        let short = t.groups[g].positions.len() - 2;
        t.groups[g].positions.truncate(short);
        assert!(refused(&t), "a position short");
        let mut t = postcard::from_bytes::<LightRoundWire>(&bytes).unwrap();
        t.groups.pop();
        assert!(refused(&t), "a query group's slots missing");
    }

    #[test]
    fn db452_shift_bind_honest_accepts_and_every_lie_is_refused() {
        for (nv, lie) in [(5usize, 0u8), (5, 1), (5, 2), (3, 0), (3, 2)] {
            let size = 1usize << nv;
            let mut rng = SmallRng::seed_from_u64(11 + nv as u64);
            let cols: Vec<Vec<Fa4>> =
                (0..3).map(|_| (0..size).map(|_| Fa4::from_u64(u64::from(rng.random::<u32>()))).collect()).collect();
            let other: Vec<Vec<Fa4>> = vec![(0..64).map(|i| Fa4::from_u64(i)).collect()];
            let mut pch = chl();
            let mut prover = LightCommitProver::commit(vec![other, cols.clone()], &mut pch).expect("commit");
            let r: Vec<Ea4> = (0..nv).map(|_| pch.sample_algebra_element()).collect();
            let mut shifted: Vec<Ea4> = cols
                .iter()
                .map(|c| mle_eval(&(0..size).map(|i| c[(i + 1) % size]).collect::<Vec<_>>(), &r))
                .collect();
            if lie == 1 {
                shifted[1] += Ea4::ONE;
            }
            absorb_ext(&mut pch, &shifted);
            let mut proof = prove_shift_bind(&cols, &[0, 1, 2], &r, 1, &mut prover, &mut pch);
            let round = prover.finish(&mut pch);
            if lie == 2 {
                proof.opened[2] += Ea4::ONE;
            }
            let mut vch = chl();
            let mut v = LightCommitVerifier::begin(&[(6, 1), (nv, 3)], &round, &mut vch).expect("begin");
            let rv: Vec<Ea4> = (0..nv).map(|_| vch.sample_algebra_element()).collect();
            assert_eq!(rv, r);
            absorb_ext(&mut vch, &shifted);
            let chain = verify_shift_bind(&proof, &r, &shifted, &[0, 1, 2], 1, &mut v, &mut vch);
            let ok = chain && v.finish(&mut vch);
            assert_eq!(ok, lie == 0, "nv {nv} lie {lie}: chain {chain}");
        }
    }
}
