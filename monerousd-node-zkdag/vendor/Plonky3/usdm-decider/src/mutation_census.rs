// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//! ⭐⭐⭐ THE MUTATION CENSUS + THE STATEMENT CENSUS (H13, user 2026-10-05: "sound is measured, not declared").
//!
//! Two of the register's hard rows asked for the same thing from two sides: (1) a WRITTEN statement per AIR, checked
//! against its constraints, and (2) a mutation census — drop each residual in turn; a mutant no pin notices is a hole.
//! The degree and free-witness censuses prove a gate sound AS WRITTEN; nothing checked that the writing binds what the
//! door relies on, and nothing checked that every residual bites. This module measures both, mechanically, with no
//! per-gate code, at the one core every prover reaches (`prove_air_zerocheck`, the hook the free-cell census uses).
//!
//! HOW. Under `#[cfg(test)]`, when `MUTATION_CENSUS=<ledger path>` is set, every (gate type, rows, columns) shape the
//! suite proves is censused once per process:
//!  - CONTROL: the honest trace's residual vector ([`AirConstraint::residuals`]) is zero on every data row; a trace
//!    that is not is a TAMPER trace proving on purpose and is reported VOID, never clean, and the shape stays unseen.
//!  - DROP-A-RESIDUAL: for each residual `i`, a single-cell perturbation at some probe row (or the row before it, for
//!    next-row reads) must move residual `i`. Two deltas are tried per cell: `+1` and `+K` for a large constant `K`
//!    (`b·(b−1)` is satisfied at both 0 and 1, so `+1` cannot move a booleanity or small-range residual; `+K` can — the
//!    first run's "dead" list was mostly these). A residual NO single-cell perturbation moves is DEAD — the gate with that
//!    residual dropped is a mutant every tamper pin survives, because no tamper can reach it.
//!  - FLIP-A-CONSTANT is the control seen from the other side: the honest row's residuals are zero exactly because the
//!    gate's constants are what they are; a residual that is identically zero (dead) is the one a flipped constant could
//!    hide in. Dead = the surviving-mutant class; the census names it.
//!  - HOMOGENEITY (the DB-213 class): whether the all-zero row satisfies the gate (no public input in any residual).
//!  One ledger row per shape: `gate \t rows \t cols \t residuals \t dead \t homogeneous \t verdict`.
//!
//! THE STATEMENT CENSUS reads that ledger: every PRODUCTION gate censused must have an entry in [`STATEMENTS`] — what
//! is proven, over which public inputs — whose residual count equals the MEASURED one, and no dead residual. A gate the
//! suite proves with no written statement is an unwritten row; a statement whose count differs from the gate's is a
//! statement about a different circuit. A gate meant as an inner AIR that still folds its residuals into one reports
//! `residuals = 1`: the statement census then checks the fold, not the parts, and says so.
//!
//! STALENESS: the pin refuses a ledger older than the decider's newest source file. A measurement of yesterday's gates
//! is not a measurement of today's.
//!
//! O1-FOOTPRINT-REVIEWED: test-only, env-gated, bounded by the number of distinct gate shapes the suite proves.
//! MUST-STAY-GREEN: the whole decider suite — the hook is inert without the variable.

use crate::air_zerocheck::{AirConstraint, OobLatch, Row};
use crate::hiding_decider::{Ea4, Fa4};
use p3_field::PrimeCharacteristicRing;
use std::io::Write;

/// The second perturbation delta: outside every boolean and small-range set a residual may test (see the module doc).
const K: u64 = 0x9E37_79B9_7F4A_7C15;

/// Rows at each end of a tall trace the escalation probes contiguously (one full 256-level insert span, plus slack).
const ESCALATION_SPAN: usize = 1024; // four 256-level insert spans: the band's padding inserts sit at the END of the trace, and the monotone law `(1−live)·live_n` is reachable only at a padding insert's boundary row that is not the last row

/// Each (gate type, rows, columns) shape is censused once per process.
static SEEN: std::sync::Mutex<Vec<(String, usize, usize, usize)>> = std::sync::Mutex::new(Vec::new());
/// How many traces of one shape the census examines before it stops looking for a row that reaches a residual.
const SHAPE_PASSES: usize = 8; // the member-row suite proves depths 0, 1, 3 and 8 of one shape after two tamper traces

fn point_of(r: usize, n: usize) -> Vec<Ea4> {
    (0..n).map(|k| if (r >> (n - 1 - k)) & 1 == 1 { Ea4::ONE } else { Ea4::ZERO }).collect()
}

fn residuals_row<C: AirConstraint>(c: &C, cols: &[Vec<Fa4>], r: usize, n: usize) -> Vec<Ea4> {
    let h = 1usize << n;
    let vals: Vec<Ea4> = cols.iter().map(|col| Ea4::from(col[r])).collect();
    let oob = OobLatch::new();
    let row = Row::new(&vals, &oob);
    let next = (r + 1) % h;
    let at = |ci: usize, _p: &[Ea4]| -> Ea4 { Ea4::from(cols[ci][next]) };
    c.residuals(&row, &at, &point_of(r, n))
}

/// Called by `prove_air_zerocheck` under `#[cfg(test)]`. Inert unless `MUTATION_CENSUS` names the ledger.
pub(crate) fn observe<C: AirConstraint>(cols: &[Vec<Fa4>], c: &C) {
    let Some(ledger) = std::env::var_os("MUTATION_CENSUS") else { return };
    let width = cols.len();
    let h = cols.first().map_or(0, Vec::len);
    if width == 0 || h < 2 || !h.is_power_of_two() || cols.iter().any(|col| col.len() != h) {
        return;
    }
    let name = std::any::type_name::<C>().to_string();
    // A shape is censused again on a LATER trace while its best census so far still has a dead residual (bounded at
    // SHAPE_PASSES traces): the first trace the suite proves may walk 3 of 8 levels or carry no padding insert, and a
    // residual only a deeper or padded trace can reach is not dead — the census just had not seen the row yet.
    {
        let seen = SEEN.lock().expect("the census lock is never held across a panic");
        let passes = seen.iter().filter(|(g, r, w, _)| g == &name && *r == h && *w == width).count();
        let clean = seen.iter().any(|(g, r, w, d)| g == &name && *r == h && *w == width && *d == 0);
        if clean || passes >= SHAPE_PASSES {
            return;
        }
    }
    let n = h.trailing_zeros() as usize;
    let data = if name.contains("Blinded<") { h / 2 } else { h };
    let k = residuals_row(c, cols, 0, n).len();
    let mut record = |verdict: &str, dead: &[usize], homogeneous: Option<bool>| {
        let line = format!(
            "{name}\t{h}\t{width}\t{k}\t{}\t{}\t{verdict}\n",
            if dead.is_empty() { "-".to_string() } else { format!("{dead:?}") },
            homogeneous.map_or("?".to_string(), |b| b.to_string())
        );
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&ledger) {
            let _ = f.write_all(line.as_bytes());
        }
        eprintln!("[mutation-census] {verdict} {name} rows={h} cols={width} residuals={k} dead={dead:?}");
    };
    // CONTROL
    let bad: Vec<usize> = (0..data).filter(|&r| residuals_row(c, cols, r, n).iter().any(|v| *v != Ea4::ZERO)).collect();
    if !bad.is_empty() {
        record("VOID", &[], None);
        return;
    }

    let mut probes: Vec<usize> = if data <= 64 { (0..data).collect() } else { (0..16).map(|q| q * data / 16).chain([1, data - 1]).collect() };
    probes.sort_unstable();
    probes.dedup();
    let zero_cols: Vec<Vec<Fa4>> = vec![vec![Fa4::ZERO; h]; width];
    let homogeneous = probes.iter().all(|&r| residuals_row(c, &zero_cols, r, n).iter().all(|v| *v == Ea4::ZERO));
    // DROP-A-RESIDUAL: which residuals does ANY single-cell perturbation reach?
    let mut reached = vec![false; k];
    let mut work = cols.to_vec();
    let deltas = [Fa4::ONE, Fa4::from_u64(K)];
    'outer: for col in 0..width {
        for &r in &probes {
            let orig = work[col][r];
            let prev = (r + h - 1) % h;
            for d in deltas {
                work[col][r] = orig + d;
                for row in [r, prev] {
                    for (i, v) in residuals_row(c, &work, row, n).iter().enumerate() {
                        if *v != Ea4::ZERO {
                            reached[i] = true;
                        }
                    }
                }
            }
            work[col][r] = orig;
            if reached.iter().all(|b| *b) {
                break 'outer;
            }
        }
    }
    let mut dead: Vec<usize> = (0..k).filter(|&i| !reached[i]).collect();
    if !dead.is_empty() && data > probes.len() {
        // ESCALATE before calling anything dead: the sampled probes may simply have missed the rows where a residual is
        // active (a selector-gated residual on a tall trace). Probe EVERY data row (bounded: a trace above 4096 rows is
        // probed on 512 evenly spaced rows) for the unreached residuals only.
        // The rows: a contiguous HEAD and TAIL (every residue of a level counter — a 256-level insert's boundary row is
        // r ≡ 255 mod 256, which a stride of 16 never meets) plus the even spread the first pass used.
        let mut rows: Vec<usize> = (0..data.min(ESCALATION_SPAN)).chain(data.saturating_sub(ESCALATION_SPAN)..data).collect();
        rows.extend((0..64).map(|q| q * data / 64));
        rows.sort_unstable();
        rows.dedup();
        'full: for col in 0..width {
            for &r in &rows {
                let orig = work[col][r];
                let prev = (r + h - 1) % h;
                for d in deltas {
                    work[col][r] = orig + d;
                    for row in [r, prev] {
                        for (i, v) in residuals_row(c, &work, row, n).iter().enumerate() {
                            if *v != Ea4::ZERO {
                                reached[i] = true;
                            }
                        }
                    }
                }
                work[col][r] = orig;
                if reached.iter().all(|b| *b) {
                    break 'full;
                }
            }
        }
        dead = (0..k).filter(|&i| !reached[i]).collect();
    }
    SEEN.lock().expect("the census lock is never held across a panic").push((name.clone(), h, width, dead.len()));
    record(if dead.is_empty() { "ok" } else { "DEAD" }, &dead, Some(homogeneous));
}

/// ⭐ THE WRITTEN STATEMENTS — one per production gate: `(type name suffix, measured residual count, what is proven over
/// which public inputs)`. The census pin checks each against the ledger: present, count equal, no dead residual.
/// A gate reaching the ledger with no entry here is an UNWRITTEN statement (red). Test-only gates are listed in
/// [`TEST_ONLY`] and are never statements.
pub const STATEMENTS: &[(&str, usize, &str)] = &[
    // ── the chain's accumulator and block carriers ────────────────────────────────────────────────────────────────
    ("AccStepConstraint", 1, "acc_out == fold(acc_in, summary) anchored at the genesis constant, plus the accumulated work of the step; every value is a committed column, public inputs: acc_in, acc_out, the step summary digest and the work figure"),
    ("FixedDegreeMergedStepConstraint", 1, "a fixed-degree merged carrier constraint plus constant residuals extra[i] = new_acc[c] − fold(prev_acc, block_pre, tags_digest)[c], zero exactly when the accumulator transition the linked absence chain rides on is honest; public inputs: prev_acc, new_acc, block_pre, tags_digest"),
    ("CarrierVerifyAir", 1, "the WHIR carrier's in-circuit verification: the committed carrier verifies against its statement bind, so a deeper fold level recursively refuses a carrier that does not; public inputs: the carrier statement digest and the fold level"),
    ("SparseFoldGate", 1, "the height-1 fold row of the count-free monotone sparse nullifier tree is well-formed: selector 1 on the live row and 0 on padding, a row-local degree-2 gate over the committed trace; public inputs: pre_root, post_root"),
    // ── notes: membership and the spend ───────────────────────────────────────────────────────────────────────────
    ("NoteMemberStepGate", 1, "note membership by recursive fold: each row folds acc_in with its sibling in the direction the bit says, rows chain from the note's leaf to exactly the block root; public inputs: the note commitment leaf and the block's membership root"),
    ("NoteMemberRowGate", 1808, "the one-step note membership carrier on the blinded committed path: one row proves the spent note's commitment is a member of the named record's set, hiding under the spender's per-send blinding lanes; public inputs: the record root, the blinded commitment and the send's statement bind"),
    ("SpendConservationGate", 1, "spend conservation over u64 values as four 16-bit limbs (no reduction mod p): inputs equal outputs plus fee, each public value welded limb-wise into the transcript; public inputs: the output commitments, the nullifier and the fee"),
    ("StakeGate", 3164, "the stake carrier: the locked value and the reward derive from the committed stake inputs through whole in-circuit permutations, binding the one output note commitment to sk ‖ inner block ‖ inner out ‖ outer block ‖ cm; public inputs: the stake statement bind and the output commitment"),
    // ── LogUp buses ────────────────────────────────────────────────────────────────────────────────────────────────
    ("LogupHConstraint", 1, "the LogUp helper column is the correct rational bus term: h·(α − value) − mult == 0 on every row, with h reconstructed from its limbs; public inputs: α and the bus multiplicities"),
    ("LogupKeyfoldConstraint", 1, "the LogUp helper over an inline-folded bus key keyfold = idx + Σ β^{i+1}·val[i] (leaf_bus_key): h·(α − keyfold) − mult == 0 on every row; public inputs: α, β and the multiplicities"),
    // ── confidential solvency (the peg's over-collateralisation, proven without any plaintext total) ───────────────
    ("ConservationLimbAir", 1, "a + b == s over 16 carry-linked 16-bit limbs, every carry in {0,1} and no carry out of the top limb (a 257th bit is refused); public inputs: the three value commitments"),
    ("CompareGeLimbAir", 1, "a >= b limb-wise over 16-bit limbs with carry-linked borrows, fail-closed on any out-of-range limb; public inputs: the two value commitments"),
    ("ScaleByConstAir", 1, "s == c·a for a consensus constant c, as a 17-limb bit decomposition with carry bounds and the input limbs' own range bind; public inputs: the input and result commitments and the constant"),
    ("CommitOpenAir", 1, "one Poseidon2 compression opens a value commitment: the whole permutation then the digest it produced equals the committed digest; public inputs: the commitment digest"),
    ("BoundTransitionAir", 1, "the solvency bound transition: reserve' and minted' follow from reserve, minted and the move under the collateral ratio, every value hidden behind its commitment; public inputs: the four value-hiding commitments"),
    ("PinnedBoundTransitionAir", 1, "BoundTransitionAir with the four value-hiding commitments pinned to consensus-known constants instead of free columns; public inputs: the four consensus commitments"),
    ("PinnedBoundTransitionDeltaAir", 1, "the pinned bound transition stated as a delta: the move between two consensus-known commitment pairs stays within the ratio; public inputs: the pinned before/after commitments"),
    ("PinnedBoundTransitionBothAir", 1, "the pinned bound transition on both the reserve and the minted side at once; public inputs: both pairs of consensus commitments"),
    ("PinnedBondAir", 1, "bond conservation a + delta == s bound to the two consensus-known bond commitments (a→a_commit, s→s_commit), no backing term; public inputs: the two bond commitments"),
    ("TransitionAir", 1, "a confidential state transition over committed values: the after-state commitment equals the before-state commitment moved by the committed delta under the conservation limb law; public inputs: the before, after and delta commitments"),
    ("PoolStepAir", 1, "one stability-pool step: the pool's committed balance after the step equals before plus deposits minus the drain the epoch close allowed, never owing more than it holds; public inputs: the pool commitments before and after and the epoch parameters"),
    ("WithdrawAir", 1, "a confidential withdrawal: the released amount leaves the committed reserve exactly once and the remainder stays within the solvency bound; public inputs: the reserve commitments before and after and the release commitment"),
    ("YieldMintAir", 1, "the custody-yield mint: the minted yield equals the pendulum rate applied to the eligible committed weight for the epoch, in-circuit, with the reserve kept confidential; public inputs: the epoch rate, the weight commitment and the minted commitment"),
    ("LiquidationAmountAir", 1, "the liquidation amount: the seized value is the committed shortfall scaled by the consensus penalty constant, laid as consecutive limb columns on every row of the replicated trace; public inputs: the shortfall commitment and the penalty constant"),
    // ── the DSOL machine ───────────────────────────────────────────────────────────────────────────────────────────
    ("DsolCpuGate", 1, "the DSOL machine as constraints: the witness is an execution the machine could have made from the named contract and storage root to the produced storage root and outputs; public inputs: the contract id, the storage roots before and after and the outputs digest"),
    // ── the recursive verifier's own AIRs (whir_rec_block, whole_chain, recursion_bound, transcript_bind) ──────────────
    ("FixedDegreeMergedConstraint", 1, "the O(1) recursion's merged row relation V + γ^shift·O: the fixed-degree-3 verifier half and the opening half are γ-separated with no overlapping powers, so the whole relation has degree max(3, wire_size+1) independent of the inner proof; public inputs: the merged carrier's statement bind"),
    ("BoundStepConstraint", 1, "the recursion bound's step relation: the inner round polynomial, interpolated at the challenge by the same Lagrange formula the native verifier uses (air_zerocheck::lagrange_eval), equals the claimed next-round sum, so circuit and native verifier agree on every bound step; public inputs: the step's challenge and claimed sums"),
    ("OodCheckZerocheckConstraint", 1, "the recursive verifier's out-of-domain check: the committed OOD lanes (EXT_D base limbs each) lift to extension values through the basis Σ limb_i·Xⁱ and satisfy acc − q·z_h == 0 as one extension equation; public inputs: the OOD point, z_h and the claimed acc"),
    ("OodInputZerocheckConstraint", 1, "the OodInput rec-AIR (width 1): the single active column is boolean on every row, active·(active−1) == 0; its z_h and q are PUBLIC values the verifier sends, never columns; public inputs: z_h, q"),
    ("SymEvalR6Constraint", 1, "the composed SymEvalR6 r6-table constraint: the twelve register-op relations (γ⁰…γ¹¹) and the row_idx transition family as one row-local γ-batch; public inputs: the table's evaluation claims"),
    ("SymEvalR6FullConstraint", 1, "the FULL row-local constraint of the production SymEvalR6Leaf rec trace: register-op relations, the row_idx transition and the is_out boundary as one γ-batch; public inputs: the leaf's statement values"),
    ("SymEvalR6IsOutConstraint", 1, "the is_out column (SYMX_ISOUT) is boolean, equals 1 on the last hypercube row (Π x_k) and 0 on every transition row — exactly what the real rec r6t trace satisfies; public inputs: none beyond the row point"),
    ("SymEvalR6RegConstraint", 1, "the per-coefficient register relation out[k]·op_active == op(a,b)[k] for k in 0..EXT_D with op in {add, sub, ext-mul, neg, copy} over Fa4[X]/(X⁴−3); public inputs: the op selectors' claims"),
    ("SymEvalR6RowIdxTransitionConstraint", 1, "the strict row sequence row_idx = 0,1,2,…: the first row is 0 under the is-first selector Π(1−x_k) and every transition increments by one through the cyclic shift σ (shifted_opened); public inputs: none beyond the row point"),
    ("WholeChainMainConstraint", 1, "the γ-batched row-local main constraint over the light-decider openings, reconstructed by prover and verifier from the PUBLIC AIR and public values alone (nothing about it is served); public inputs: the whole-chain statement's public values"),
    ("TieConstraint", 1, "the two-table transcript-bind batch: table 0 is the sponge over the absorbed statement, table 1 the register that ties the sponge's output to the bound transcript challenge; public inputs: the statement digest and the challenge"),
    ("IvcStepConstraint", 1, "the transcript-bind IVC batch: the merged fixed step, the transcript sponge and the accumulator step as one batch, each table satisfying its own relation with the sponge chaining the step into the transcript; public inputs: the step's statement bind and the accumulator endpoints"),
    ("SpongeChainConstraint", 1, "the Poseidon2 sponge as rows: each row is one full permutation and the chaining welds the rows into one sponge over the absorbed input; public inputs: the absorbed input digest and the squeezed output"),
    ("MerklePathConstraint", 1, "a Merkle path as an AIR: each row hashes the running accumulator with its sibling in the direction the bit says, from the PUBLIC leaf to the PUBLIC root — the only statement an opening needs; public inputs: leaf and root"),
    ("OpeningAuthConstraint", 1, "opening authentication: the leaf hashed from the value sequence refolds through its path to the PUBLIC root and the value sequence folds to the PUBLIC open_fold; the leaf itself stays private; public inputs: root and open_fold"),
    ("WorkTargetConstraint", 1, "the proof-of-work target gate: header digest and work are COMMITTED columns and the row proves the digest meets the target — an unmet target has no witness and is unprovable, not merely refused; public inputs: none, so a recursive verifier rebuilds it without the digest or the work"),
    // ── notes: spends, mints, membership ────────────────────────────────────────────────────────────────────────────
    ("SpendValidityGate", 2511, "the production single-input spend row: value_in, sk, leaf, value_out, fee, nf, the note-open lanes, the nullifier lanes, one 33-wide block per membership level and the two output notes' openings — conservation, nullifier derivation, frontier membership and output binding in one row, and (§BR-14) the four-limb weld of block A's fee limbs to the verifier's protocol fee; public inputs: value_out, the protocol fee, nf, the root, the output commitments"),
    ("MultiSpendValidityGate", 1, "the row-local N-input spend: each input block proves its note opening (B), its nullifier (C), its membership fold levels (D), its public-nullifier weld (F) and its DB-395 owner block; one conservation Σ value_in_i == value_out + fee over PRIVATE amounts, its fee limbs welded to the verifier's protocol fee (§BR-14); the two outputs bound by block E; public inputs: the nullifiers, output commitments, the protocol fee and root"),
    ("AssetSpendValidityGate", 1, "the asset-tagged spend: SpendValidityGate's column map plus the 3-column asset tag welded into every leg's note opening, so inputs and outputs are denominated in ONE asset and conservation cannot cross assets; public inputs: the spend's publics and the asset tag"),
    ("SpendMainGate", 1, "the spend-main row: conservation in == out + fee over the range-bound u64 block plus the twenty Poseidon-nullifier lane residuals binding nf to (sk, leaf), γ-folded; public inputs: out, fee, nf"),
    ("SpendMembershipGate", 1, "a note's frontier membership: the leaf commitment folds through the depth-d copath with per-level direction bits (true = right child) to the public frontier root; public inputs: the root"),
    ("MintValidityGate", 1, "the native-USDm mint row: the output commitment is the in-circuit Poseidon opening of (value, spend secret) with NO root, depth or membership, so a mint is never a path by which a capacity ceiling re-enters; public inputs: value and output commitment"),
    ("MintValidityCommittedGate", 1, "the native-USDm mint on the committed path: the note commitment opens to (value, owner opening) with the value's 16 limbs range-bound inside the opening gadget (DB-362); no root, depth or membership; public inputs: the note commitment and value"),
    ("AssetMintValidityGate", 1, "the asset-tagged mint row: the HEAD layout is the mint row plus the three asset-tag columns, and the inner round of the two-round opening P([t0,t1,t2,0], sk) after the range block binds the output commitment to the declared tag; public inputs: value, asset tag, output commitment"),
    ("AssetMintValidityCommittedGate", 1, "the asset-tagged mint on the committed path: the minted note's commitment opens to (value, asset tag, owner opening) with the value's 16 limbs range-bound inside the opening gadget (DB-362), no root, depth or membership; public inputs: the note commitment and the asset tag lanes"),
    ("RewardFollowsPrincipalGate", 1, "the reward note's spend secret is P(REWARD_KEY_LANES, sk_principal) in-circuit — the derivation the wallet seals the reward under — so a reward note can only ever be spent by the principal's owner (per-user derived, never one value for all); public inputs: the principal's and the reward's public lanes"),
    ("MemberPathGate", 550, "the one-step membership relation over a MEMBER_PATH_DEPTH-row trace with blinded-boundary masks, unfolded residuals and the declared rotation: the leaf refolds through its copath to the stated root; public inputs: MEMBER_PATH_DOMAIN ‖ the four digests the bind absorbs"),
    ("MemberRingAir", 1, "the member ring's per-table circuit: the Step table (zero == 0, is_spend ∈ {0,1}, the anchor bound by the bus and the member ledger's column ties), the Mult table (zero == 0, negm bound by the bus balance, (1 − on_stride(x))·s_spend == 0 with on_stride a function of the evaluation POINT, never a prover choice) and the Chain table (the ring's sponge chain ending at the PUBLIC ring_digest); public inputs: the ring digest"),
    ("MemberLedgerAir", 1, "the member ledger's per-table circuit: the member class's own bound tables, the ring's MULT and CHAIN tables, and on every step row the ledger laws folded from γ^K past every power the class's bound step uses — L1 is_spend ∈ {0,1}; L2 the published anchor lane is zero (the anchor is looked up in the ring, never travels); L3 a spend publishes its absorbed lc ‖ binder ‖ outs; L4 a cover row's lc' is P(COVER_LC_DOMAIN ‖ slot_lc, seed) under the header seed commitment, so a spend row is matched only by a real path; public inputs: the header seed commitment and the ring digest, the step tuples published through the settlement delta"),
    ("SplitStepGate", 1, "one split-ladder step: N_cur = P(sk, S_cur), S_next = P([v_next,0,0,0], sk), X_cur = P(N_cur, S_next), the ladder accumulator folds X_cur, the base check binds the anchor leaf, and the x⁷ anchor/leaf commitment chains weld only when seal is set; public inputs: the ladder endpoints and the sealed commitments"),
    ("SlotLedgerRowGate", 1, "one slot-ledger row: the five absorbed digests chain through the permutation into the seed commitment, and law B8 (1−s)·(1−j)·block_out welds the published block when the row is neither a skip nor a join; public inputs: the seed commitment and the published block"),
    // ── the nullifier set: inserts, non-membership, the sparse tree, the band ───────────────────────────────────────
    ("NullifierInsertGate", 1, "one sparse-tree nullifier insert: the leaf hash binds to its seed, the low neighbour is strictly below the nullifier in canonical bit-magnitude order, and the post root is the fold of the flipped leaf through the copath; public inputs: pre_root, post_root, nullifier"),
    ("NullifierBlockGate", 1, "the nullifier-insert block: per-row insert validity, the pre→post root chain across rows (the cyclic-shift σ carry) and the block-boundary binds to the public pre and post roots; public inputs: pre_root and post_root"),
    ("NullifierBlockGatePadded", 1, "NullifierBlockGate with a boolean is_real selector: a real row inserts, a padding row is the no-op identity post == pre, and the same root chain and boundary binds hold; public inputs: pre_root, post_root"),
    ("NfUnspentStepGate", 1, "one step of the nullifier non-membership chain: the running Poseidon absorb over the block's tags advances by one tag and the nullifier differs from that tag in the selected limb (one-hot selector, witnessed inverse); public inputs: the chain endpoints and the nullifier"),
    ("NfUnspentBatchGate", 1, "N nullifiers proved absent from one block's tag set at once: the absorb chain over the block's tags (columns 0..27) is proved once and each nullifier carries its own one-hot differing-limb selector and inverse, so a tag equal to ANY batched nullifier is unsatisfiable; public inputs: the block's tag digest and the N nullifiers"),
    ("CoverOrSpendGate", 713, "every carried tag is EITHER a decoy the prover holds the cover secret for OR a real spend whose note opening the prover holds, with the real-input count a WITNESS column (K = Σs never appears) so a 1-input and a 5-input tx are indistinguishable at one width; public inputs: domain ‖ W ‖ tags"),
    ("AccFoldGate", 1, "the one-row leaf-fold carrier of the nullifier accumulator: the block's output lanes are welded to the PUBLIC leaf the native addition check consumes (new_acc = prev_acc ⊞ leaf is native), so the proof attests the derivation the native check uses; public inputs: domain ‖ prev_acc ‖ post ‖ digest ‖ new_acc ‖ leaf"),
    ("SparseChainGate", 1, "the sparse chain's transition layout: per-row Poseidon on both chains, the σ accumulator chain, and the first/last boundary welds to the endpoint roots; public inputs: the endpoint roots"),
    ("SparseChainLink", 1, "one insert's table of the streamed sparse chain: interior links carry no endpoint weld, the first and last tables weld to block_pre/block_post, and the committed-cell cross-tie post_i == pre_{i+1} is the double-spend gate (interior roots never exposed); public inputs: block_pre, block_post"),
    ("SparseChainFolded", 1, "the N-insert sparse chain in ONE table: per-row Poseidon on both chains, the σ accumulator chain, with is_start/is_end welds generalising SparseChainLink's first/last welds — byte-identical to it at N = 1; public inputs: block_pre, block_post"),
    ("SparseBlockGate", 1, "the nested sparse-nullifier block: the whole block_pre → block_post chain of inserts proved in one circuit with the intermediate roots private; public inputs: block_pre and block_post"),
    ("SparseBandGate", 649, "the band sub-carrier of the sparse nullifier tree: per insert both Poseidon chains fold the tag through 256 levels under a boolean direction, the running root chains insert to insert from the public pre to the public post root, the live flag is boolean and monotone and is counted to the public real count, and every tag's bits are absorbed into the public tags digest; public inputs: pre, post, n_real, the tags digest"),
    ("SparseKeyedGate", 1, "the keyed sparse nullifier block carrier, two tables under one constraint: table 0 is SparseBlockGate (the block_pre → block_post insert chain, intermediate roots private), table 1 the keys-digest chain — 2 rows per insert, the running digest absorbs each insert's key lanes times live, live is 1 for every real insert and 0 for every padding insert by the PUBLIC bind_at selector, the lanes frozen within an insert and column-tied to the chain table — from keys_digest_init() to the PUBLIC digest; public inputs: block_pre, block_post, the keys digest and the real count it absorbs"),
    ("CompactBandGate", 1, "the compact shard nullifier tree's band carrier (DB-453), two tables under one constraint: table 0 the chain gate (DB-453 §4.4 laws 1–8: per insert a 63-level compact window plus a leaf row fold the key to its shard root, chained insert to insert from the public pre root to the public post root), table 1 the ten-lane keys-digest chain, the twin of SparseKeysDigestGate (the live laws, the frozen lanes, from compact_keys_digest_init to the PUBLIC digest); public inputs: the endpoint roots and the keys digest"),
    // ── the DEX and the stability pool ───────────────────────────────────────────────────────────────────────────────
    ("MakerHalfGate", 1, "the maker's half of a DEX fill: the resting note opens to ONE lot of asset_a and is nullified, and the pre-built payout note opens to exactly pay_b of asset_b — proven by the maker, the only party able to open that note, so a zero-opening payout cannot be published; public inputs: the fill terms, the nullifier, the payout commitment"),
    ("TakerHalfGate", 1, "the taker's half of a DEX fill: the taker's input notes open and are nullified, the maker is paid exactly pay_b, the taker receives one lot, and the fee is BURNED by conservation — paid to nobody, with no new mint path — so fee evasion has no proof at all; public inputs: the fill terms, the nullifiers, the output commitments"),
    ("PoolDepositGate", 2809, "a stability-pool deposit: the deposited note opens and is nullified under its owner's DB-395 secret, the receipt is sealed to the depositor's OWN secret, the change note opens to the remainder, and the pool's committed (P, S) snapshot words are bound; public inputs: the nullifier, the receipt and change commitments, the snapshot words"),
    ("PoolReceiptGate", 3734, "a stability-pool receipt redemption: the receipt opens under the depositor's secret and is spent once, the withdrawn note opens to the entitled share under the pool's committed words (DB-395: no spend authority leaks), and nothing the deposit published is revealed; public inputs: the receipt nullifier, the withdrawn commitment, the pool words"),
    ("PoolBridgeAir", 1, "the stability pool's epoch-bridge rule in-circuit: (P_b, S_b) = (⌊P₁·P₂ / 2^128⌋, S₁ + ⌊P₁·S₂ / 2^128⌋) over 16-bit limbs, both rounded DOWN (P_b is the product's limbs above 2^128, the rest zero) with no carry out of S_b, every word opened from its value commitment by an embedded permutation, row-local on the blinded committed door; public inputs: the six commitments (P₁, S₁, P₂, S₂, P_b, S_b)"),
    ("SettlementDeltaAir", 1, "the block-level settlement delta aggregate: every row rebuilds its bound inner gate (a blinded cover-or-spend, spend-validity or member-path row) from the row's own public tuple cells, and the delta accumulator step acc_out = fold(acc_in, row) chains the rows from the public pre-delta to the public post-delta, γ-batched above the bound step's own powers so no row law can cancel a step law; public inputs: the delta endpoints and the per-row tuple cells"),
    ("TagLedgerAir", 1, "the tag ledger's per-table circuit: the cover class's own bound tables, and on every step row the tag laws folded above the class's powers — L1 is_pair, is_head, is_last ∈ {0,1}, head and last only on a pair row, the zero lane zero; L2 the bus multiplicities memit = p·(1−l), mcons = −p·(1−h); L3 three Poseidon2 blocks welded to their inputs (pub = P(t0 ‖ t1), mid = P(cin ‖ t0), out = P(mid ‖ t1), the carrier's own chain spelling); L4 a head row's cin is the zero IV and a cover row's cin is forced zero; L5 a last row's out is the absorbed tag-set digest; public inputs: the absorbed D_tags through the settlement delta tuples"),
    ("LedgerDeltaAir", 1, "the ledger aggregate's per-table circuit: the note class's circuit on every table, plus on the step table the slot-ledger laws over the row's extension reading the row's ABSORBED tuple as the spend statement, folded from γ^K above the bound step's powers so the two sets never share a coefficient; public inputs: the ledger's pre and post digests and the absorbed tuples"),
    ("CommittedWeldAir", 1, "the committed weld's two tables under one constraint type: table 0 is the bound recursion step over the committed carrier (the inner gate rebuilt per row, the step's residuals γ-folded under the bound layout) and table 1 the Poseidon2 sponge that DERIVES that step's challenges, cross-tied so the step can only use the challenges the sponge produced; public inputs: the carrier's statement bind and the sponge's absorbed digest"),
    ("PoolSnapshotGate", 1064, "the pool snapshot carrier: the pool's committed (P, S) words and the deposit's FRESH commitments to the same two values, so a depositor's receipt is keyed to the pool's real snapshot and never to one an executor invented; public inputs: the pool words and the fresh commitments"),
];

/// Gates that exist only to test the prover (fixtures, pins, shapes under test). Never a statement.
pub const TEST_ONLY: &[&str] = &["Mul14TestAir", "MulHHTestAir", "Cubic", "Equal", "OneSum", "NullGate", "OldShape", "Pinned", "FetchOnlyGate", "G", "SumGate", "TwoSums", "ValueGate", "ProdConstraint", "RowShiftConsistencyConstraint", "Triv", "ColEqConstraint", "SparseFoldGateShim", "RecInnerConservationConstraint", "InnerGate"];

#[cfg(test)]
mod tests {
    use super::*;

    /// The ledger: `MUTATION_CENSUS` when set (the census pass and the pin share one spelling), else the repo's
    /// `scratchpad/mutation-census.tsv` found by walking up from the crate (a worktree's crate sits four levels below
    /// the worktree root, whose scratchpad is the main checkout's — untracked, so it is searched, never assumed).
    fn ledger_path() -> std::path::PathBuf {
        if let Some(p) = std::env::var_os("MUTATION_CENSUS") {
            return std::path::PathBuf::from(p);
        }
        let mut dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf();
        loop {
            let cand = dir.join("scratchpad/mutation-census.tsv");
            if cand.exists() {
                return cand;
            }
            if !dir.pop() {
                return std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("mutation-census.tsv");
            }
        }
    }

    fn short(type_name: &str) -> &str {
        // `usdm_decider::nf_sparse_air::NfSparseGate` → `NfSparseGate`; `Blinded<…::X>` → `X` (the blinding wrapper is
        // not the gate); any OTHER generic aggregate (`SettlementDeltaAir<…, …::{{closure}}>`, `BoundStepConstraint<…>`)
        // is named by its OUTER type — the aggregate is the gate, its parameters are the rows it carries.
        let t = type_name.trim_end_matches('>');
        let outer = t.split('<').next().unwrap_or(t);
        let outer_name = outer.rsplit("::").next().unwrap_or(outer);
        if outer_name == "Blinded" {
            let inner = t.strip_prefix(outer).and_then(|r| r.strip_prefix('<')).unwrap_or(t);
            let inner = inner.split('<').next().unwrap_or(inner).split(',').next().unwrap_or(inner);
            return inner.rsplit("::").next().unwrap_or(inner);
        }
        outer_name
    }

    /// ⭐⭐⭐ H13 — BOTH ROWS, MEASURED. Reads the ledger the census wrote during a `MUTATION_CENSUS=<path> cargo test`
    /// pass over the gate modules and asserts: the ledger is newer than every decider source (no stale measurement);
    /// every production gate censused is `ok` (no VOID-only gate: unmeasured; no DEAD residual: a surviving mutant);
    /// every production gate has a written statement whose residual count equals the measured one; no statement
    /// names a gate the suite never proved (a statement about nothing).
    #[test]
    fn the_mutation_census_finds_no_dead_residual_and_every_production_gate_has_a_written_statement() {
        let path = ledger_path();
        let Ok(text) = std::fs::read_to_string(&path) else {
            panic!("⛔ no mutation-census ledger at {} — run the gate modules with MUTATION_CENSUS={} (holes.sh does)", path.display(), path.display());
        };
        let ledger_m = std::fs::metadata(&path).and_then(|m| m.modified()).expect("ledger mtime");
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let newest_src = std::fs::read_dir(&src)
            .expect("src dir")
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "rs") && e.file_name() != "mutation_census.rs")
            .filter_map(|e| e.metadata().and_then(|m| m.modified()).ok())
            .max()
            .expect("sources");
        assert!(ledger_m >= newest_src, "⛔ STALE: the mutation-census ledger predates a decider source change — re-run the census pass");
        let mut best: std::collections::BTreeMap<String, (usize, String, String)> = Default::default();
        for line in text.lines() {
            let f: Vec<&str> = line.split('\t').collect();
            if f.len() < 7 {
                continue;
            }
            let (gate, k, dead, verdict) = (short(f[0]).to_string(), f[3].parse::<usize>().unwrap_or(0), f[4].to_string(), f[6].to_string());
            // an `ok` row for a shape beats a VOID row for the same gate (a tamper trace proving on purpose)
            // The gate's best census: a clean row beats a dead one beats an unmeasured one; between two dead rows the
            // one that reached more residuals (a later, deeper or padded trace) stands.
            let rank = |v: &str, d: &str| -> (u8, usize) {
                match v {
                    "ok" => (2, 0),
                    "DEAD" => (1, usize::MAX - d.matches(',').count()),
                    _ => (0, 0),
                }
            };
            let e = best.entry(gate).or_insert((k, dead.clone(), verdict.clone()));
            if rank(&verdict, &dead) > rank(&e.2, &e.1) {
                *e = (k, dead, verdict);
            }
        }
        assert!(!best.is_empty(), "⛔ the ledger holds no censused gate");
        let production: Vec<(&String, &(usize, String, String))> = best.iter().filter(|(g, _)| !TEST_ONLY.contains(&g.as_str())).collect();
        let mut holes = Vec::new();
        for (g, (k, dead, verdict)) in &production {
            match verdict.as_str() {
                "VOID" => holes.push(format!("{g}: censused only on a trace that fails its own gate (UNMEASURED)")),
                "DEAD" => holes.push(format!("{g}: DEAD residual(s) {dead} — no single-cell tamper reaches them; the gate with them dropped is a surviving mutant")),
                _ => {}
            }
            match STATEMENTS.iter().find(|(name, _, _)| name == g) {
                None => holes.push(format!("{g}: proven by the suite ({k} residual(s)) with NO WRITTEN STATEMENT")),
                Some((_, want, text)) => {
                    if want != k {
                        holes.push(format!("{g}: the statement says {want} residual(s), the gate has {k} — a statement about a different circuit"));
                    }
                    if text.trim().len() < 40 {
                        holes.push(format!("{g}: the statement is not written out"));
                    }
                }
            }
        }
        for (name, _, _) in STATEMENTS {
            if !best.contains_key(*name) {
                holes.push(format!("{name}: a written statement for a gate the suite never proved under the census"));
            }
        }
        eprintln!("[statement-census] {} production gate(s) censused, {} hole(s)", production.len(), holes.len());
        assert!(holes.is_empty(), "⛔ H13 holes:\n  {}", holes.join("\n  "));
    }
}
