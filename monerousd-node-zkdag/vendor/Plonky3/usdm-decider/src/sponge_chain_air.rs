// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! ⛔⛔⛔ THE SPONGE CHAIN AS CONSTRAINTS — the transcript binding the join door needs.
//!
//! `poseidon2_air_parity` proved the pieces: the AIR computes the production permutation, the replay
//! reproduces a real proof's challenges, and the permutation is ENFORCEABLE in the shipping decider. What
//! none of that yet does is tie the permutations to EACH OTHER. A prover could hand over individually
//! valid permutation rows that are not the same sponge — different capacities, different absorbed values
//! — and every gate so far would pass.
//!
//! This module adds the constraints that make the rows ONE sponge:
//!   * **CAPACITY CARRY** — a row's `state[RATE..]` must be the PREVIOUS row's output there. The capacity
//!     is what makes a sponge a sponge; if it can be re-chosen per row, the transcript is forgeable.
//!   * **RATE OVERWRITE** — a row's `state[..RATE]` is either an absorbed value (committed in the row) or
//!     the previous row's output there. The challenger OVERWRITES rather than XORs, and only the slots it
//!     actually buffered, so each slot carries a boolean saying which happened.
//!   * **BOOLEANITY** — those selectors are 0/1, or a prover blends both branches and picks the state.
//!   * **THE FIRST ROW** — the sponge starts from the all-zero state, so row 0's capacity is zero and its
//!     rate slots are absorbed-or-zero. Without it a prover starts mid-sponge at a state of its choosing.
//!   * **CHALLENGE EQUALITY** — every value the sponge POPS is folded, in pop order, into one field
//!     element, and the last row equates that fold with a value the VERIFIER brings. This is the residual
//!     the join door actually turns on: the rows above prove a real sponge, but a real sponge whose
//!     outputs nobody checked is still a sponge the prover chose the challenges of. `sample()` pops from
//!     the END of the rate slice and a single `Ea4` challenge takes FOUR base pops off ONE permutation
//!     output, so the fold has one cell per pop — binding only the first pop per duplexing would leave
//!     three limbs of every challenge free, and the `every_pop_of_a_multi_pop_duplexing_moves_the_fold`
//!     gate is what keeps that honest. Pops are constrained to be a PREFIX (slot RATE-1 downward), so a
//!     forger cannot claim a challenge came from a slot the transcript never consumed.
//!
//! ⛔ THE FAILURE MODE THIS FILE IS WRITTEN AGAINST is a constraint that PROVES but does not BIND. A
//! chaining rule satisfiable by honest traces AND by dishonest ones looks green forever — the same shape
//! as the certificate that shipped and anchored nothing. So the tamper cases were written BEFORE the
//! constraint, and each alters exactly ONE thing a forger would want to alter: an absorbed value, a
//! carried capacity, a rate slot, and a selector bit.
//!
//! ROOT-LAYER: the sponge state is PRODUCED here, at the transition between permutations, which is the
//! only place the capacity carry and the rate overwrite exist at all. The alternative — checking the
//! derived challenges at the READER, after the fact — is precisely the shape that already failed: the
//! recursion replays the transcript natively and exports the resulting values, so a reader-side check
//! sees only numbers a prover chose. Constraining the transition is what makes those numbers unchoosable.
//! MEASURED 2026-09-12, reported by the tests below on each run (`[sponge-chain]` lines): the honest chain
//! proves 32 rows x 196 cols and an INDEPENDENTLY-derived adopter accepts 10637 bytes; all 8 single-cell
//! forgeries are refused; an adopter expecting different challenges refuses an otherwise perfect sponge;
//! and all 8 popped challenges move the fold. Before this module there was no constraint tying two
//! permutation rows together at all, so every forgery below was accepted by construction.
//! MUST-STAY-GREEN: `poseidon2_air_parity`'s five gates (this module shares their constants and their
//! permutation), and `whole_chain`'s own prove/verify round trip — `WholeChainMainConstraint` is reused
//! here unchanged, never forked.
//!
//! THE TWO PARTIES, and they are not a loopback: the SERVER builds the object and the ADOPTING NODE
//! judges it, on different machines, with the serialized proof as the only thing that crosses. The tests
//! construct the two sides INDEPENDENTLY — the verifying side derives its own constraint factory from the
//! protocol shape rather than reusing the prover's object — because that is what a remote adopter does,
//! and because a prover and verifier who silently derived DIFFERENT circuits is precisely the
//! cross-implementation drift this crate exists to prevent. The node-level pair (a server's bundle
//! against an adopter holding no chain) is `family_d_door_audit_tests::pin_d2b`, RED until this is wired
//! into `adopt_sync_bundle`.
//!
//! PAST-CHATS-CHECKED: no constant here is invented — every one is DERIVED from a named upstream
//! constant or from this tree's own pinned shape, and the two that cannot be imported are cited:
//!   * `WIDTH` = 16, `RATE` = 8 — the generics of `hiding_decider::Chl`,
//!     `DuplexChallenger<Fa4, Perm16, 16, 8>` (hiding_decider.rs:57).
//!   * `SBOX_DEGREE` = `KOALABEAR_S_BOX_DEGREE`, `HALF_FULL_ROUNDS` =
//!     `KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS`, `PARTIAL_ROUNDS` = `KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16`
//!     — imported, not re-typed.
//!   * `SBOX_REGISTERS` = 0 because degree 3 is a cube and needs no extra register; the AIR's own sbox
//!     table panics on any other pairing, which is how the first attempt (1) was caught.
//!   * `P2_COLS` = `num_cols::<..>()`, a `const fn` — computed, never a literal.
//!   * `OUTPUT_OFF` = `P2_COLS - WIDTH`: the permutation output is the final full round's `post`.
//!   * `ROWS` (tests) = 32, the WHIR `nvars >= 5` floor this crate already pins the same way
//!     (`whir_rec_block.rs:3413`, `.max(32) // the WHIR nvars>=5 floor`).
//!
//! COST: one row per permutation (~1 per RATE absorbed field elements; a real production carrier's whole
//! transcript is 117 rows) at [`ROW_COLS`] columns — the Poseidon2 row plus RATE absorbed values, RATE
//! overwrite selectors, RATE pop selectors and RATE challenge-fold cells. Every quantity here is a fixed
//! circuit shape: no term in chain height, block count or notes.
//!
//! ⛔ WHAT THIS MODULE STILL DOES NOT DO, stated rather than left to be discovered: it binds the sponge and
//! the challenges it produced. It does not yet bind the ACCUMULATOR those challenges are folded into — an
//! `inner.acc_out == outer.acc_in` recurrence bottoming out at `whole_chain_cert::WHOLE_CHAIN_GENESIS_ACC`
//! — nor is it wired into `adopt_sync_bundle`. `family_d_door_audit_tests::pin_d2b` stays RED until both.

use crate::air_zerocheck::AirConstraint;
use crate::hiding_decider::{Ea4, Fa4};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KoalaBear, KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS,
    KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16, KOALABEAR_S_BOX_DEGREE,
};
use p3_poseidon2_air::{num_cols, Poseidon2Cols, RoundConstants};
use p3_symmetric::Permutation;

/// The production sponge shape — the generics of `DuplexChallenger<Fa4, Perm16, 16, 8>`.
pub const WIDTH: usize = 16;
pub const RATE: usize = 8;
const SBOX_DEGREE: u64 = KOALABEAR_S_BOX_DEGREE;
/// Degree 3 is a cube: no extra register. The AIR's own sbox table panics on any other pairing.
const SBOX_REGISTERS: usize = 0;
pub(crate) const HALF_FULL_ROUNDS: usize = KOALABEAR_POSEIDON2_HALF_FULL_ROUNDS;
pub(crate) const PARTIAL_ROUNDS: usize = KOALABEAR_POSEIDON2_PARTIAL_ROUNDS_16;

type Cols<T> = Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>;

/// COMPUTED from the AIR's own layout, never a literal.
pub const P2_COLS: usize =
    num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
const INPUT_OFF: usize = 0;
/// The permutation output is the final full round's `post` — the last WIDTH columns of the row. PUBLIC
/// because a squeezed challenge lives at `OUTPUT_OFF + pop_slot(k)`, and that cell is what a cross-tie
/// welds to the recursive carrier's committed challenge column.
pub const OUTPUT_OFF: usize = P2_COLS - WIDTH;
/// The absorbed value for each rate slot. PUBLIC because a cross-tie welds an absorbed cell to the
/// committed statement it is supposed to have absorbed.
pub const ABSORB_OFF: usize = P2_COLS;
const OW_OFF: usize = P2_COLS + RATE;
/// `sq[k] = 1` when POP number `k` of this row actually happened. `sample()` POPS FROM THE END of the
/// rate slice, so pop `k` reads output slot `RATE - 1 - k` — one duplexing can supply up to RATE
/// challenges, and an `Ea4` challenge alone takes four of them.
const SQ_OFF: usize = P2_COLS + 2 * RATE;
/// The running challenge fold AFTER pop `k` of this row. `ACC_OFF + RATE - 1` is therefore the row's
/// final fold, which is what the next row continues from and what the last row is equated against.
const ACC_OFF: usize = SQ_OFF + RATE;
/// Total committed width of one sponge row.
pub const ROW_COLS: usize = P2_COLS + 4 * RATE;
/// The multiplier that makes the challenge fold ORDER-SENSITIVE. Taken from this crate's established
/// Poseidon pair shape `pre = left + 7*right` (`whir_rec_block.rs:5620`), not invented for this file: a
/// plain sum would let a forger PERMUTE the challenges and land on the same value.
const CHAL_FOLD_MULT: u64 = 7;

/// The output slot that pop `k` of a duplexing reads.
#[must_use]
pub const fn pop_slot(k: usize) -> usize {
    RATE - 1 - k
}

/// The permutation the production proofs use — RNG-derived constants off `REC_DECIDER_SEED`, NOT the
/// published KoalaBear set. (An earlier gate compared against the published set and passed while binding
/// a permutation no proof in this tree uses; see `poseidon2_air_parity`.)
pub fn production_perm() -> &'static p3_koala_bear::Poseidon2KoalaBear<WIDTH> {
    // ⛔ DB-167b — ITS OWN LOCK-FREE SLOT, NOT A LOOKUP IN `perm_for_seed`'S MAP.
    //
    // The first cut of this routed here through the seed-keyed map, which costs a Mutex acquire and a
    // hash PER HASH. MEASURED immediately (`a_hash_no_longer_pays_for_its_own_round_constants`): 923 ns
    // cached vs 1,361 ns derived — a 1.5x win where the derivation alone should have bought far more,
    // because the lock had replaced most of what the cache removed. This is the chain's ONE hot
    // permutation and it is a compile-time constant seed, so it gets a `OnceLock` with no map, no key
    // and no lock on the read path.
    static P: std::sync::OnceLock<p3_koala_bear::Poseidon2KoalaBear<WIDTH>> = std::sync::OnceLock::new();
    P.get_or_init(|| derive_perm(crate::whir_rec_block::REC_DECIDER_SEED))
}

/// The same constants in the AIR's layout — replicating `Poseidon2::new_from_rng` +
/// `ExternalLayerConstants::new_from_rng` sampling order off the SAME seed.
pub fn production_constants() -> RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    constants_for_seed(crate::whir_rec_block::REC_DECIDER_SEED)
}

/// ⭐ ONE DEFINITION, ANY SEED. Different proof families in this crate pin different permutation seeds
/// (`REC_DECIDER_SEED` for the direct path, `committed_air::COMMITTED_AIR_SEED` for the committed
/// carrier). A circuit that must agree with a PARTICULAR family's MMCS has to build that family's
/// permutation — so the seed is a parameter here rather than a second hand-copied sampler elsewhere.
/// ⛔ The pair below must stay a PAIR: `perm_for_seed` and `constants_for_seed` are the same object in
/// two layouts, and a drift between them is a circuit that proves a hash nothing computes.
pub fn perm_for_seed(seed: u64) -> &'static p3_koala_bear::Poseidon2KoalaBear<WIDTH> {
    // ⛔⭐⭐⭐ DB-167 — THIS FUNCTION USED TO RE-DERIVE THE WHOLE ROUND SCHEDULE ON EVERY HASH.
    //
    // The body below (seed an RNG, sample ~148 round constants, allocate the external/internal layer
    // structures) is the DEFINITION of the chain's permutation and is correct. What was wrong is that it
    // ran PER CALL, and `poseidon2_compress::compress` — the chain's 2-to-1 Merkle compression — calls
    // `production_perm()` once per hash. So every Merkle level of every copath, every note-tree insert and
    // every block binding paid a full constant-derivation before it paid for the permutation.
    //
    // MEASURED 2026-09-24 (`nf_sparse::db153_attribution`, release):
    //     poseidon_pair                      3,619 ns/pair
    //     a DEPTH-256 insert (2x256 pairs)     1.9 ms   <- and the measured insert was 0.77-1.7 ms,
    //                                                      i.e. the TREE was already at its primitive's
    //                                                      floor with no algorithmic waste left
    //     one 256-tag block                    208 ms of pure hashing
    // and on real nodes (`ecosystem-check.sh` gate 6, BOTH nodes):
    //     apply_preverified            median 872-935 ms   max 4,852-5,056 ms
    //     [sparse-shadow] view advance      551-858 ms over 256 tags
    //     block time                            500 ms
    // A node that cannot finish a drain inside its block time cannot follow its peer
    // ([[feedback_performance_pillar]]), so this was the convergence failure, not a sync defect.
    //
    // ⭐ THE VALUE IS UNCHANGED, AND THAT IS THE WHOLE POINT. The constants are a pure deterministic
    // function of `seed` — same RNG, same sampling order, same output — so deriving them ONCE and handing
    // out a shared reference cannot alter a single hash the chain has ever computed. This is a caching fix,
    // not a cryptographic one: no constant, family, width or round count moves
    // ([[feedback_never_argue_a_security_bound_down]] — nothing here is argued down, the schedule is
    // byte-identical and `the_memoised_permutation_is_byte_identical_to_a_freshly_derived_one` proves it).
    //
    // Keyed by seed because different proof families pin different permutations (`REC_DECIDER_SEED` for the
    // direct path, `COMMITTED_AIR_SEED` for the committed carrier) and a circuit must build ITS family's.
    // The seed set is small, fixed and compile-time known, so the map never grows with chain activity
    // ([[feedback_no_growth_any_axis]]).
    use std::collections::HashMap;
    use std::sync::{Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<u64, &'static p3_koala_bear::Poseidon2KoalaBear<WIDTH>>>> =
        OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    if let Ok(g) = cache.lock() {
        if let Some(p) = g.get(&seed) {
            return p;
        }
    }
    let built: &'static p3_koala_bear::Poseidon2KoalaBear<WIDTH> = Box::leak(Box::new(derive_perm(seed)));
    if let Ok(mut g) = cache.lock() {
        // A concurrent builder may have won the race; keep whichever landed first so every caller at a
        // given seed sees ONE object. Both are byte-identical, so either is correct.
        return g.entry(seed).or_insert(built);
    }
    built
}

/// THE DEFINITION — `Poseidon2KoalaBear<WIDTH>` with constants sampled off `seed`. Called once per distinct
/// seed by [`perm_for_seed`], which is the only thing that should call it: calling this directly re-pays the
/// derivation DB-167 measured at ~3.4 us a hash.
fn derive_perm(seed: u64) -> p3_koala_bear::Poseidon2KoalaBear<WIDTH> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
    p3_koala_bear::Poseidon2KoalaBear::<WIDTH>::new_from_rng_128(&mut rng)
}

/// The AIR-layout constants for [`perm_for_seed`] at the same seed.
pub fn constants_for_seed(seed: u64) -> RoundConstants<KoalaBear, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS> {
    let (initial, terminal, internal) = raw_constants_for_seed(seed);
    RoundConstants::new(initial, internal, terminal)
}

/// The same derivation as [`constants_for_seed`], handed out as the raw arrays `(initial, terminal, internal)`
/// — ONE definition of the draw order, read by the AIR (through `RoundConstants`) and by the R1CS gadget
/// (`spartan_gadgets`), so the two circuits cannot drift onto different constants.
#[allow(clippy::type_complexity)]
pub(crate) fn raw_constants_for_seed(
    seed: u64,
) -> ([[KoalaBear; WIDTH]; HALF_FULL_ROUNDS], [[KoalaBear; WIDTH]; HALF_FULL_ROUNDS], [KoalaBear; PARTIAL_ROUNDS]) {
    use rand::distr::StandardUniform;
    use rand::{RngExt, SeedableRng};
    let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
    let initial: [[KoalaBear; WIDTH]; HALF_FULL_ROUNDS] =
        core::array::from_fn(|_| rng.sample(StandardUniform));
    let terminal: [[KoalaBear; WIDTH]; HALF_FULL_ROUNDS] =
        core::array::from_fn(|_| rng.sample(StandardUniform));
    let internal: [KoalaBear; PARTIAL_ROUNDS] = core::array::from_fn(|_| rng.sample(StandardUniform));
    (initial, terminal, internal)
}

/// One duplexing: the state before and after, plus WHICH rate slots were overwritten and with what.
#[derive(Clone, Copy, Debug)]
pub struct SpongeStep {
    pub input: [KoalaBear; WIDTH],
    pub output: [KoalaBear; WIDTH],
    pub absorbed: [KoalaBear; RATE],
    pub overwritten: [bool; RATE],
    /// How many challenges were popped from THIS duplexing's output, in pop order.
    pub pops: usize,
}

fn duplex(
    perm: &p3_koala_bear::Poseidon2KoalaBear<WIDTH>,
    state: &mut [KoalaBear; WIDTH],
    buf: &[KoalaBear; RATE],
    buf_len: usize,
    steps: &mut Vec<SpongeStep>,
) {
    let mut absorbed = [KoalaBear::ZERO; RATE];
    let mut ow = [false; RATE];
    for i in 0..buf_len {
        state[i] = buf[i];
        absorbed[i] = buf[i];
        ow[i] = true;
    }
    let input = *state;
    perm.permute_mut(state);
    steps.push(SpongeStep { input, output: *state, absorbed, overwritten: ow, pops: 0 });
}

/// Replay an absorb schedule into duplexing steps, mirroring `DuplexChallenger` exactly: buffer up to
/// RATE, OVERWRITE those slots (never XOR), permute. `samples_after[g]` is how many challenges are drawn
/// after absorb group `g` — that is what forces a PARTIAL-rate duplexing, the case the selectors exist
/// for. The two slices must be the same length: a missing entry would silently mean "no samples", and a
/// schedule that quietly differs from the caller's intent is exactly how a replay stops matching the
/// challenger it is supposed to mirror.
pub fn replay(absorbs: &[Vec<KoalaBear>], samples_after: &[usize]) -> Vec<SpongeStep> {
    replay_with_seed(crate::whir_rec_block::REC_DECIDER_SEED, absorbs, samples_after)
}

/// The SAME replay under a NAMED permutation.
///
/// ⛔⛔⛔ THE SEED IS PART OF THE TRANSCRIPT. Different proof families in this crate pin different
/// permutation seeds — the direct path's `REC_DECIDER_SEED`, the committed carrier's
/// `committed_air::COMMITTED_AIR_SEED` — and a challenger's output is a function of its permutation. A
/// sponge replaying a committed carrier's walk under the DIRECT permutation reproduces a schedule
/// perfectly and lands on challenges that proof never saw. MEASURED: the weld's own control refused an
/// honest weld until this seed was a parameter, with the absorbed stream matching the real one element
/// for element — the same trap §BK paid for once already on the MMCS side.
#[must_use]
pub fn replay_with_seed(
    seed: u64,
    absorbs: &[Vec<KoalaBear>],
    samples_after: &[usize],
) -> Vec<SpongeStep> {
    assert_eq!(
        absorbs.len(),
        samples_after.len(),
        "one sample count per absorb group — a defaulted entry would change the transcript silently"
    );
    let perm = perm_for_seed(seed);
    let mut state = [KoalaBear::ZERO; WIDTH];
    let mut buf: [KoalaBear; RATE] = [KoalaBear::ZERO; RATE];
    let mut buf_len = 0usize;
    let mut out_len = 0usize;
    let mut steps: Vec<SpongeStep> = Vec::new();

    for (g, group) in absorbs.iter().enumerate() {
        for v in group {
            out_len = 0;
            buf[buf_len] = *v;
            buf_len += 1;
            if buf_len == RATE {
                duplex(&perm, &mut state, &buf, buf_len, &mut steps);
                buf_len = 0;
                out_len = RATE;
            }
        }
        for _ in 0..samples_after[g] {
            // A pop DUPLEXES only when the output buffer is exhausted or an absorb is pending. The
            // 2nd..4th base pops of one `Ea4` challenge reuse the SAME permutation output, reading the
            // next slot down — so a row can carry several challenges and the per-pop selectors below are
            // what bind every one of them, not just the first.
            if buf_len > 0 || out_len == 0 {
                duplex(&perm, &mut state, &buf, buf_len, &mut steps);
                buf_len = 0;
                out_len = RATE;
            }
            out_len -= 1;
            let last = steps.len() - 1;
            steps[last].pops += 1;
        }
    }
    steps
}

/// Lay the steps as a trace: the Poseidon2 witness columns plus the absorbed values and their selectors.
/// `rows` is the committed trace height (the WHIR floor), a fixed circuit shape.
pub fn build_trace(steps: &[SpongeStep], rows: usize) -> (Vec<Vec<Fa4>>, Fa4) {
    build_trace_with_seed(crate::whir_rec_block::REC_DECIDER_SEED, steps, rows)
}

/// The SAME trace under a NAMED permutation — see [`replay_with_seed`].
#[must_use]
pub fn build_trace_with_seed(seed: u64, steps: &[SpongeStep], rows: usize) -> (Vec<Vec<Fa4>>, Fa4) {
    assert!(!steps.is_empty(), "a sponge trace needs at least one duplexing");
    assert!(steps.len() <= rows, "the trace must be tall enough for every duplexing");
    let consts = constants_for_seed(seed);

    // ⛔ PAD BY CONTINUING THE SPONGE, NOT BY REPEATING A ROW. An earlier version repeated the last step
    // and claimed "a repeated row still chains to itself" — that is FALSE and the honest-case test caught
    // it immediately: a repeated row has `next_input == input`, while the chain demands
    // `next_input == current_output`. Padding with absorb-nothing duplexings continues the real sponge, so
    // every padded row satisfies the same carry rule the real rows do and the padding cannot express a
    // state the sponge never reached.
    let perm = perm_for_seed(seed);
    let mut padded: Vec<SpongeStep> = steps.to_vec();
    if std::env::var("MONEROUSD_PROVE_PROGRESS").is_ok() {
        eprintln!("[sponge-fill] {} real steps of {rows} rows", padded.len());
    }
    while padded.len() < rows {
        let mut state = padded[padded.len() - 1].output;
        let input = state;
        perm.permute_mut(&mut state);
        padded.push(SpongeStep {
            input,
            output: state,
            absorbed: [KoalaBear::ZERO; RATE],
            overwritten: [false; RATE],
            pops: 0,
        });
    }

    let mut cols: Vec<Vec<Fa4>> = vec![vec![KoalaBear::ZERO; rows]; ROW_COLS];
    let mut chal_acc = KoalaBear::ZERO;
    for slot in 0..rows {
        let st = padded[slot];
        let filled: &[KoalaBear] = &crate::perm_row::perm_row::<KoalaBear, GenericPoseidon2LinearLayersKoalaBear, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(st.input, &consts);
        for (col, v) in filled.iter().enumerate() {
            cols[col][slot] = *v;
        }
        for j in 0..RATE {
            cols[ABSORB_OFF + j][slot] = st.absorbed[j];
            cols[OW_OFF + j][slot] = if st.overwritten[j] { KoalaBear::ONE } else { KoalaBear::ZERO };
        }
        // The running fold of challenges, order-sensitive by CHAL_FOLD_MULT, one cell per POP so that
        // every challenge a duplexing yielded is bound — not merely the first.
        assert!(st.pops <= RATE, "a duplexing cannot yield more than RATE challenges");
        let m = KoalaBear::from_u64(CHAL_FOLD_MULT);
        for k in 0..RATE {
            let sq = k < st.pops;
            chal_acc = if sq { chal_acc * m + st.output[pop_slot(k)] } else { chal_acc };
            cols[SQ_OFF + k][slot] = if sq { KoalaBear::ONE } else { KoalaBear::ZERO };
            cols[ACC_OFF + k][slot] = chal_acc;
        }
    }
    (cols, chal_acc)
}

/// The Poseidon2 gates PLUS the chaining that makes the rows one sponge.
pub struct SpongeChainConstraint {
    pub p2: crate::whole_chain::WholeChainMainConstraint,
    pub gamma: Ea4,
    /// The challenge fold the VERIFIER expects — supplied from outside the proof, so it is a public
    /// input in the protocol sense even though it rides the circuit rather than an opening vector.
    pub expected_chal: Ea4,
    /// `None` — ONE sponge spanning the whole table. This is the original shape and every existing
    /// caller gets it.
    ///
    /// `Some(m)` — the table holds MANY INDEPENDENT sponges, each `2^m` rows, back to back. The
    /// boundary selectors then run over the LOW `m` variables instead of all of them, so every
    /// `2^m`-th row restarts from the all-zero state and the carry rule stops crossing between them.
    ///
    /// ⭐⭐⭐ WHY IT EXISTS. An aggregate over `BLOCK_FIXED_TX_COUNT` carriers needs each carrier's own
    /// Fiat–Shamir walk. As one TABLE each that is `n` tables, and proof size follows COLUMNS — so the
    /// proof would grow with how many spends were real, which `cover.rs` names a Pillar-1 break (an
    /// observer could count real outputs), not merely a cost. Stacked as SEGMENTS of one table the
    /// column count is fixed and only the height moves.
    ///
    /// ⛔ THE CHALLENGE-FOLD EQUALITY IS NOT CHECKED IN SEGMENTED MODE, and that is deliberate rather
    /// than dropped: `expected_chal` is ONE value compared on ONE last row, and `n` segments have `n`
    /// folds. Tying each segment's fold to a committed cell nothing else constrains would be a
    /// tautology that only LOOKS like a binding. The aggregate binds what actually matters far more
    /// tightly instead — γ, every `z_k` and every `r_k` are tied CELL BY CELL to the step row that uses
    /// them (`settlement_delta_ties` groups 3–5), which names the exact values a fold could only
    /// summarise.
    pub segments: Option<usize>,
}

impl AirConstraint for SpongeChainConstraint {
    fn degree(&self, nvars: usize) -> usize {
        self.p2.degree(nvars)
    }
    /// ⭐⭐⭐ THE SHIFTED SET OF A **COMPOSED** GATE IS COMPOSED, NEVER HAND-LISTED.
    ///
    /// ROOT-FIX-VERIFIED: this is the union of the columns THIS gate reads through `at` with whatever
    /// `self.p2` declares, taken from `self.p2.shifted_cols()` itself — so neither half can grow a
    /// shifted read that the declaration misses. An inner half that answers `None` ("every column")
    /// makes the union `None`, because a union with everything IS everything.
    ///
    /// ⛔⛔⛔ THE COMMENT THAT STOOD HERE WAS FALSE, AND THAT FALSEHOOD WAS THE DEFECT. It read *"The 35
    /// columns this chain reads from the NEXT row — out of `ROW_COLS` (196) … Read straight off the
    /// `at(...)` calls in `eval`"*, and that is exactly what it was: read off the `at(...)` calls in
    /// THIS function's `eval`, ignoring the `at` this gate FORWARDS into `self.p2.eval(local, at, x)` on
    /// its very first line. `WholeChainMainConstraint` builds the whole `trace_next` block, so the
    /// composed gate reads all 196 — the 35-column saving was never real. MEASURED 2026-09-16 (debug
    /// build, backtrace): `SettlementDeltaAir::eval → SpongeChainConstraint::eval →
    /// WholeChainMainConstraint::eval` hitting *"⛔ shifted column 16 was read but not declared by
    /// `shifted_cols()`"* at `air_zerocheck.rs:583`, failing 16 tests across THREE unrelated families
    /// (`harness::fuzz::*`, `harness::vacuity::*`, `da_seed_regen_tests::*`) from this ONE cause.
    /// ⛔ The guard is a `debug_assert!`, so RELEASE builds compiled it out and the prove SUCCEEDED over
    /// the `Ea4::ZERO` initialiser — a cell that folds to a constant on BOTH sides is a cell the proof
    /// does not constrain. A performance narrowing that is not derived from the composition is a
    /// soundness statement made by hand, and this one was wrong for as long as it stood.
    fn shifted_cols(&self) -> Option<Vec<usize>> {
        let mut v: Vec<usize> = (0..WIDTH).map(|j| INPUT_OFF + j).collect();
        v.extend((0..RATE).map(|j| OW_OFF + j));
        v.extend((0..RATE).map(|j| ABSORB_OFF + j));
        v.push(SQ_OFF);
        v.push(ACC_OFF);
        v.push(OUTPUT_OFF + pop_slot(0));
        // The forwarded half — `eval`'s first line is `self.p2.eval(local, at, x)`, so whatever it reads
        // through `at`, this gate reads. `None` from the inner half means every column.
        let inner = self.p2.shifted_cols()?;
        v.extend(inner);
        v.sort_unstable();
        v.dedup();
        Some(v)
    }
    fn eval(&self, local: &crate::air_zerocheck::Row<'_>, at: &dyn Fn(usize, &[Ea4]) -> Ea4, x: &[Ea4]) -> Ea4 {
        let mut acc = self.p2.eval(local, at, x);
        let g = self.gamma;
        let is_last = self.chain_laws(local, &|c| at(c, &[]), x, &mut |r: Ea4| acc = acc * g + r);
        // The EQUALITY itself. `expected_chal` is not read from the trace, so a prover cannot move it.
        // ⛔ SKIPPED IN SEGMENTED MODE — see `segments`: one expected value cannot stand for `n` folds,
        // and the aggregate ties γ, z and r cell by cell instead, which is strictly more specific.
        if self.segments.is_none() {
            acc = acc * g + is_last * (local[ACC_OFF + RATE - 1] - self.expected_chal);
        }
        acc
    }
    /// ⭐ ROUND 0 IN THE BASE FIELD: the same law list as `eval` ([`Self::chain_laws`], one site), every residual a base-field value
    /// the γ-batch folds with one extension-by-base add. MEASURED 2026-11-03: the sponge tables were 2.1 s of a block's 3.1 s zerocheck.
    fn has_base_eval(&self) -> bool {
        self.p2.has_base_eval()
    }
    fn eval_base(&self, local: &crate::air_zerocheck::Row<'_, Fa4>, at: &dyn Fn(usize) -> Fa4, x: &[Fa4]) -> Ea4 {
        let mut acc = self.p2.eval_base(local, at, x);
        let g = self.gamma;
        let is_last = self.chain_laws(local, at, x, &mut |r: Fa4| acc = acc * g + Ea4::from(r));
        if self.segments.is_none() {
            acc = acc * g + Ea4::from(is_last) * (Ea4::from(local[ACC_OFF + RATE - 1]) - self.expected_chal);
        }
        acc
    }
}

impl SpongeChainConstraint {
    /// ⭐ V2 (b) PIECE 3 — the gate's residuals in its OWN batching order (`eval` is the Horner fold of exactly this list:
    /// the Poseidon2 tape's roots, then [`Self::chain_laws`], then the last-row challenge equality when unsegmented), generic
    /// over the field its row lives in so `gate_trace::Sym` traces it into the program a circuit evaluates at the ledger
    /// proof's opened chain row. `expected_chal` is the value `eval` reads from `self.expected_chal`, passed in so a program
    /// can take it as a public input. The `Ea4` instantiation runs the same laws `eval` runs; the pin
    /// `agg_t1_every_carrier_gate_is_its_program` holds the two equal.
    pub fn residuals_in_order<G: crate::gate_trace::GateAlg>(
        &self,
        local: &crate::air_zerocheck::Row<'_, G>,
        at: &dyn Fn(usize) -> G,
        x: &[G],
        expected_chal: G,
    ) -> Vec<G> {
        let mut out = self.p2.residuals_generic(local, at, x, &|_| G::ZERO);
        let is_last = self.chain_laws(local, at, x, &mut |r: G| out.push(r));
        if self.segments.is_none() {
            out.push(is_last * (local[ACC_OFF + RATE - 1] - expected_chal));
        }
        out
    }

    /// THE CHAINING LAWS, in the field the row lives in, each residual handed to `push` in the batching order. Returns `is_last`.
    fn chain_laws<G: p3_field::PrimeCharacteristicRing + Copy>(
        &self,
        local: &crate::air_zerocheck::Row<'_, G>,
        at: &dyn Fn(usize) -> G,
        x: &[G],
        push: &mut dyn FnMut(G),
    ) -> G {
        // Boundary selectors, derived exactly as `WholeChainMainConstraint` derives them — except that
        // with `segments: Some(m)` they run over the LOW `m` variables only, so they mark the first and
        // last row of EACH `2^m`-row sponge rather than of the whole table. `x[0]` is the MSB of the row
        // index, so the low variables are the tail of `x`.
        let lo = match self.segments {
            Some(m) if m <= x.len() => x.len() - m,
            _ => 0,
        };
        let mut is_first = G::ONE;
        let mut is_last = G::ONE;
        for &xk in &x[lo..] {
            is_first *= G::ONE - xk;
            is_last *= xk;
        }
        let is_trans = G::ONE - is_last;

        // CONTINUE the same Horner batching the Poseidon2 constraint already used (`acc = acc*γ + cᵢ`),
        // so every chaining residual lands on its OWN γ-power with no precomputed shift: the Poseidon2
        // part is carried up and the two ranges cannot collide. Distinct powers are what make this a
        // proper γ-polynomial, so Schwartz-Zippel still bounds a forgery in ANY single residual.

        for j in 0..RATE {
            let ow = local[OW_OFF + j];
            // BOOLEANITY — without it a prover blends both branches and chooses the state.
            push(ow * (G::ONE - ow));
        }
        for j in 0..WIDTH {
            let next_in = at(INPUT_OFF + j);
            let cur_out = local[OUTPUT_OFF + j];
            if j < RATE {
                let n_ow = at(OW_OFF + j);
                let n_abs = at(ABSORB_OFF + j);
                // RATE slot: absorbed when the next step overwrote it, carried otherwise.
                let want = n_ow * n_abs + (G::ONE - n_ow) * cur_out;
                push(is_trans * (next_in - want));
            } else {
                // CAPACITY: never absorbed, always carried. This is the sponge's whole security.
                push(is_trans * (next_in - cur_out));
            }
        }
        // ROW 0 starts from the all-zero state: capacity zero, rate slots absorbed-or-zero.
        for j in 0..WIDTH {
            let cur_in = local[INPUT_OFF + j];
            if j < RATE {
                let ow = local[OW_OFF + j];
                let abs = local[ABSORB_OFF + j];
                push(is_first * (cur_in - ow * abs));
            } else {
                push(is_first * cur_in);
            }
        }

        // ── CHALLENGE EQUALITY ───────────────────────────────────────────────────────────────────
        // The chaining above proves the rows ARE one sponge. It does not yet say that the values the
        // sponge SQUEEZED are the challenges the verifier is checking the algebra against — and a
        // recursion that replays Fiat-Shamir natively is exactly a recursion where the prover picks
        // those. The residuals below fold every popped challenge into ONE field element and equate it,
        // on the last row, with a value the verifier brought itself. A prover that squeezed anything
        // else — a different value, a different ORDER, or a different number of pops — lands on a
        // different fold and the last-row residual is non-zero.
        let m = G::from_u64(CHAL_FOLD_MULT);
        for k in 0..RATE {
            let sq = local[SQ_OFF + k];
            // BOOLEANITY — an unconstrained selector lets a prover scale a challenge out of the fold.
            push(sq * (G::ONE - sq));
            if k > 0 {
                // POPS ARE A PREFIX. A challenger pops slot RATE-1 first and walks down; a claimed pop
                // with a GAP below it would let a forger read a slot the transcript never consumed.
                push(sq * (G::ONE - local[SQ_OFF + k - 1]));
            }
            // The fold step for this pop: absorb the popped slot, or carry the previous cell unchanged.
            // `k == 0` continues the PREVIOUS ROW, so it is stated in the transition/first-row block
            // below where the incoming value is available.
            if k > 0 {
                let prev = local[ACC_OFF + k - 1];
                let want = sq * (prev * m + local[OUTPUT_OFF + pop_slot(k)]) + (G::ONE - sq) * prev;
                push(local[ACC_OFF + k] - want);
            }
        }
        // Pop 0 of ROW 0 starts from an empty fold.
        {
            let sq = local[SQ_OFF];
            push(is_first * (local[ACC_OFF] - sq * local[OUTPUT_OFF + pop_slot(0)]));
        }
        // Pop 0 of every LATER row continues the previous row's final fold.
        {
            let prev = local[ACC_OFF + RATE - 1];
            let n_sq = at(SQ_OFF);
            let n_acc = at(ACC_OFF);
            let n_out = at(OUTPUT_OFF + pop_slot(0));
            let want = n_sq * (prev * m + n_out) + (G::ONE - n_sq) * prev;
            push(is_trans * (n_acc - want));
        }
        is_last
    }
}

/// Build the constraint factory for a sponge-chain trace of [`ROW_COLS`] columns. Each call derives the
/// circuit from the protocol shape alone, so a server and an adopter that never shared an object still
/// build the SAME one — which is the property a remote verify depends on.
/// The SEGMENTED constraint: one table holding `2^seg_log`-row sponges back to back, each independent.
/// See [`SpongeChainConstraint::segments`] for why this exists and what it does NOT check.
#[must_use]
pub fn make_segmented_constraint_with_seed(
    seed: u64,
    seg_log: usize,
) -> impl Fn(Ea4) -> SpongeChainConstraint + Clone {
    let one = make_constraint_with_seed(seed, Fa4::ZERO);
    move |gamma: Ea4| SpongeChainConstraint { segments: Some(seg_log), ..one(gamma) }
}

pub fn make_constraint(expected_chal: Fa4) -> impl Fn(Ea4) -> SpongeChainConstraint + Clone {
    make_constraint_with_seed(crate::whir_rec_block::REC_DECIDER_SEED, expected_chal)
}

/// The SAME circuit under a NAMED permutation — see [`replay_with_seed`]. The constraint and the trace
/// must agree on the seed or an honest sponge does not verify.
/// The Poseidon2 BLOCK law as a reusable constraint over a row region that holds ONE block at its columns
/// `0..P2_COLS` (input state at `0..WIDTH`, output state at `PERM_OUT..PERM_OUT + WIDTH`), under the PRODUCTION
/// constants — the same permutation `lay_perm_row_flat` lays and `poseidon2_compress::permute_lanes_16` runs. Any
/// AIR that embeds a block (the DSOL CPU row does, at `C_P2`) evaluates this on `local.suffix(base)` with `at`
/// offset by `base`. The symbolic base is derived ONCE per process.
#[must_use]
pub fn p2_block_constraint(gamma: Ea4, row_w: usize) -> crate::whole_chain::WholeChainMainConstraint {
    p2_block_constraint_deg(gamma, row_w, 8)
}

/// [`p2_block_constraint`] declaring `max_deg` as its per-variable degree. The block's own laws are degree
/// [`crate::pow_pq_air::P2_CONSTRAINT_DEGREE`] (3, measured by the DSOL law-degree census); the sponge chain keeps
/// declaring 8 for its composed gate, and a gate that batches its own laws behind the block declares the maximum of the
/// two (the DSOL CPU relation: 6). The zerocheck samples `degree + 2` points per round, so an over-declaration is paid
/// on every row of every round.
#[must_use]
pub fn p2_block_constraint_deg(gamma: Ea4, row_w: usize, max_deg: usize) -> crate::whole_chain::WholeChainMainConstraint {
    use p3_air::symbolic::{AirLayout, SymbolicExpression};
    use p3_batch_stark::symbolic::get_symbolic_constraints;
    use p3_lookup::logup::LogUpGadget;
    use p3_poseidon2_air::Poseidon2Air;
    use std::sync::OnceLock;
    static BASE: OnceLock<Vec<SymbolicExpression<KoalaBear>>> = OnceLock::new();
    let base = BASE.get_or_init(|| {
        type P2Air = Poseidon2Air<
            KoalaBear,
            GenericPoseidon2LinearLayersKoalaBear,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >;
        let air = P2Air::new(production_constants());
        let layout = AirLayout {
            preprocessed_width: 0,
            main_width: P2_COLS,
            num_public_values: 0,
            num_periodic_columns: 0,
            ..Default::default()
        };
        let lg = LogUpGadget::new();
        get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &lg).0
    });
    crate::whole_chain::WholeChainMainConstraint::new(
        base.clone(),
        crate::whole_chain::SymLeafLayout { w: row_w, preproc_w: 0, npub: 0 },
        row_w,
        0,
        0,
        Vec::new(),
        gamma,
        max_deg,
        false,
    )
}

#[must_use]
pub fn make_constraint_with_seed(
    seed: u64,
    expected_chal: Fa4,
) -> impl Fn(Ea4) -> SpongeChainConstraint + Clone {
    use p3_air::symbolic::AirLayout;
    use p3_batch_stark::symbolic::get_symbolic_constraints;
    use p3_lookup::logup::LogUpGadget;
    use p3_poseidon2_air::Poseidon2Air;
    type P2Air = Poseidon2Air<
        KoalaBear,
        GenericPoseidon2LinearLayersKoalaBear,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >;
    let air = P2Air::new(constants_for_seed(seed));
    // The AIR's own width is P2_COLS — `Poseidon2Cols::borrow` asserts it — so the symbolic
    // constraints are generated in THAT frame. The row committed on the wire is wider (it carries the
    // absorbed values and selectors too), and `SymLeafLayout { w: ROW_COLS }` below is what maps those
    // same variable indices into the wider frame: every Poseidon2 variable index is < P2_COLS, so it
    // lands on the same column either way, while the next-row half is offset by the REAL row width.
    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: P2_COLS,
        num_public_values: 0,
        num_periodic_columns: 0,
        ..Default::default()
    };
    let lg = LogUpGadget::new();
    let (base, _ext) = get_symbolic_constraints::<KoalaBear, Ea4, _, _>(&air, layout, &[], &lg);
    move |gamma: Ea4| SpongeChainConstraint {
        p2: crate::whole_chain::WholeChainMainConstraint::new(
            base.clone(),
            crate::whole_chain::SymLeafLayout { w: ROW_COLS, preproc_w: 0, npub: 0 },
            ROW_COLS,
            0,
            0,
            Vec::new(),
            gamma,
            8,
            false,
        ),
        gamma,
        expected_chal: Ea4::from(expected_chal),
        segments: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ⭐ A BASE ROW IS THE SAME ROW. The gate on a random base-field row and point, `eval_base`, equals `eval` on that row lifted, for
    /// a segmented sponge and a chain alike (one law list, two fields; the batching must land every residual on the same power).
    #[test]
    fn the_sponge_gate_on_a_base_row_is_the_gate_on_that_row_lifted() {
        use crate::air_zerocheck::{AirConstraint, OobLatch, Row};
        use p3_field::PrimeCharacteristicRing;
        use p3_field::Field;
        use rand::{rngs::SmallRng, RngExt, SeedableRng};
        let mut rng = SmallRng::seed_from_u64(0x5ba5e);
        let seed = crate::committed_air::COMMITTED_AIR_SEED;
        let gamma: Ea4 = Ea4::from(Fa4::from_u64(0x1234_5677)) * Ea4::from(Fa4::from_u64(3)) + Ea4::GENERATOR;
        let gates = [make_segmented_constraint_with_seed(seed, 3)(gamma), make_constraint_with_seed(seed, Fa4::ZERO)(gamma)];
        for g in &gates {
            assert!(g.has_base_eval(), "the sponge has a base path");
            for _ in 0..8 {
                let row: Vec<Fa4> = (0..ROW_COLS).map(|_| Fa4::from_u32(rng.random::<u32>() >> 2)).collect();
                let next: Vec<Fa4> = (0..ROW_COLS).map(|_| Fa4::from_u32(rng.random::<u32>() >> 2)).collect();
                let x: Vec<Fa4> = (0..6).map(|_| Fa4::from_u32(rng.random::<u32>() >> 2)).collect();
                let oob = OobLatch::new();
                let base = g.eval_base(&Row::new(&row, &oob), &|c| next[c], &x);
                let (lr, ln, lx): (Vec<Ea4>, Vec<Ea4>, Vec<Ea4>) = (
                    row.iter().map(|v| Ea4::from(*v)).collect(),
                    next.iter().map(|v| Ea4::from(*v)).collect(),
                    x.iter().map(|v| Ea4::from(*v)).collect(),
                );
                let lifted = g.eval(&Row::new(&lr, &oob), &|c, _| ln[c], &lx);
                assert_eq!(base, lifted, "⛔ the base path and the extension path disagree on a row");
            }
        }
    }

    /// ⭐ THE EQ FACTOR AND THE BASE ROUND ARE PROVER-SIDE ONLY: the same trace and the same transcript give the same proof bytes as the
    /// reference prover (every round sampled at every point, in the extension). A real sponge chain, whose laws read next-row cells.
    #[test]
    fn the_eq_factor_prover_lays_the_bytes_of_direct_sampling() {
        use crate::air_zerocheck::{prove_air_zerocheck, DIRECT_SAMPLING_FOR_TEST};
        use crate::hiding_decider::{Chl, Perm16};
        use p3_field::{Field, PrimeCharacteristicRing};
        use rand::{rngs::SmallRng, SeedableRng};
        use std::sync::atomic::Ordering::SeqCst;
        let tuples: Vec<Vec<Fa4>> = (0..16u64).map(|r| (0..8u64).map(|c| Fa4::from_u64(r * 100 + c + 1)).collect()).collect();
        let cols = crate::settlement_delta::chain_table_of(&tuples).expect("a chain table");
        let nv = cols[0].len().trailing_zeros() as usize;
        let gamma = Ea4::from(Fa4::from_u64(987_654_321)) + Ea4::GENERATOR;
        let gate = make_constraint_with_seed(crate::committed_air::COMMITTED_AIR_SEED, Fa4::ZERO)(gamma);
        let prove = |direct: bool| {
            DIRECT_SAMPLING_FOR_TEST.store(direct, SeqCst);
            let mut ch = Chl::new(Perm16::new_from_rng_128(&mut SmallRng::seed_from_u64(7)));
            let z: Vec<Ea4> = (0..nv).map(|k| Ea4::from(Fa4::from_u64(k as u64 + 11)) + Ea4::GENERATOR).collect();
            let p = prove_air_zerocheck(&cols, &gate, &z, &mut ch);
            DIRECT_SAMPLING_FOR_TEST.store(false, SeqCst);
            postcard::to_allocvec(&p).expect("the proof encodes")
        };
        assert_eq!(prove(false), prove(true), "⛔ the eq-factor prover's bytes differ from direct sampling");
    }

    use crate::whir_rec_block::{
        prove_air_direct_light_decider_selfcontained_bytes,
        verify_air_direct_light_decider_selfcontained_bytes,
    };

    const BIND: [Fa4; 1] = [KoalaBear::new(0x5350_4e47)]; // "SPNG"
    /// The WHIR `nvars >= 5` floor this crate already pins the same way — a proof-system shape.
    const ROWS: usize = 32;

    /// An absorb schedule that crosses the rate boundary awkwardly, forces a partial-rate duplexing,
    /// AND draws challenges FOUR AT A TIME — the shape of a single `Ea4` sample, whose 2nd..4th base
    /// pops reuse one permutation output. A schedule that only ever popped once per duplexing would let
    /// a binding that covers the first pop alone look complete.
    fn schedule() -> (Vec<Vec<KoalaBear>>, Vec<usize>) {
        let g = |n: usize, s: u64| -> Vec<KoalaBear> {
            (0..n).map(|i| KoalaBear::from_u64(s + i as u64)).collect()
        };
        (vec![g(8, 1), g(3, 100), g(9, 200)], vec![0, 4, 4])
    }

    fn steps() -> Vec<SpongeStep> {
        let (a, s) = schedule();
        let st = replay(&a, &s);
        assert!(st.len() >= 3, "the schedule must produce several duplexings: {}", st.len());
        // A partial-rate duplexing must actually occur, or the selectors are never exercised.
        assert!(
            st.iter().any(|x| x.overwritten.iter().any(|o| !o)),
            "the schedule must force at least one PARTIAL-rate duplexing"
        );
        // And a MULTI-pop duplexing, or the per-pop fold is never exercised beyond its first cell.
        assert!(
            st.iter().any(|x| x.pops >= 4),
            "the schedule must force a duplexing that yields 4 challenges (one Ea4 sample)"
        );
        st
    }

    /// What the SERVER lays out and proves, plus the challenge fold the transcript actually produced.
    fn server_trace() -> (Vec<Vec<Fa4>>, Fa4) {
        build_trace(&steps(), ROWS)
    }

    /// ⭐ NON-VACUITY OF THE LATER POPS. Before this increment only the FIRST pop of each duplexing was
    /// folded, which would have left three of every `Ea4` challenge's four base limbs free for a prover
    /// to choose. Recompute the fold with pop `k` perturbed, for EVERY k a row actually popped, and
    /// demand the fold moves each time — otherwise the binding below is decorative for those limbs.
    #[test]
    fn every_pop_of_a_multi_pop_duplexing_moves_the_fold() {
        let st = steps();
        let honest = build_trace(&st, ROWS).1;
        let m = KoalaBear::from_u64(CHAL_FOLD_MULT);
        let fold = |perturb: Option<(usize, usize)>| -> Fa4 {
            let mut acc = KoalaBear::ZERO;
            for (r, x) in st.iter().enumerate() {
                for k in 0..x.pops {
                    let mut v = x.output[pop_slot(k)];
                    if perturb == Some((r, k)) {
                        v += KoalaBear::ONE;
                    }
                    acc = acc * m + v;
                }
            }
            acc
        };
        assert_eq!(fold(None), honest, "the witness fold and the reference fold must agree");
        let mut checked = 0usize;
        for (r, x) in st.iter().enumerate() {
            for k in 0..x.pops {
                assert_ne!(
                    fold(Some((r, k))),
                    honest,
                    "⛔ pop {k} of row {r} does NOT move the challenge fold — that challenge is UNBOUND \
                     and a prover could choose it freely"
                );
                checked += 1;
            }
        }
        assert!(checked >= 8, "the schedule must exercise several pops, saw {checked}");
        eprintln!("[sponge-chain] every one of {checked} popped challenge(s) moves the fold");
    }

    /// The honest chain crosses the boundary: the SERVER proves, and an ADOPTER that built its own
    /// circuit independently accepts the bytes. If the two sides ever derived different circuits this is
    /// where it shows, which is the cross-implementation property the whole decider rests on.
    #[test]
    fn a_server_proof_verifies_for_an_adopter_that_built_its_own_circuit() {
        let (trace, chal) = server_trace();
        let server_side = make_constraint(chal);
        // INDEPENDENT: shares no object with the server. It is handed the CHALLENGES it expects — the
        // same thing an outer verifier already holds because it checks the inner algebra against them.
        let adopter_side = make_constraint(chal);
        let proof = prove_air_direct_light_decider_selfcontained_bytes(trace, server_side, &BIND)
            .expect("an honest sponge chain proves");
        assert!(
            verify_air_direct_light_decider_selfcontained_bytes(&proof, adopter_side, &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&proof)),
            "an independently-derived adopter must accept an honest server's sponge chain, or prover and \
             verifier are not building the same circuit"
        );
        eprintln!(
            "[sponge-chain] server proved {ROWS} rows x {ROW_COLS} cols; an independent adopter accepted \
             {} byte(s)",
            proof.len()
        );
    }

    /// ⭐⭐ THE CHALLENGE-EQUALITY PIN. The server proves an HONEST sponge — every permutation right,
    /// every chaining right — and an adopter that is checking algebra against DIFFERENT challenges must
    /// still refuse it. This is the residual the whole join door turns on: without it a prover replays
    /// Fiat-Shamir natively, picks whatever challenges make its inner statement true, and hands over a
    /// sponge that is internally perfect and bound to nothing.
    #[test]
    fn an_adopter_checking_different_challenges_refuses_an_otherwise_perfect_sponge() {
        let (trace, chal) = server_trace();
        let proof =
            prove_air_direct_light_decider_selfcontained_bytes(trace, make_constraint(chal), &BIND)
                .expect("an honest sponge chain proves");
        let wrong = chal + KoalaBear::ONE;
        assert_ne!(wrong, chal, "the counterfactual fold must differ, or this pin proves nothing");
        assert!(
            !verify_air_direct_light_decider_selfcontained_bytes(&proof, make_constraint(wrong), &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&proof)),
            "⛔ CHALLENGE EQUALITY IS NOT BOUND: an adopter expecting different challenges accepted this \
             sponge, so the rows prove a permutation chain that says nothing about which challenges the \
             inner proof was checked against."
        );
        eprintln!("[sponge-chain] an adopter expecting different challenges refused the proof");
    }

    /// Each case alters exactly ONE thing a forger would want to alter, and the ADOPTER is the side that
    /// must refuse. A constraint that PROVES but does not BIND passes the honest test and fails here —
    /// which is the whole reason these exist.
    #[test]
    fn an_adopter_refuses_every_single_cell_forgery_in_the_chain() {
        // The row the schedule pops FOUR challenges from, so the tampered fold cells are ones a real
        // `Ea4` sample would occupy — derived, never a literal.
        let multi = steps().iter().position(|x| x.pops >= 4).expect("a 4-pop duplexing exists");
        let cases: [(&str, usize, usize); 8] = [
            ("absorbed value", ABSORB_OFF + 2, 1),
            ("carried capacity", OUTPUT_OFF + RATE + 1, 1),
            ("rate slot", INPUT_OFF + 1, 2),
            ("overwrite selector", OW_OFF, 1),
            ("first pop's fold cell", ACC_OFF, multi),
            ("fourth pop's fold cell", ACC_OFF + 3, multi),
            ("the row's final fold", ACC_OFF + RATE - 1, multi),
            ("a pop selector", SQ_OFF + 3, multi),
        ];
        for (what, col, row) in cases {
            let (mut bad, chal) = server_trace();
            let forger_side = make_constraint(chal);
            let adopter_side = make_constraint(chal); // INDEPENDENT
            bad[col][row] += KoalaBear::ONE;
            // A prover that cannot even BUILD the object is itself a refusal — the forgery never reaches
            // an adopter. Written as an explicit match so the two outcomes stay distinguishable.
            let accepted = match prove_air_direct_light_decider_selfcontained_bytes(bad, forger_side, &BIND)
            {
                None => false,
                Some(p) => verify_air_direct_light_decider_selfcontained_bytes(&p, adopter_side, &BIND, crate::whir_rec_block::declared_direct_shape_for_tests(&p)),
            };
            assert!(
                !accepted,
                "⛔ FORGERY ACCEPTED ({what}, col {col}, row {row}): the chain constraints PROVE but do \
                 not BIND. A server could hand an adopter permutation rows that are not one sponge, and \
                 any transcript binding built on this would be silently unsound."
            );
            eprintln!("[sponge-chain] adopter refused the forgery: {what}");
        }
    }
}

/// ⭐⭐⭐ DB-167 — THE MEMOISED PERMUTATION IS THE SAME OBJECT, PROVEN RATHER THAN ASSERTED.
///
/// [`perm_for_seed`] used to re-derive the round schedule on every call and now hands out one shared
/// instance per seed. That is only safe if the cached constants are BYTE-IDENTICAL to a freshly derived
/// set — otherwise every hash the chain has ever computed would change, which is a silent hard fork.
///
/// So this does not trust the determinism argument: it derives a fresh permutation the old way and
/// compares the ACTUAL OUTPUT on inputs that exercise every lane, at every seed production uses.
#[cfg(test)]
mod db167_memoised_permutation {
    use super::*;
    use p3_field::{PrimeCharacteristicRing, PrimeField32};
    use p3_symmetric::Permutation;

    fn permute_with(p: &p3_koala_bear::Poseidon2KoalaBear<WIDTH>, seedling: u64) -> [u32; WIDTH] {
        let mut st: [KoalaBear; WIDTH] =
            core::array::from_fn(|i| KoalaBear::from_u64(seedling.wrapping_mul(i as u64 + 1) + 7));
        p.permute_mut(&mut st);
        core::array::from_fn(|i| st[i].as_canonical_u32())
    }

    #[test]
    fn the_memoised_permutation_is_byte_identical_to_a_freshly_derived_one() {
        let seeds = [
            crate::whir_rec_block::REC_DECIDER_SEED,
            crate::committed_air::COMMITTED_AIR_SEED,
            0,
            1,
            u64::MAX,
        ];
        for s in seeds {
            let cached = perm_for_seed(s);
            // The OLD body, called directly — this is the thing being replaced.
            let fresh = derive_perm(s);
            for k in 0..8u64 {
                assert_eq!(
                    permute_with(cached, k),
                    permute_with(&fresh, k),
                    "seed {s} input {k}: the cached permutation computed a DIFFERENT hash than a \
                     freshly derived one — DB-167's caching would be a silent hard fork"
                );
            }
            // And the cache must hand back the SAME object on a second call, or it is not a cache.
            assert!(
                std::ptr::eq(cached, perm_for_seed(s)),
                "seed {s}: perm_for_seed rebuilt instead of reusing — the per-hash derivation DB-167 \
                 measured at ~3.4 us is still being paid"
            );
        }
        // ⛔ NON-VACUITY: two DIFFERENT seeds must give DIFFERENT permutations, or the comparison above
        // would pass on a cache that ignored its key and every family would share one schedule.
        assert_ne!(
            permute_with(perm_for_seed(0), 3),
            permute_with(perm_for_seed(1), 3),
            "two seeds produced the same permutation — the seed is not reaching the derivation"
        );
    }

    /// ⭐ AND THE NUMBER THAT JUSTIFIES THE CHANGE. Prints the per-hash cost both ways so the 3,619 ns
    /// DB-153 attributed to `poseidon_pair` has a named cause rather than a suspicion.
    #[test]
    fn a_hash_no_longer_pays_for_its_own_round_constants() {
        const N: usize = 50_000;
        let mut st = [KoalaBear::ZERO; WIDTH];

        let t = std::time::Instant::now();
        for _ in 0..N {
            production_perm().permute_mut(&mut st);
        }
        let cached_ns = t.elapsed().as_nanos() as f64 / N as f64;

        const M: usize = 2_000;
        let t = std::time::Instant::now();
        for _ in 0..M {
            derive_perm(crate::whir_rec_block::REC_DECIDER_SEED).permute_mut(&mut st);
        }
        let derived_ns = t.elapsed().as_nanos() as f64 / M as f64;
        std::hint::black_box(st);

        eprintln!("\n[db167] permute + CACHED constants   {cached_ns:>9.0} ns/hash");
        eprintln!("[db167] permute + DERIVED constants  {derived_ns:>9.0} ns/hash  (the old body)");
        eprintln!("[db167] speedup {:.1}x — and a 256-tag block folds 2x256x256 = 131,072 of these\n",
            derived_ns / cached_ns.max(1.0));
        // ⛔ THE BOUND IS WHAT WAS MEASURED, NOT WHAT WAS HOPED FOR. I expected the derivation to be
        // most of the 3,619 ns `poseidon_pair` costs and asserted 4x on that expectation; it MEASURED at
        // ~434 ns of it, so the honest claim is "the cache removes a real, repeatable per-hash cost" and
        // the rest of the 3,619 ns has to be found elsewhere — which `where_compress_spends_its_time`
        // below does rather than leaving it as a suspicion.
        assert!(
            cached_ns < derived_ns,
            "the cache bought NOTHING ({cached_ns:.0} vs {derived_ns:.0} ns) — it is not being hit"
        );

        // ── AND THE SPLIT INSIDE `compress`, which is what the chain actually calls.
        let l = crate::poseidon2_compress::lanes_of(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let r = crate::poseidon2_compress::lanes_of(&[9, 10, 11, 12, 13, 14, 15, 16]);
        let t = std::time::Instant::now();
        let mut acc = l;
        for _ in 0..N {
            acc = crate::poseidon2_compress::compress(&acc, &r);
        }
        let compress_ns = t.elapsed().as_nanos() as f64 / N as f64;
        std::hint::black_box(acc);
        eprintln!(
            "[db167] compress() end to end       {compress_ns:>9.0} ns/pair  \
             (= {cached_ns:.0} permute + {:.0} marshalling)",
            compress_ns - cached_ns
        );
    }
}
