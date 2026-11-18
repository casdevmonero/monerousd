// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0
//
// This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
// zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
// the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

//! THE LEVEL AGGREGATE'S PROBES (lane agg, docs/LEVEL-AGGREGATE-SPEC-20261115.md §6). Measurement only: nothing here is
//! a consensus object, nothing is called by the node or the wallet, and every test is `#[ignore]` so the landing gate
//! never runs it. Each replaces one NOT MEASURED input of `tools/speedmodel/agg_model.py`.
//!
//! P1 — the row rate of the STACKED carrier door (`committed_air`, the door the aggregate's leaves and merges must use:
//! it binds its trace through WHIR and observes its statement first through `public_bind`), unblinded and blinded, on
//! the NARROW permutation layout (`pow_pq_air::P2_COLS` columns a row: one Poseidon2-16 permutation, the unit the
//! aggregate's hashing is made of). The model's input today is the WIDE batch-engine table (lane c4 §14.1f: 16,384 rows ×
//! 258 columns in 5.3 s at 4 threads = 3,091 rows/s); P1 says whether the narrow layout is the faster one per row and
//! what blinding costs, at the threads the caller gives (`RAYON_NUM_THREADS`). It prints the machine's load beside every
//! number: a figure taken on a loaded machine is labelled so, never compared with a solo one.
//!
//! Cons: none to the chain (test-only, ignored). Cost to the machine: one table proved at each of three heights, two
//! doors, the largest 2^14 rows (2^14 × 256 = 2^22 cells, under the 2^24 cap).

#[cfg(test)]
mod tests {
    use crate::hiding_decider::Fa4;
    use p3_field::PrimeCharacteristicRing;

    fn load() -> String {
        std::process::Command::new("sysctl")
            .args(["-n", "vm.loadavg"])
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
    }

    #[test]
    #[ignore] // P1: a measurement, run by hand through lane_run (docs/LEVEL-AGGREGATE-SPEC-20261115.md §6)
    fn p1_the_stacked_door_row_rate_on_the_narrow_permutation_layout() {
        let threads = rayon::current_num_threads();
        let seed = [p3_koala_bear::KoalaBear::new(7); crate::pow_pq_air::WIDTH];
        let bind: Vec<Fa4> = (0..8u64).map(Fa4::from_u64).collect();
        eprintln!("[agg-p1] start · {threads} thread(s) · load {}", load());
        for rows in [1usize << 12, 1 << 13, 1 << 14] {
            // committed (unblinded): the merge's door when its children's openings are public bytes
            let cols = crate::pow_pq_air::build_perm_chain(seed, rows);
            let t = std::time::Instant::now();
            let p = crate::committed_air::prove_air_committed_bytes(cols, crate::pow_pq_air::make_perm_constraint(), &bind)
                .expect("the permutation table proves on the committed door");
            let prove = t.elapsed().as_secs_f64();
            let shape = crate::committed_air::declared_committed_shape_for_tests(&p);
            let t = std::time::Instant::now();
            assert!(
                crate::committed_air::verify_air_committed_bytes(&p, crate::pow_pq_air::make_perm_constraint(), &bind, shape),
                "an honest table verifies on the committed door"
            );
            let verify = t.elapsed().as_secs_f64();
            let mut other = bind.clone();
            other[0] += Fa4::ONE;
            assert!(
                !crate::committed_air::verify_air_committed_bytes(&p, crate::pow_pq_air::make_perm_constraint(), &other, shape),
                "the statement is bound: the same proof under another public_bind is refused"
            );
            eprintln!(
                "[agg-p1] committed · {rows} rows × {} cols · {threads} thread(s) · prove {:.0} ms · {:.0} rows/s · verify {:.0} ms · {} B · load {}",
                crate::pow_pq_air::P2_COLS, prove * 1e3, rows as f64 / prove, verify * 1e3, p.len(), load()
            );
            // blinded: the door a leaf needs when it holds the private real/decoy bit (spec §1.4)
            let cols = crate::pow_pq_air::build_perm_chain(seed, rows);
            let t = std::time::Instant::now();
            let b = crate::committed_air::prove_air_blinded_bytes(cols, crate::pow_pq_air::make_perm_constraint(), &bind)
                .expect("the permutation table proves on the blinded door");
            let prove_b = t.elapsed().as_secs_f64();
            let laid = crate::committed_air::declared_blinded_laid_shape_for_tests(&b);
            assert!(
                crate::committed_air::verify_air_blinded_bytes(&b, crate::pow_pq_air::make_perm_constraint(), &bind, laid),
                "an honest table verifies on the blinded door"
            );
            eprintln!(
                "[agg-p1] blinded   · {rows} rows × {} cols · {threads} thread(s) · prove {:.0} ms · {:.0} rows/s · {} B · load {}",
                crate::pow_pq_air::P2_COLS, prove_b * 1e3, rows as f64 / prove_b, b.len(), load()
            );
        }
    }
}
