# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0
#
# This file is an original work of the MoneroUSD Protocol, a post-quantum GHOSTDAG block-DAG
# zero-knowledge confidential-value protocol. It is NOT part of the Monero Project. Licensed under
# the Apache License, Version 2.0; see the LICENSE and NOTICE files at the repository root.

import sys
f = "/root/MoneroUSD-clean/monero/external/Plonky3/pqpool/src/circuit.rs"
s = open(f).read()
if "nf_public" in s:
    print("nf_public already present; skip"); sys.exit(0)

# 1) struct: add the flag
struct_anc = "    pub emit_leaf_buses: bool,\n}"
if s.count(struct_anc) != 1: print("FATAL struct anchor x%d" % s.count(struct_anc)); sys.exit(1)
s = s.replace(struct_anc, "    pub emit_leaf_buses: bool,\n    /// CRY-6 public-nf: when true, EXPOSE the computed nullifier as public inputs (appended after\n    /// anchor‖chain‖commitment) instead of sending it on NS_LEAF_BUS. The daemon maintains a public\n    /// nullifier SET and rejects duplicates (Zcash/Monero model) — enables multi-spend.\n    pub nf_public: bool,\n}", 1)

# 2) num_public_values
npv_anc = "    fn num_public_values(&self) -> usize {\n        DIGEST + 1 + 4 // anchor ‖ chain ‖ batch_commitment\n    }"
if s.count(npv_anc) != 1: print("FATAL npv anchor x%d" % s.count(npv_anc)); sys.exit(1)
s = s.replace(npv_anc, "    fn num_public_values(&self) -> usize {\n        DIGEST + 1 + 4 + if self.nf_public { DIGEST } else { 0 } // anchor ‖ chain ‖ batch_commitment [‖ nf]\n    }", 1)

# 3) eval: split the bus send + add the public-nf binding
eval_anc = '''        if self.emit_leaf_buses {
            builder.push_interaction(CMT_LEAF_BUS, outcm.clone(), -AB::Expr::ONE, 1); // send
            builder.push_interaction(NS_LEAF_BUS, nf.clone(), -AB::Expr::ONE, 1); // send
        }'''
if s.count(eval_anc) != 1: print("FATAL eval anchor x%d" % s.count(eval_anc)); sys.exit(1)
s = s.replace(eval_anc, '''        if self.emit_leaf_buses {
            builder.push_interaction(CMT_LEAF_BUS, outcm.clone(), -AB::Expr::ONE, 1); // send out_cm
            if !self.nf_public {
                builder.push_interaction(NS_LEAF_BUS, nf.clone(), -AB::Expr::ONE, 1); // send nf (hidden-nf path)
            }
        }
        // CRY-6 public-nf: bind the proven nullifier to the public inputs appended after anchor‖chain‖commitment.
        if self.nf_public {
            for j in 0..DIGEST {
                builder.assert_eq(nf[j].clone(), pis[DIGEST + 1 + 4 + j].into());
            }
        }''', 1)

# 4) update existing call sites (preserve behavior with nf_public: false)
for pat in [", emit_leaf_buses: false }", ", emit_leaf_buses: true }"]:
    s = s.replace(pat, pat[:-2] + ", nf_public: false }")

open(f, "w").write(s)
print("SpendBatchAir: nf_public flag + eval binding + callers updated")
print("remaining bare-init call sites:", s.count("emit_leaf_buses:") - s.count("nf_public:"))
