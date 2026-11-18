#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""LANE M - THE ENGINE'S CHECK ON ITSELF.

An instrument that decides whether the chain's own checks are real has to be held to a higher bar
than the code it measures, and "higher bar" has to mean something executable. This file executes it:
it exercises the engine's structural promises against a fixture module, in under a second, with no
build and no machine load, so there is never a reason to skip it.

WHAT IT PROVES (each one a promise the engine makes in mutate.py's header):
  1. RESTORE IS EXACT      - a mutated file comes back byte-identical to its pristine copy.
  2. THE ORACLE IS SAFE    - no mutation site is ever selected inside cfg-test code.
  3. DRIFT IS REFUSED      - a mutant whose recorded site text no longer matches is refused rather
                             than applied to whatever now sits at that line number.
  4. IDS ARE CONTENT-BOUND - a mutant id is derived from the bytes it was cut from, so a manifest
                             cannot silently re-target a moved line.
  5. SITES ARE CHECKS      - selection lands on refusals, bounds and comparisons rather than on
                             plumbing.
  6. A CRASH LEAVES NOTHING - after a simulated death mid-mutant, recovery restores the file.

Run:  python3 tools/harness/mutate/selfcheck.py
Exit: 0 = every promise held. Non-zero = the engine is not fit to judge anything today.

COST ARITHMETIC - cons: none. Pure Python under tools/, never in the crate graph; it reads and
writes only a temporary fixture directory it creates and removes.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import mutate      # noqa: E402
import operators   # noqa: E402
import rustsrc     # noqa: E402
import selection   # noqa: E402

ATTR = "#[" + "test" + "]"
CFG_ATTR = "#[cfg(" + "test" + ")]"

FIXTURE = """// fixture module for the engine's own check
pub fn meets_bound(value: u128, bound: u128) -> bool {
    if bound == 0 {
        return false;
    }
    if value > bound {
        return false;
    }
    value != 0 && bound < 4096
}

pub fn admit(count: usize, shape: usize) -> Result<(), &'static str> {
    if count > 256 {
        return Err("too many");
    }
    if shape != 32 {
        return Err("wrong shape");
    }
    Ok(())
}

pub fn name(&self) -> &str {
    self.label
}

""" + CFG_ATTR + """
mod tests {
    use super::*;

    """ + ATTR + """
    fn the_bound_holds() {
        assert!(meets_bound(1, 4));
        assert!(!meets_bound(9, 4));
        assert_eq!(admit(1, 32).is_ok(), true);
    }
}
"""

failures = []


def check(name, ok, detail=""):
    print("  %-46s %s%s" % (name, "OK" if ok else "BROKEN", ("  " + detail) if detail else ""))
    if not ok:
        failures.append(name)


def main():
    print("[lane-m selfcheck] the engine's promises, executed")
    root = tempfile.mkdtemp(prefix="lane-m-selfcheck-")
    try:
        src = os.path.join(root, "src")
        os.makedirs(src)
        rel = "src/fixture.rs"
        path = os.path.join(root, rel)
        with open(path, "w") as fh:
            fh.write(FIXTURE)
        original = open(path, "rb").read()
        rf = rustsrc.RustFile(rel, FIXTURE)

        # 5. SITES ARE CHECKS
        sites = selection.sites_in_file(rf)
        kinds = sorted(set(s["kind"] for s in sites))
        check("sites land on checks, not plumbing",
              "fail_closed_guard" in kinds and any(k in kinds for k in ("comparison", "logic")),
              "kinds=%s" % ",".join(kinds))
        check("no site is a plumbing accessor",
              all(s["fn"] != "name" for s in sites))

        # 2. THE ORACLE IS SAFE
        in_oracle = [s for s in sites if rf.in_oracle_region(s["line"])]
        check("no site inside cfg-test code", not in_oracle,
              "%d violations" % len(in_oracle))
        oracle_fns = [f["name"] for f in rf.fns if f["is_oracle_fn"]]
        check("the oracle function is recognised as oracle", oracle_fns == ["the_bound_holds"],
              str(oracle_fns))

        muts = selection.mutants_for_file(rf, focus_fns=["meets_bound"], cap=0)
        check("mutants were produced", len(muts) > 6, "%d mutants" % len(muts))

        # 4. IDS ARE CONTENT-BOUND
        ids = [m.mutant_id for m in muts]
        check("mutant ids are unique", len(ids) == len(set(ids)))
        again = selection.mutants_for_file(rf, focus_fns=["meets_bound"], cap=0)
        check("mutant ids are deterministic across runs",
              [m.mutant_id for m in again] == ids)
        check("a mutant id carries the hash of the bytes it was cut from",
              all(m.site_hash in m.mutant_id for m in muts))

        # 1. RESTORE IS EXACT, over every operator the fixture produces
        pristine_dir = os.path.join(root, "pristine")
        os.makedirs(pristine_dir)
        ws = mutate.Workspace(root, pristine_dir, lambda _m: None)
        applied_ops = set()
        exact = True
        changed_every_time = True
        for m in muts:
            ws.apply(m)
            if open(path, "rb").read() == original:
                changed_every_time = False
            applied_ops.add(m.op)
            ws.restore(m.relpath)
            if open(path, "rb").read() != original:
                exact = False
        check("every mutant actually changed the file", changed_every_time)
        check("restore is byte-identical after every mutant", exact,
              "%d mutants, ops=%s" % (len(muts), ",".join(sorted(applied_ops))))
        check("the operator set exercised is broad",
              len(applied_ops) >= 5, ",".join(sorted(applied_ops)))

        # 3. DRIFT IS REFUSED. The mutation below is a real one whose recorded `before` no longer
        # matches the file - exactly what happens when a manifest is replayed after the code moved.
        moved = muts[0]
        stale = operators.Mutation(moved.op, moved.direction, rel, moved.a, moved.b,
                                   moved.before + "  // this line has since moved",
                                   moved.after, moved.fn_name, moved.site_kind)
        refused = False
        try:
            ws.apply(stale)
        except mutate.SiteDrift:
            refused = True
        check("a drifted site is refused, not applied", refused)
        check("a refused drift left the file untouched", open(path, "rb").read() == original)

        # 6. A CRASH LEAVES NOTHING BEHIND
        victim = muts[0]
        ws.apply(victim)
        check("the in-flight marker exists while a mutant is applied",
              os.path.exists(ws.in_flight_path))
        with open(ws.in_flight_path) as fh:
            marker = json.load(fh)
        check("the marker names the mutated file", marker.get("file") == rel)
        del ws  # the pass dies here, with the mutation still on disk
        check("the file is still mutated after the simulated death",
              open(path, "rb").read() != original)
        ws2 = mutate.Workspace(root, pristine_dir, lambda _m: None)
        ws2.recover_if_needed()
        check("the next start recovers the file byte-identically",
              open(path, "rb").read() == original)
        check("recovery cleared the in-flight marker", not os.path.exists(ws2.in_flight_path))

        # backup copies of production files are never sources
        check("`.pre` backup copies are not live source",
              not rustsrc.is_live_source("src/node.rs.preLanding-20260904")
              and rustsrc.is_live_source("src/node.rs"))

        # ⛔⛔⛔ SUPERVISION REACHES THE GRANDCHILD, OR IT REACHES NOTHING.
        #
        # This file checked every promise the engine makes about MUTANTS and none about the only
        # promise the SUPERVISOR makes, and the supervisor was broken for the engine's whole life:
        # `cmd` is `cargo test`, the compiled test binary is cargo's child, and a bare `proc.kill()`
        # reached cargo alone. The orphan kept the inherited stdout pipe open, so the `communicate()`
        # on the next line waited on it and the pass hung with no line printed. MEASURED 2026-09-08:
        # `[2/12] pow.rs@159:body_false` still running at 25 min against 883 s of supervision, 49% CPU,
        # machine load 107, ended by hand — and the previous night's `~30 min, unresolved` was the same
        # defect, filed then as "the restrictive half is pathologically slow".
        #
        # The shape below is the one that ALSO defeated the first repair: the direct child exits at
        # once and leaves the grandchild running, so a group-kill gated on `proc.poll() is None` is
        # skipped in exactly the case it exists for. Both halves are asserted — that the supervisor
        # RETURNS, and that nothing it was supervising is left alive.
        #
        # cons: none. f(fixed constants) — one `/bin/sh`, one `/bin/sleep`, one 3 s supervision, both
        # processes killed by the assertion itself. Nothing scales with the crate, the suite, the
        # chain or the number of mutants; 0 bytes on the DA, 0 bytes of node RAM, 0 checks removed
        # from any shipping path. It runs in tools/, never in the crate graph.
        import runner as _runner  # noqa: E402  (the supervisor, checked here like any other promise)
        marker = "sleep 4457"
        t0 = time.time()
        sup = _runner.run(["/bin/sh", "-c", "/bin/sleep 4457 & exit 0"], root, dict(os.environ), 3)
        took = time.time() - t0
        time.sleep(1)
        leaked = subprocess.run(["pgrep", "-f", marker],
                                stdout=subprocess.PIPE).stdout.decode().split()
        check("supervision stops a process whose CHILD outlives it", sup["stopped"] and took < 60,
              "returned in %.1fs, stopped=%s" % (took, sup["stopped"]))
        check("supervision leaves no orphan of what it stopped", not leaked,
              "survivors: %s" % (leaked or "none"))
    finally:
        shutil.rmtree(root, ignore_errors=True)

    print("")
    if failures:
        print("[lane-m selfcheck] %d PROMISE(S) BROKEN: %s" % (len(failures), ", ".join(failures)))
        print("The engine is not fit to judge the suite until these hold.")
        return 1
    print("[lane-m selfcheck] every promise held.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
