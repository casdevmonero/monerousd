#!/usr/bin/env python3
# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""LANE M - THE MUTATION ENGINE.

THE QUESTION THIS ANSWERS: *does our suite actually defend this invariant, or does it merely run?*
A green suite proves that the code we wrote passes the checks we wrote. It does not prove that the
checks would notice if the code stopped checking. This engine breaks one production check at a time
and asks whether anything goes red. A mutant that SURVIVES is an invariant nothing defends.

COST ARITHMETIC (written down rather than assumed) - cons: NONE on chain. This driver is Python
under tools/; it never enters the crate graph, so its delta to every cardinal is exactly zero: 0
bytes on the DA, 0 bytes of node RAM, 0 checks removed from any shipping path. Engine cost per
nightly pass is (mutants selected) x (1 incremental rebuild + 1 targeted pin subset), and mutants
selected is a fixed budget in targets.json - f(budget), never f(chain height / notes / records).

SIX PROPERTIES MAKE IT TRUSTWORTHY, and each is enforced in code rather than promised:

  1. THE LIVE TREE IS NEVER MUTATED. Not "restored afterwards" - never touched. The engine works in
     an isolated APFS clone under the warm dir. Every live file is hashed before and after the pass,
     and if ANY file the engine mutated differs in the live tree the run STOPS LOUD (exit 2). Other
     files moving means another agent edited the repo mid-pass; that is reported by name, separately,
     because "the engine wrote where it must not" and "someone else saved a file" are different
     findings and collapsing them into one boolean teaches you to ignore the alarm.
  2. NO MUTATION OUTLIVES ITS MUTANT. Inside the clone, every file is copied pristine before its
     first mutation, restored after every mutant, and byte-verified against the pristine copy. An
     in-flight marker on disk means a previous pass died mid-mutant; the next start restores from
     pristine before doing anything else.
  3. A BASELINE THAT IS NOT GREEN VOIDS THE RUN. If a pin is already red before any mutation, every
     mutant would look "killed" for free. The engine runs the pin subset on pristine source first
     and refuses to score if anything is red.
  4. A KILL MUST SURVIVE ISOLATION. Seven of thirteen reds in this project's own gate history were
     parallelism flakes. A red here is re-run alone, single-threaded, and only a red that reproduces
     is a kill; one that does not is INCONCLUSIVE_FLAKE and counts neither way.
  5. NO CLOCK EVER DECIDES ANYTHING. Every clock in this engine lives in runner.py, a module that
     cannot express an outcome. When supervision has to stop a wedged compile, that is a fact about
     the machine: the mutant is recorded NO_VERDICT_STOPPED, excluded from every score, and listed
     for re-running. Late is not the same as never.
  6. THE ENGINE'S OWN FAILINGS NEVER INFLATE THE SCORE. A mutant that does not compile is
     UNCOMPILABLE; a mutant no pin claims is NO_PINS. Neither counts as a kill, and both are printed.

VERDICTS: KILLED · SURVIVED · UNCOMPILABLE · NO_PINS · INCONCLUSIVE_FLAKE · NO_VERDICT_STOPPED ·
          SITE_DRIFTED · CONFIRMED_SURVIVED · KILLED_BY_UNCLAIMED

WHAT `SURVIVED` MEANS, EXACTLY: no pin that CLAIMS this site (see selection.py) went red. That is
the honest, narrow claim. The broader claim - that the WHOLE suite misses it - requires
`--verify-survivors`, which re-runs each survivor against the full library suite and records
CONFIRMED_SURVIVED, or KILLED_BY_UNCLAIMED when some other pin catches what the claiming pins did
not (itself a finding: the pins that name the site are not the ones defending it).

USAGE
  mutate.py plan  --target pow
  mutate.py run   --target pow [--max-mutants N] [--verify-survivors] [--ops guard_disable,body_true]
  mutate.py replay --manifest <path>
"""

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import doors       # noqa: E402
import operators   # noqa: E402
import runner      # noqa: E402
import rustsrc     # noqa: E402
import selection   # noqa: E402
import semantic    # noqa: E402

EXCLUDE_TOP = {"target", "target-wf-strand-review", ".git", "~", ".DS_Store"}
SENTINEL_PATHS = ("src", "tests", "Cargo.toml", "Cargo.lock", "build.rs")
IN_FLIGHT = "MUTATION_IN_FLIGHT.json"

RESULT_LINE = re.compile(r"^test ([^\s]+) \.\.\. (ok|ignored|[A-Z]+)$")
RED = "FAILED"   # the token libtest prints for a red pin

# A verdict that is FINAL for a given source digest: re-measuring it would produce the same answer,
# so a resumed pass reuses it. Everything else (a stopped build, a flake, a drifted site) is
# deliberately absent - those are re-run, because they are the states where the engine learned
# nothing. Results are keyed by the live tree's content digest, so a single changed byte anywhere in
# the crate discards the whole cache rather than carrying a stale verdict forward.
FINAL_VERDICTS = ("KILLED", "KILLED_BY_UNCLAIMED", "SURVIVED", "CONFIRMED_SURVIVED",
                  "UNCOMPILABLE", "NO_PINS")


class ResultCache(object):
    """Per-digest, append-as-you-go results so an interrupted pass RESUMES instead of restarting.

    Nightly work that has to start over after every interruption does not get run. Each record is
    appended the moment its mutant is judged, so a pass killed at any point keeps everything it
    measured and re-measures only what it did not.
    """

    def __init__(self, root, digest):
        self.dir = os.path.join(root, "results")
        if not os.path.isdir(self.dir):
            os.makedirs(self.dir)
        self.path = os.path.join(self.dir, digest + ".jsonl")
        self.prior = {}
        if os.path.exists(self.path):
            with open(self.path) as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    rec = json.loads(line)
                    self.prior[rec["mutant_id"]] = rec

    def settled(self, mutant_id):
        rec = self.prior.get(mutant_id)
        if rec and rec.get("verdict") in FINAL_VERDICTS:
            return rec
        return None

    def append(self, rec):
        with open(self.path, "a") as fh:
            fh.write(json.dumps(rec, sort_keys=True) + "\n")


# -- machine discipline ----------------------------------------------------------------------------
def load_1min():
    out = subprocess.check_output(["sysctl", "-n", "vm.loadavg"]).decode()
    return float(out.replace("{", " ").replace("}", " ").split()[0])


def wait_for_quiet(gate, log):
    """A measurement taken under load is void. Refuse to MEASURE until the machine is quiet.

    This gates measuring; it never gates judging. Nothing here can make a mutant look killed or
    alive - if the machine stays busy, the engine produces no verdict at all and says so.
    """
    ceiling = float(gate.get("max_1min", 12.0))
    naps = int(gate.get("max_waits", 40))
    nap_s = int(gate.get("sleep_s", 180))
    paused = 0
    for _ in range(naps + 1):
        cur = load_1min()
        if cur < ceiling:
            log("load gate: 1-min load %.2f < %.1f -- measuring" % (cur, ceiling))
            return cur, paused
        log("load gate: 1-min load %.2f >= %.1f -- pausing %ds (paused %ds so far)"
            % (cur, ceiling, nap_s, paused))
        runner.pause(nap_s)
        paused += nap_s
    raise SystemExit("load gate: the machine never went quiet (1-min load stayed >= %.1f). "
                     "NO VERDICT is produced under load." % ceiling)


# -- content integrity -----------------------------------------------------------------------------
def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            chunk = fh.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def tree_map(root, subpaths):
    """{relpath: sha256} over the named subtrees - the evidence behind every integrity claim.

    A single boolean ("did the tree change?") is not enough on a shared machine: this repo has other
    agents editing it while a pass runs, and a bare NO would report their edit as if this engine had
    contaminated the tree. Keeping the per-file map lets the run say exactly WHICH files moved, so
    "the engine wrote into the live tree" and "someone else edited node.rs while we measured" are
    different findings instead of the same alarm.
    """
    out = {}
    for sub in subpaths:
        p = os.path.join(root, sub)
        if os.path.isfile(p):
            out[sub] = file_sha(p)
        elif os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames.sort()
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    if os.path.islink(full) or not os.path.isfile(full):
                        continue
                    out[os.path.relpath(full, root)] = file_sha(full)
    return out


def digest_of(m):
    h = hashlib.sha256()
    for rel in sorted(m):
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(m[rel].encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def changed_paths(before, after):
    keys = set(before) | set(after)
    return sorted(k for k in keys if before.get(k) != after.get(k))


def tree_digest(root, subpaths):
    """A stable digest over (relpath, content) for the named subtrees."""
    entries = []
    for sub in subpaths:
        p = os.path.join(root, sub)
        if os.path.isfile(p):
            entries.append((sub, file_sha(p)))
        elif os.path.isdir(p):
            for dirpath, dirnames, filenames in os.walk(p):
                dirnames.sort()
                for fn in sorted(filenames):
                    full = os.path.join(dirpath, fn)
                    if os.path.islink(full) or not os.path.isfile(full):
                        continue
                    entries.append((os.path.relpath(full, root), file_sha(full)))
    entries.sort()
    h = hashlib.sha256()
    for rel, sha in entries:
        h.update(rel.encode("utf-8"))
        h.update(b"\0")
        h.update(sha.encode("ascii"))
        h.update(b"\n")
    return h.hexdigest(), len(entries)


def clone_tree(src_root, dst_root, log, live_digest=None):
    """APFS clone of the crate into the warm dir. Copy-on-write: near-zero disk, near-zero time.

    A clone whose contents already equal the live tree is REUSED rather than rebuilt. That is not a
    shortcut, it is a correctness point as well as a cost one: re-cloning resets every file's mtime,
    which throws away cargo's incrementality and makes each nightly pay a cold build. The check is on
    CONTENT (the same digest the live-tree sentinel uses), so a reused clone is byte-for-byte the tree
    that was measured, and any drift at all forces a fresh clone.
    """
    stamp_path = os.path.join(os.path.dirname(dst_root), "clone-of.txt")
    if live_digest and os.path.isdir(dst_root) and os.path.exists(stamp_path):
        with open(stamp_path) as fh:
            prev = fh.read().strip()
        if prev == live_digest:
            have, _n = tree_digest(dst_root, SENTINEL_PATHS)
            if have == live_digest:
                log("clone: reusing the existing clone (content identical to the live tree)")
                return
    # ⛔⛔⛔ THE PRISTINE STORE IS A PROPERTY OF THE CLONE AND MUST DIE WITH IT.
    #
    # `Workspace.ensure_pristine` is "if os.path.exists(dst): return dst" — it keeps whatever is
    # already in `warm/pristine/`. That store was never cleared when the clone was rebuilt, so it
    # survived from one night's run into the next, and RESTORE — which copies pristine over work —
    # wrote a STALE file into a FRESH clone.
    #
    # MEASURED 2026-09-08, run 20260908T060815, target pow: `pristine/src/pow.rs` was 21,790 bytes
    # from 22:46 the previous night; the live (and freshly cloned) `src/pow.rs` was 29,066 bytes and
    # carried the C-5 coinbase-reward fix landed at 05:18. Mutant 1 applied to the fresh file and was
    # KILLED correctly. Its restore then dropped last night's pow.rs on top of the clone, and all
    # ELEVEN remaining mutants came back SITE_DRIFTED because their recorded text no longer existed.
    # The run then printed `src/pow.rs score=1.0 killed=1 survived=0` — a PERFECT SCORE from a single
    # mutant, with eleven losses reported nowhere in the score line and the damage noted as the
    # four-character footnote `clone restored to pristine: NO`.
    #
    # ⛔ AND `selfcheck.py` PASSES 19/19 ON THIS TREE, including "restore is byte-identical after
    # every mutant", because it builds its own pristine store in a temp dir inside ONE run. The
    # promise it verifies is scoped to a run; the defect lives BETWEEN runs, which is precisely where
    # a nightly lives. A self-check that cannot see across the boundary its subject crosses is not a
    # self-check for that subject.
    #
    # THE FIX IS HERE, NOT IN `ensure_pristine`, because this is the ONE place both paths pass
    # through: the reuse path has already proven the clone's content equals the digest the pristine
    # store was taken against, so its store is valid; every other path is REBUILDING the clone, and a
    # rebuilt clone has no valid pristine store by definition.
    pristine_root = os.path.join(os.path.dirname(dst_root), "pristine")
    if os.path.isdir(pristine_root):
        shutil.rmtree(pristine_root)
        log("clone: discarded the pristine store of the PREVIOUS clone (it is not this clone's)")
    if os.path.exists(dst_root):
        shutil.rmtree(dst_root)
    os.makedirs(dst_root)
    for entry in sorted(os.listdir(src_root)):
        if entry in EXCLUDE_TOP:
            continue
        src = os.path.join(src_root, entry)
        rc = subprocess.call(["cp", "-Rc", src, dst_root + "/"])
        if rc != 0:
            raise SystemExit("clone: `cp -Rc %s` did not succeed (rc=%d). The engine requires a clone "
                             "it can mutate in isolation; it never mutates the live tree." % (src, rc))
    if live_digest:
        with open(stamp_path, "w") as fh:
            fh.write(live_digest)
    log("clone: %s -> %s" % (src_root, dst_root))


# -- the mutated workspace -------------------------------------------------------------------------
class SiteDrift(Exception):
    pass


class ExclusiveRun(object):
    """ONE pass at a time over the warm dir. Two overlapping passes would mutate the same clone and
    hand each other a file in a state neither expects - and the verdicts would look ordinary. The
    lock is an OS-level exclusive flock, so it is released even when a pass is killed outright."""

    def __init__(self, warm):
        self.path = os.path.join(warm, "RUN.lock")
        self.fh = None

    def __enter__(self):
        self.fh = open(self.path, "w")
        try:
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError:
            raise SystemExit("another pass already holds %s. Only one pass may use the warm dir; "
                             "two would mutate the same clone at once." % self.path)
        self.fh.write(str(os.getpid()))
        self.fh.flush()
        return self

    def __exit__(self, *_exc):
        try:
            fcntl.flock(self.fh.fileno(), fcntl.LOCK_UN)
            self.fh.close()
        except Exception:
            pass
        return False


class Workspace(object):
    """The isolated clone: applies one mutation at a time and always puts the file back."""

    def __init__(self, work_root, pristine_root, log):
        self.work = work_root
        self.pristine = pristine_root
        self.log = log
        self.in_flight_path = os.path.join(os.path.dirname(pristine_root), IN_FLIGHT)

    def recover_if_needed(self):
        """A marker on disk means a previous pass died mid-mutant. Restore before anything else."""
        if not os.path.exists(self.in_flight_path):
            return None
        with open(self.in_flight_path) as fh:
            info = json.load(fh)
        rel = info.get("file")
        if rel:
            self.restore(rel, verify=False)
            self.log("recovery: restored %s left mutated by a previous pass" % rel)
        if os.path.exists(self.in_flight_path):
            os.remove(self.in_flight_path)
        return info

    def _pristine_path(self, rel):
        return os.path.join(self.pristine, rel)

    def ensure_pristine(self, rel):
        dst = self._pristine_path(rel)
        if os.path.exists(dst):
            return dst
        d = os.path.dirname(dst)
        if not os.path.isdir(d):
            os.makedirs(d)
        shutil.copy2(os.path.join(self.work, rel), dst)
        return dst

    def apply(self, mut):
        rel = mut.relpath
        self.ensure_pristine(rel)
        with open(self.in_flight_path, "w") as fh:
            json.dump({"file": rel, "mutant_id": mut.mutant_id}, fh)
        path = os.path.join(self.work, rel)
        with open(path, "r") as fh:
            lines = fh.read().split("\n")
        current = "\n".join(lines[mut.a:mut.b + 1])
        if current != mut.before:
            raise SiteDrift("site drifted: %s no longer holds the recorded text" % mut.mutant_id)
        new_lines = lines[:mut.a] + mut.after.split("\n") + lines[mut.b + 1:]
        with open(path, "w") as fh:
            fh.write("\n".join(new_lines))

    def restore(self, rel, verify=True):
        src = self._pristine_path(rel)
        dst = os.path.join(self.work, rel)
        if not os.path.exists(src):
            return
        shutil.copy2(src, dst)
        if verify and file_sha(src) != file_sha(dst):
            raise SystemExit("restore: %s did not come back byte-identical. Stopping." % rel)
        if os.path.exists(self.in_flight_path):
            os.remove(self.in_flight_path)

    def restore_all(self):
        if not os.path.isdir(self.pristine):
            return
        for dirpath, _d, filenames in os.walk(self.pristine):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                rel = os.path.relpath(full, self.pristine)
                self.restore(rel)


# -- cargo -----------------------------------------------------------------------------------------
class Cargo(object):
    """Runs the crate's own library suite and reports what cargo said. It decides nothing."""

    def __init__(self, work, target_dir, cfg, log):
        self.work = work
        self.env = dict(os.environ)
        self.env["CARGO_TARGET_DIR"] = target_dir
        self.env["CARGO_TERM_COLOR"] = "never"
        self.cfg = cfg
        self.log = log

    def _base(self):
        cmd = ["cargo", "test", "--lib"]
        feats = self.cfg.get("features")
        if feats:
            cmd += ["--features", feats]
        return cmd

    def build(self):
        return runner.run(self._base() + ["--no-run"], self.work, self.env,
                          self.cfg.get("build_supervision_s", 2400))

    def list_pins(self):
        r = runner.run(self._base() + ["--", "--list"], self.work, self.env,
                       self.cfg.get("build_supervision_s", 2400))
        paths = []
        for line in r["out"].split("\n"):
            line = line.strip()
            if line.endswith(": test"):
                paths.append(line[:-len(": test")])
        r["paths"] = paths
        return r

    def run_pins(self, pins, threads=None, full=False):
        cmd = self._base() + ["--"]
        if not full:
            cmd += ["--exact"] + list(pins)
        cmd += ["--test-threads", str(threads or self.cfg.get("test_threads", 4))]
        r = runner.run(cmd, self.work, self.env, self.cfg.get("pin_supervision_s", 1800))
        green, red, skipped = [], [], []
        for line in r["out"].split("\n"):
            m = RESULT_LINE.match(line.strip())
            if not m:
                continue
            name, outcome = m.group(1), m.group(2)
            if outcome == "ok":
                green.append(name)
            elif outcome == "ignored":
                skipped.append(name)
            elif outcome == RED:
                red.append(name)
        r["green"], r["red"], r["skipped"] = green, red, skipped
        r["ran"] = len(green) + len(red)
        return r


# -- the engine ------------------------------------------------------------------------------------
def read_sources(root):
    files = []
    src = os.path.join(root, "src")
    for dirpath, dirnames, filenames in os.walk(src):
        dirnames.sort()
        for fn in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, fn), root)
            if not rustsrc.is_live_source(rel):
                continue
            with open(os.path.join(root, rel), "r", errors="replace") as fh:
                files.append(rustsrc.RustFile(rel, fh.read()))
    return files


def read_sources_at(root, at, wanted=None):
    """Read the named files LIVE, or their `.<at>` backups when a calibration point is named.

    A capability that cannot be pointed at the tree as it was BEFORE a fix cannot prove it would have
    caught the fix's defect, and an instrument nobody can calibrate is an instrument nobody should
    cite. Every file of the subject is read at the SAME point or the run is refused: comparing a
    pre-fix `node.rs` against a post-fix `sync.rs` is a diff between two trees, not a measurement.
    """
    if wanted is None:
        return read_sources(root)
    out = []
    for rel in wanted:
        path = os.path.join(root, rel)
        if at:
            cand = path + "." + at
            if not os.path.exists(cand):
                raise SystemExit("no backup `.%s` for %s -- a calibration point must exist for EVERY "
                                 "file of the target, or the report compares two different trees" % (at, rel))
            path = cand
        with open(path, "r", errors="replace") as fh:
            out.append(rustsrc.RustFile(rel, fh.read()))
    return out


def plan_mutants(root, target, cfg, ops_filter, budget):
    oracle_extra = cfg.get("oracle_extra_files", [])
    files = read_sources(root)
    by_rel = dict((f.relpath, f) for f in files)
    muts = []
    for rel in target["files"]:
        rf = by_rel.get(rel)
        if rf is None:
            raise SystemExit("plan: %s is not a live source file of the crate" % rel)
        if rustsrc.is_oracle_file(rel, oracle_extra):
            raise SystemExit("plan: %s is oracle scaffolding; mutating the oracle measures nothing" % rel)
        muts += selection.mutants_for_file(rf, target.get("focus_fns", []), cap=budget,
                                           ops_filter=ops_filter,
                                           focus_only=bool(target.get("focus_only")))
    # M2 is not a per-file operator: it empties one cell of the door x check matrix, so it is planned
    # over the target's files as a set, from the door table. Its EMPTY cells are a report, not mutants.
    fams = target.get("door_families")
    if fams:
        muts += semantic.m2_mutants([by_rel[r] for r in target["files"] if r in by_rel], fams)
    return muts, files


def families_for(cfg, files_wanted=None):
    """The door table from targets.json PLUS the families `doors.py` generates from name siblings."""
    out = {}
    cols = {}
    for name, spec in (cfg.get("door_families") or {}).items():
        if name.startswith("_") or not isinstance(spec, dict):
            continue
        if files_wanted and not set(spec.get("files", [])) & set(files_wanted):
            continue
        out[name] = spec["doors"]
        if spec.get("checks"):
            cols[name] = spec["checks"]
    return out, cols


def verdict_of(res, cargo, log):
    """Turn one pin run into a verdict. A kill must reproduce ALONE before it counts."""
    if res["stopped"]:
        return "NO_VERDICT_STOPPED", []
    if res["ran"] == 0:
        return "NO_PINS", []
    if not res["red"]:
        return "SURVIVED", []
    confirmed = []
    for name in res["red"]:
        iso = cargo.run_pins([name], threads=1)
        if iso["stopped"]:
            log("    isolation of %s was stopped by supervision -- it yields nothing either way" % name)
            continue
        if name in iso["red"]:
            confirmed.append(name)
        else:
            log("    isolation: %s did not reproduce alone -- not counted as a kill" % name)
    if confirmed:
        return "KILLED", confirmed
    return "INCONCLUSIVE_FLAKE", []


def score_by_file(records):
    out = {}
    for r in records:
        f = r["file"]
        s = out.setdefault(f, {"killed": 0, "survived": 0, "uncompilable": 0, "no_pins": 0,
                               "inconclusive": 0, "no_verdict_stopped": 0, "site_drifted": 0,
                               "permissive_survivors": 0, "selected": 0})
        s["selected"] += 1
        v = r["verdict"]
        if v in ("KILLED", "KILLED_BY_UNCLAIMED"):
            s["killed"] += 1
        elif v in ("SURVIVED", "CONFIRMED_SURVIVED"):
            s["survived"] += 1
            if r["direction"] == operators.PERMISSIVE:
                s["permissive_survivors"] += 1
        elif v == "UNCOMPILABLE":
            s["uncompilable"] += 1
        elif v == "NO_PINS":
            s["no_pins"] += 1
        elif v == "NO_VERDICT_STOPPED":
            s["no_verdict_stopped"] += 1
        elif v == "SITE_DRIFTED":
            s["site_drifted"] += 1
        else:
            s["inconclusive"] += 1
    for f, s in out.items():
        denom = s["killed"] + s["survived"]
        s["scored_mutants"] = denom
        s["mutation_score"] = round(float(s["killed"]) / denom, 3) if denom else None
    return out


def rank_survivors(records):
    def key(r):
        return (0 if r["direction"] == operators.PERMISSIVE else 1,
                selection.SITE_RANK.get(r["site_kind"], 9),
                0 if r["operator"] in ("body_true", "guard_disable") else 1,
                r["file"], r["line"])
    surv = [r for r in records if r["verdict"] in ("SURVIVED", "CONFIRMED_SURVIVED")]
    surv.sort(key=key)
    return surv


def main():
    ap = argparse.ArgumentParser(description="LANE M mutation engine")
    ap.add_argument("command", choices=["plan", "run", "replay", "matrix", "dataflow", "coverage"])
    ap.add_argument("--crate", default=os.path.abspath(os.path.join(HERE, "..", "..", "..")))
    ap.add_argument("--config", default=os.path.join(HERE, "targets.json"))
    ap.add_argument("--target", default=None)
    ap.add_argument("--max-mutants", type=int, default=None)
    ap.add_argument("--ops", default=None, help="comma-separated operator allow-list")
    ap.add_argument("--verify-survivors", action="store_true")
    ap.add_argument("--manifest", default=None)
    ap.add_argument("--skip-load-gate", action="store_true",
                    help="ONLY for a plan/parse check that runs no build and produces no verdict")
    # `--at` and `--expect-empty-cells` are READ-ONLY report flags. cons: none — they add no chain
    # cost of any kind (this driver never enters the crate graph: 0 bytes on the DA, 0 node RAM, 0
    # gates), and no engine cost that is f(history): `--at` reads ONE alternative source file per
    # target file instead of the live one, so the work is f(bytes of the named files) exactly as
    # before, and it can reach no build, no verdict and no score. Nothing is weakened: the three
    # report commands take no load gate because they compile nothing and measure no timing, which is
    # the same reason `plan` does not.
    ap.add_argument("--at", default=None,
                    help="a backup suffix (e.g. preDoorAudit-20260907): run the READ-ONLY reports "
                         "(matrix/dataflow/coverage) against the tree AS OF that point. This is how a "
                         "capability proves it reproduces a known-missed calibration row.")
    ap.add_argument("--expect-empty-cells", default=None,
                    help="matrix only: `door!->check` entries, comma separated. Exit 1 unless the "
                         "measured empty-cell set matches EXACTLY.")
    args = ap.parse_args()

    with open(args.config) as fh:
        cfg = json.load(fh)

    def log(msg):
        sys.stdout.write("[lane-m] %s\n" % msg)
        sys.stdout.flush()

    crate = os.path.abspath(args.crate)
    warm = os.path.expanduser(cfg["warm_dir"])
    work = os.path.join(warm, "work")
    pristine = os.path.join(warm, "pristine")
    target_dir = os.path.join(warm, "cargo-target")
    runs = os.path.join(warm, "runs")

    ops_filter = set(args.ops.split(",")) if args.ops else None
    budget = args.max_mutants or cfg["budgets"]["mutants_per_file"]

    # ── THE THREE READ-ONLY REPORTS ───────────────────────────────────────────────────────────────
    # They compile nothing, run nothing and score nothing: each is a pure reader over the source, and
    # each is a FIND half whose corresponding operator can only DEFEND a check that already exists.
    # That asymmetry is the whole reason they are here — the calibration rows lane M missed are checks
    # that were never written, and no mutation operator can express the absence of a check.
    if args.command in ("matrix", "dataflow", "coverage"):
        wanted = cfg["targets"][args.target]["files"] if args.target else None
        files = read_sources_at(crate, args.at, wanted)
        where = ("AS OF ." + args.at) if args.at else "the LIVE tree"

        if args.command == "matrix":
            # THE DECLARED TABLE AND THE GENERATED ONE ARE REPORTED SEPARATELY, and that is not
            # cosmetic. A DECLARED family is a human statement that these doors admit the same class,
            # so an empty cell in it is a claim about consensus. A GENERATED family is a name-sibling
            # guess, so an empty cell in it is a QUESTION. Merging the two would let 30 questions bury
            # one claim, which is how a loud instrument gets switched off.
            declared, columns = families_for(cfg, wanted)
            generated = doors.generated_families(files)
            for k in list(generated):
                if k in declared:
                    del generated[k]
            measured = []

            def emit(rows, kind):
                for r in rows:
                    log("  [%s] family %s  doors=%s" % (kind, r["family"], ",".join(r["doors"])))
                    for (d, c) in r["empty"]:
                        fillers = [d2 for d2 in r["doors"] if r["cells"].get((d2, c))]
                        if kind == "DECLARED":
                            measured.append("%s!->%s" % (d, c))
                        log("    %s EMPTY CELL  %s does NOT reach `%s`  —  sibling door(s) %s do"
                            % ("⛔" if kind == "DECLARED" else "· ", d, c, ",".join(fillers)))

            log("DOOR x CHECK MATRIX over %s, %s" % (", ".join(f.relpath for f in files), where))
            drows = doors.matrix(files, declared, columns)
            emit(drows, "DECLARED")
            if not drows:
                log("  [DECLARED] no empty cells: every declared door reaches every check its siblings do")
            grows = doors.matrix(files, generated)
            log("  ---- name-sibling families below are ADVISORY: a question, not a claim ----")
            emit(grows, "generated")
            if not grows:
                log("  [generated] no empty cells")
            if args.expect_empty_cells is not None:
                want = set(x for x in args.expect_empty_cells.split(",") if x)
                got = set(measured)
                log("EXPECTED empty cells: %s" % (sorted(want) or "(none)"))
                log("MEASURED empty cells: %s" % (sorted(got) or "(none)"))
                # ⛔⛔⛔ THE NEGATIVE HALF OF A CALIBRATION HAS TO BE ABLE TO FAIL.
                #
                # This was `if not want <= got` — CONTAINMENT — while `--help` promised "Exit 1 unless
                # the measured empty-cell set matches EXACTLY". Under containment the empty expectation
                # is a tautology: ∅ ⊆ anything, so `--expect-empty-cells ''` printed CALIBRATION HELD
                # against ANY tree, including one where every declared door had lost every check. That
                # command is written down in this repo AS the negative control for two rows, and it was
                # unfalsifiable — the shape this whole instrument exists to refuse, sitting inside the
                # instrument. MEASURED 2026-09-08: the recorded B3 command expected 1 cell, measured 8,
                # and exited 0.
                #
                # Exact both ways, and the two directions are named separately because they mean
                # opposite things: a MISSING cell says the capability no longer reproduces the row it
                # was built for (the instrument regressed); an UNEXPECTED cell says the TREE grew a
                # door difference nobody has adjudicated (the code regressed, or the expectation is
                # stale). Neither may be silent, so neither is folded into the other's message.
                missing = sorted(want - got)
                unexpected = sorted(got - want)
                if missing:
                    log("⛔ CALIBRATION FAILED — expected empty cell(s) NOT reproduced: %s" % missing)
                if unexpected:
                    log("⛔ CALIBRATION FAILED — empty cell(s) measured but NOT declared: %s" % unexpected)
                    log("   Each is a door that does not run a check its sibling does. Adjudicate it,")
                    log("   then name it in --expect-empty-cells so it stays measured, or close it.")
                if missing or unexpected:
                    return 1
                log("✅ CALIBRATION HELD — the measured empty-cell set matches EXACTLY.")
            return 0

        if args.command == "dataflow":
            log("VERDICT-DATAFLOW (M3 find half) over %s, %s"
                % (", ".join(f.relpath for f in files), where))
            n = 0
            for rf in files:
                for d in semantic.discarded_verdicts(rf):
                    n += 1
                    log("  [%-8s] %s:%d  %s()  `%s` -> consumed only by a %s"
                        % (d["severity"], d["file"], d["line"], d["fn"], d["door"] or d["cond"],
                           d["consumed_by"]))
            log("%d site(s) where a verdict is produced and not consulted" % n)
            return 0

        log("SHARED-CHECK COVERAGE MAP (M12 find half) over %s, %s"
            % (", ".join(f.relpath for f in files), where))
        cov = semantic.shared_check_coverage(files)
        for name in sorted(cov):
            log("  %s  — %d call site(s)" % (name, len(cov[name])))
            for (rel, fn) in cov[name]:
                log("      %s::%s" % (rel, fn))
        log("%d shared check helper(s) with more than one call site" % len(cov))
        return 0

    if args.command == "plan":
        target = dict(cfg["targets"][args.target])
        target["door_families"] = families_for(cfg, target["files"])[0]
        muts, _files = plan_mutants(crate, target, cfg, ops_filter, budget)
        log("target %s: %d mutants selected (budget %d/file)" % (args.target, len(muts), budget))
        for m in muts:
            log("  %-56s %-14s %-11s %s" % (m.mutant_id, m.op, m.direction, m.note))
        return 0

    if args.command == "replay":
        with open(args.manifest) as fh:
            man = json.load(fh)
        log("replay of run %s over %d mutants" % (man["run_id"], len(man["mutants"])))
        log("live digest when measured : %s" % man["source_snapshot"]["live_digest"])
        cur, n = tree_digest(crate, SENTINEL_PATHS)
        log("live digest now           : %s (%d files)" % (cur, n))
        if cur != man["source_snapshot"]["live_digest"]:
            log("the live tree has MOVED since this manifest; re-run `run`. Verdicts never carry "
                "across a source change -- each mutant is bound to the exact bytes it was cut from.")
            return 3
        log("the tree is unchanged: every mutant in this manifest is still cut from these bytes.")
        for r in man["mutants"]:
            log("  %-56s %-20s %s" % (r["mutant_id"], r["verdict"], r["note"]))
        return 0

    # -- run ---------------------------------------------------------------------------------------
    target = cfg["targets"][args.target]
    run_id = runner.stamp()
    if not os.path.isdir(runs):
        os.makedirs(runs)
    run_dir = os.path.join(runs, run_id)
    os.makedirs(run_dir)

    if not os.path.isdir(warm):
        os.makedirs(warm)
    lock = ExclusiveRun(warm)
    lock.__enter__()

    if args.skip_load_gate:
        cur_load, paused = load_1min(), 0
        log("load gate SKIPPED by flag; 1-min load %.2f" % cur_load)
    else:
        cur_load, paused = wait_for_quiet(cfg["load_gate"], log)

    live_map_before = tree_map(crate, SENTINEL_PATHS)
    live_before = digest_of(live_map_before)
    log("live tree sentinel: %s over %d files" % (live_before[:16], len(live_map_before)))

    # A TORN CLONE IS A SILENT WRONG ANSWER. Another agent edits this repo while passes run, so a
    # clone taken across someone else's save can hold half of one edit - and every verdict cut from
    # it would be about a tree that never existed. So: clone, then re-read the live tree, and accept
    # the clone only when the live tree held still for the whole copy. If it moved, take the new
    # state and copy again. The loop runs to stability rather than to a count; if the tree never
    # holds still, the pass says so and produces no verdict at all.
    for _attempt in iter(int, 1):
        clone_tree(crate, work, log, live_digest=live_before)
        live_map_now = tree_map(crate, SENTINEL_PATHS)
        live_now = digest_of(live_map_now)
        if live_now == live_before:
            break
        log("clone: the live tree moved while copying (%s -> %s); re-copying from the new state"
            % (live_before[:12], live_now[:12]))
        live_map_before, live_before = live_map_now, live_now
    if not os.path.isdir(pristine):
        os.makedirs(pristine)
    ws = Workspace(work, pristine, log)
    ws.recover_if_needed()

    def bail(_signum=None, _frame=None):
        ws.restore_all()
        log("interrupted: every mutated file restored from pristine")
        sys.exit(130)

    signal.signal(signal.SIGINT, bail)
    signal.signal(signal.SIGTERM, bail)

    records = []
    snap_digest = None
    incomplete = []
    quarantined = []
    baseline_pin_secs = None
    try:
        snap_digest, snap_n = tree_digest(work, SENTINEL_PATHS)
        log("clone snapshot: %s over %d files" % (snap_digest[:16], snap_n))

        cargo = Cargo(work, target_dir, cfg["cargo"], log)
        log("baseline build of the pristine clone ...")
        b = cargo.build()
        if b["stopped"]:
            raise SystemExit("the baseline build was stopped by supervision. NO VERDICT: raise "
                             "cargo.build_supervision_s and re-run.")
        if b["rc"] != 0:
            # Only real diagnostics, each with the location line that follows it. Sweeping up every
            # `-->` would bury the one error under a hundred warning locations, and a report nobody
            # can read is a report nobody acts on.
            lines = b["out"].split("\n")
            errs = []
            for k, ln in enumerate(lines):
                if ln.startswith("error"):
                    errs.append(ln)
                    if k + 1 < len(lines) and lines[k + 1].strip().startswith("--> "):
                        errs.append(lines[k + 1])
            raise SystemExit("the baseline build did not succeed (rc=%d). No verdict is produced "
                             "from a tree that does not build. This is a statement about the SOURCE, "
                             "not about the suite.\n%s" % (b["rc"], "\n".join(errs[:20])))
        log("baseline build ok in %ss" % b["secs"])

        lst = cargo.list_pins()
        if lst["rc"] != 0 or not lst["paths"]:
            raise SystemExit("could not enumerate the library pins (rc=%d)" % lst["rc"])
        log("library pins available: %d" % len(lst["paths"]))

        muts, files = plan_mutants(work, target, cfg, ops_filter, budget)
        index = selection.PinIndex(files)
        index.load_libtest_paths(lst["paths"])
        log("target %s: %d mutants selected" % (args.target, len(muts)))

        pin_cache = {}
        union = []
        for m in muts:
            pins, tiers = index.pins_for(m.relpath, m.fn_name, cfg["budgets"]["pins_per_mutant"])
            pin_cache[m.mutant_id] = (pins, tiers)
            for p in pins:
                if p not in union:
                    union.append(p)
        log("union of claiming pins across all mutants: %d" % len(union))

        # The baseline is a property of (these exact bytes, this exact pin set), so once it has been
        # established green it is not re-established on every resumed pass. Re-running it each time
        # would spend most of a short pass proving again what it already proved, and the resumed pass
        # would never reach a mutant.
        base_key = hashlib.sha256(("|".join(union)).encode("utf-8")).hexdigest()[:16]
        results_dir = os.path.join(warm, "results")
        if not os.path.isdir(results_dir):
            os.makedirs(results_dir)
        base_stamp = os.path.join(results_dir, "%s.baseline.%s.json" % (snap_digest, base_key))
        if union and os.path.exists(base_stamp):
            with open(base_stamp) as fh:
                prior_base = json.load(fh)
            quarantined = list(prior_base.get("quarantined", []))
            baseline_pin_secs = prior_base.get("baseline_pin_secs")
            log("baseline: established %s over %d pins -- not re-established"
                % (prior_base["run_id"], prior_base["ran"]))
        elif union:
            base = cargo.run_pins(union)
            if base["stopped"]:
                raise SystemExit("the baseline pin run was stopped by supervision. NO VERDICT.")
            if base["ran"] == 0:
                raise SystemExit("the pin subset matched 0 tests. Refusing to score: every mutant "
                                 "would 'survive' for free.")
            log("baseline pin subset: %d ran, %d red" % (base["ran"], len(base["red"])))
            # INSTRUMENT SELF-CHECK: the engine must prove it actually ran the pins it asked for.
            # If the selector silently drops names, every mutant "survives" against tests that never
            # executed - the exact shape of a measurement that reports safety it did not measure.
            accounted = base["ran"] + len(base["skipped"])
            if accounted != len(union):
                raise SystemExit(
                    "the pin selector did not select what it was asked for: %d names given, %d "
                    "accounted for (%d ran, %d skipped). Refusing to score against tests that may "
                    "never have executed." % (len(union), accounted, base["ran"], len(base["skipped"])))
            log("selector self-check: all %d requested pins accounted for" % len(union))
            quarantined = list(base["red"])
            baseline_pin_secs = base["secs"]
            with open(base_stamp, "w") as fh:
                json.dump({"run_id": run_id, "ran": base["ran"], "skipped": len(base["skipped"]),
                           "pins": union, "quarantined": quarantined,
                           "baseline_pin_secs": baseline_pin_secs}, fh, indent=2)

        # A PIN THAT IS ALREADY RED CANNOT DECIDE ANYTHING. It is red before the mutation and red
        # after it, so it distinguishes nothing - and the original rule (void the whole run on any
        # baseline red) let one stuck pin block every measurement the other pins could still make.
        # It is QUARANTINED instead: removed from every kill-set, named in the manifest, and printed
        # here, so no score can be read as if that pin were doing its job. The failure this protects
        # against - a red pin being counted as a kill - is impossible once it is removed outright.
        if quarantined:
            log("")
            log("BASELINE QUARANTINE: %d pin(s) are RED before any mutation and are removed from "
                "every kill-set. They decide nothing here, and the invariant each one guards is "
                "UNMEASURED by this pass:" % len(quarantined))
            for q in quarantined:
                log("    %s" % q)
            log("")

        # The cache is keyed on the CLONE digest - the exact bytes that were measured - not on the
        # live tree. On a machine where another agent is landing edits, keying on live would discard
        # a pass's work every time someone else saved a file, while the clone the verdicts were cut
        # from had not moved at all. Verdicts still never cross a source change: a changed live tree
        # forces a fresh clone, which is a new digest and therefore a new cache.
        cache = ResultCache(warm, snap_digest)

        def finish(record):
            """One place where a judged mutant lands: the run's list AND the resume cache."""
            records.append(record)
            cache.append(record)
        if cache.prior:
            log("resume: %d mutant(s) already judged against this exact source digest" % len(cache.prior))

        # CALIBRATE THE SUPERVISION LIMIT TO WHAT THESE PINS ACTUALLY COST when nothing is broken,
        # instead of guessing a number. MEASURED: a `body_false` mutant on `hash_meets_target` makes
        # the target unsatisfiable, and `PowMiner::mine` grinds a nonce with no way to notice that -
        # so that pin does not slow down, it never returns. A guessed hour-long limit turned one such
        # mutant into an hour of a nightly. The limit stays a RESOURCE decision and still yields
        # NO_VERDICT_STOPPED, never a result; deriving it from the honest cost only makes it honest
        # about what "no longer making progress" means for THIS pin set.
        if baseline_pin_secs:
            pin_limit = max(180, int(round(6 * baseline_pin_secs)))
            cargo.cfg = dict(cargo.cfg)
            cargo.cfg["pin_supervision_s"] = pin_limit
            log("pin supervision calibrated to %ds (6x the measured baseline of %.1fs for these "
                "same %d pins)" % (pin_limit, baseline_pin_secs, len(union)))

        qset = set(quarantined)
        for i, m in enumerate(muts):
            claimed, tiers = pin_cache[m.mutant_id]
            pins = [p for p in claimed if p not in qset]
            log("[%d/%d] %s  (%s, %s)" % (i + 1, len(muts), m.mutant_id, m.op, m.direction))
            done = cache.settled(m.mutant_id)
            if done:
                done = dict(done)
                done["from_cache"] = True
                records.append(done)
                log("    %s (from a previous pass on the same source digest)" % done["verdict"])
                continue
            rec = m.to_json()
            rec["pins"] = pins
            rec["claimed_pins"] = claimed
            rec["quarantined_pins"] = [p for p in claimed if p in qset]
            rec["pin_tiers"] = dict((p, tiers.get(p)) for p in pins)
            rec["invariant"] = target.get("invariant")
            rec["killed_by"] = []
            if not pins:
                rec["verdict"] = "NO_USABLE_PINS" if rec["quarantined_pins"] else "NO_PINS"
                finish(rec)
                log("    %s -- %s" % (rec["verdict"],
                                      "every pin that claims this site is already red"
                                      if rec["quarantined_pins"]
                                      else "not one test in the library names this site"))
                continue
            try:
                ws.apply(m)
            except SiteDrift as e:
                rec["verdict"] = "SITE_DRIFTED"
                rec["detail"] = str(e)
                finish(rec)
                continue
            try:
                bres = cargo.build()
                rec["build_s"] = bres["secs"]
                if bres["stopped"]:
                    rec["verdict"] = "NO_VERDICT_STOPPED"
                    rec["detail"] = "the build was stopped by process supervision"
                    incomplete.append(rec["mutant_id"])
                    finish(rec)
                    log("    NO_VERDICT_STOPPED (build) -- re-run this mutant; it is not judged")
                    continue
                if bres["rc"] != 0:
                    rec["verdict"] = "UNCOMPILABLE"
                    rec["detail"] = "\n".join(
                        [ln for ln in bres["out"].split("\n") if ln.startswith("error")][:4])
                    finish(rec)
                    log("    UNCOMPILABLE (an engine defect, never a kill): %s" % rec["detail"][:110])
                    continue
                pres = cargo.run_pins(pins)
                rec["pin_s"] = pres["secs"]
                rec["pins_ran"] = pres["ran"]
                v, killers = verdict_of(pres, cargo, log)
                rec["verdict"] = v
                rec["killed_by"] = killers
                if v == "NO_VERDICT_STOPPED":
                    incomplete.append(rec["mutant_id"])
                log("    %s%s" % (v, (" by " + ", ".join(killers)) if killers else ""))
                if v == "SURVIVED" and args.verify_survivors:
                    log("    survivor: re-running the FULL library suite ...")
                    full = cargo.run_pins([], full=True)
                    if full["stopped"]:
                        rec["full_suite"] = "stopped by supervision -- the narrow verdict stands"
                    elif full["red"]:
                        rec["verdict"] = "KILLED_BY_UNCLAIMED"
                        rec["killed_by"] = full["red"]
                        log("    KILLED_BY_UNCLAIMED by %s -- the pins that NAME this site are not "
                            "the ones defending it" % ", ".join(full["red"][:4]))
                    else:
                        rec["verdict"] = "CONFIRMED_SURVIVED"
                        log("    CONFIRMED_SURVIVED: the whole library suite stayed green")
                finish(rec)
            finally:
                ws.restore(m.relpath)
    finally:
        ws.restore_all()
        clone_after = None
        if snap_digest is not None:
            clone_after, _n = tree_digest(work, SENTINEL_PATHS)
        live_map_after = tree_map(crate, SENTINEL_PATHS)
        live_after = digest_of(live_map_after)
        moved = changed_paths(live_map_before, live_map_after)
        # THE CLAIM THAT MATTERS: no file this engine mutated may differ in the LIVE tree. Every
        # write it performs goes into the clone, so a live file among the targets would mean the
        # isolation failed - that is the alarm, and it is checked by name rather than by a
        # whole-tree boolean. Other files moving means someone else edited the repo while this pass
        # ran; that is worth recording (it says the live tree has since drifted from what was
        # measured) but it is not this engine writing where it must not.
        touched_targets = sorted(set(moved) & set(target["files"]))
        contaminated = bool(touched_targets)
        if clone_after is not None:
            log("clone restored to pristine: %s" % ("YES" if clone_after == snap_digest else "NO"))
        log("ENGINE CONTAMINATION OF THE LIVE TREE: %s"
            % ("NONE -- no mutated file differs in the live tree"
               if not contaminated else "YES -- STOP: " + ", ".join(touched_targets)))
        if moved:
            log("concurrent edits by something else during this pass (%d file(s)): %s"
                % (len(moved), ", ".join(moved[:6]) + (" ..." if len(moved) > 6 else "")))
            log("  the measurement stands: it was taken against the CLONE snapshot %s, which is a "
                "byte-exact copy of the live tree as of the sentinel above." % (snap_digest or "")[:16])
        clean = not contaminated
        manifest = {
            "run_id": run_id,
            "engine": "lane-m/mutate.py",
            "engine_version": 1,
            "target": args.target,
            "target_spec": target,
            "invariant": target.get("invariant"),
            "budgets": {"mutants_per_file": budget,
                        "pins_per_mutant": cfg["budgets"]["pins_per_mutant"]},
            "ops_filter": sorted(ops_filter) if ops_filter else None,
            "machine": {"load_1min_at_start": cur_load, "paused_s_for_quiet": paused},
            "source_snapshot": {"live_root": crate, "live_digest": live_before,
                                "live_digest_after": live_after,
                                "engine_contaminated_live_tree": contaminated,
                                "mutated_files_differing_in_live_tree": touched_targets,
                                "concurrent_edits_during_run": moved,
                                "clone_root": work, "clone_digest": snap_digest,
                                "clone_digest_after": clone_after,
                                "clone_restored": (clone_after == snap_digest)
                                if clone_after is not None else None},
            "verify_survivors": bool(args.verify_survivors),
            "baseline_quarantined_pins": quarantined,
            "incomplete_mutants": incomplete,
            "complete": not incomplete,
            "mutants": records,
            "scores": score_by_file(records),
        }
        mpath = os.path.join(run_dir, "manifest.json")
        with open(mpath, "w") as fh:
            json.dump(manifest, fh, indent=2, sort_keys=True)
        log("manifest: %s" % mpath)

        log("")
        log("MUTATION SCORE (killed / scored; UNCOMPILABLE, NO_PINS, NO_VERDICT_STOPPED and "
            "SITE_DRIFTED are excluded and never counted as kills)")
        # ⛔⛔⛔ A SCORE IS UNREADABLE WITHOUT THE SIZE OF THE THING IT WAS TAKEN OVER.
        # `site_drifted` was tallied and then printed NOWHERE, so run 20260908T060815 reported
        # `src/pow.rs score=1.0 killed=1 survived=0 ... stopped=0` while ELEVEN of its twelve mutants
        # had drifted and produced no verdict at all. Every excluded class now appears, and `coverage`
        # states scored-out-of-selected on the same line as the ratio, so 1.0 over one mutant can
        # never again be read as 1.0 over the file.
        for f, s in sorted(manifest["scores"].items()):
            log("  %-24s score=%s  coverage=%d/%d scored  killed=%d survived=%d "
                "(permissive survivors=%d) uncompilable=%d no_pins=%d inconclusive=%d stopped=%d "
                "drifted=%d"
                % (f, s["mutation_score"], s["scored_mutants"], s.get("selected", 0),
                   s["killed"], s["survived"], s["permissive_survivors"],
                   s["uncompilable"], s["no_pins"], s["inconclusive"], s["no_verdict_stopped"],
                   s["site_drifted"]))
            lost = s.get("selected", 0) - s["scored_mutants"]
            if lost > 0:
                log("      ⛔ COVERAGE LOST: %d of %d selected mutant(s) yielded NO verdict "
                    "(drifted=%d uncompilable=%d no_pins=%d inconclusive=%d stopped=%d). The ratio "
                    "above describes ONLY the %d that were scored — it is not a statement about this "
                    "file." % (lost, s.get("selected", 0), s["site_drifted"], s["uncompilable"],
                               s["no_pins"], s["inconclusive"], s["no_verdict_stopped"],
                               s["scored_mutants"]))
            if s["site_drifted"]:
                log("      ⛔ SITE DRIFT IS AN ENGINE FAULT, NOT A TREE FACT: the clone changed under "
                    "the run. Check that the pristine store belongs to THIS clone (clone_tree "
                    "discards a previous one) before citing anything from this pass.")
        surv = rank_survivors(records)
        log("")
        log("SURVIVING MUTANTS, ranked (permissive first -- a survivor there is an undefended "
            "soundness invariant)")
        for r in surv:
            log("  %-56s %-14s %-11s %s" % (r["mutant_id"], r["operator"], r["direction"], r["note"]))
            log("      claimed by %d pin(s): %s" % (len(r["pins"]), ", ".join(r["pins"][:4])))
        if quarantined:
            log("")
            log("UNMEASURED BY THIS PASS: %d claiming pin(s) were red before any mutation and were "
                "quarantined. Any score above is the score of the pins that still work."
                % len(quarantined))
            for q in quarantined:
                log("    %s" % q)
        if incomplete:
            log("")
            log("INCOMPLETE: %d mutant(s) produced no verdict and must be re-run: %s"
                % (len(incomplete), ", ".join(incomplete)))
        # NOTE: no `return` in this `finally`. A return here would swallow whatever exception (or
        # SystemExit from the interrupt handler) was already propagating, and the pass would exit
        # looking merely "non-zero" instead of saying what actually stopped it. The contamination
        # result is carried out in a flag and acted on after the block.
        exit_code = 2 if contaminated else 0
    return exit_code


if __name__ == "__main__":
    sys.exit(main())
