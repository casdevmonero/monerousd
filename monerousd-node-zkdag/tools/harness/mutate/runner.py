# Copyright (c) 2026, The MoneroUSD Protocol
# SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
"""LANE M - PROCESS SUPERVISION. This module owns the clock and NOTHING ELSE.

THE SEPARATION IS THE POINT, and it is structural rather than promised: no clock in this engine may
ever decide an outcome, so the clock lives here, in a module that cannot express an outcome. This
file has no notion of killed, survived, red or green; it starts a process, collects its bytes, and
reports two facts - what the process returned, and whether supervision had to stop it because it
stopped making progress. The caller (mutate.py) owns every judgement and owns no clock.

Why supervision exists at all: a wedged compile would otherwise hold a nightly pass open forever.
Stopping a wedged process is a resource decision. It is NOT information about the code under test,
and the caller treats it accordingly - a stopped run yields no result of any kind and the mutant is
re-run rather than judged. Late is not the same as never.

⛔⛔⛔ THE STOP HAS TO REACH THE GRANDCHILD, AND FOR THE ENGINE'S WHOLE LIFE IT DID NOT.

`cmd` is `cargo test`. Cargo's own child is the compiled test binary, so a bare `proc.kill()` reached
cargo ALONE: the test binary is a GRANDCHILD, it inherits the stdout pipe, and it went on running.
The `proc.communicate()` on the next line then waited for that pipe to close - so the supervisor
BLOCKED, forever, on the orphan it had just failed to kill. The one thing this module exists to do
was the one thing it could not do, and nothing said so, because a supervisor that never returns
prints no line.

MEASURED 2026-09-08, target `pow`, mutant `[2/12] src/pow.rs@159:body_false` - collapse
`hash_meets_target` to `false`, so every mining loop spins with nothing to find. The engine's log sat
frozen on the `[2/12]` line while `usdmd_node-88f43e5fe0b40592` ran on at 49% CPU and the machine's
1-minute load reached 107. It ended by hand, not by supervision.

⛔ THAT IS ALSO THE REAL CAUSE OF THE PREVIOUS NIGHT'S `[2/12] ... ~30 min, unresolved`, which
`docs/harness-report.md` recorded as finding N-6, "the restrictive half is pathologically slow". The
restrictive arm IS slow and that cost is real and separate - but slowness was the symptom, and a stop
that could not reach the process was the defect. A slow mutant the supervisor can end is a budgeting
question; a slow mutant it cannot end is an instrument that hangs and takes the machine with it.

The repair is `start_new_session=True` plus `os.killpg`: the child gets its OWN process group, every
descendant cargo spawns joins it, and one signal reaches all of them. Nothing new is bounded and no
second clock is introduced - once the group is dead every holder of the pipe is dead, so the read
returns on its own. The separation above is untouched: the group-kill is a resource decision, it
yields no outcome, and `stopped` is still the only thing this module reports.

COST ARITHMETIC - cons: none. Python under tools/, never in the crate graph: 0 bytes on the DA, 0
bytes of node RAM, 0 checks removed from any shipping path.
"""

import os
import signal
import subprocess
import time


def run(cmd, cwd, env, supervision_s):
    """Start `cmd`, collect its output, and report (rc, out, secs, stopped).

    `stopped` is True when supervision had to end a process that was no longer making progress. It
    describes THE MACHINE, never the code: the caller must not read any outcome out of it.
    """
    started = time.monotonic()
    # `start_new_session` puts the child in a new session and process group, so every descendant
    # cargo spawns shares its pgid and ONE signal reaches all of them. See the kill below.
    proc = subprocess.Popen(cmd, cwd=cwd, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            start_new_session=True)
    stopped = False
    try:
        out, _ = proc.communicate(timeout=supervision_s)
    except subprocess.TimeoutExpired:
        # Kill the GROUP, unconditionally - see the module docstring for what `proc.kill()` alone did.
        # A negative pid names a process group, and it is this child's OWN group because of
        # `start_new_session` above, so this can never reach the engine, the shell or another lane.
        # ⛔ NOT `if proc.poll() is None` first: MEASURED 2026-09-08, cargo had ALREADY exited while
        # its test binary ran on - reparented to launchd, still a member of this group, still holding
        # the pipe. Gating the group kill on the DIRECT CHILD being alive skipped it in exactly the
        # case it exists for, and the read below then blocked on the orphan. The child's liveness says
        # nothing about the group's.
        # ProcessLookupError here means the group is empty: the postcondition already holds and the
        # read returns at once. It is not a second attempt at anything.
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, _ = proc.communicate()
        stopped = True
    return {
        "rc": proc.returncode,
        "out": out.decode("utf-8", "replace"),
        "secs": round(time.monotonic() - started, 1),
        "stopped": stopped,
    }


def pause(seconds):
    """Hold for `seconds`. Used only by the load gate, which gates MEASURING, never judging."""
    time.sleep(seconds)


def stamp():
    """A run identifier from the wall clock. Names a run; decides nothing about one."""
    return time.strftime("%Y%m%dT%H%M%S")
