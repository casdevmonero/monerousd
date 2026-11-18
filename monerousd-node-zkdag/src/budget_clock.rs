// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ THE BUDGET CLOCK — the one clock every per-tick WORK BUDGET of the runtime reads (PERF TIER step 1, 2026-10-08).
//!
//! A budget ("apply for at most 200 ms per drain", "graft a page for at most 400 ms") bounds how long one call holds the
//! runtime lock. On a daemon that is wall time, and this clock reads wall time there — nothing changes in production.
//!
//! In the simulator a node's thread is MARKED CHARGED ([`charge_this_thread`]): the simulator charges that node the CPU its
//! lock-held work costs and keeps the lock busy for it in simulated time (`harness/netsim.rs`, the Shadow simulator's CPU
//! model: a virtual host is delayed by the measured execution time of its code). A budget on that thread must count the
//! SAME unit — the thread's own CPU time — or a loaded host (four simulations side by side) stops each drain after fewer
//! blocks than an idle one: the node does less work per simulated tick while being charged less, and the simulated
//! schedule depends on the host. MEASURED why (link 33, night/simpar-20261008-035629): the same seed's per-step simulated
//! times differed between SIM_PAR=2 and SIM_PAR=4.
//!
//! CPU time on a thread counts only that thread's work: a wait (a channel receive, a lock, a core the host gave to another
//! simulation) costs nothing, which is what a node on its own hardware would have spent on it. Pinned two-party by
//! `harness::netsim::tests::perf_tier_a_node_whose_lock_work_costs_seconds_follows_its_peer_slower_than_one_at_milliseconds`.
//! cons: none in production (the same wall reading through one call); in the simulator, work a charged call hands to OTHER
//! threads (a rayon pool) is not on this thread's clock — the in-lock paths it bounds run on the calling thread.

use std::cell::Cell;

thread_local! {
    static CHARGED: Cell<bool> = const { Cell::new(false) };
    /// A REPLAYABLE simulated node's thread ([`freeze_this_thread`]): its budget clock stands still.
    static FROZEN: Cell<bool> = const { Cell::new(false) };
    /// A REPLAYABLE simulated node's simulated instant (ms), set by the simulator every step ([`cadence_now_ms`]).
    static SIM_NOW_MS: Cell<Option<u64>> = const { Cell::new(None) };
    /// A REPLAYABLE simulated node's entropy stream ([`SimEntropy`]); `None` on every daemon thread.
    static ENTROPY: Cell<Option<SimEntropy>> = const { Cell::new(None) };
    /// Wall µs this (charged) thread's [`OffLockJob::poll`]s spent waiting for their workers — the simulator's step profile
    /// reads it ([`job_wait_us`]); a daemon's poll never waits, so it stays 0 there.
    static JOB_WAIT_US: Cell<u64> = const { Cell::new(0) };
    /// The off-lock workers this (charged) thread spawned and has not yet waited for ([`settle_spawned_jobs`]).
    static SPAWNED: std::cell::RefCell<Vec<std::sync::mpsc::Receiver<()>>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// ⭐ THE SIMULATOR'S OFF-LOCK WAIT (T1.4, 2026-10-23). A charged thread's first [`OffLockJob::poll`] after a spawn waits
/// (wall) for the worker, and that poll ran INSIDE the node's tick under its runtime lock — so a wallet request arriving
/// at that node during a band proof blocked for the proof's wall time and its 8 s read timed out (MEASURED
/// scratchpad/farm/queue-20261023-000739-21175.log:2039: the send after the restarts "could not read the node's certified
/// fold base", 18.4 s = its proving + the 8 s timeout; jobwait 508 s of a 614 s run). A daemon's poll never waits, so a
/// daemon never holds its lock for a proof. The simulator calls this OFF the lock after every node step: it waits for
/// every worker this thread spawned since the last call, so the next poll (under the lock) finds the answer and judges
/// the instant exactly as before — the same wall, charged to the same [`job_wait_us`], moved outside the lock.
/// cons: none in a daemon (nothing registers on an uncharged thread); none in simulated time (the verdict is still
/// spawn + the job's cost, read at the same poll); a job polled again before its step ends still waits in the poll.
pub fn settle_spawned_jobs() {
    let pending = SPAWNED.with(|s| std::mem::take(&mut *s.borrow_mut()));
    for rx in pending {
        let t = std::time::Instant::now();
        let _ = rx.recv();
        JOB_WAIT_US.with(|w| w.set(w.get().saturating_add(u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX))));
    }
}

/// On a charged thread, the `()` sender a spawned worker signals once its answer is sent (see [`settle_spawned_jobs`]).
fn register_spawn() -> Option<std::sync::mpsc::Sender<()>> {
    if !charged() {
        return None;
    }
    let (tx, rx) = std::sync::mpsc::channel();
    SPAWNED.with(|s| s.borrow_mut().push(rx));
    Some(tx)
}

/// The wall µs this thread's charged polls have waited for off-lock workers so far (monotone; see `JOB_WAIT_US`).
#[must_use]
pub fn job_wait_us() -> u64 {
    JOB_WAIT_US.with(Cell::get)
}

/// Mark this thread as a simulated node's (true) or a daemon's (false, the default): what [`Stamp::now`] reads on it.
pub fn charge_this_thread(on: bool) {
    CHARGED.with(|c| c.set(on));
}

/// Whether this thread is a simulated node's charged thread.
#[must_use]
pub fn charged() -> bool {
    CHARGED.with(Cell::get)
}

/// ⭐ THE REPLAYABLE SIMULATOR'S CLOCK (lane b 2026-10-24). On an UNCHARGED simulated node the simulator's model is that
/// computing costs no simulated time (netsim.rs, NOT MODELED: node CPU time), yet every budget here read the HOST's wall,
/// so how many blocks a drain applied per tick — and an off-lock job's first `Ready` poll — depended on the host's speed and
/// load. MEASURED (joiner-restart-d1.log): one seed, two runs in one process, uncharged: tips 620/619/621 vs 601/601/603.
/// A frozen thread's clock stands still (every budget runs its call to completion, as a CPU-free model says) and its
/// off-lock jobs are waited for and ready at their first poll, so a run is a function of its seed (FoundationDB's
/// simulator, TigerBeetle's VOPR: simulated time never reads the host). Charged threads ignore it. cons: none in a daemon
/// (nothing freezes a daemon thread); a frozen node's budgets bound nothing, which is the uncharged model's own premise.
pub fn freeze_this_thread(on: bool) {
    FROZEN.with(|c| c.set(on));
}

/// The simulator names this node thread's simulated instant (every step; `None` off a simulated node).
pub fn set_sim_now_ms(ms: Option<u64>) {
    SIM_NOW_MS.with(|c| c.set(ms));
}

/// ⭐ THE CADENCE CLOCK (lane b 2026-10-24) — milliseconds for a node's own housekeeping cadences (the checkpoint's
/// minimum interval): the wall (UNIX ms) on a daemon and on every charged or ordinary thread; on a REPLAYABLE simulated
/// node the simulated instant the simulator set ([`set_sim_now_ms`]; 0 before its first step). BORROWED-FROM Bitcoin
/// Core's mockable `GetTime` (`-mocktime`) and FoundationDB's simulated `now()`: a cadence a test replays reads the
/// clock the test controls. MEASURED why (replay-r18-seq.log, replay-r19.log): with every node thread run one after
/// another, one seed still parted at 104 s and the run went green with only a slower host (a draw trace on) — the
/// checkpoint's `Instant` cadence decided, per host speed, when a capture with side effects ran. cons: none in a daemon.
#[must_use]
pub fn cadence_now_ms() -> u64 {
    if frozen() {
        return SIM_NOW_MS.with(Cell::get).unwrap_or(0);
    }
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0, |d| d.as_millis() as u64)
}

/// Whether this thread runs a replayable (frozen-clock) simulated node — see [`freeze_this_thread`].
#[must_use]
pub fn frozen() -> bool {
    FROZEN.with(Cell::get) && !charged()
}

/// ⭐ A REPLAYABLE SIMULATED NODE'S ENTROPY (lane b 2026-10-24). Every random draw a node makes (the KEM's and the
/// signature scheme's C `randombytes`: a block's seed note, a cover ciphertext, a vote's signature) came from the OS, so
/// a block's bytes — its id, its PoW nonce, hence its grind time and GHOSTDAG's hash tie-breaks — differed per run.
/// MEASURED (joiner-restart-d2.log): one seed, frozen clock, equal blocks produced by t = 10 s yet 254 vs 175 PoW tries.
/// On a replayable node thread the draws come from this stream instead: blake3 keyed by a per-(seed, node, process)
/// key over a counter (FoundationDB's `deterministicRandom()`, TigerBeetle's VOPR PRNG). A worker an [`OffLockJob`]
/// spawns gets a child stream forked at spawn, so its draws never race the node thread's. A daemon thread holds `None`
/// and the vendored `randombytes` then reads the OS exactly as upstream. cons: one TLS read per draw and per spawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SimEntropy {
    key: [u8; 32],
    ctr: u64,
}

impl SimEntropy {
    /// The stream of simulated node `node`'s process `incarnation` under simulation seed `seed`.
    #[must_use]
    pub fn new(seed: u64, node: u64, incarnation: u64) -> Self {
        let mut h = blake3::Hasher::new_derive_key("MonerousD netsim node entropy v1");
        h.update(&seed.to_le_bytes());
        h.update(&node.to_le_bytes());
        h.update(&incarnation.to_le_bytes());
        Self { key: *h.finalize().as_bytes(), ctr: 0 }
    }

    /// The stream of sub-task `k` under this one (a parallel lane's slot `k`): a function of the parent and `k` alone,
    /// so a fan-out replays whatever the host's core count splits it into.
    #[must_use]
    pub fn child(&self, k: u64) -> Self {
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(b"child");
        h.update(&k.to_le_bytes());
        Self { key: *h.finalize().as_bytes(), ctr: 0 }
    }

    /// Which stream this is, in short (a replay trace's node label: stable across runs of one seed).
    #[must_use]
    pub fn label(&self) -> String {
        format!("{:02x}{:02x}", self.key[0], self.key[1])
    }

    /// How many draws this stream has served (a replay trace compares it).
    #[must_use]
    pub fn draws(&self) -> u64 {
        self.ctr
    }

    fn draw(&mut self, buf: &mut [u8]) {
        self.trace();
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(&self.ctr.to_le_bytes());
        h.finalize_xof().fill(buf);
        self.ctr += 1;
    }

    /// One 32-byte draw — the same bytes [`Self::draw`] fills a 32-byte buffer with (blake3's XOF opens with its hash).
    fn draw_key(&mut self) -> [u8; 32] {
        self.trace();
        let mut h = blake3::Hasher::new_keyed(&self.key);
        h.update(&self.ctr.to_le_bytes());
        self.ctr += 1;
        *h.finalize().as_bytes()
    }

    #[cfg_attr(not(test), allow(clippy::unused_self))]
    fn trace(&self) {
        // REPLAY_DRAW_TRACE=<lo>-<hi>: name the caller of every draw whose counter falls in [lo, hi] (a replay red's window).
        // The WHOLE body is test-only: gating the `let` alone left the daemon build naming `lo`/`hi` it never bound.
        #[cfg(test)]
        {
            let (lo, hi) = std::env::var("REPLAY_DRAW_TRACE")
                .ok()
                .and_then(|v| v.split_once('-').and_then(|(a, b)| Some((a.parse::<u64>().ok()?, b.parse::<u64>().ok()?))))
                .unwrap_or((1, 0));
            if (lo..=hi).contains(&self.ctr) {
                let bt = std::backtrace::Backtrace::force_capture().to_string();
                let ours: Vec<&str> = bt.lines().filter(|l| l.contains("usdmd_node::") && !l.contains("budget_clock")).take(8).map(str::trim).collect();
                eprintln!("[draw-trace] {:?} key {:02x}{:02x} ctr {} · {ours:?}", std::thread::current().name(), self.key[0], self.key[1], self.ctr);
            }
        }
    }
}

/// Replay calibration (lane b, T3): `REPLAY_TX_TRACE=<hex prefix>|all` prints every relay and pool event of the matching
/// tx — the node's stream label, its clock, the event, the link (and, for a prefix, the first frames of the caller). A
/// daemon build compiles it to nothing.
#[cfg_attr(not(test), allow(unused_variables))]
pub fn replay_tx_trace(ev: &str, id: &[u8; 32], link: Option<u64>) {
    #[cfg(test)]
    if let Ok(p) = std::env::var("REPLAY_TX_TRACE") {
        let hex = crate::hash::Hash32(*id).to_hex();
        // `all`: every tx, without the caller (a whole run's sequence, diffed run against run)
        // (`all` leaves out the pool's own inserts and removals: every block mints and drops 256 cover txs)
        if (p == "all" && !ev.starts_with("pool")) || (!p.is_empty() && hex.starts_with(p.as_str())) {
            let bt = if p == "all" { String::new() } else { std::backtrace::Backtrace::force_capture().to_string() };
            let ours: Vec<&str> = bt.lines().filter(|l| l.contains("usdmd_node::") && !l.contains("tx_trace")).take(14).map(str::trim).collect();
            eprintln!("[tx-trace] {} t {} {ev} {} link {link:?} · {ours:?}", entropy_of_this_thread().map_or_else(|| "-".to_string(), |e| e.label()), cadence_now_ms(), &hex[..8]);
        }
    }
}

/// Install (or clear, `None`) this thread's simulated entropy stream.
pub fn seed_entropy_this_thread(e: Option<SimEntropy>) {
    ENTROPY.with(|c| c.set(e));
}

/// This thread's simulated entropy stream where it now stands (the simulator carries it into the node's next window).
#[must_use]
pub fn entropy_of_this_thread() -> Option<SimEntropy> {
    ENTROPY.with(Cell::get)
}

/// The vendored `randombytes` source: fills `buf` from this thread's simulated stream; `false` (the OS RNG) when it has none.
pub fn sim_entropy_fill(buf: &mut [u8]) -> bool {
    ENTROPY.with(|c| match c.get() {
        Some(mut e) => {
            e.draw(buf);
            c.set(Some(e));
            true
        }
        None => false,
    })
}

/// A child stream for a worker (or a fan-out's base, split per slot by [`SimEntropy::child`]) this thread spawns —
/// `None` on a daemon thread. Every thread a simulated node spawns that may draw randomness takes one at spawn.
#[must_use]
pub fn fork_entropy() -> Option<SimEntropy> {
    ENTROPY.with(|c| {
        c.get().map(|mut e| {
            let key = e.draw_key();
            c.set(Some(e));
            SimEntropy { key, ctr: 0 }
        })
    })
}

/// Fresh material for an INSTANCE TAG — a nonce that must only be unique per (node, call), never secret (a peg
/// proposal's nonce). On a replayable simulated node it is the node's next entropy draw, so a seed replays it; on a
/// daemon it is blake3(wall ms ‖ a process counter), exactly the material the call sites hashed before. MEASURED why
/// (lane b 2026-10-24): two peg nonce sites hashed `unix_ms_now()` and a process-wide static counter, so the same
/// seed proposed different bytes per run, and a second in-process run continued the first run's counter.
/// cons: none in a daemon (the same inputs, one extra blake3); one draw per tag on a sim node.
#[must_use]
pub fn instance_nonce() -> [u8; 32] {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    ENTROPY.with(|c| match c.get() {
        Some(mut e) => {
            let k = e.draw_key();
            c.set(Some(e));
            k
        }
        None => {
            let mut h = blake3::Hasher::new_derive_key("MonerousD instance nonce v1");
            h.update(&cadence_now_ms().to_le_bytes());
            h.update(&COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed).to_le_bytes());
            *h.finalize().as_bytes()
        }
    })
}

/// This thread's CPU time in microseconds (`CLOCK_THREAD_CPUTIME_ID`, macOS ≥ 10.12 and Linux).
#[must_use]
pub fn thread_cpu_us() -> u64 {
    crate::oscall::thread_cpu_us()
}

/// ⭐ THE CHARGE CLOCK (µs): this thread's CPU plus, in a test build, the CPU its memo hits stood in for
/// (`usdm_decider::poseidon2_compress::sim_charge` — a node binary has no memo and pays every call, so a simulated node is
/// charged that). Every charged reader goes through here: [`Stamp::now`] on a charged thread, the simulator's step charge,
/// and an [`OffLockJob`]'s own cost. In a node binary it is exactly [`thread_cpu_us`].
#[must_use]
pub fn charged_cpu_us() -> u64 {
    thread_cpu_us().saturating_add(memo_phantom_us())
}

#[cfg(test)]
fn memo_phantom_us() -> u64 {
    usdm_decider::poseidon2_compress::sim_charge::phantom_ns() / 1_000
}

#[cfg(not(test))]
fn memo_phantom_us() -> u64 {
    0 // no memo in a node binary: nothing stands in for a call it did not make
}

/// What [`OffLockJob::poll`] found.
pub enum JobPoll<T> {
    /// The job's result, due now.
    Ready(T),
    /// Still running — or, on a charged thread, finished but not yet due in simulated time.
    Pending,
    /// The worker thread died without an answer.
    Lost,
}

/// ⭐⭐ A JOB THE RUNTIME RUNS OFF ITS LOCK, ON ITS OWN THREAD, AND POLLS ONCE A TICK (MonerousD 2026-10-08).
///
/// A daemon takes the result the tick it is ready — unchanged. A CHARGED (simulated) node thread takes it once its clock
/// reaches the spawn instant plus the job's OWN CPU on the charge clock: that is when the worker, on a core of its own,
/// would have finished on a node's hardware. Before, the simulator polled a wall-clock thread while its clock ran ~21×
/// wall, so a job's simulated duration was its wall time × the simulation's speed — a property of the host, not the node.
/// MEASURED (P14 high leg on 865e797, night/perf-flat-20261008-205812-high.log): the joiner's P8 was 44 s against 18 s
/// at the low leg, and the match came right after `[nf-pivot] the warm INSTALLED … after 19100 served tag(s)` ≈ 30 sim s
/// after the adopt (pump-line clock) — the warm's worker polled in wall time. The band prover's test door
/// (`band_job_settle_for_sim`, deleted at link 84: the band prover is an `OffLockJob` now) closed the same class for one job.
/// BORROWED-FROM: Shadow / FoundationDB — simulated time is charged for work, never a wall-clock wait.
/// On a charged thread the poll WAITS (wall) for the worker before judging the instant: a wait costs the node thread no
/// CPU, and the verdict is then a function of the job's cost, never of how far the host let the simulation run meanwhile.
/// cons: none in a daemon (one `try_recv`, plus two CPU-clock reads on the worker); in the simulator the node thread
/// waits out a job it polls before its own due instant — wall time, never simulated time.
pub struct OffLockJob<T> {
    rx: std::sync::mpsc::Receiver<(T, u64)>,
    spawned_ms: u64,
    done: Option<(T, u64)>,
}

impl<T: Send + 'static> OffLockJob<T> {
    /// Spawn `f` on a thread named `name` at the node's clock `now_ms`. `None` when the thread cannot be spawned.
    pub fn spawn(name: &str, now_ms: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        let done = register_spawn();
        let (entropy, freeze) = (fork_entropy(), FROZEN.with(Cell::get)); // a replayable node's worker replays too
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                seed_entropy_this_thread(entropy);
                freeze_this_thread(freeze);
                let c0 = charged_cpu_us();
                let out = f();
                let _ = tx.send((out, charged_cpu_us().saturating_sub(c0)));
                if let Some(d) = done {
                    let _ = d.send(());
                }
            })
            .ok()?;
        Some(Self { rx, spawned_ms: now_ms, done: None })
    }

    /// ⛔ TEST BUILDS ONLY — a stand-in's DECLARED cost (DB-454, link 85): the job runs as [`Self::spawn`] and reports its own
    /// CPU plus `declared_ms` more, so a charged (simulated) node takes it at spawn + that. The simulator's bound band-step
    /// double costs microseconds where the real compact carrier costs `BAND_FOLD_PROVE_MS_REF`; charging the double the
    /// reference gives the fast simulation the real lane's band timing, which is what hid the relay defect DB-454 names
    /// (MEASURED: fast lane 1.22× redundant band proving, real lane 2.05×+ — every node proved every step). A daemon's job
    /// is never declared anything: this door does not exist in a node binary.
    #[cfg(test)]
    pub fn spawn_with_declared_cost(name: &str, now_ms: u64, declared_ms: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<Self> {
        let (tx, rx) = std::sync::mpsc::channel();
        let done = register_spawn();
        let (entropy, freeze) = (fork_entropy(), FROZEN.with(Cell::get)); // a replayable node's worker replays too
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                seed_entropy_this_thread(entropy);
                freeze_this_thread(freeze);
                let c0 = charged_cpu_us();
                let out = f();
                let own = charged_cpu_us().saturating_sub(c0);
                let _ = tx.send((out, own.saturating_add(declared_ms.saturating_mul(1_000))));
                if let Some(d) = done {
                    let _ = d.send(());
                }
            })
            .ok()?;
        Some(Self { rx, spawned_ms: now_ms, done: None })
    }

    /// ⭐⭐ A PARALLEL JOB (a prove that fans out over the process's rayon pool) spawned at the node's clock `now_ms` (link
    /// 84, 2026-10-21). Its work runs on pool threads, so its own thread's CPU counts almost none of it: on a CHARGED spawner
    /// (captured at spawn) the worker runs `f` ALONE ([`prove_alone`] — the process's one prove gate, the cores to itself as
    /// on a node's own hardware) and is charged the WALL time it held the gate; a daemon's job is exactly [`Self::spawn`]'s.
    /// MEASURED why (the real lane, night/link83-real.txt): the band prover was a raw thread polled in wall time, so the
    /// real lane had to pace its clock to wall (`NetSim::pace`) and the journey's ≈ 2,600 simulated s needed ≈ 2,600 wall
    /// s — over the 2,700 s cap with the census, while the step loop used 15–17 % of the wall.
    /// BORROWED-FROM Shadow / FoundationDB: a simulated host is charged the measured cost of ITS work, never a wall wait.
    /// cons: none in a daemon; in the simulator a gated job and another simulated node's template prove no longer share the
    /// cores (they run one after another in wall time — the same CPU work, each at its full speed).
    pub fn spawn_on_cores(name: &str, now_ms: u64, f: impl FnOnce() -> T + Send + 'static) -> Option<Self> {
        if !charged() {
            return Self::spawn(name, now_ms, f);
        }
        let (tx, rx) = std::sync::mpsc::channel();
        let done = register_spawn();
        let (entropy, freeze) = (fork_entropy(), FROZEN.with(Cell::get)); // a replayable node's worker replays too
        std::thread::Builder::new()
            .name(name.into())
            .spawn(move || {
                seed_entropy_this_thread(entropy);
                freeze_this_thread(freeze);
                let (out, held_us) = alone_us(f);
                let _ = tx.send((out, held_us));
                if let Some(d) = done {
                    let _ = d.send(());
                }
            })
            .ok()?;
        Some(Self { rx, spawned_ms: now_ms, done: None })
    }

    /// The node's clock when the job was spawned: a poller's `now_ms − spawned_ms` is how long the job took on that clock
    /// (wall on a daemon, its charged cost on a simulated node, rounded up to the poll).
    #[must_use]
    pub fn spawned_ms(&self) -> u64 {
        self.spawned_ms
    }

    /// The result if it is due at the node's clock `now_ms` (see the type's doc for a charged thread).
    pub fn poll(&mut self, now_ms: u64) -> JobPoll<T> {
        if self.done.is_none() {
            if charged() || frozen() {
                if !self.wait_done() {
                    return JobPoll::Lost;
                }
            } else {
                match self.rx.try_recv() {
                    Ok(d) => self.done = Some(d),
                    Err(std::sync::mpsc::TryRecvError::Empty) => return JobPoll::Pending,
                    Err(std::sync::mpsc::TryRecvError::Disconnected) => return JobPoll::Lost,
                }
            }
        }
        if charged() && self.done.as_ref().is_some_and(|(_, cpu_us)| now_ms < self.due_ms(*cpu_us)) {
            return JobPoll::Pending;
        }
        match self.done.take() {
            Some((t, _)) => JobPoll::Ready(t),
            None => JobPoll::Pending,
        }
    }

    /// Wait (wall) for the worker's answer and hold it; `false` when the worker died. The wait is this thread's
    /// [`job_wait_us`].
    fn wait_done(&mut self) -> bool {
        if self.done.is_some() {
            return true;
        }
        let t = std::time::Instant::now();
        let got = self.rx.recv();
        JOB_WAIT_US.with(|w| w.set(w.get().saturating_add(u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX))));
        match got {
            Ok(d) => {
                self.done = Some(d);
                true
            }
            Err(_) => false,
        }
    }

    /// TEST DOOR (the simulator's fast lane on an UNCHARGED node): wait, in wall time, for the worker so the next poll
    /// finds it finished — the job then costs exactly one poll interval of simulated time whatever the host's wall did. A
    /// charged node's poll already waits ([`Self::poll`]); a dead worker is reported by that next poll as `Lost`.
    #[cfg(test)]
    pub fn settle(&mut self) {
        let _ = self.wait_done();
    }

    /// The simulated instant a job that spent `cpu_us` on the charge clock is due (spawn + its CPU, rounded up to a ms).
    fn due_ms(&self, cpu_us: u64) -> u64 {
        self.spawned_ms.saturating_add(cpu_us.div_ceil(1_000))
    }
}

/// ⭐ THE PROVE GATE (link 73, 2026-10-21; moved here from `harness/netsim.rs` at link 84 so an off-lock job can take it) —
/// one simulated node's prove at a time in this process. Every simulated node steps on its own thread and all of them share
/// ONE rayon pool, so two proves at the same simulated instant split the pool and each took ~2× its wall time — and the
/// simulation charged that wall time as the node's busy span. On a node's own hardware no other node's prove shares its
/// cores: the charge was a property of how many simulated nodes happened to prove at once, not of the node. MEASURED why
/// (night/perf-load-20261021-085026-n8.log): a constant-shape note transition proved in p50 3,378 / p95 6,539 ms — a
/// constant shape is one trace size, and the spread is the pool split. The wait for the gate is the host's wall time, never
/// the node's simulated time. A daemon never takes it (only a charged thread's work does).
/// ROOT-LAYER: a job's cost is produced where the job RUNS (its worker, holding the cores alone), so it is measured there
/// and carried to the poll with the result — never re-derived by the reader from the wall clock it polls on.
/// MEASURED: real lane at pace 1.0 (night/link83-real.txt) — step loop 15–17 % of wall, T3 cut at 2,700 s; the gate's
/// template-prove spread p95 6,539 → solo ms (link 73).
/// MUST-STAY-GREEN: `off_lock_job_tests` (both ways), netsim's gated-prove calibration pin, the fast + eco journeys.
/// BORROWED-FROM Shadow / FoundationDB: a simulated host is charged the measured cost of ITS work, never another host's.
/// cons: none on the simulated schedule's honesty; in wall time, proves that would have overlapped run one after another.
static PROVE_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Run `f` alone ([`PROVE_GATE`]) and return it with the wall µs it took once it held the gate. A gate poisoned by a
/// panicking prove still serializes (the guard carries no data, so its poison carries no meaning).
fn alone_us<R>(f: impl FnOnce() -> R) -> (R, u64) {
    let _alone = PROVE_GATE.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let t = std::time::Instant::now();
    let r = f();
    (r, u64::try_from(t.elapsed().as_micros()).unwrap_or(u64::MAX))
}

/// Run a simulated node's prove `f` alone ([`PROVE_GATE`]) and return it with the wall milliseconds it took once it held
/// the gate — what the simulation charges as the node's busy span.
pub fn prove_alone<R>(f: impl FnOnce() -> R) -> (R, u64) {
    let (r, us) = alone_us(f);
    (r, us / 1_000)
}

fn wall_us() -> u64 {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    EPOCH.get_or_init(std::time::Instant::now).elapsed().as_micros().min(u128::from(u64::MAX)) as u64
}

/// An instant on this thread's budget clock (µs). Stamps compare only with stamps taken on the same thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Stamp(u64);

impl Stamp {
    /// Now, on this thread's budget clock.
    #[must_use]
    pub fn now() -> Stamp {
        Stamp(if charged() {
            charged_cpu_us()
        } else if frozen() {
            0
        } else {
            wall_us()
        })
    }

    /// An instant `ms` before now (a budget already spent — a test's expired deadline).
    #[must_use]
    pub fn ago_ms(ms: u64) -> Stamp {
        Stamp(Self::now().0.saturating_sub(ms.saturating_mul(1_000)))
    }

    /// Milliseconds since this stamp.
    #[must_use]
    pub fn elapsed_ms(self) -> u128 {
        u128::from(Self::now().0.saturating_sub(self.0) / 1_000)
    }

    /// The deadline `ms` after this stamp.
    #[must_use]
    pub fn plus_ms(self, ms: u64) -> Stamp {
        Stamp(self.0.saturating_add(ms.saturating_mul(1_000)))
    }

    /// Milliseconds left until this deadline (0 once it has passed).
    #[must_use]
    pub fn remaining_ms(self) -> u64 {
        self.0.saturating_sub(Self::now().0) / 1_000
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod off_lock_job_tests {
    //! ⭐ CALIBRATION BOTH WAYS (PERF TIER): an off-lock job's result is due at spawn + its OWN CPU on a simulated node's
    //! charged thread — never earlier because the host ran it fast in wall time, never later because the simulation ran
    //! ahead — and a daemon takes it the moment it is ready, whatever its clock says. And the charge clock carries the CPU a
    //! memo hit stood in for. MEASURED why: the joiner's P8 (night/perf-flat-20261008-205812-high.log).
    use super::*;

    /// Burn ~`ms` of this thread's CPU; returns the CPU it measured (µs) on the charge clock.
    fn spin_cpu(ms: u64) -> u64 {
        let c0 = charged_cpu_us();
        let mut x = 0x9e37_79b9_7f4a_7c15u64;
        while charged_cpu_us().saturating_sub(c0) < ms * 1_000 {
            for _ in 0..10_000 {
                x = x.rotate_left(7).wrapping_mul(0x51_7c_c1_b7_27_22_0a_95) ^ 0xA5;
            }
        }
        std::hint::black_box(x);
        charged_cpu_us().saturating_sub(c0)
    }

    #[test]
    fn an_off_lock_job_is_due_at_spawn_plus_its_own_cpu_on_a_charged_thread_and_at_once_on_a_daemon() {
        // ── charged (a simulated node's thread): the clock reads 1 ms past the spawn and the worker is FINISHED in wall time
        //    (the poll waits for it) — the job still is not due until its own CPU has passed on the node's clock.
        charge_this_thread(true);
        let spawned = 1_000_000u64;
        let mut job = OffLockJob::spawn("calib-charged", spawned, || spin_cpu(60)).expect("a thread spawns");
        assert!(
            matches!(job.poll(spawned + 1), JobPoll::Pending),
            "⛔ OFF-LOCK STRETCH: a simulated node took a 60 ms job 1 ms after its spawn — its duration is the host's wall \
             time, not the job's cost"
        );
        let cpu_ms = match job.done.as_ref() {
            Some((spent_us, charged_us)) => {
                assert!(*charged_us >= *spent_us, "the job's charge ({charged_us} µs) is at least the CPU it measured ({spent_us} µs)");
                charged_us.div_ceil(1_000)
            }
            None => panic!("a charged poll waits for the worker, so its result is held after the first poll"),
        };
        assert!(cpu_ms >= 60, "the spin measured {cpu_ms} ms of CPU on its own thread");
        assert!(matches!(job.poll(spawned + cpu_ms - 1), JobPoll::Pending), "not due 1 ms before spawn + its CPU ({cpu_ms} ms)");
        assert!(matches!(job.poll(spawned + cpu_ms), JobPoll::Ready(_)), "due at spawn + its CPU ({cpu_ms} ms)");
        // ── a daemon's thread: the result is taken the tick it is ready, whatever the clock reads.
        charge_this_thread(false);
        let mut job = OffLockJob::spawn("calib-daemon", spawned, || spin_cpu(20)).expect("a thread spawns");
        let t0 = std::time::Instant::now();
        loop {
            match job.poll(spawned) {
                JobPoll::Ready(_) => break,
                JobPoll::Pending => std::thread::sleep(std::time::Duration::from_millis(1)),
                JobPoll::Lost => panic!("the worker died"),
            }
            assert!(t0.elapsed() < std::time::Duration::from_secs(30), "a daemon's job never became ready");
        }
    }

    /// A parallel job: `helpers` threads each burn ~`ms` of their own CPU while the calling (worker) thread only joins them.
    /// Returns (the job's wall µs, the worker thread's own CPU µs on the charge clock).
    fn fan_out_cpu(helpers: usize, ms: u64) -> (u64, u64) {
        let t = std::time::Instant::now();
        let c0 = charged_cpu_us();
        std::thread::scope(|s| {
            for _ in 0..helpers {
                s.spawn(|| spin_cpu(ms));
            }
        });
        (t.elapsed().as_micros() as u64, charged_cpu_us().saturating_sub(c0))
    }

    #[test]
    fn a_parallel_job_is_charged_its_gated_wall_never_its_own_threads_cpu_nor_another_provers_wait() {
        // ── charged (a simulated node's thread): the work runs on helper threads, so the worker's own CPU is ~0 — a
        //    `spawn` would have made it due at once. `spawn_on_cores` charges the wall it held the cores for.
        charge_this_thread(true);
        let spawned = 2_000_000u64;
        // another simulated node's prove holds the gate for 150 ms of wall while this job is spawned: the job waits for
        // it in wall time and is never charged that wait
        let held = std::thread::spawn(|| prove_alone(|| std::thread::sleep(std::time::Duration::from_millis(150))));
        std::thread::sleep(std::time::Duration::from_millis(20)); // the holder has the gate first
        let mut job = OffLockJob::spawn_on_cores("calib-cores", spawned, || fan_out_cpu(2, 60)).expect("a thread spawns");
        assert!(matches!(job.poll(spawned + 1), JobPoll::Pending), "⛔ PARALLEL UNDER-CHARGE: a 60 ms fan-out was due 1 ms after its spawn");
        let _ = held.join();
        let (cost_ms, wall_us, own_cpu_us) = match job.done.as_ref() {
            Some(((wall_us, own_cpu_us), held_us)) => (held_us.div_ceil(1_000), *wall_us, *own_cpu_us),
            None => panic!("a charged poll waits for the worker, so its result is held after the first poll"),
        };
        assert!(cost_ms >= 60, "⛔ PARALLEL UNDER-CHARGE: charged {cost_ms} ms for a fan-out that ran ≥ 60 ms of wall on its helpers");
        assert!(cost_ms * 1_000 >= wall_us, "the charge ({cost_ms} ms) covers the job's own wall ({wall_us} µs)");
        assert!(
            own_cpu_us < cost_ms * 1_000 / 2,
            "the calibration's premise: the worker thread's own CPU ({own_cpu_us} µs) counts under half the job"
        );
        assert!(
            cost_ms < 150,
            "⛔ GATE-WAIT OVER-CHARGE: the job was charged {cost_ms} ms — the 150 ms another prover held the gate is the host's \
             wall, never this node's time"
        );
        assert!(matches!(job.poll(spawned + cost_ms - 1), JobPoll::Pending), "not due 1 ms before spawn + its charge ({cost_ms} ms)");
        assert!(matches!(job.poll(spawned + cost_ms), JobPoll::Ready(_)), "due at spawn + its charge ({cost_ms} ms)");
        assert_eq!(job.spawned_ms(), spawned);
        // ── a daemon's thread: taken the tick it is ready, whatever the clock reads (no gate).
        charge_this_thread(false);
        let mut job = OffLockJob::spawn_on_cores("calib-cores-daemon", spawned, || fan_out_cpu(2, 20)).expect("a thread spawns");
        let t0 = std::time::Instant::now();
        loop {
            match job.poll(spawned) {
                JobPoll::Ready(_) => break,
                JobPoll::Pending => std::thread::sleep(std::time::Duration::from_millis(1)),
                JobPoll::Lost => panic!("the worker died"),
            }
            assert!(t0.elapsed() < std::time::Duration::from_secs(30), "a daemon's job never became ready");
        }
    }

    #[test]
    fn the_charge_clock_carries_the_cpu_a_memo_hit_stood_in_for() {
        // A sparse pair: one miss on this thread measures it; a thousand hits must each charge this thread that cost.
        let a = [7u64, 11, 13, 17, 19, 23, 29, 31];
        let b = [37u64, 41, 43, 47, 53, 59, 61, 67];
        let _ = usdm_decider::poseidon2_compress::compress_sparse(&a, &b);
        let p0 = usdm_decider::poseidon2_compress::sim_charge::phantom_ns();
        let c0 = charged_cpu_us();
        for _ in 0..1_000 {
            let _ = std::hint::black_box(usdm_decider::poseidon2_compress::compress_sparse(&a, &b));
        }
        let phantom = usdm_decider::poseidon2_compress::sim_charge::phantom_ns().saturating_sub(p0);
        let charged = charged_cpu_us().saturating_sub(c0);
        assert!(
            phantom >= 1_000 * 50,
            "⛔ MEMO UNDER-CHARGE: 1,000 pair-cache hits charged this thread {phantom} ns — a node binary computes each one \
             (one Poseidon2 permutation, ≥ 50 ns)"
        );
        assert!(charged >= phantom / 1_000, "the charge clock ({charged} µs) carries the hits' charge ({} µs)", phantom / 1_000);
    }
}
