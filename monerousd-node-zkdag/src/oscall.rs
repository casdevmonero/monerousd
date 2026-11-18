// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! ⭐ EVERY OS CALL THE NODE MAKES, THROUGH A SAFE AUDITED WRAPPER — the shipping tree holds no `unsafe`.
//!
//! The hole scanner's "memory-unsafe code" class (lane d 2026-10-27) counted nine hand-checked `unsafe { libc::… }`
//! blocks across `log_cap`, `budget_clock`, `arti_transport`, `main` and `serve`: a file path behind fd 2, a dup2, the
//! thread CPU clock, the owner-only umask, two copies of a SIGTERM/SIGINT flag handler, a mach task-info read, the
//! iOS syslog. Each is now ONE call here, by the crate the ecosystem already trusts for that call (BORROW, NEVER
//! RE-DERIVE): `nix` (the fd path, dup2, umask, the thread clock, syslog, a liveness `kill(pid, 0)`), `signal-hook`
//! (the TERM flag — `sigaction` through `signal-hook-registry`, the same registry tokio's own signal driver uses) and
//! `memory-stats` (the resident set). Memory safety then rests on wrappers thousands of crates measure, not on a
//! comment a reviewer must believe. cons: three locked crates (nix, signal-hook, memory-stats); none at run time.

use std::path::PathBuf;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

/// The file currently behind fd 2, or `None` when stderr is a terminal or a pipe (nothing to rotate).
#[must_use]
pub fn path_of_stderr() -> Option<PathBuf> {
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        let mut path = PathBuf::new();
        nix::fcntl::fcntl(std::io::stderr(), nix::fcntl::FcntlArg::F_GETPATH(&mut path)).ok()?;
        if path.as_os_str().is_empty() {
            None
        } else {
            Some(path)
        }
    }
    #[cfg(all(unix, not(any(target_os = "macos", target_os = "ios"))))]
    {
        std::fs::read_link("/proc/self/fd/2").ok().filter(|p| p.is_absolute())
    }
    // Windows (lane speed5 2026-11-18, wallet audit W4): a handle has no path the process can read back without more
    // APIs, so the starter names it: the wallet sets MONEROUSD_STDERR_PATH to the file it gave the node as stderr. Unset
    // (a console, a pipe) means nothing to rotate, as on the other systems.
    #[cfg(not(unix))]
    {
        std::env::var_os("MONEROUSD_STDERR_PATH").map(PathBuf::from).filter(|p| p.is_absolute() && p.is_file())
    }
}

/// Re-point fd 2 at `fresh` (dup2 onto stderr); `fresh` keeps its own descriptor and closes only that on drop.
pub fn replace_stderr_with(fresh: &std::fs::File) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        nix::unistd::dup2_stderr(fresh).map_err(std::io::Error::from)
    }
    #[cfg(not(unix))]
    {
        let _ = fresh;
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no dup2 onto stderr on this platform"))
    }
}

/// This thread's CPU time in microseconds (`CLOCK_THREAD_CPUTIME_ID`); 0 when the clock is unavailable.
#[must_use]
pub fn thread_cpu_us() -> u64 {
    #[cfg(unix)]
    {
        match nix::time::clock_gettime(nix::time::ClockId::CLOCK_THREAD_CPUTIME_ID) {
            Ok(ts) => (ts.tv_sec() as u64).saturating_mul(1_000_000).saturating_add(ts.tv_nsec() as u64 / 1_000),
            Err(_) => 0,
        }
    }
    #[cfg(not(unix))]
    {
        0 // the clock is unavailable here: the documented answer
    }
}

/// Owner-only file creation for the whole process: every file this node creates is `-rw-------` from its first byte.
pub fn umask_owner_only() {
    // Windows has no umask: files take the user profile's ACL, which other accounts cannot read by default
    #[cfg(unix)]
    let _ = nix::sys::stat::umask(nix::sys::stat::Mode::from_bits_truncate(0o077));
}

/// A flag SIGTERM and SIGINT set (the handler stores `true` and nothing else). Registration is best-effort and
/// says so on stderr: the file-based shutdown (`shutdown-<port>`) stays the signal-free path either way.
#[must_use]
pub fn term_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGTERM, signal_hook::consts::SIGINT] {
        if let Err(e) = signal_hook::flag::register(sig, Arc::clone(&flag)) {
            eprintln!("[term] ⛔ could not register signal {sig}: {e} — the shutdown file remains the stop path");
        }
    }
    flag
}

/// Resident set of THIS process in KiB — the phone-class figure a node must keep flat; `None` where unreadable.
#[must_use]
pub fn resident_kb() -> Option<u64> {
    memory_stats::memory_stats().map(|m| (m.physical_mem / 1024) as u64)
}

/// A user-facing notice in the platform's unified log (iOS: the only log an operator can read off a phone).
#[cfg(any(target_os = "macos", target_os = "ios"))]
pub fn syslog_notice(msg: &str) -> nix::Result<()> {
    use nix::syslog::{Facility, Priority, Severity};
    nix::syslog::syslog(Priority::new(Severity::LOG_NOTICE, Facility::LOG_USER), msg)
}

/// Is `pid` a process this machine still runs? `EPERM` counts as ALIVE: the PID resolves, it just is not ours to
/// signal — and "someone else's live process" is precisely the case a sweeper must not touch.
#[must_use]
pub fn pid_is_alive(pid: u32) -> bool {
    #[cfg(unix)]
    {
        match nix::sys::signal::kill(nix::unistd::Pid::from_raw(pid as i32), None) {
            Ok(()) => true,
            Err(nix::errno::Errno::EPERM) => true,
            Err(_) => false,
        }
    }
    // no signal-0 probe here: ALIVE, the conservative answer (a sweeper must never touch a process it cannot prove gone)
    #[cfg(not(unix))]
    {
        let _ = pid;
        true
    }
}
