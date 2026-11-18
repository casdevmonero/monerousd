// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

// Repro harness: call the PHONE'S EXACT in-process node entry (`serve::run_in_process`) on the host, with a
// process-global panic hook (same shape as the wallet's) so any panic on any thread prints its message +
// location to stderr. A watchdog exits(0) after a grace period if the node stayed alive — so a clean run means
// "no crash in the in-process bring-up on this host", and a crash prints the exact panic we are hunting.
fn main() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let loc = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "<unknown>".into());
        let msg = info
            .payload()
            .downcast_ref::<&str>()
            .map(|s| s.to_string())
            .or_else(|| info.payload().downcast_ref::<String>().cloned())
            .unwrap_or_else(|| "<non-string panic payload>".into());
        let thread = std::thread::current()
            .name()
            .unwrap_or("<unnamed>")
            .to_string();
        eprintln!("[PANIC] thread '{thread}' panicked at {loc}: {msg}");
        default_hook(info);
    }));

    // Watchdog: if the in-process node is still alive after the grace period, the bring-up did NOT crash here.
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_secs(14));
        eprintln!("[repro] node still ALIVE after 14s — no in-process crash on this host (crash is iOS-specific)");
        std::process::exit(0);
    });

    // The phone's exact call: canonical testnet, a spare port to avoid colliding with a running node (the
    // genesis-override arg was REMOVED from run_in_process — genesis is a deterministic f(network) now).
    // Blocks on the RPC accept loop (or crashes on the way up).
    eprintln!("[repro] calling run_in_process(27782, \"testnet\") …");
    match usdmd_node::serve::run_in_process(27782, "testnet") {
        Ok(()) => eprintln!("[repro] run_in_process returned Ok (node exited cleanly)"),
        Err(e) => eprintln!("[repro] run_in_process returned Err: {e}"),
    }
}
