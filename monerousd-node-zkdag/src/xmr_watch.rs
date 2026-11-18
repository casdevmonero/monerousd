// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! DB-121x — THE MONERO DEPOSIT WATCHER: a custodian reads the reserve's incoming coins from ITS OWN custody wallet
//! (EXTERNAL-CHAIN code, the Monero twin of `btc_watch`).
//!
//! Monero is confidential: nobody reads a reserve address's balance off a public explorer. The k-of-n custody
//! wallet every bonded custodian's `monero-wallet-rpc` holds (`xmr_custody`) sees the reserve's incoming outputs
//! with their payment ids, so each custodian confirms a deposit INDEPENDENTLY from its own wallet — the deposit to
//! a swap's INTEGRATED address is the incoming transfer whose payment id is that address's. Nothing here decides
//! anything for the chain: it is the cache the peg-in gate reads, filled by this node's own wallet read on a fixed
//! cadence, exactly as the Bitcoin watcher's cache is filled by its own source read. ROOT-LAYER: the figure is
//! PRODUCED here, by the wallet read, and only read elsewhere.
//!
//! A user's node holds no custody wallet and reads nothing here; it does not need to — it requests the mint and the
//! custodians confirm from their wallets (owner 2026-09-21: "users should not have to be custodians to peg in and
//! out"). "Confirmed" means MATURED: Monero's own 10-block output lock, or THORChain's ⌈value / block reward⌉ if
//! that is larger, so a shallow reorg can never unwind a deposit worth more than a block reward after it minted.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use crate::xmr_rpc::WalletRpc;

/// Monero's tail emission per block (0.6 XMR) — the reward a confirmation-count is measured against.
/// PAST-CHATS-CHECKED: Monero protocol figure (tail emission 0.6 XMR/block); the Bitcoin leg's twin is
/// `btc_watch::BTC_BLOCK_SUBSIDY_SATS`.
pub const XMR_TAIL_EMISSION_ATOMIC: u64 = 600_000_000_000;
/// Monero's own output lock: a received output is spendable after this many confirmations.
/// PAST-CHATS-CHECKED: Monero protocol constant (CRYPTONOTE_DEFAULT_TX_SPENDABLE_AGE = 10).
pub const XMR_SPEND_LOCK_BLOCKS: u64 = 10;
/// The sweep cadence — the Bitcoin watcher's own.
/// PAST-CHATS-CHECKED: `btc_watch::start_deposit_watch` sleeps 8 s between sweeps; same figure.
const SWEEP_EVERY: Duration = Duration::from_secs(8);

/// How many confirmations a deposit of `amount` atomic units needs before it counts: Monero's spend lock, or
/// THORChain's ⌈value / block reward⌉ when the deposit is worth more than that many rewards.
pub fn required_confirmations(amount: u64) -> u64 {
    let by_value = amount.div_ceil(XMR_TAIL_EMISSION_ATOMIC);
    by_value.max(XMR_SPEND_LOCK_BLOCKS)
}

/// The watched integrated addresses and what this node's own wallet last saw at each — the Bitcoin watcher's own
/// shape: one row per OPEN swap this node issued or was asked to attest, removed by `retire_reserve_watch` when the
/// swap settles, so the set is a function of the open swaps and never of history.
#[derive(Default)]
struct DepositCache {
    want: BTreeSet<String>,
    seen: BTreeMap<String, (u64, u64)>,
    /// ⭐ §22 6: per watched address, the deposits (txids) three onion daemons agreed are matured — kept once agreed,
    /// dropped with the address. O1-FOOTPRINT-REVIEWED: bounded by the open swaps' deposits.
    crossed: BTreeMap<String, BTreeSet<String>>,
}

fn cache() -> MutexGuard<'static, DepositCache> {
    static CACHE: OnceLock<Mutex<DepositCache>> = OnceLock::new();
    let m = CACHE.get_or_init(|| Mutex::new(DepositCache::default()));
    // A poisoned lock holds a cache another thread was mid-write on; the figures inside are still this node's
    // own last reads, so the cache is taken as it stands rather than abandoned.
    match m.lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}

/// Register a swap's INTEGRATED Monero address for sweeping. VALIDATED AT THE DOOR: only a checksummed integrated
/// address on this node's Monero network is sweep work; anything else registers nothing.
pub fn watch_issued_reserve(address: &str) -> bool {
    let a = address.trim();
    let net_ok = crate::bridge::xmr_address_net(a) == Some(crate::bridge::xmr_net_byte());
    if !net_ok || crate::bridge::xmr_integrated_parts(a).is_none() {
        eprintln!("[xmr-watch] ⛔ REFUSED a reserve-watch registration: not an integrated Monero address on this node's network. Nothing added to the sweep.");
        return false;
    }
    cache().want.insert(a.to_string());
    true
}

/// Retire a swept address once its swap settled — what keeps the sweep f(open swaps).
pub fn retire_reserve_watch(address: &str) {
    let mut c = cache();
    c.want.remove(address.trim());
    c.seen.remove(address.trim());
    c.crossed.remove(address.trim());
}

/// (matured atomic, pending atomic) this node's own wallet last saw at `address`; `None` for an address it has
/// never read — the caller says what an unread address means to it.
pub fn confirmed_pending_cached(address: &str) -> Option<(u64, u64)> {
    cache().seen.get(address.trim()).copied()
}

/// One sweep: read every incoming transfer from this node's custody wallet and total, per watched integrated
/// address, the deposits whose payment id is the address's — matured by `required_confirmations`, or pending.
fn sweep_once(
    rpc: &WalletRpc,
    want: &[String],
    crossed: &mut BTreeMap<String, BTreeSet<String>>,
) -> Result<BTreeMap<String, (u64, u64)>, String> {
    rpc.refresh()?;
    let incoming = rpc.incoming()?;
    let mut out = BTreeMap::new();
    for a in want {
        let Some((pid, _main)) = crate::bridge::xmr_integrated_parts(a) else { continue };
        let pid_hex = crate::btc_tx::hex(&pid);
        let mut matured = 0u64;
        let mut pending = 0u64;
        for t in &incoming {
            if t.payment_id != pid_hex {
                continue;
            }
            // §22 6: matured by this node's wallet AND by three onion daemons agreeing on its block (its own daemon alone could
            // be lying or eclipsed); the agreed verdict is kept, so a matured deposit is asked about once
            let need = required_confirmations(t.amount);
            let agreed = crossed.get(a).is_some_and(|s| s.contains(&t.txid))
                || (t.confirmations >= need
                    && crate::xmr_daemons::cross_checked_confirmations(&t.txid).is_some_and(|c| c >= need));
            if t.confirmations >= need && agreed {
                crossed.entry(a.clone()).or_default().insert(t.txid.clone());
                matured = matured.saturating_add(t.amount);
            } else {
                pending = pending.saturating_add(t.amount);
            }
        }
        out.insert(a.clone(), (matured, pending));
    }
    Ok(out)
}

/// Start the self-maintaining sweep exactly once: on a fixed cadence, this node's own custody wallet is read and
/// every watched address's (matured, pending) stored, so every RPC / mint check stays O(1) and current. A node with
/// no wallet-rpc sweeps nothing. Idempotent.
pub fn start_deposit_watch() {
    static STARTED: OnceLock<()> = OnceLock::new();
    if STARTED.set(()).is_err() {
        return;
    }
    std::thread::spawn(|| loop {
        if !cache().want.is_empty() {
            if let Some(rpc) = WalletRpc::from_env() {
                if let Err(e) = sweep_now(&rpc) {
                    eprintln!("[xmr-watch] this node's wallet did not answer the sweep: {e}");
                }
            }
        }
        std::thread::sleep(SWEEP_EVERY);
    });
}

/// ONE sweep of every watched address from `rpc` into the cache — the thread's body, the one site that writes the
/// cache from a wallet read. The simulator and its pins call it on demand (§NETSIM-LAUNCH: the production read path
/// on the simulated clock instead of the wall-clock cadence); a node with nothing watched sweeps nothing.
///
/// ⭐ SAFE AT SCALE, stage three — A SWEEP READS ONLY THE ADDRESSES OF THE WALLET IT HAS OPEN. A custodian keeps one
/// wallet per custody key (member set) and its wallet-rpc has one open at a time. A deposit paid to a key the chain has
/// just replaced — still a valid deposit address inside its window (spec §3f R2) — arrives in THAT key's wallet, which
/// the lanes no longer keep open: read from the current wallet it showed nothing, and it was never minted. So each
/// sweep writes the addresses whose main address IS the open wallet's, and no others: the sweep lane's visit to an
/// old key's wallet (`xmr_sweep`) reads that key's deposits, the cadence above reads the current key's, and neither
/// writes a zero over what the other read.
pub fn sweep_now(rpc: &WalletRpc) -> Result<(), String> {
    let open = rpc.address()?;
    let want: Vec<String> =
        cache().want.iter().filter(|a| crate::bridge::xmr_integrated_parts(a).is_some_and(|(_, main)| main == open)).cloned().collect();
    if want.is_empty() {
        return Ok(());
    }
    let mut crossed = cache().crossed.clone();
    let seen = sweep_once(rpc, &want, &mut crossed)?;
    let mut c = cache();
    for (a, v) in seen {
        c.seen.insert(a, v);
    }
    crossed.retain(|a, _| c.want.contains(a));
    c.crossed = crossed;
    Ok(())
}

/// TEST-ONLY (dev builds and the `bridge-test-oracle` feature — compiled out of a release): plant what a custody
/// wallet would have read, so an in-process fixture can exercise the gate without a Monero daemon.
#[cfg(any(test, feature = "bridge-test-oracle"))]
pub fn inject_confirmed_for_test(address: &str, atomic: u64) {
    let mut c = cache();
    c.want.insert(address.trim().to_string());
    c.seen.insert(address.trim().to_string(), (atomic, 0));
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn confirmations_are_moneros_lock_or_thorchains_value_over_reward() {
        assert_eq!(required_confirmations(1), XMR_SPEND_LOCK_BLOCKS);
        assert_eq!(required_confirmations(XMR_TAIL_EMISSION_ATOMIC * 10), 10);
        assert_eq!(required_confirmations(XMR_TAIL_EMISSION_ATOMIC * 10 + 1), 11);
        assert_eq!(required_confirmations(XMR_TAIL_EMISSION_ATOMIC * 100), 100);
    }

    #[test]
    fn only_an_integrated_address_on_this_network_is_sweep_work() {
        // a standard address carries no payment id: nothing to match a deposit against
        assert!(!watch_issued_reserve("477y8v2RXYGLMktERaQ6eQh3wMQhY2eWyTCm2qzngDfvKLrcqM1gsyYfhkRZ5U2DNYWm6JtD1pHTRNDiKjVDR7oN8JZnsHQ"));
        assert!(!watch_issued_reserve("not an address"));
        assert_eq!(confirmed_pending_cached("never read"), None);
    }
}
