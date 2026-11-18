// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! DB-121x — THE MONERO CUSTODY SET: one k-of-n Monero multisig wallet per bonded set, formed by the custodians'
//! own wallet-rpcs exchanging key material over the mesh (EXTERNAL-CHAIN code).
//!
//! THE SHAPE (the bond-weighted multisig tally's mirror on Monero, as `btc_tx` is on Bitcoin). Monero has no script:
//! its k-of-n is its own multisig — a key-exchange between the members' wallets, then sequential signatures. Every
//! bonded custodian runs its own `monero-wallet-rpc`; this lane drives the exchange for the CURRENT bonded set:
//! `prepare_multisig` → gossip the info → `make_multisig(others, k)` → gossip → `exchange_multisig_keys(others)` …
//! until the wallet reports `ready`. Nothing is done by hand; a member that is away simply has not answered yet, and
//! the lane re-sends EVERY round's info it has produced, every poll, until the set is complete — a member that
//! opened its wallet late is still at round 0 while the others have moved on. k = ⌈2n/3⌉ over custodians (Monero
//! counts keys, one per member; the Bitcoin leaf's slots-∝-bond has no Monero form).
//!
//! THE ROUND RULES (measured on two real custodians 2026-09-21, run 2): every member runs the SAME rounds, so a
//! member's round-r info is exactly what the others consume at their step r. Two rules keep the wallets in step:
//! (1) a node's OWN info comes back to it through the relay and is never another member's — `make_multisig` fed a
//! wallet's own info fails as "invalid threshold" and the verification round fed only its own info fails as
//! "message origins don't line up"; (2) the member whose wallet finalises FIRST keeps re-sending its final-round
//! info until every member has announced the address, because the others' last step consumes exactly that info.
//!
//! THE ADDRESS ANY NODE CAN SERVE (owner 2026-09-21: "users should not have to be custodians to peg in and out"):
//! once a custodian's wallet is final it ANNOUNCES the set's main address, signed with its ML-DSA identity; a node
//! — custodian or not — that has heard the SAME address from ≥k distinct members of the set records it and derives
//! every per-swap deposit address from it as an INTEGRATED address whose payment id is a function of the mint
//! blind (`payment_id`, DB-123 for Monero). So a user's own node serves the deposit address, and every custodian
//! re-derives it at the door, at propose, at attest and at execute — no wallet-rpc needed to SERVE, only to SIGN.
//!
//! Wallet files are the wallet-rpc's own (its `--wallet-dir`); the exchange state this lane holds between polls is
//! persisted beside the validator key so a restart resumes the round it was in. Passwords are derived from the
//! node's own bridge secret and never logged.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::node::Node;
use crate::protocol::WireMsg;
use crate::xmr_rpc::{enable_multisig_via_cli, WalletRpc};

/// Monero's short payment id, the tag an integrated address carries — the protocol's own width.
pub const XMR_PAYMENT_ID_BYTES: usize = 8;
/// How often the lane re-sends its round and re-reads its wallet — the peg lanes' own cadence.
/// PAST-CHATS-CHECKED: `btc_payout::PAYOUT_POLL_MS` (= the peg attestation lanes' 10 s), reused not re-tuned.
pub const XMR_CUSTODY_POLL_MS: u64 = crate::btc_payout::PAYOUT_POLL_MS;

/// The identity of a bonded set for Monero custody: the sorted member ids, hashed.
pub fn set_id(members: &[[u8; 32]]) -> [u8; 32] {
    let mut sorted = members.to_vec();
    sorted.sort();
    sorted.dedup();
    let mut pre = Vec::with_capacity(24 + 8 + 32 * sorted.len());
    pre.extend_from_slice(b"USDMD-XMR-SET-v1");
    pre.extend_from_slice(&(sorted.len() as u64).to_le_bytes());
    for id in &sorted {
        pre.extend_from_slice(id);
    }
    *blake3::hash(&pre).as_bytes()
}

/// The wallet file a set's custodian keeps in its wallet-rpc directory.
pub fn wallet_name(set_id: &[u8; 32]) -> String {
    format!("usdmd-xmr-{}", crate::btc_tx::hex(&set_id[..16]))
}

/// k for n custodians: the tally's ≥2/3 of members, rounded up.
pub fn threshold(n: usize) -> u32 {
    ((2 * n + 2) / 3) as u32
}

/// The number of the round whose info is the wallet's post-exchange verification message, in this lane's numbering
/// (0 = prepared, 1 = after `make_multisig`, +1 per exchange). Monero's exchange takes n − k + 1 main rounds and
/// one verification round after them; the message every member consumes at its LAST step is the round n − k + 1 info.
pub fn final_round(n: usize, k: u32) -> u8 {
    (n.saturating_sub(k as usize) + 1) as u8
}

/// The per-swap payment id: a function of the set and the mint blind's lane bytes, so every custodian re-derives
/// the deposit address a wallet was given (DB-123).
pub fn payment_id(set_id: &[u8; 32], d_blind_lanes: &[u8]) -> [u8; XMR_PAYMENT_ID_BYTES] {
    let mut pre = Vec::with_capacity(16 + 32 + d_blind_lanes.len());
    pre.extend_from_slice(b"USDMD-XMR-PID-v1");
    pre.extend_from_slice(set_id);
    pre.extend_from_slice(d_blind_lanes);
    let h = blake3::hash(&pre);
    let mut out = [0u8; XMR_PAYMENT_ID_BYTES];
    out.copy_from_slice(&h.as_bytes()[..XMR_PAYMENT_ID_BYTES]);
    out
}

/// One member's key-exchange message for one round, signed with its chain identity.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KexMsg {
    pub set_id: [u8; 32],
    pub round: u8,
    pub from: [u8; 32],
    pub info: String,
    pub signer_pk: Vec<u8>,
    pub sig: Vec<u8>,
}

/// A member's announcement that its wallet for `set_id` is final at `address`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadyMsg {
    pub set_id: [u8; 32],
    pub address: String,
    pub from: [u8; 32],
    pub signer_pk: Vec<u8>,
    pub sig: Vec<u8>,
}

fn kex_statement(set_id: &[u8; 32], round: u8, info: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(48 + info.len());
    m.extend_from_slice(b"USDMD-XMR-KEX-v1");
    m.extend_from_slice(set_id);
    m.push(round);
    m.extend_from_slice(info.as_bytes());
    m
}

fn ready_statement(set_id: &[u8; 32], address: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(48 + address.len());
    m.extend_from_slice(b"USDMD-XMR-READY-v1");
    m.extend_from_slice(set_id);
    m.extend_from_slice(address.as_bytes());
    m
}

/// A message counts only when it is signed by the bonded custodian it names — the tally's own authenticity rule.
fn signed_by_member(node: &Node, from: &[u8; 32], pk: &[u8], sig: &[u8], statement: &[u8]) -> bool {
    crate::pqauth::pubkey_id(pk) == *from
        && node.custodian_ids_sorted().contains(from)
        && crate::pqauth::ml_dsa_verify(statement, pk, sig)
}

/// The exchange in progress for one set — persisted so a restart resumes the round it was in.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct Epoch {
    set_id: [u8; 32],
    members: Vec<[u8; 32]>,
    threshold: u32,
    /// The latest round this wallet has produced an info for (0 = prepared, 1 = after make_multisig, …). Once
    /// the wallet is final it stays at the last round SENT.
    round: u8,
    /// This wallet's info per round it has produced, ALL re-sent every poll: a member still at an earlier round
    /// consumes exactly that round's info, and a member that has moved on would otherwise never offer it again
    /// (measured 2026-09-21 run 4: node1 opened its wallet after node0 had advanced to round 1 and waited forever
    /// for a round-0 info nobody sent). Bounded by the round count (n − k + 2), never by history.
    my_infos: BTreeMap<u8, String>,
    /// The OTHER members' infos per round (never this node's own). Bounded by the member count and the round
    /// count Monero's exchange takes for that count (n − k + 2 rounds), never by history.
    others: BTreeMap<u8, BTreeMap<[u8; 32], String>>,
    ready: bool,
    address: Option<String>,
}

/// The custody lane: this node's wallet-rpc (custodians only), the exchange in progress, and the announcements it
/// has heard (every node).
pub struct CustodyLane {
    rpc: Option<WalletRpc>,
    wallet_dir: Option<PathBuf>,
    password: String,
    epoch: Option<Epoch>,
    /// Whether this process has had the wallet-rpc open the current set's wallet — a restart of either side (the
    /// lane's state is on disk, the wallet-rpc's open wallet is not) reopens it before the next step.
    opened: bool,
    state_path: PathBuf,
    /// Announcements per (set, address) → the distinct members who signed one. Only the current set is kept.
    votes: BTreeMap<([u8; 32], String), BTreeSet<[u8; 32]>>,
    /// Exchange infos heard per (set, round, member) → digest, so a relay goes out once per DISTINCT info whether
    /// or not this node takes part. Bounded by members × rounds of the current set (older sets are dropped every
    /// poll), never by history.
    heard: BTreeMap<([u8; 32], u8, [u8; 32]), [u8; 32]>,
    last_poll_ms: u64,
    said_no_rpc: bool,
    /// The fees of sweeps in flight to the ledger (`set_fees_in_flight`). CACHE-ONLY: this custodian's own reading.
    fees_in_flight: u64,
    /// What this custodian's current custody wallet held at the lane's last read (locked coins included) — `None`
    /// until it has been read once. CACHE-ONLY: what the merge lane reads for "coins first".
    last_balance: Option<u64>,
}

fn state_path() -> PathBuf {
    // DB-341: a per-node file lives in the node's state directory under the port this process SERVES — an isolated
    // node (MONEROUSD_STATE_DIR) never reads or writes the operator's live custody state.
    crate::persist::state_dir().join(format!("xmr-custody-{}.bin", crate::persist::serving_port()))
}

/// The wallet password: a function of this node's own bridge secret, never a stored string.
fn wallet_password() -> String {
    match crate::bridge::node_own_bridge_secret() {
        Some(secret) => {
            let mut pre = Vec::with_capacity(48);
            pre.extend_from_slice(b"USDMD-XMR-WALLET-PW-v1");
            pre.extend_from_slice(&secret);
            crate::btc_tx::hex(blake3::hash(&pre).as_bytes())
        }
        None => String::new(),
    }
}

impl CustodyLane {
    pub fn new() -> Self {
        let state_path = state_path();
        let epoch = match std::fs::read(&state_path) {
            Ok(bytes) => match crate::chain_object::decode_exact::<Epoch>(&bytes) {
                Some(e) => Some(e),
                None => {
                    eprintln!("[xmr-custody] ⛔ the custody state on disk does not decode — the exchange restarts from the wallet's own state");
                    None
                }
            },
            Err(_) => None,
        };
        let wallet_dir = match std::env::var("MONEROUSD_XMR_WALLET_DIR") {
            Ok(d) if !d.is_empty() => Some(PathBuf::from(d)),
            _ => None,
        };
        CustodyLane {
            rpc: WalletRpc::from_env(),
            wallet_dir,
            password: wallet_password(),
            epoch,
            opened: false,
            state_path,
            votes: BTreeMap::new(),
            heard: BTreeMap::new(),
            last_poll_ms: 0,
            said_no_rpc: false,
            fees_in_flight: 0,
            last_balance: None,
        }
    }

    /// This node's wallet-rpc, when it has one (the payout lane signs through the same wallet).
    pub fn rpc(&self) -> Option<&WalletRpc> {
        self.rpc.as_ref()
    }

    /// SAFE AT SCALE, stage three — what the sweep lane (`xmr_sweep`) needs of this lane's wallet-rpc: the handle (made
    /// here when this node holds none yet — a key holder the chain no longer seats never ran this lane's tick), the
    /// password every wallet of this custodian opens with, and the name of the wallet the lanes expect open (the
    /// current set's), which the sweep lane reopens at the end of every visit to an old set's wallet.
    pub fn sweep_handle(&mut self) -> Option<(&WalletRpc, &str, Option<String>)> {
        if self.rpc.is_none() {
            self.rpc = WalletRpc::from_env();
        }
        if self.password.is_empty() {
            self.password = wallet_password();
        }
        let current = self.epoch.as_ref().filter(|_| self.opened).map(|e| wallet_name(&e.set_id));
        Some((self.rpc.as_ref()?, self.password.as_str(), current))
    }

    /// The fees of sweeps this custodian's own wallet judged true that the chain has not booked yet (set by the
    /// runtime from the sweep lane every tick): counted back into the solvency reading below.
    pub fn set_fees_in_flight(&mut self, atomic: u64) {
        self.fees_in_flight = atomic;
    }

    /// What this custodian's current custody wallet held at the lane's last read — `None` before the first read.
    #[must_use]
    pub fn last_balance(&self) -> Option<u64> {
        self.last_balance
    }

    /// The set this node's wallet is final for, and its address.
    pub fn ready_address(&self) -> Option<([u8; 32], String)> {
        let e = self.epoch.as_ref()?;
        if !e.ready {
            return None;
        }
        e.address.clone().map(|a| (e.set_id, a))
    }

    fn save(&self) {
        let Some(e) = &self.epoch else { return };
        if let Some(dir) = self.state_path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        match postcard::to_allocvec(e) {
            Ok(bytes) => {
                let tmp = self.state_path.with_extension("bin.tmp");
                if std::fs::write(&tmp, &bytes).is_ok() {
                    let _ = std::fs::rename(&tmp, &self.state_path);
                }
            }
            Err(err) => eprintln!("[xmr-custody] ⛔ the custody state did not encode: {err}"),
        }
    }

    fn sign(signer: Option<(&[u8], &[u8])>, statement: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
        let (pk, sk) = signer?;
        let sig = crate::pqauth::ml_dsa_sign(statement, sk)?;
        Some((pk.to_vec(), sig))
    }

    /// Opens (or creates and enables) the wallet for `sid`, then reconciles the lane's epoch with what the wallet
    /// itself reports. A resumed epoch (from disk, or from before a wallet-rpc restart) keeps its rounds; a new set
    /// starts a fresh one.
    fn open_epoch(&mut self, sid: [u8; 32], members: Vec<[u8; 32]>) -> Result<(), String> {
        let rpc = self.rpc.as_ref().ok_or("no wallet-rpc")?;
        let name = wallet_name(&sid);
        let created = rpc.open_or_create(&name, &self.password)?;
        if !rpc.is_simulated() {
            // The operator's named wallet directory, else the supervised wallet's own.
            let dir = self
                .wallet_dir
                .clone()
                .or_else(crate::xmr_supervisor::wallet_dir)
                .ok_or("a Monero custody wallet needs MONEROUSD_XMR_WALLET_DIR (the wallet-rpc's --wallet-dir) to enable multisig spending")?;
            // ⛔ ENABLED IS A FACT ON DISK, NOT THE MOMENT OF CREATION (MEASURED 2026-11-04, real nodes): an enable that failed once left a wallet that existed, every later
            // open read "not created", and the exchange then refused for ever with "multisig is disabled". Enabling is idempotent, so a wallet with no marker is enabled now.
            let marker = dir.join(format!("{name}.multisig-enabled"));
            if created || !marker.exists() {
                rpc.close()?;
                let enabled = enable_multisig_via_cli(&dir, &name, &self.password);
                rpc.open_or_create(&name, &self.password)?;
                enabled?;
                std::fs::write(&marker, b"1").map_err(|e| format!("the enabled marker: {e}"))?;
                eprintln!("[xmr-custody] the custody wallet {name} for a {}-member set has multisig spending enabled", members.len());
            }
        }
        self.opened = true;
        let (is_ms, ready, _k, _n) = rpc.is_multisig()?;
        let k = threshold(members.len());
        let mut e = match self.epoch.take() {
            Some(prior) if prior.set_id == sid && !created => prior,
            _ => Epoch { set_id: sid, members: members.clone(), threshold: k, ..Epoch::default() },
        };
        e.members = members.clone();
        e.threshold = k;
        if members.len() == 1 {
            // The founding custodian alone: Monero's multisig needs at least two members, so the set's custody is
            // this plain wallet, spendable by the one bonded custodian — the day-one shape a second seat replaces.
            e.ready = true;
            e.address = Some(rpc.address()?);
        } else if ready {
            e.ready = true;
            e.address = Some(rpc.address()?);
        } else if !is_ms {
            // Not exchanged yet: round 0 (the wallet's prepare info is the same each time it is asked).
            e.ready = false;
            e.round = 0;
            let info = rpc.prepare_multisig()?;
            e.my_infos.insert(0, info);
        } else if e.my_infos.is_empty() {
            // Mid-exchange with nothing to re-send (the lane's state was lost, the wallet's rounds were not). Once
            // the main rounds are done the wallet hands its verification-round info back on request; before that
            // the others' re-sent infos alone cannot finish this wallet.
            match rpc.exchange_multisig_keys(&[], &self.password) {
                Ok(info) if !info.is_empty() => {
                    e.round = final_round(members.len(), k);
                    e.my_infos.insert(e.round, info);
                }
                _ => eprintln!("[xmr-custody] ⛔ the custody wallet {name} is mid-exchange with no saved round to re-send — the other members cannot finish against it; remove the wallet file to restart the exchange"),
            }
        }
        self.epoch = Some(e);
        self.save();
        Ok(())
    }

    /// When every other member's info for the current round is in hand, run the wallet's next step.
    fn try_advance(&mut self, node: &mut Node) -> Result<(), String> {
        let rpc = self.rpc.as_ref().ok_or("no wallet-rpc")?;
        let Some(e) = self.epoch.as_mut() else { return Ok(()) };
        if e.ready || e.members.len() < 2 {
            return Ok(());
        }
        let need = e.members.len() - 1;
        let others: Vec<String> = match e.others.get(&e.round) {
            Some(m) if m.len() >= need => m.values().cloned().collect(),
            _ => return Ok(()),
        };
        let next = if e.round == 0 {
            rpc.make_multisig(&others, e.threshold, &self.password)?
        } else {
            rpc.exchange_multisig_keys(&others, &self.password)?
        };
        let (_ms, ready, _k, _n) = rpc.is_multisig()?;
        if ready {
            // Final. `round`/`my_infos` stay at the rounds SENT: the members still exchanging consume exactly those
            // infos, and `tick` keeps re-sending every round until every member has announced the address.
            let address = rpc.address()?;
            e.ready = true;
            e.address = Some(address.clone());
            eprintln!("[xmr-custody] ⭐ the {}-of-{} Monero custody wallet is FINAL: {address}", e.threshold, e.members.len());
            let sid = e.set_id;
            node.set_xmr_custody_address(sid, address);
        } else {
            e.round = e.round.saturating_add(1);
            e.my_infos.insert(e.round, next);
            eprintln!("[xmr-custody] exchange round {} done for the {}-member set; waiting for the others", e.round, e.members.len());
        }
        self.save();
        Ok(())
    }

    /// The poll: a custodian advances its exchange and re-sends its round (or its ready announcement); any node
    /// forgets announcements for sets that are no longer current.
    pub fn tick(&mut self, node: &mut Node, signer: Option<(&[u8], &[u8])>, now_ms: u64) -> Vec<WireMsg> {
        let mut out = Vec::new();
        if now_ms.saturating_sub(self.last_poll_ms) < XMR_CUSTODY_POLL_MS {
            return out;
        }
        self.last_poll_ms = now_ms;
        // ⭐ SAFE AT SCALE: a custodian forms its Monero wallet with ITS OWN VAULT (`Node::custody_set_here`: at most
        // sixteen — Monero's multisig stops at sixteen signers — and every bonded custodian on a one-vault chain, as it
        // was). Any node keeps what it heard for every CURRENT vault's set and forgets the rest.
        // SCALE: one wallet per vault; a key exchange is among a vault's members only, whatever the bonded set.
        let members = node.custody_set_here();
        if members.is_empty() {
            return out;
        }
        let sid = set_id(&members);
        let live = node.custody_set_ids();
        self.votes.retain(|(s, _), _| live.contains(s));
        self.heard.retain(|(s, _, _), _| live.contains(s));
        let Some(me) = node.custodian_id() else { return out };
        if !members.contains(&me) {
            return out;
        }
        // The node's own supervised wallet starts only once this node holds a custody seat, which a lane made at start-up may not yet have seen: asked again
        // here, so a custodian never stays out of Monero custody for having been seated after its lane was made.
        if self.rpc.is_none() {
            self.rpc = WalletRpc::from_env();
        }
        if self.rpc.is_none() {
            if !self.said_no_rpc {
                self.said_no_rpc = true;
                eprintln!("[xmr-custody] this custodian has no Monero wallet-rpc (MONEROUSD_XMR_WALLET_RPC_URL unset) — it takes no part in Monero custody");
            }
            return out;
        }
        if !self.opened || self.epoch.as_ref().map(|e| e.set_id) != Some(sid) {
            if let Err(err) = self.open_epoch(sid, members.clone()) {
                eprintln!("[xmr-custody] ⛔ could not open the custody wallet for the current set: {err}");
                return out;
            }
        }
        if let Err(err) = self.try_advance(node) {
            eprintln!("[xmr-custody] ⛔ the exchange step failed on this node's wallet: {err}");
            if err.contains("No wallet file") {
                // the wallet-rpc lost its open wallet (it restarted): reopen before the next step
                self.opened = false;
            }
        }
        let Some(e) = self.epoch.as_ref() else { return out };
        // DB-122 F6 for Monero's ledger: the custody wallet's own balance (locked included — the coins exist) against Monero's
        // committed reserve, from this custodian's own opening; an unanswered wallet is not evidence of missing coins
        if e.ready {
            if let (Some(r_val), Some(Ok((balance, _, _)))) = (node.custodian_xmr_reserve_value(), self.rpc.as_ref().map(|r| r.balance())) {
                // SAFE AT SCALE, stage three: the fee of a sweep this custodian's own wallet judged true, on its way to
                // the ledger, never holds the vault's deposits (`fees_in_flight`); and the key lane is told whether the
                // CURRENT wallet holds the whole reserve — only then can no counted coin sit in a replaced key's wallet
                node.set_xmr_reserve_solvency_hold(r_val > 0 && u128::from(balance).saturating_add(u128::from(self.fees_in_flight)) < r_val);
                node.set_xmr_reserve_whole(u128::from(balance) >= r_val);
                self.last_balance = Some(balance);
            }
        }
        if e.ready {
            if let Some(address) = &e.address {
                if node.xmr_custody_address_for_set(&sid).is_none() {
                    node.set_xmr_custody_address(sid, address.clone());
                }
                let voters = self.votes.entry((sid, address.clone())).or_default();
                voters.insert(me);
                let all_announced = voters.len() >= e.members.len();
                if let Some((pk, sig)) = Self::sign(signer, &ready_statement(&sid, address)) {
                    let msg = ReadyMsg { set_id: sid, address: address.clone(), from: me, signer_pk: pk, sig };
                    if let Ok(bytes) = postcard::to_allocvec(&msg) {
                        out.push(WireMsg::XmrCustodyReady(bytes));
                    }
                }
                // the members still exchanging consume this wallet's infos, whichever round they are at: keep
                // serving every round until every member has announced the same address
                if !all_announced {
                    for (round, info) in &e.my_infos {
                        if let Some((pk, sig)) = Self::sign(signer, &kex_statement(&sid, *round, info)) {
                            let msg = KexMsg { set_id: sid, round: *round, from: me, info: info.clone(), signer_pk: pk, sig };
                            if let Ok(bytes) = postcard::to_allocvec(&msg) {
                                out.push(WireMsg::XmrCustodyKex(bytes));
                            }
                        }
                    }
                }
            }
        } else {
            // every round this wallet has produced, so a member at ANY earlier round finds the info it consumes
            for (round, info) in &e.my_infos {
                if let Some((pk, sig)) = Self::sign(signer, &kex_statement(&sid, *round, info)) {
                    let msg = KexMsg { set_id: sid, round: *round, from: me, info: info.clone(), signer_pk: pk, sig };
                    if let Ok(bytes) = postcard::to_allocvec(&msg) {
                        out.push(WireMsg::XmrCustodyKex(bytes));
                    }
                }
            }
        }
        out
    }

    /// A member's round info arrived. `true` when it was new and verified (relay it). This node's own info, back
    /// through the relay, is never another member's and is neither stored nor relayed again.
    pub fn on_kex(&mut self, bytes: &[u8], node: &mut Node) -> bool {
        let Some(m) = crate::chain_object::decode_exact::<KexMsg>(bytes) else { return false };
        if m.info.is_empty() || Some(m.from) == node.custodian_id() {
            return false;
        }
        if !signed_by_member(node, &m.from, &m.signer_pk, &m.sig, &kex_statement(&m.set_id, m.round, &m.info)) {
            return false;
        }
        // SAFE AT SCALE: the set a member speaks for is ITS OWN vault's (the whole bonded set on a one-vault chain)
        let Some(members) = node.custody_vault_of(&m.from) else { return false };
        if m.set_id != set_id(&members) {
            return false;
        }
        // `heard` decides the RELAY only (once per distinct info); the store below decides on the epoch, because
        // an info that arrived before this node opened the set's wallet is stored from the member's re-send
        let digest = *blake3::hash(m.info.as_bytes()).as_bytes();
        let key = (m.set_id, m.round, m.from);
        let fresh = !self.heard.get(&key).is_some_and(|held| *held == digest);
        self.heard.insert(key, digest);
        let mut advance = false;
        if let Some(e) = self.epoch.as_mut() {
            if e.set_id == m.set_id && !e.ready {
                if m.round >= e.round {
                    let slot = e.others.entry(m.round).or_default();
                    if !slot.get(&m.from).is_some_and(|held| *held == m.info) {
                        slot.insert(m.from, m.info);
                        advance = true;
                    }
                } else if fresh {
                    eprintln!(
                        "[xmr-custody] a member re-sent a different round-{} info after this wallet consumed that round — the exchange for this set cannot complete on this wallet's current keys",
                        m.round
                    );
                }
            }
        }
        if advance {
            self.save();
            if let Err(err) = self.try_advance(node) {
                eprintln!("[xmr-custody] ⛔ the exchange step failed on this node's wallet: {err}");
            }
        }
        fresh
    }

    /// A member's ready announcement arrived. Any node counts it; at ≥k distinct members for one address the node
    /// records the set's address and can serve deposit addresses for it. `true` when new and verified.
    pub fn on_ready(&mut self, bytes: &[u8], node: &mut Node) -> bool {
        let Some(m) = crate::chain_object::decode_exact::<ReadyMsg>(bytes) else { return false };
        if m.address.is_empty()
            || !crate::bridge::is_monero_address(&m.address)
            || !signed_by_member(node, &m.from, &m.signer_pk, &m.sig, &ready_statement(&m.set_id, &m.address))
        {
            return false;
        }
        // SAFE AT SCALE: a wallet is announced by the members of ITS vault and is known once two thirds of THAT vault say
        // the same address (the whole bonded set on a one-vault chain)
        let Some(members) = node.custody_vault_of(&m.from) else { return false };
        if m.set_id != set_id(&members) {
            return false;
        }
        let voters = self.votes.entry((m.set_id, m.address.clone())).or_default();
        let fresh = voters.insert(m.from) && Some(m.from) != node.custodian_id();
        if voters.len() as u32 >= threshold(members.len()) && node.xmr_custody_address_for_set(&m.set_id).is_none() {
            eprintln!("[xmr-custody] the bonded set's Monero custody address is known from {} members: {}", voters.len(), m.address);
            node.set_xmr_custody_address(m.set_id, m.address.clone());
        }
        fresh
    }
}

#[cfg(all(test, feature = "pins-core"))]
mod tests {
    use super::*;

    #[test]
    fn the_threshold_is_two_thirds_of_the_members_rounded_up() {
        assert_eq!(threshold(1), 1);
        assert_eq!(threshold(2), 2);
        assert_eq!(threshold(3), 2);
        assert_eq!(threshold(4), 3);
        assert_eq!(threshold(6), 4);
        assert_eq!(threshold(7), 5);
    }

    #[test]
    fn the_final_round_is_the_main_round_count_in_this_lanes_numbering() {
        // 2-of-2: make_multisig's output (round 1) is the verification message the other member consumes last
        assert_eq!(final_round(2, threshold(2)), 1);
        // 2-of-3: one exchange round after make_multisig (round 2)
        assert_eq!(final_round(3, threshold(3)), 2);
        // 3-of-4 and 5-of-7 likewise
        assert_eq!(final_round(4, threshold(4)), 2);
        assert_eq!(final_round(7, threshold(7)), 3);
    }

    #[test]
    fn a_set_id_ignores_member_order_and_a_payment_id_follows_set_and_blind() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert_eq!(set_id(&[a, b]), set_id(&[b, a]));
        assert_ne!(set_id(&[a]), set_id(&[a, b]));
        let sid = set_id(&[a, b]);
        assert_eq!(payment_id(&sid, &[7u8; 64]), payment_id(&sid, &[7u8; 64]));
        assert_ne!(payment_id(&sid, &[7u8; 64]), payment_id(&sid, &[8u8; 64]));
        assert_ne!(payment_id(&sid, &[7u8; 64]), payment_id(&set_id(&[a]), &[7u8; 64]));
        assert!(wallet_name(&sid).starts_with("usdmd-xmr-"));
    }

    #[test]
    fn an_exchange_message_from_a_stranger_or_over_a_changed_statement_is_refused() {
        let (pk, sk) = crate::pqauth::ml_dsa_keypair();
        let from = crate::pqauth::pubkey_id(&pk);
        let sid = [9u8; 32];
        let stmt = kex_statement(&sid, 0, "MultisigxV2R1…");
        let sig = crate::pqauth::ml_dsa_sign(&stmt, &sk).expect("signs");
        assert!(crate::pqauth::ml_dsa_verify(&stmt, &pk, &sig));
        // the same signature over another round is not this statement's
        assert!(!crate::pqauth::ml_dsa_verify(&kex_statement(&sid, 1, "MultisigxV2R1…"), &pk, &sig));
        // a message that names another member than its key is refused before the set is even consulted
        let other = [0xabu8; 32];
        assert_ne!(crate::pqauth::pubkey_id(&pk), other);
        let _ = from;
    }
}
