// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)

//! THE ETHEREUM VAULT ADAPTER AGAINST A REAL ETHEREUM VIRTUAL MACHINE (the real-chain check `eth-vault`,
//! `scratchpad/net/eth_vault.py`; docs/BRIDGE-MORE-COINS-SPEC-20261110.md §9 step 3).
//!
//! What it proves: that the node's OWN code (`eth_vault`, `eth_tx`, `eth_rpc`, nothing else) deploys the vault, derives
//! a deposit's one-time address, reads a deposit, builds and signs a payout batch with a bonded custody set's keys,
//! hands the vault to the next set, and that a real chain REFUSES every attack the vault exists to refuse. Every
//! assertion reads what the CHAIN holds afterwards (balances, the vault's own words), never what a call returned.
//!
//! It runs against a LOCAL Ethereum chain the check raises (Foundry's `anvil`) and is given that chain's own funded
//! test key on its command line. It holds no key of its own and is not part of a node: nothing here mints or burns
//! on MoneroUSD (the deposit door and the payout lane do that, from these same functions).
//!
//! usage: eth_vault_check <rpc url on this machine> <funded test key, 64 hex digits>

use usdmd_node::eth_rpc::EthRpc;
use usdmd_node::eth_tx::{created_address, Tx1559};
use usdmd_node::eth_vault as ev;

const ETHER: u128 = 1_000_000_000_000_000_000;

struct Run {
    rpc: EthRpc,
    chain_id: u64,
    passed: u32,
}

fn fail(what: &str) -> ! {
    eprintln!("ETH-VAULT-CHECK FAIL: {what}");
    std::process::exit(1);
}

impl Run {
    fn ok(&mut self, cond: bool, what: &str) {
        if !cond {
            fail(what);
        }
        self.passed += 1;
        println!("ok {:>2}: {what}", self.passed);
    }

    /// A local test chain makes blocks final only as more are mined: mine enough that what was just mined is final.
    /// (On Ethereum itself time does this; the adapter never asks a chain to hurry.)
    fn make_final(&self) {
        let _ = self.rpc.call("anvil_mine", serde_json::json!(["0x80"]));
    }

    /// Send one transaction from `key` and return its hash. `gas` of `None` asks the chain for its own estimate (a call
    /// that would revert then has none); `Some` forces a limit, for an attack that must be MINED to be seen refused.
    fn send(&self, key: &[u8; 32], to: Option<&ev::Address>, value: u128, data: &[u8], gas: Option<u64>) -> Result<[u8; 32], String> {
        let from = ev::address_of_secret(key).ok_or("the sender's key is not a key")?;
        let gas_limit = match gas {
            Some(g) => g,
            None => self.rpc.estimate_gas(&from, to, data, value)?.saturating_mul(13) / 10,
        };
        let (base, tip) = self.rpc.fees()?;
        let tx = Tx1559 {
            chain_id: self.chain_id,
            nonce: self.rpc.nonce_pending(&from)?,
            max_priority_fee_per_gas: tip,
            max_fee_per_gas: base.saturating_mul(2).saturating_add(tip),
            gas_limit,
            to: to.copied(),
            value,
            data: data.to_vec(),
        };
        let raw = tx.sign(key).ok_or("the transaction did not sign")?;
        self.rpc.send_raw(&raw)
    }

    /// The transaction's outcome once Ethereum has made it final: did it succeed?
    fn outcome(&self, hash: &[u8; 32]) -> bool {
        let t = std::time::Instant::now();
        loop {
            self.make_final();
            match self.rpc.settled(hash) {
                Ok(Some(success)) => return success,
                Ok(None) if t.elapsed().as_secs() < 60 => std::thread::sleep(std::time::Duration::from_millis(200)),
                Ok(None) => fail("a sent transaction was not final after 60 s"),
                Err(e) => fail(&format!("the source could not say whether a transaction settled: {e}")),
            }
        }
    }

    fn balance(&self, who: &ev::Address) -> u128 {
        self.make_final();
        self.rpc.balance_finalized(who).unwrap_or_else(|e| fail(&format!("no balance: {e}")))
    }
}

/// The custodians of `set` sign `digest`, heaviest first, until `enough` says stop; in the contract's order.
fn sign_by(set: &ev::SignerSet, keys: &[[u8; 32]], digest: &[u8; 32], want_weight: u128) -> Vec<ev::Sig> {
    let mut order: Vec<usize> = (0..set.signers.len()).collect();
    order.sort_by_key(|i| std::cmp::Reverse(set.weights[*i]));
    let (mut picked, mut weight) = (Vec::new(), 0u128);
    for i in order {
        if weight >= want_weight {
            break;
        }
        picked.push(i);
        weight += set.weights[i];
    }
    picked.sort_unstable();
    picked
        .into_iter()
        .map(|i| {
            let key = keys.iter().find(|k| ev::address_of_secret(k) == Some(set.signers[i])).unwrap_or_else(|| fail("a signer has no key in this run"));
            let (v, r, s) = ev::sign(key, digest).unwrap_or_else(|| fail("a custodian's key did not sign"));
            ev::Sig { index: i as u32, v, r, s }
        })
        .collect()
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: eth_vault_check <rpc url on this machine> <funded test key, 64 hex digits>");
        std::process::exit(2);
    }
    let rpc = EthRpc::at(&args[1]).unwrap_or_else(|| fail("the source is not this machine or a .onion"));
    let funder: [u8; 32] = (0..32)
        .map(|i| args[2].get(2 * i..2 * i + 2).and_then(|h| u8::from_str_radix(h, 16).ok()))
        .collect::<Option<Vec<u8>>>()
        .and_then(|v| v.try_into().ok())
        .unwrap_or_else(|| fail("the funded key is not 64 hex digits"));
    let chain_id = rpc.chain_id().unwrap_or_else(|e| fail(&format!("the source does not answer: {e}")));
    let mut run = Run { rpc, chain_id, passed: 0 };
    let funder_addr = ev::address_of_secret(&funder).unwrap_or_else(|| fail("the funded key is not a key"));

    // ── a bonded custody set: five custodians, their registered custody points and bond weights ──
    let custody_secrets: Vec<[u8; 32]> = (1u8..=5).map(|i| *blake3::hash(&[b'c', i, 0xE7]).as_bytes()).collect();
    let weights = [400u128, 250, 150, 120, 80];
    let members: Vec<([u8; 32], u128)> = custody_secrets
        .iter()
        .zip(weights)
        .map(|(s, w)| (usdmd_node::btc_tx::xonly_pubkey(s).unwrap_or_else(|| fail("a custody secret has no point")), w))
        .collect();
    let set = ev::signer_set(&members).unwrap_or_else(|| fail("the custody set forms no signer set"));
    let eth_keys: Vec<[u8; 32]> = custody_secrets.iter().map(|s| ev::custodian_signing_key(s).unwrap_or_else(|| fail("no Ethereum key"))).collect();
    let leaf = usdmd_node::btc_tx::custody_leaf(&members).unwrap_or_else(|| fail("no Bitcoin leaf"));
    run.ok(set.threshold == u128::from(leaf.k) && set.total() == Some(leaf.slot_keys.len() as u128), "the Ethereum signer set has the Bitcoin leaf's quorum and slots");

    // ── 1. the vault is deployed and its code and state are the ones the node expects ──
    let data = ev::deploy_data(&set).unwrap_or_else(|| fail("no deployment data"));
    let nonce = run.rpc.nonce_pending(&funder_addr).unwrap_or_else(|e| fail(&e));
    let h = run.send(&funder, None, 0, &data, None).unwrap_or_else(|e| fail(&format!("the deployment was not taken: {e}")));
    run.ok(run.outcome(&h), "the vault's deployment is final and succeeded");
    let vault = created_address(&funder_addr, nonce);
    run.ok(run.rpc.code_hash_finalized(&vault) == Ok(ev::VAULT_RUNTIME_CODE_HASH), "the code at the vault's address is the vault's own (its hash is the node's constant)");
    let st = run.rpc.vault_state(&vault).unwrap_or_else(|e| fail(&format!("the vault does not answer: {e}")));
    run.ok(st.signer_set_hash == set.hash(0) && st.epoch == 0 && st.balance_wei == 0 && st.owed_total_wei == 0, "the vault stores the custody set's hash at epoch 0 and holds nothing");

    // ── 2. a deposit: a plain transfer to the one-time address any node derives ──
    let tag = ev::keccak(b"eth_vault_check deposit one");
    let dep = ev::deposit_address(&vault, &tag);
    let deposit_wei = 2 * ETHER + 123_456_789;
    let h = run.send(&funder, Some(&dep), deposit_wei, &[], None).unwrap_or_else(|e| fail(&format!("the deposit was not taken: {e}")));
    run.ok(run.outcome(&h), "a plain transfer to the deposit's one-time address is final");
    run.ok(run.balance(&dep) == deposit_wei, "the custodian's source reads the exact deposit at the derived address, at the finalized block");
    run.ok(ev::atoms_of_wei(deposit_wei) == Some(2_000_000_000), "the ledger credits whole gwei (2,000,000,000 atoms); the 123,456,789 wei under one gwei stay in the vault");

    // the custodian that will carry the calls needs ether for gas (repaid by the vault inside the signed cap)
    let carrier = eth_keys[0];
    let carrier_addr = ev::address_of_secret(&carrier).unwrap_or_else(|| fail("no carrier address"));
    let h = run.send(&funder, Some(&carrier_addr), ETHER, &[], None).unwrap_or_else(|e| fail(&e));
    run.ok(run.outcome(&h), "the carrying custodian holds gas money");

    // ── 3. a payout batch, with the waiting deposit swept in passing ──
    let recipient = |n: u8| -> ev::Address {
        let h = ev::keccak(&[b'r', n]);
        let mut a = [0u8; 20];
        a.copy_from_slice(&h[12..]);
        a
    };
    let (r1, r2) = (recipient(1), recipient(2));
    let pays = vec![
        ev::Payout { id: ev::keccak(b"burn one"), to: r1, wei: ev::wei_of_atoms(700_000_000) },
        ev::Payout { id: ev::keccak(b"burn two"), to: r2, wei: ev::wei_of_atoms(300_000_000) },
    ];
    let tags = vec![tag];
    let cap = ETHER / 100;
    let digest = ev::pay_digest(chain_id, &vault, 0, &pays, &tags, cap);

    // ATTACK: a minority of bond signs. The node's own check says no, and the chain says no.
    let minority = sign_by(&set, &eth_keys, &digest, set.threshold - 1);
    let minority: Vec<ev::Sig> = minority.into_iter().take(1).collect();
    run.ok(!ev::passes(&digest, &set, &minority), "ATTACK minority: the node's own check refuses one signer's weight");
    let call = ev::pay_calldata(&pays, &tags, cap, &set, &minority).unwrap_or_else(|| fail("no calldata"));
    run.ok(run.rpc.estimate_gas(&carrier_addr, Some(&vault), &call, 0).is_err(), "ATTACK minority: the chain will not even estimate the call (it reverts)");
    let h = run.send(&carrier, Some(&vault), 0, &call, Some(1_500_000)).unwrap_or_else(|e| fail(&e));
    run.ok(!run.outcome(&h), "ATTACK minority: mined anyway, the call is final and FAILED");
    run.ok(run.balance(&r1) == 0 && run.balance(&r2) == 0 && run.balance(&dep) == deposit_wei, "ATTACK minority: nobody was paid and the deposit was not moved");

    // ATTACK: a quorum signs, and the carrier changes one amount after the fact.
    let sigs = sign_by(&set, &eth_keys, &digest, set.threshold);
    run.ok(ev::passes(&digest, &set, &sigs), "a quorum of bond signs the batch (the node's own check passes it)");
    let mut richer = pays.clone();
    richer[0].wei += ETHER;
    let call = ev::pay_calldata(&richer, &tags, cap, &set, &sigs).unwrap_or_else(|| fail("no calldata"));
    let h = run.send(&carrier, Some(&vault), 0, &call, Some(1_500_000)).unwrap_or_else(|e| fail(&e));
    run.ok(!run.outcome(&h) && run.balance(&r1) == 0, "ATTACK altered amount: the signatures do not carry over; the call FAILED and nobody was paid");

    // the honest batch
    let carrier_before = run.balance(&carrier_addr);
    let call = ev::pay_calldata(&pays, &tags, cap, &set, &sigs).unwrap_or_else(|| fail("no calldata"));
    let h = run.send(&carrier, Some(&vault), 0, &call, None).unwrap_or_else(|e| fail(&format!("the honest batch was not taken: {e}")));
    run.ok(run.outcome(&h), "the honest batch is final and succeeded");
    run.ok(run.balance(&r1) == pays[0].wei && run.balance(&r2) == pays[1].wei, "each recipient holds exactly its payout");
    run.ok(run.rpc.paid_finalized(&vault, &pays[0].id) == Ok(true) && run.rpc.paid_finalized(&vault, &pays[1].id) == Ok(true), "the vault records both ids as paid");
    run.ok(run.balance(&dep) == 0, "the waiting deposit was swept into the vault in passing");
    let vault_after = run.balance(&vault);
    let refund = deposit_wei - pays[0].wei - pays[1].wei - vault_after;
    run.ok(refund > 0 && refund <= cap, "the vault holds the deposit less the payouts and a gas refund inside the signed cap");
    let carrier_after = run.balance(&carrier_addr);
    run.ok(carrier_after + cap / 10 >= carrier_before, "the carrying custodian was repaid its gas (it is not out of pocket by more than a tenth of the cap)");

    // ATTACK: the same batch again.
    run.ok(run.rpc.estimate_gas(&carrier_addr, Some(&vault), &call, 0).is_err(), "ATTACK replay: the chain will not estimate a second run of the batch");
    let h = run.send(&carrier, Some(&vault), 0, &call, Some(1_500_000)).unwrap_or_else(|e| fail(&e));
    run.ok(!run.outcome(&h) && run.balance(&r1) == pays[0].wei && run.balance(&vault) == vault_after, "ATTACK replay: mined anyway it FAILED; nobody was paid twice and the vault did not move");

    // ATTACK: a batch signed for another chain.
    let third = vec![ev::Payout { id: ev::keccak(b"burn three"), to: r1, wei: ev::wei_of_atoms(100_000_000) }];
    let other_chain = ev::pay_digest(chain_id + 1, &vault, 0, &third, &[], cap);
    let sigs_other = sign_by(&set, &eth_keys, &other_chain, set.threshold);
    run.ok(ev::signed_weight(&ev::pay_digest(chain_id, &vault, 0, &third, &[], cap), &set, &sigs_other).is_none(), "ATTACK other chain: the node's own check finds no signer in signatures made for another chain");
    let call = ev::pay_calldata(&third, &[], cap, &set, &sigs_other).unwrap_or_else(|| fail("no calldata"));
    let h = run.send(&carrier, Some(&vault), 0, &call, Some(1_500_000)).unwrap_or_else(|e| fail(&e));
    run.ok(!run.outcome(&h) && run.rpc.paid_finalized(&vault, &third[0].id) == Ok(false), "ATTACK other chain: the call FAILED and the id is not paid");

    // ── 4. a recipient that refuses ether does not stop the batch, and its ether is set aside, not lost ──
    // (the swept deposit address now holds the forwarder's eight bytes, which refuse every call)
    let mixed = vec![
        ev::Payout { id: ev::keccak(b"burn four"), to: dep, wei: ev::wei_of_atoms(50_000_000) },
        ev::Payout { id: ev::keccak(b"burn five"), to: r2, wei: ev::wei_of_atoms(60_000_000) },
    ];
    let d = ev::pay_digest(chain_id, &vault, 0, &mixed, &[], cap);
    let call = ev::pay_calldata(&mixed, &[], cap, &set, &sign_by(&set, &eth_keys, &d, set.threshold)).unwrap_or_else(|| fail("no calldata"));
    let h = run.send(&carrier, Some(&vault), 0, &call, None).unwrap_or_else(|e| fail(&format!("the mixed batch was not taken: {e}")));
    run.ok(run.outcome(&h), "a batch with a recipient that refuses ether is final and succeeded");
    run.ok(run.balance(&r2) == pays[1].wei + mixed[1].wei, "the other recipient of that batch was paid");
    let st = run.rpc.vault_state(&vault).unwrap_or_else(|e| fail(&e));
    run.ok(st.owed_total_wei == mixed[0].wei && run.balance(&dep) == 0, "the refused payout is set aside in the vault for its recipient (not paid, not lost)");

    // ── 5. the vault is handed to the next custody set ──
    let newcomer = *blake3::hash(&[b'c', 9, 0xE7]).as_bytes();
    let mut next_secrets: Vec<[u8; 32]> = custody_secrets[1..].to_vec();
    next_secrets.push(newcomer);
    let next_members: Vec<([u8; 32], u128)> = next_secrets
        .iter()
        .zip([250u128, 150, 120, 80, 300])
        .map(|(s, w)| (usdmd_node::btc_tx::xonly_pubkey(s).unwrap_or_else(|| fail("no point")), w))
        .collect();
    let next = ev::signer_set(&next_members).unwrap_or_else(|| fail("the next custody set forms no signer set"));
    let next_keys: Vec<[u8; 32]> = next_secrets.iter().map(|s| ev::custodian_signing_key(s).unwrap_or_else(|| fail("no Ethereum key"))).collect();
    let rd = ev::rotate_digest(chain_id, &vault, 0, &next);
    let call = ev::rotate_calldata(&next, &set, &sign_by(&set, &eth_keys, &rd, set.threshold)).unwrap_or_else(|| fail("no calldata"));
    let h = run.send(&carrier, Some(&vault), 0, &call, None).unwrap_or_else(|e| fail(&format!("the hand-over was not taken: {e}")));
    run.ok(run.outcome(&h), "the hand-over, signed by the current set's quorum, is final and succeeded");
    let st = run.rpc.vault_state(&vault).unwrap_or_else(|e| fail(&e));
    run.ok(st.epoch == 1 && st.signer_set_hash == next.hash(1), "the vault now stores the next set's hash at epoch 1");

    // ATTACK: the old set signs a payout after the hand-over.
    let sixth = vec![ev::Payout { id: ev::keccak(b"burn six"), to: r1, wei: ev::wei_of_atoms(10_000_000) }];
    let old = ev::pay_digest(chain_id, &vault, 1, &sixth, &[], cap);
    let call = ev::pay_calldata(&sixth, &[], cap, &set, &sign_by(&set, &eth_keys, &old, set.threshold)).unwrap_or_else(|| fail("no calldata"));
    let h = run.send(&carrier, Some(&vault), 0, &call, Some(1_500_000)).unwrap_or_else(|e| fail(&e));
    run.ok(!run.outcome(&h) && run.rpc.paid_finalized(&vault, &sixth[0].id) == Ok(false), "ATTACK departed set: a payout signed by the old set after the hand-over FAILED (no key outlives its seat)");
    // the next set pays it
    let d = ev::pay_digest(chain_id, &vault, 1, &sixth, &[], cap);
    let call = ev::pay_calldata(&sixth, &[], cap, &next, &sign_by(&next, &next_keys, &d, next.threshold)).unwrap_or_else(|| fail("no calldata"));
    let r1_before = run.balance(&r1);
    let h = run.send(&carrier, Some(&vault), 0, &call, None).unwrap_or_else(|e| fail(&format!("the next set's batch was not taken: {e}")));
    run.ok(run.outcome(&h) && run.balance(&r1) == r1_before + sixth[0].wei, "the next set's quorum pays, and the recipient holds it");

    println!("ETH-VAULT-CHECK PASS {} of {} (chain id {chain_id})", run.passed, run.passed);
}
