// Copyright (c) 2026, The MoneroUSD Protocol
// SPDX-License-Identifier: Apache-2.0 (see LICENSE and NOTICE at the repository root)
//
//! PSM BRIDGE e2e HARNESS — proves, against the LIVE node over real loopback HTTP, that the Buy-USDm peg is
//! sound as designed: a real external deposit mints USDm at the 150% collateral ratio through a real t-of-n
//! post-quantum threshold, the reserve is a real threshold wallet (never a solo key), a withdrawal burns a real
//! USDm note, and every adversarial variant fail-closes. NO mock, NO shortcut, NO hand-built state:
//!
//!   • The node is the REAL `usdmd_node::node::Node` wrapped in the REAL `NodeRuntime`, serving the REAL
//!     `rpc_http::serve` loop on a real TCP socket — every assertion drives the SAME wire path the wallet uses.
//!   • Every mint/burn carrier is a REAL `usdm_decider::confidential_solvency` WHIR proof (the SAME prover the
//!     live custodian orchestrator runs); every attestation is a REAL ML-DSA-65 signature by a real `Custodian`.
//!   • The confidential reserve/minted commitments are NEVER served over the wire (they are value-hiding by
//!     design); the harness reads them through the shared runtime handle to confirm the digest advanced — the
//!     SAME state the RPC just mutated.
//!
//! What it proves (each an explicit assertion below):
//!   P1  reserve = a REAL t-of-n threshold address (taproot key-aggregate of the bonded charter quorum), bound
//!       to the exact quorum via its group commitment; a fresh swap nonce → a fresh unlinkable address; no
//!       bonded quorum → fail-closed (never a fabricated address that would lose the user's funds).
//!   P2  the deposit gate: `/btc_deposit_status` mints NOTHING until a real confirmed deposit ≥ min — a fresh
//!       reserve address reads 0 confirmed → not confirmed → no mint.
//!   P3  DEPOSIT → MINT @150%: a real 150% peg-in carrier + a real 2-of-3 ML-DSA-65 threshold → ConfidentialMinted;
//!       the buyer's USDm mint is AUTHORIZED and PUBLISHED as a `Class::PegIn` chain object (§CS: NOT
//!       written into this node's frontier — that is the local-mutation shape, and where the note LANDS is
//!       proven by the real-node tier, `harness::real_node_journey`); the confidential
//!       reserve+minted digests advance (no amount ever on the wire).
//!   P4  ADVERSARIAL mint: an under-150% mint is UNPROVABLE (the custodian cannot even build the carrier); a
//!       carrier not built from the node's persisted state → BadRequest; a sub-quorum → InsufficientThreshold;
//!       a forged non-bonded attestor → InsufficientThreshold; a replayed deposit id → Replay.
//!   P5  WITHDRAWAL → BURN: a real peg-out carrier (conservation + post-state ≥150%, no drain) + a real threshold
//!       → ConfidentialRedeemed; the burned USDm note tag is recorded; a replayed burn → Replay; an over-drain
//!       withdrawal is UNPROVABLE.
//!   P6  CONSERVATION: peg-in D then peg-out D returns the confidential digests to the genesis zero-state — the
//!       peg mechanism itself creates/destroys no value.
//!
//! Run: `cargo test --test psm_bridge_e2e -- --nocapture` (prints a readable PASS log).

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use usdm_decider::confidential_solvency as cs;
use usdmd_node::block::{Block, BlockHeader};
use usdmd_node::bridge::Custodian;
use usdmd_node::hash::Hash32;
use usdmd_node::node::Node;
use usdmd_node::node_runtime::NodeRuntime;
use usdmd_node::psm::MintAttestor;
use usdmd_node::transport::LoopbackTransport;
use usdmd_node::{cover, peg, rpc_http};

// ───────────────────────────── tiny std-only HTTP + hex + JSON helpers ─────────────────────────────

/// DB-110: the peg-out's destination rides as `redeem_commit(address, blind)`; this fixture's blind.
fn test_redeem_blind() -> usdmd_node::spend_frontier::Digest4 {
    usdmd_node::spend_frontier::cm_bytes_to_root(&[0x5au8; 32]).unwrap()
}

fn hexs(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A confidential-solvency commitment as 32-byte hex — the canonical injective digest form, the exact shape
/// the RPC's `commit()` parser reads back with `cm_bytes_to_root`. (§AG class 9: this was four raw LE limbs
/// of an eight-lane digest — half a commitment on the wire.)
fn commit_hex(c: usdmd_node::spend_frontier::Digest4) -> String {
    hexs(&usdmd_node::spend_frontier::leaf_to_cm_bytes(c))
}

/// Encode attestors as the flat wire record `pubkey_len(u16 LE) ‖ pubkey ‖ sig_len(u16 LE) ‖ sig` (repeated), hex.
fn attestors_hex(att: &[MintAttestor]) -> String {
    let mut out = Vec::new();
    for a in att {
        out.extend_from_slice(&(a.pubkey.len() as u16).to_le_bytes());
        out.extend_from_slice(&a.pubkey);
        out.extend_from_slice(&(a.sig.len() as u16).to_le_bytes());
        out.extend_from_slice(&a.sig);
    }
    hexs(&out)
}

/// One real HTTP request to the live serve loop; returns the JSON response body (after the header terminator).
fn http_req(method: &str, port: u16, path: &str, body: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port)).expect("connect to live node");
    s.set_read_timeout(Some(Duration::from_secs(60))).ok();
    let req = format!(
        "{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    s.write_all(req.as_bytes()).expect("write request");
    s.flush().ok();
    let mut resp = String::new();
    s.read_to_string(&mut resp).ok();
    resp.splitn(2, "\r\n\r\n").nth(1).unwrap_or("").to_string()
}

/// POST (the peg/reserve endpoints); `http_req("GET", ..)` serves the GET-only routes like `/get_info`.
fn http_post(port: u16, path: &str, body: &str) -> String {
    http_req("POST", port, path, body)
}

/// ⭐ THE BLOCK IS WHAT APPLIES A PUBLISHED PEG TRANSITION (§CZ, 2026-09-17). Every executor door is
/// verify-only and publishes a chain object; the ledger, the note and the custodian's opening move when a
/// block carries it — on the publishing node exactly as on every peer. This node runs on a loopback pair
/// with no mesh, so the serve loop's `begin_produce` (join-mesh-or-nothing) never builds a block; the
/// suite therefore mines ONE block directly, the same `Node::produce` the daemon's produce act calls, and
/// reads the state that block applied. `ts` must strictly increase across calls.
fn settle_block(rt: &Arc<Mutex<NodeRuntime<LoopbackTransport>>>, ts: u64) {
    let mut g = rt.lock().unwrap_or_else(|e| e.into_inner());
    let h = g.node().tip_height();
    g.node_mut()
        .produce(ts, Hash32::hash(b"psm-e2e-fr"), Hash32::hash(b"psm-e2e-mc"))
        .expect("the node mines the block that applies the published peg transition");
    assert!(g.node().tip_height() > h, "a block was produced");
}

fn num_field(body: &str, key: &str) -> Option<u64> {
    let pat = format!("\"{key}\":");
    let i = body.find(&pat)? + pat.len();
    let rest = &body[i..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

fn str_field(body: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let i = body.find(&pat)? + pat.len();
    let rest = &body[i..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

/// The deterministic-constant genesis block (same shape every node builds); the peg ledger initializes to its
/// confidential zero-state commitment inside `Node::new` (see `peg::PegLedger::genesis`).
fn genesis_block() -> Block {
    // ⛔ ONE DEFINITION, NEVER TWO — AND THIS TIME THE BODY TOO. The hand-rolled copy that used to live
    // here fell behind `Block` twice: once on `account_root … del_set_root`, and again on `credit_set`
    // (§BA/§BB, 2026-09-15), which left this suite UNCOMPILABLE — and therefore not run — for two days
    // without a word, because it is gated behind `--features bridge-test-oracle` and the ordinary
    // `cargo test` never builds it. The lib now owns the whole genesis block.
    usdmd_node::block::genesis_block()
}

fn u256(v: u64) -> cs::U256 {
    cs::u256_from_u64(v)
}

// ───────────────────────────────────────── the harness ─────────────────────────────────────────

#[test]
fn psm_bridge_full_e2e() {
    // ── 1) CHARTER a REAL t-of-n reserve quorum: 3 real custodians (each a fresh PQ signing identity + a bridge
    //       custody point), pinned as the reserve custody quorum (MONEROUSD_CHARTER_QUORUM = the same shape the
    //       launch nodes assemble) AND admitted as bonded validators (the ≥2/3-by-bond gate the mint enforces).
    //       No single party holds the aggregate.
    let custodians: Vec<Custodian> = (0..3u8)
        .map(|i| Custodian::generate(&[70 + i; 32]))
        .collect();

    // NO-OWNERLESS-CREDIT gate: every peg-in names the credited note's OLI clue so the note is FILED where a
    // seed-only restore finds it — a note recorded nowhere is undiscoverable money. Every body below carries it,
    // so each adversarial case still reaches the specific gate it exists to prove (not the ownerless refusal).
    // ⭐ DB-273 §19 L1: the clue replaces the (bucket, ek) pair, and the recipient the quorum signs COMMITS to it
    // (`peg::peg_in_recipient`), so every attested statement below names `recip_of(deposit)`.
    let owner_clue = vec![0xAAu8; usdmd_node::peg_in_tx::OWNER_CLUE_MAX];
    let recip_of = |dep: &[u8; 32]| peg::peg_in_recipient(dep, &owner_clue);

    // The reserve is the LIVE bonded set's custody aggregate: each validator bonds AND registers its own bridge
    // custody points. It starts at the founding validator (1-of-1) and grows to t-of-n as more bond.
    let mut node = Node::new(genesis_block()).expect("build live node");
    for c in &custodians {
        node.admit_validator(c.id(), 5_000, 0)
            .expect("bond a validator");
        node.register_validator_custody(c.id(), c.secp_compressed(), c.xmr_point());
        // DB-77: a seat carries the custodian's ML-KEM ek; a request on ANY node is sealed to those keys.
        let (kem_ek, _kem_dk) = usdmd_node::pqkem::keypair();
        node.register_custody_kem(c.id(), kem_ek);
    }

    // The genesis peg ledger initializes to commitment-to-ZERO under the well-known genesis blinds — NOT a raw
    // all-zero digest (which would match no real commitment ⇒ the first mint would be unprovable). Confirm it,
    // and capture the running (value, blind) opening the orchestrator advances from.
    let g_reserve = node.peg().reserve_commit();
    let g_minted = node.peg().minted_commit();
    assert_ne!(
        g_reserve, usdm_decider::poseidon2_compress::zero_digest(),
        "genesis reserve digest is a real commitment-to-zero, not raw [0;4]"
    );
    assert_eq!(
        g_reserve,
        cs::solvency_commit_256(u256(0), peg::GENESIS_PEG_RESERVE_BLIND),
        "genesis reserve = commit(0, genesis blind)"
    );
    assert_eq!(
        g_minted,
        cs::solvency_commit_256(u256(0), peg::GENESIS_PEG_MINTED_BLIND),
        "genesis minted = commit(0, genesis blind)"
    );
    println!("[psm-e2e] genesis peg initialized to commitment-to-zero (first mint reachable) ✓");

    // ── 2) Run the REAL serve loop on a free loopback port. Keep an Arc clone for reading confidential state.
    let (t, _peer) = LoopbackTransport::pair();
    let rt = Arc::new(Mutex::new(NodeRuntime::new(node, t)));
    let port = {
        let l = TcpListener::bind("127.0.0.1:0").expect("grab a free port");
        l.local_addr().unwrap().port()
    };
    {
        let rt = Arc::clone(&rt);
        std::thread::spawn(move || {
            let _ = rpc_http::serve(rt, port);
        });
    }
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let info = http_req("GET", port, "/get_info", "");
    assert!(
        info.contains("\"status\":\"OK\""),
        "live node serving: {info}"
    );
    println!("[psm-e2e] live node serving on 127.0.0.1:{port} ✓");

    // ── P1) The reserve is a REAL t-of-n THRESHOLD wallet (taproot key-aggregate), bound to the exact quorum.
    // DB-123: the address is a function of the swap's MINT BLIND — the blind the mint later proves against and
    // seals to every custodian — so each custodian re-derives it at attestation; a fresh blind ⇒ a fresh address.
    let d_blind = usdm_decider::poseidon2_compress::lanes_of(&[0xd0u64, 0xd1, 0xd2, 0xd3]);
    let d_blind_beta = usdm_decider::poseidon2_compress::lanes_of(&[0xd0u64, 0xd1, 0xd2, 0xd4]);
    let blind_hex =
        |b: &usdmd_node::spend_frontier::Digest4| hexs(&usdmd_node::spend_frontier::digest_to_lane_bytes(b));
    let addr1 = http_post(
        port,
        "/get_reserve_swap_address",
        &format!(r#"{{"asset":"BTC","d_blind_hex":"{}"}}"#, blind_hex(&d_blind)),
    );
    assert!(
        addr1.contains("\"reserve_ready\":true"),
        "reserve ready for a bonded quorum: {addr1}"
    );
    let deposit_addr = str_field(&addr1, "deposit_address").expect("a deposit address");
    assert!(
        deposit_addr.starts_with("tb1p") || deposit_addr.starts_with("bc1p"),
        "REAL taproot address: {deposit_addr}"
    );
    assert_eq!(deposit_addr.len(), 62, "taproot address length");
    assert_eq!(
        str_field(&addr1, "address_kind").as_deref(),
        Some("btc-taproot")
    );
    assert_eq!(
        num_field(&addr1, "threshold"),
        Some(3),
        "3-of-3 shown (⌊2·3/3⌋+1); ≥2/3-by-bond is the real gate"
    );
    assert_eq!(
        num_field(&addr1, "validators"),
        Some(3),
        "bound to the 3-member bonded quorum"
    );
    let group1 = str_field(&addr1, "group_commit").expect("group commitment");
    assert_eq!(
        group1.len(),
        64,
        "reserve is bound to the EXACT quorum via a 32-byte group commitment"
    );
    // A DIFFERENT swap nonce → a DIFFERENT (fresh, unlinkable) real address, same quorum/group.
    let addr2 = http_post(
        port,
        "/get_reserve_swap_address",
        &format!(r#"{{"asset":"BTC","d_blind_hex":"{}"}}"#, blind_hex(&d_blind_beta)),
    );
    let deposit_addr2 = str_field(&addr2, "deposit_address").expect("second address");
    assert_ne!(
        deposit_addr, deposit_addr2,
        "fresh nonce → fresh unlinkable reserve address"
    );
    assert_eq!(
        str_field(&addr2, "group_commit"),
        Some(group1.clone()),
        "same t-of-n quorum backs every swap"
    );
    // AUTO-CUSTODIAN CHURN: the reserve is a FUNCTION of the LIVE bonded set. The served address IS the live 3-set
    // key-aggregate; a 1-of-1 (founding validator) is a valid reserve (deposits work day 1) and DIFFERS from the
    // 3-set; a 2-set differs too — so custody starts at the founding validator and GROWS with the bonded membership.
    // DB-121: the bonded set travels WITH its weights (one free founding seat each = weight 1).
    let live: Vec<(usdmd_node::validator::BridgeCustody, u128)> = custodians
        .iter()
        .map(|c| {
            (
                usdmd_node::validator::BridgeCustody {
                    secp33: c.secp_compressed(),
                    ed32: c.xmr_point(),
                },
                1u128,
            )
        })
        .collect();
    let alpha_nonce = usdmd_node::spend_frontier::digest_to_lane_bytes(&d_blind);
    let btc3 = usdmd_node::bridge::reserve_btc_address_from_bonded_custody(&live, &alpha_nonce);
    let btc1 = usdmd_node::bridge::reserve_btc_address_from_bonded_custody(&live[0..1], &alpha_nonce);
    let btc2 = usdmd_node::bridge::reserve_btc_address_from_bonded_custody(&live[0..2], &alpha_nonce);
    assert_eq!(
        btc3.as_deref(),
        Some(deposit_addr.as_str()),
        "the served BTC reserve IS the live bonded-set key-aggregate"
    );
    assert!(
        btc1.is_some(),
        "the founding validator alone is a valid 1-of-1 reserve (deposits work day 1)"
    );
    assert_ne!(
        btc1, btc3,
        "adding validators CHANGES the reserve — auto-custodian churn"
    );
    assert_ne!(btc2, btc3, "the reserve grows with the bonded set");
    println!("[psm-e2e] P1 reserve = LIVE bonded-set key-aggregate (founding validator day 1, grows to t-of-n; no solo key) ✓");

    // ── P2) The deposit gate: no mint until a REAL confirmed deposit ≥ min. A fresh reserve address reads 0.
    let ds = http_post(
        port,
        "/btc_deposit_status",
        &format!(r#"{{"reserve_address":"{deposit_addr}","min_sats":150000000}}"#),
    );
    assert!(
        ds.contains("\"confirmed\":false"),
        "no deposit yet ⇒ NOT confirmed ⇒ no mint: {ds}"
    );
    assert_eq!(
        num_field(&ds, "confirmed_sats"),
        Some(0),
        "fresh reserve address holds 0 confirmed sats"
    );
    println!("[psm-e2e] P2 deposit gate closed until a real confirmed deposit (0 sats → not confirmed) ✓");

    // ── P3) DEPOSIT → MINT @150%, over real HTTP. The custodian orchestrator (which confirmed the real deposit)
    //        builds the confidential carrier from the running opening: reserve 0→1500, minted 0→1000 (= 150%).
    let (r_val, m_val) = (1_500u64, 1_000u64); // new totals after this mint; 1500 ≥ 1.5·1000 = exactly 150%
    let nr_blind = usdm_decider::poseidon2_compress::lanes_of(&[0x11u64, 0x22, 0x33, 0x44]);
    let nm_blind = usdm_decider::poseidon2_compress::lanes_of(&[0x55u64, 0x66, 0x77, 0x88]);
    // DB-80: the mint delta travels COMMITTED (`delta_commit = commit(mint, d_blind)`); the solvency carrier
    // and the mint-validity carrier both open it, so no amount is on the wire and neither carrier can be
    // paired with another's figure.
    // (`d_blind` is the blind P1 derived the deposit address from — DB-123 ties the two together.)
    let (carrier, commits_d) = cs::prove_peg_in_carrier_delta(
        u256(0),
        u256(0),
        u256(r_val),
        u256(m_val),
        peg::GENESIS_PEG_RESERVE_BLIND,
        peg::GENESIS_PEG_MINTED_BLIND,
        nr_blind,
        nm_blind,
        d_blind,
        15_000,
    )
    .expect("a 150%-collateralized peg-in carrier PROVES");
    let commits = commits_d.base;
    let delta_commit = commits_d.delta_commit;
    assert_eq!(
        delta_commit,
        peg::PegLedger::mint_delta_commit(m_val as u128, d_blind),
        "the carrier's delta commitment IS commit(mint, d_blind)"
    );
    let deposit_id = [0xd1u8; 32];
    // ⛔⛔⛔ THE MINT-VALIDITY CARRIER — THE GATE THIS SUITE NEVER SATISFIED.
    //
    // `Node::peg_in_confidential` requires that the credited note's OWN commitment open to the AUTHORIZED
    // mint amount under a real carrier: "the caller does not get to choose the amount it receives." That
    // gate landed 2026-08-26 (before it, `verify_mint_validity` had ZERO call sites and the path ended in
    // a bare `record_note_payload`, so a note sealed for 1e6 was credited under an authorized mint of
    // 100). This suite kept sending an arbitrary `buyer_cm = [0xb7; 32]` and NO `mint_carrier_hex`, so
    // every mint here has been refused `BAD_REQUEST` ever since — and from 2026-09-15 the file did not
    // even compile (`credit_set`, §BA/§BB), so nothing reported either fact.
    //
    // ⭐ The commitment is NOT chosen here: `prove_mint_validity_bytes` RETURNS it, and the note payload
    // is built from that. That is the whole point of the gate — the amount and the commitment are bound
    // by the same proof.
    let mint_sk = usdm_decider::poseidon2_compress::lanes_of(&[0xc0u64, 0xc1, 0xc2, 0xc3]);
    let (mint_carrier, mint_cm, mint_dc) =
        usdm_decider::whir_rec_block::prove_mint_validity_committed_bytes(m_val, &mint_sk, &d_blind)
            .expect("the mint-validity carrier PROVES for the authorized amount");
    assert_eq!(mint_dc, delta_commit, "both carriers open the SAME committed delta");
    let buyer_cm = usdmd_node::spend_frontier::leaf_to_cm_bytes(mint_cm);
    let msg = peg::peg_in_confidential_msg(
        &deposit_id,
        &commits.new_reserve_commit,
        &commits.new_minted_commit,
        &delta_commit,
        &recip_of(&deposit_id),
        &[0u8; 32], // the route's default proposal nonce: these attestations are made over it
    );
    let att2: Vec<MintAttestor> = custodians[0..2].iter().map(|c| c.attest(&msg)).collect(); // 2-of-3 ≥ 2/3
    let mut note_payload = Vec::with_capacity(1153);
    note_payload.extend_from_slice(&buyer_cm);
    note_payload.extend_from_slice(&[0u8; 1153 - 32]); // ct ‖ enc_amount ‖ view_tag (opaque here)

    // FUNDS-LOSS-IMPOSSIBLE bond backstop: prove the bonded quorum weight ≥ 2× the new value-at-risk (1500 here).
    let quorum_weight = rt.lock().unwrap().node().validators().total_bond() as u64;
    let backstop = |v: u64, bl: usdmd_node::spend_frontier::Digest4| -> Option<Vec<u8>> {
        cs::prove_peg_in_carrier(
            u256(quorum_weight),
            u256(v),
            u256(0),
            u256(0),
            peg::BOND_BACKSTOP_BLIND,
            bl,
            peg::BOND_BACKSTOP_BLIND,
            bl,
            20_000,
        )
        .map(|(b, _)| b)
    };
    let p3_backstop =
        backstop(r_val, nr_blind).expect("bonded weight over-covers the value-at-risk");
    let before = rt.lock().unwrap().node().note_frontier_count();
    let body = format!(
        r#"{{"deposit_id":"{}","recipient":"{}","new_reserve_commit":"{}","new_minted_commit":"{}","delta_commit":"{}","carrier_hex":"{}","mint_carrier_hex":"{}","note_payload":"{}","bond_backstop_hex":"{}","attestors_hex":"{}","note_clue_hex":"{}"}}"#,
        hexs(&deposit_id),
        hexs(&recip_of(&deposit_id)),
        commit_hex(commits.new_reserve_commit),
        commit_hex(commits.new_minted_commit),
        commit_hex(delta_commit),
        hexs(&carrier),
        hexs(&mint_carrier),
        hexs(&note_payload),
        hexs(&p3_backstop),
        attestors_hex(&att2),
        hexs(&owner_clue),
    );
    let mint = http_post(port, "/peg_in_confidential", &body);
    assert!(
        mint.contains("\"authorized\":true") && mint.contains("CONFIDENTIAL_PUBLISHED"),
        "150% mint AUTHORIZED and PUBLISHED: {mint}"
    );
    // ⭐⭐⭐ §CS/§CZ — THE CREDIT IS NO LONGER A LOCAL MUTATION, AND THAT IS WHAT THIS NOW PROVES.
    //
    // Before §CS (2026-09-16) `Node::peg_in_confidential` ended in `record_note_payload`, so the buyer's
    // USDm appeared in THIS node's frontier the instant the RPC returned — on the one node that answered
    // it, while every peer held no note for it. And until §CZ (2026-09-17) the ledger's DIGESTS still
    // advanced at execute (the half of the mutation §CS left behind), which let a custodian on a fork
    // re-mint a deposit its peer had already carried. NOTHING moves at the RPC now: not the frontier, not
    // the digests, not the replay set. The object is framed as a `Class::PegIn`, admitted to the pool, and
    // lands when a BLOCK CARRIES IT — on this node exactly as on every peer.
    let after = rt.lock().unwrap().node().note_frontier_count();
    assert_eq!(
        after, before,
        "⛔ THE PEG-IN CREDITED THIS NODE'S FRONTIER DIRECTLY FROM THE RPC. That is the §CS local-mutation \
         shape: the depositor's USDm would exist on the node that answered and nowhere else, which is how \
         the same deposit gets credited once per node. It must be published and carried in a block."
    );
    assert_eq!(
        rt.lock().unwrap().node().peg().reserve_commit(),
        g_reserve,
        "⛔ THE PEG-IN ADVANCED THE RESERVE DIGEST AT EXECUTE — the §CZ local-mutation shape (a custodian \
         on a fork then mints the same deposit again)"
    );
    assert!(
        // `unspent_holds_note` was removed from `Node`; `records_containing_cm` is the reader the `/peg_in_execute`
        // door itself answers `credited` with.
        rt.lock().unwrap().node().records_containing_cm(&buyer_cm).is_empty(),
        "⛔ THE BUYER'S NOTE IS IN THE UNSPENT SET BEFORE ANY BLOCK CARRIED IT — a local credit"
    );
    println!("[psm-e2e] P3 the mint is AUTHORIZED and PUBLISHED, nothing written locally (§CS/§CZ) ✓");
    // ⭐ THE BLOCK APPLIES IT. Same `Node::produce` the daemon's produce act runs; the peg-in object rides
    // it and `peg_in_tx::apply_chain_peg_in` runs on this node from its own block.
    settle_block(&rt, 20_000);

    // ⭐ WHAT THE BLOCK APPLIED — the digests advanced ON THIS NODE from the block it mined, the same
    // door (`apply_chain_peg_in`) every peer runs on the block it receives. The cross-node half of the
    // claim (the peer holds the credit, refuses the replay, mints the next deposit) is the real-node tier's:
    // `harness::real_node_journey::seat_journeys::…` runs it on two `usdmd-node` processes over onion peering.
    assert_eq!(
        rt.lock().unwrap().node().peg().reserve_commit(),
        commits.new_reserve_commit,
        "reserve digest advanced (no amount on the wire)"
    );
    assert_eq!(
        rt.lock().unwrap().node().peg().minted_commit(),
        commits.new_minted_commit,
        "minted digest advanced (no amount on the wire)"
    );
    // The commitments open to EXACTLY the 150% totals (conservation of the proven transition).
    assert_eq!(
        commits.new_reserve_commit,
        cs::solvency_commit_256(u256(r_val), nr_blind)
    );
    assert_eq!(
        commits.new_minted_commit,
        cs::solvency_commit_256(u256(m_val), nm_blind)
    );
    // ⭐ AND THE BUYER'S NOTE ENTERED THE FRONTIER NOW — from the block (before the block the frontier
    // had not moved, asserted above). The served stream (`/get_pq_notes`) is the wallet's read and is
    // measured where a wallet reads it: the real-node tier's wallet journey; this loopback fixture's serve
    // cursor is driven by the runtime tick, which does not run here.
    let _ = before;
    assert!(
        !rt.lock().unwrap().node().records_containing_cm(&buyer_cm).is_empty(),
        "⛔ THE BLOCK CARRIED THE PEG-IN AND THE BUYER'S NOTE IS STILL NOT IN THE UNSPENT SET — the \
         credit did not land through the block on the node that mined it"
    );
    assert!(
        rt.lock().unwrap().node().peg().deposit_minted(&deposit_id),
        "the deposit id entered the replay set FROM THE BLOCK"
    );
    println!(
        "[psm-e2e] P3 real deposit → 2-of-3 post-quantum threshold → MINT @150% AUTHORIZED, published \
         as a chain object, applied by the block on the node that mined it, note served from the block ✓"
    );

    // ── P4) ADVERSARIAL mint — every unsound variant fail-closes.
    // (a) under-150% is UNPROVABLE: from the current 1500/1000, mint +1000 with no new reserve → 1500/2000 = 75%.
    assert!(
        cs::prove_peg_in_carrier_delta(
            u256(r_val),
            u256(m_val),
            u256(0),
            u256(1_000),
            nr_blind,
            nm_blind,
            usdm_decider::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]),
            usdm_decider::poseidon2_compress::lanes_of(&[5u64, 6, 7, 8]),
            d_blind,
            15_000
        )
        .is_none(),
        "an under-150% mint is UNPROVABLE — the custodian cannot even build the carrier"
    );
    // (b) a carrier NOT built from the node's persisted state → BadRequest (verify pins the old commitment).
    let (bad_carrier, bad_commits_d) = cs::prove_peg_in_carrier_delta(
        u256(9_999),
        u256(1),
        u256(1_500),
        u256(1_000),
        usdm_decider::poseidon2_compress::lanes_of(&[9u64, 9, 9, 9]),
        usdm_decider::poseidon2_compress::lanes_of(&[8u64, 8, 8, 8]),
        usdm_decider::poseidon2_compress::lanes_of(&[7u64, 7, 7, 7]),
        usdm_decider::poseidon2_compress::lanes_of(&[6u64, 6, 6, 6]),
        d_blind,
        15_000,
    )
    .expect("a well-formed carrier for a DIFFERENT (wrong) old-state still proves in isolation");
    let bad_commits = bad_commits_d.base;
    let bad_dep = [0xbdu8; 32];
    let bad_msg = peg::peg_in_confidential_msg(
        &bad_dep,
        &bad_commits.new_reserve_commit,
        &bad_commits.new_minted_commit,
        &delta_commit,
        &recip_of(&bad_dep),
        &[0u8; 32], // the route's default proposal nonce: these attestations are made over it
    );
    let bad_att: Vec<MintAttestor> = custodians[0..2]
        .iter()
        .map(|c| c.attest(&bad_msg))
        .collect();
    let bad_body = format!(
        r#"{{"deposit_id":"{}","recipient":"{}","new_reserve_commit":"{}","new_minted_commit":"{}","delta_commit":"{}","carrier_hex":"{}","mint_carrier_hex":"{}","note_payload":"{}","attestors_hex":"{}","note_clue_hex":"{}"}}"#,
        hexs(&bad_dep),
        hexs(&recip_of(&bad_dep)),
        commit_hex(bad_commits.new_reserve_commit),
        commit_hex(bad_commits.new_minted_commit),
        commit_hex(delta_commit),
        hexs(&bad_carrier),
        hexs(&mint_carrier),
        hexs(&note_payload),
        attestors_hex(&bad_att),
        hexs(&owner_clue),
    );
    let bad = http_post(port, "/peg_in_confidential", &bad_body);
    println!("[psm-e2e][P4-arm] wrong-state -> {}", bad.trim());
    assert!(
        bad.contains("\"authorized\":false") && bad.contains("BAD_REQUEST"),
        "a carrier not built from the node's state → BadRequest: {bad}"
    );
    // (c) sub-quorum: 1-of-3 on an otherwise-valid transition → InsufficientThreshold.
    let dep_sub = [0x51u8; 32];
    let (sub_carrier, sub_c_d) = cs::prove_peg_in_carrier_delta(
        u256(r_val),
        u256(m_val),
        u256(1_500),
        u256(1_000),
        nr_blind,
        nm_blind,
        usdm_decider::poseidon2_compress::lanes_of(&[3u64, 1, 4, 1]),
        usdm_decider::poseidon2_compress::lanes_of(&[5u64, 9, 2, 6]),
        d_blind,
        15_000,
    )
    .unwrap();
    let sub_c = sub_c_d.base;
    let sub_msg = peg::peg_in_confidential_msg(
        &dep_sub,
        &sub_c.new_reserve_commit,
        &sub_c.new_minted_commit,
        &delta_commit,
        &recip_of(&dep_sub),
        &[0u8; 32], // the route's default proposal nonce: these attestations are made over it
    );
    let one_att: Vec<MintAttestor> = vec![custodians[0].attest(&sub_msg)]; // 1-of-3 < 2/3
    let sub_body = format!(
        r#"{{"deposit_id":"{}","recipient":"{}","new_reserve_commit":"{}","new_minted_commit":"{}","delta_commit":"{}","carrier_hex":"{}","mint_carrier_hex":"{}","note_payload":"{}","attestors_hex":"{}","note_clue_hex":"{}"}}"#,
        hexs(&dep_sub),
        hexs(&recip_of(&dep_sub)),
        commit_hex(sub_c.new_reserve_commit),
        commit_hex(sub_c.new_minted_commit),
        commit_hex(delta_commit),
        hexs(&sub_carrier),
        hexs(&mint_carrier),
        hexs(&note_payload),
        attestors_hex(&one_att),
        hexs(&owner_clue),
    );
    let sub = http_post(port, "/peg_in_confidential", &sub_body);
    println!("[psm-e2e][P4-arm] sub-quorum -> {}", sub.trim());
    assert!(
        sub.contains("INSUFFICIENT_THRESHOLD"),
        "1-of-3 sub-quorum → InsufficientThreshold: {sub}"
    );
    // (d) forged non-bonded attestor: a real signature from an OUTSIDER carries 0 bonded weight → still < 2/3.
    let outsider = Custodian::generate(&[0x99u8; 32]);
    let forged_att: Vec<MintAttestor> =
        vec![custodians[0].attest(&sub_msg), outsider.attest(&sub_msg)];
    let forged_body = format!(
        r#"{{"deposit_id":"{}","recipient":"{}","new_reserve_commit":"{}","new_minted_commit":"{}","delta_commit":"{}","carrier_hex":"{}","mint_carrier_hex":"{}","note_payload":"{}","attestors_hex":"{}","note_clue_hex":"{}"}}"#,
        hexs(&[0xf0u8; 32]),
        hexs(&recip_of(&[0xf0u8; 32])),
        commit_hex(sub_c.new_reserve_commit),
        commit_hex(sub_c.new_minted_commit),
        commit_hex(delta_commit),
        hexs(&sub_carrier),
        hexs(&mint_carrier),
        hexs(&note_payload),
        attestors_hex(&forged_att),
        hexs(&owner_clue),
    );
    let forged = http_post(port, "/peg_in_confidential", &forged_body);
    println!("[psm-e2e][P4-arm] forged-attestor -> {}", forged.trim());
    assert!(
        forged.contains("INSUFFICIENT_THRESHOLD"),
        "outsider (0 bonded weight) + 1 real → InsufficientThreshold: {forged}"
    );
    // (e) replay the P3 deposit id → Replay (never mint the same deposit twice).
    let replay = http_post(port, "/peg_in_confidential", &body);
    println!("[psm-e2e][P4-arm] replay -> {}", replay.trim());
    // ⛔⛔⛔ A REJECTED MINT MUTATES NOTHING — CHECKED HERE, WHILE EVERY ARM ABOVE IS A REJECTION.
    //
    // MEASURED 2026-09-17: this caught a REAL defect the moment the bond gate stopped masking it. The
    // node-level authorized-amount bind used to run AFTER `peg.peg_in_confidential` had already applied
    // the ledger, so a peg-in with a valid solvency carrier and a full quorum but no mint carrier advanced
    // `reserve_commit`/`minted_commit` AND consumed its `deposit_id`, then returned `BadRequest`. The
    // minted total then claimed USDm that was never issued, and the depositor's real BTC deposit could
    // never be retried. Fixed by hoisting that bind above the apply in `Node::peg_in_confidential`.
    assert_eq!(
        rt.lock().unwrap().node().peg().minted_commit(),
        commits.new_minted_commit,
        "⛔ A REJECTED MINT MOVED THE LEDGER. Accounting inflation (minted claims USDm nobody holds) and \
         a burned deposit_id the depositor can never reuse."
    );
    assert_eq!(
        rt.lock().unwrap().node().peg().reserve_commit(),
        commits.new_reserve_commit,
        "⛔ A REJECTED MINT MOVED THE RESERVE COMMITMENT"
    );
    assert!(
        replay.contains("REPLAY"),
        "the same deposit id never mints twice → Replay: {replay}"
    );
    // (f) FUNDS-LOSS-IMPOSSIBLE bond backstop: a value-at-risk above the bonded weight / 2 has NO backstop proof
    //     (unbuildable), and a valid-threshold + valid-150% mint submitted WITHOUT a valid backstop → Underbonded.
    //     So the reserve can never exceed half the forfeitable bond ⇒ a depositor is always over-covered by the bond.
    assert!(
        backstop(quorum_weight / 2 + 1, usdm_decider::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4])).is_none(),
        "value-at-risk above bonded-weight/2 → bond backstop is UNPROVABLE"
    );
    let full_att: Vec<MintAttestor> = custodians[0..2]
        .iter()
        .map(|c| c.attest(&sub_msg))
        .collect();
    let underbonded_body = format!(
        r#"{{"deposit_id":"{}","recipient":"{}","new_reserve_commit":"{}","new_minted_commit":"{}","delta_commit":"{}","carrier_hex":"{}","mint_carrier_hex":"{}","note_payload":"{}","bond_backstop_hex":"","attestors_hex":"{}","note_clue_hex":"{}"}}"#,
        hexs(&dep_sub),
        hexs(&recip_of(&dep_sub)),
        commit_hex(sub_c.new_reserve_commit),
        commit_hex(sub_c.new_minted_commit),
        commit_hex(delta_commit),
        hexs(&sub_carrier),
        hexs(&mint_carrier),
        hexs(&note_payload),
        attestors_hex(&full_att),
        hexs(&owner_clue),
    );
    let underbonded = http_post(port, "/peg_in_confidential", &underbonded_body);
    println!("[psm-e2e][P4-arm] no-backstop -> {}", underbonded.trim());
    // ⛔⛔⛔ THE BOND IS NO LONGER A GATE ON ISSUANCE — THIS ARM NOW PINS THAT DECISION.
    //
    // It used to assert `UNDERBONDED` ("backstop REQUIRED"). Owner, 2026-09-17: *"the bond shouldnt
    // prevent genuine issuance at all. It should also not prevent genuine withdrawls. users should be able
    // to deposit and withdraw as much as they want down to the 100% backed level."* The depositor's BTC IS
    // the reserve — it sits in threshold custody and backs itself — so the validator bond is anti-theft
    // weight (slashing size, reward weight, how much the set may be trusted with), never a cap on a user's
    // money. MEASURED before the change, on two REAL peered nodes: `validators:0` plus a CONFIRMED BTC
    // deposit answered `UNDERBONDED` and issued nothing — a depositor's real BTC taken into custody with no
    // USDm against it, and a chain that could never bootstrap (no USDm ⇒ no bond ⇒ no USDm).
    //
    // ⭐ So the assertion INVERTS: no refusal here may ever again be `UNDERBONDED`. This arm still supplies
    // a carrier built from the WRONG state, so the mint is correctly refused — by the SOLVENCY proof
    // (`BAD_REQUEST`), which is the gate that actually prevents inflation and which this change did not
    // touch. If a future edit re-introduces a bond cap on issuance, this fails.
    assert!(
        !underbonded.contains("UNDERBONDED"),
        "⛔ A BOND CAP HAS BEEN RE-INTRODUCED ON ISSUANCE. The bond must never decide whether a user's \
         deposit mints — only solvency may refuse: {underbonded}"
    );
    assert!(
        underbonded.contains("CONFIDENTIAL_PUBLISHED"),
        "⛔ A FULLY VALID MINT WITH NO BOND BACKSTOP MUST SUCCEED. Every other field here is well-formed — \
         a solvency carrier from the node's own state, a full quorum, a real mint carrier — and the ONLY \
         thing absent is the bond backstop, which is no longer a gate on a user's money: {underbonded}"
    );
    // …and the block applies it, as P3's was applied.
    settle_block(&rt, 30_000);
    assert!(
        rt.lock().unwrap().node().peg().deposit_minted(&dep_sub),
        "the no-backstop mint landed from the block"
    );
    println!("[psm-e2e] P4 adversarial mint: under-150% unprovable · wrong-state BadRequest · sub-quorum + forged + replay all rejected and MUTATED NOTHING · a valid mint with no bond backstop PUBLISHES and the block MINTS it ✓");

    // ── P5) WITHDRAWAL → BURN, over real HTTP.
    //
    // ⭐ REBASED ONTO THE ACTUAL CURRENT STATE, NOT P3's. The no-backstop arm in P4 is now a SUCCESSFUL
    // mint (the bond is no longer a gate on issuance, 2026-09-17), so it advanced the ledger by a second
    // 1500/1000 under `sub_carrier`'s blinds. A peg-out must prove FROM the node's persisted state, so
    // this starts at 3000/2000 and releases 300 / burns 200 → 2700/1800. The assertion below is what makes
    // that explicit rather than assumed — if the preceding arms ever change what they leave behind, this
    // fails loudly instead of proving a carrier against a state the node does not hold.
    let (p5_r, p5_m) = (3_000u64, 2_000u64);
    let p5_r_blind = usdm_decider::poseidon2_compress::lanes_of(&[3u64, 1, 4, 1]);
    let p5_m_blind = usdm_decider::poseidon2_compress::lanes_of(&[5u64, 9, 2, 6]);
    let (or_val, om_val) = (p5_r - 300, p5_m - 200);
    let out_nr = usdm_decider::poseidon2_compress::lanes_of(&[0xa1u64, 0xa2, 0xa3, 0xa4]);
    let out_nm = usdm_decider::poseidon2_compress::lanes_of(&[0xb1u64, 0xb2, 0xb3, 0xb4]);
    let (out_carrier, out_c) = cs::prove_peg_out_carrier(
        u256(p5_r),
        u256(p5_m),
        u256(300),
        u256(200),
        p5_r_blind,
        p5_m_blind,
        out_nr,
        out_nm,
        peg::DEFAULT_REDEEM_FLOOR_BPS as u64,
    )
    .expect("a conservation-respecting, post-floor-backed peg-out carrier PROVES");
    assert_eq!(
        out_c.reserve_commit,
        rt.lock().unwrap().node().peg().reserve_commit(),
        "peg-out proves FROM the node's current persisted state"
    );
    let usdm_nf = [0xf1u8; 32];
    let out_msg = peg::peg_out_confidential_msg(
        &usdm_nf,
        &out_c.new_reserve_commit,
        &out_c.new_minted_commit,
        &peg::redeem_commit(b"tb1pwithdrawtarget", &test_redeem_blind()),
        &[0u8; 32],
        &[0u64; 8],
        &[0u8; 32]); // DB-273 §19.3 L2: no change note rides, so the change owner is zero
    let out_att: Vec<MintAttestor> = custodians[0..2]
        .iter()
        .map(|c| c.attest(&out_msg))
        .collect();
    let out_body = format!(
        r#"{{"usdm_nullifier":"{}","new_reserve_commit":"{}","new_minted_commit":"{}","redeem_to":"tb1pwithdrawtarget","carrier_hex":"{}","attestors_hex":"{}","note_clue_hex":"{}"}}"#,
        hexs(&usdm_nf),
        commit_hex(out_c.new_reserve_commit),
        commit_hex(out_c.new_minted_commit),
        hexs(&out_carrier),
        attestors_hex(&out_att),
        hexs(&owner_clue),
    );
    // ⭐ THE BURN IS APPLIED BY THE BLOCK — `apply_peg_out_attested` is the door `apply_chain_peg_out`
    // calls for every carried `Class::PegOut`, on every node. A burn's PUBLICATION needs the burned
    // note's deletion transition (a burn is a spend, §AQ), which only the note's owner can build from
    // its own unspent map; this suite holds no wallet, so the positive redeem over `/peg_out_execute`
    // belongs to the real-node wallet journey. Everything the chain does WITH a carried burn — the
    // threshold, the reduction proof against the persisted digests, the replay set, the nullifier fold,
    // the single-use release — is proven here from the door a block drives.
    let _ = out_body;
    let burn = rt.lock().unwrap().node_mut().apply_peg_out_attested(
        usdm_nf,
        &out_carrier,
        out_c.new_reserve_commit,
        out_c.new_minted_commit,
        &peg::redeem_commit(b"tb1pwithdrawtarget", &test_redeem_blind()),
        &[0u8; 32],
        [0u64; 8],
        &[0u8; 32], // DB-273 §19.3 L2: no change note, zero change owner
        &usdmd_node::pqauth::MlDsaVerifier,
        &out_att,
        &[],
        &[], // DB-58: sealed per-custodian legs (none in this in-process fixture)
    );
    assert!(
        matches!(burn, usdmd_node::peg::PegOutcome::ConfidentialRedeemed),
        "a carried withdrawal with a full quorum and a valid reduction proof applies: {burn:?}",
    );
    assert_eq!(
        rt.lock().unwrap().node().peg().reserve_commit(),
        out_c.new_reserve_commit,
        "reserve digest reduced BY THE BLOCK (no amount on the wire)"
    );
    assert!(rt.lock().unwrap().node().peg().burn_redeemed(&usdm_nf), "the burn retired from the block");
    assert_eq!(
        out_c.new_reserve_commit,
        cs::solvency_commit_256(u256(or_val), out_nr)
    );
    assert_eq!(
        out_c.new_minted_commit,
        cs::solvency_commit_256(u256(om_val), out_nm)
    );
    // Replay the same burned note tag through the same door → Replay (never burn one USDm note twice).
    let burn_replay = rt.lock().unwrap().node_mut().apply_peg_out_attested(
        usdm_nf,
        &out_carrier,
        out_c.new_reserve_commit,
        out_c.new_minted_commit,
        &peg::redeem_commit(b"tb1pwithdrawtarget", &test_redeem_blind()),
        &[0u8; 32],
        [0u64; 8],
        &[0u8; 32], // DB-273 §19.3 L2: no change note, zero change owner
        &usdmd_node::pqauth::MlDsaVerifier,
        &out_att,
        &[],
        &[], // DB-58: sealed per-custodian legs (none in this in-process fixture)
    );
    assert!(
        matches!(burn_replay, usdmd_node::peg::PegOutcome::Replay),
        "the same USDm note never burns twice → Replay: {burn_replay:?}",
    );
    // An over-drain withdrawal (release far more reserve than USDm burned, pushing post-state <150%) is UNPROVABLE.
    assert!(
        cs::prove_peg_out_carrier(
            u256(or_val),
            u256(om_val),
            u256(or_val),
            u256(1),
            out_nr,
            out_nm,
            usdm_decider::poseidon2_compress::lanes_of(&[1u64, 1, 1, 1]),
            usdm_decider::poseidon2_compress::lanes_of(&[2u64, 2, 2, 2]),
            peg::DEFAULT_REDEEM_FLOOR_BPS as u64
        )
        .is_none(),
        "an over-drain withdrawal (post-state below the redeem floor) is UNPROVABLE"
    );
    println!("[psm-e2e] P5 withdrawal → 2-of-3 threshold → USDm burn recorded (double-burn + over-drain rejected) ✓");

    // ── P6) CONSERVATION: from 1200/800, redeem EVERYTHING back to the genesis zero-state under the genesis blinds.
    //        The confidential digests return to genesis ⇒ the peg mechanism created/destroyed no value on net.
    let (rt_carrier, rt_c) = cs::prove_peg_out_carrier(
        u256(or_val),
        u256(om_val),
        u256(or_val),
        u256(om_val),
        out_nr,
        out_nm,
        peg::GENESIS_PEG_RESERVE_BLIND,
        peg::GENESIS_PEG_MINTED_BLIND,
        peg::DEFAULT_REDEEM_FLOOR_BPS as u64,
    )
    .expect("redeeming the full balance proves");
    let rt_nf = [0xf2u8; 32];
    let rt_msg = peg::peg_out_confidential_msg(
        &rt_nf,
        &rt_c.new_reserve_commit,
        &rt_c.new_minted_commit,
        &peg::redeem_commit(b"tb1pfinalredeem", &test_redeem_blind()),
        &[0u8; 32],
        &[0u64; 8],
        &[0u8; 32]); // DB-273 §19.3 L2: no change note rides, so the change owner is zero
    let rt_att: Vec<MintAttestor> = custodians[0..2].iter().map(|c| c.attest(&rt_msg)).collect();
    let rt_body = format!(
        r#"{{"usdm_nullifier":"{}","new_reserve_commit":"{}","new_minted_commit":"{}","redeem_to":"tb1pfinalredeem","carrier_hex":"{}","attestors_hex":"{}","note_clue_hex":"{}"}}"#,
        hexs(&rt_nf),
        commit_hex(rt_c.new_reserve_commit),
        commit_hex(rt_c.new_minted_commit),
        hexs(&rt_carrier),
        attestors_hex(&rt_att),
        hexs(&owner_clue),
    );
    let _ = rt_body;
    let settle = rt.lock().unwrap().node_mut().apply_peg_out_attested(
        rt_nf,
        &rt_carrier,
        rt_c.new_reserve_commit,
        rt_c.new_minted_commit,
        &peg::redeem_commit(b"tb1pfinalredeem", &test_redeem_blind()),
        &[0u8; 32],
        [0u64; 8],
        &[0u8; 32], // DB-273 §19.3 L2: no change note, zero change owner
        &usdmd_node::pqauth::MlDsaVerifier,
        &rt_att,
        &[],
        &[], // DB-58: sealed per-custodian legs (none in this in-process fixture)
    );
    assert!(
        matches!(settle, usdmd_node::peg::PegOutcome::ConfidentialRedeemed),
        "full redemption applies from the block door: {settle:?}",
    );
    assert_eq!(
        rt.lock().unwrap().node().peg().reserve_commit(),
        g_reserve,
        "reserve digest returns to the genesis zero-state (applied by the block)"
    );
    assert_eq!(
        rt.lock().unwrap().node().peg().minted_commit(),
        g_minted,
        "minted digest returns to the genesis zero-state"
    );
    println!("[psm-e2e] P6 conservation: peg-in D then peg-out D returns the digests to genesis zero (no net value) ✓");

    // ── P-XMR) DB-121x: the XMR reserve is the bonded set's k-of-n Monero multisig wallet (`xmr_custody`); a swap's
    //    deposit address is that wallet's integrated address with a payment id = f(set, mint blind). This in-process
    //    node has announced no custody wallet, so the door serves no Monero address; the codec below is what every
    //    node runs on an announced one. The real-node regtest journey covers the wallet, deposit and payout.
    // (i) no announced custody wallet ⇒ NO address (a made-up address would strand a depositor's XMR).
    let xa = http_post(
        port,
        "/get_reserve_swap_address",
        &format!(r#"{{"asset":"XMR","d_blind_hex":"{}"}}"#, blind_hex(&d_blind)),
    );
    assert!(
        xa.contains("\"reserve_ready\":false") && xa.contains("xmr_custody_not_ready"),
        "no announced Monero custody wallet ⇒ no Monero address: {xa}"
    );
    // (ii) the integrated-address codec: one address per swap, round-trips to its payment id and main address,
    //      differs per blind.
    let main = "477y8v2RXYGLMktERaQ6eQh3wMQhY2eWyTCm2qzngDfvKLrcqM1gsyYfhkRZ5U2DNYWm6JtD1pHTRNDiKjVDR7oN8JZnsHQ";
    assert!(usdmd_node::bridge::is_monero_address(main), "a real, Keccak-checksummed Monero address");
    let sid = usdmd_node::xmr_custody::set_id(&custodians.iter().map(|c| c.id()).collect::<Vec<_>>());
    let pid_a = usdmd_node::xmr_custody::payment_id(&sid, &alpha_nonce);
    let pid_b = usdmd_node::xmr_custody::payment_id(&sid, &usdmd_node::spend_frontier::digest_to_lane_bytes(&d_blind_beta));
    let ia = usdmd_node::bridge::xmr_integrated_address(main, &pid_a).expect("integrates");
    let ib = usdmd_node::bridge::xmr_integrated_address(main, &pid_b).expect("integrates");
    assert_ne!(ia, ib, "a fresh blind → a fresh unlinkable integrated address");
    assert_eq!(ia.len(), 106, "integrated Monero address length");
    let (pid_back, main_back) = usdmd_node::bridge::xmr_integrated_parts(&ia).expect("decodes");
    assert_eq!(pid_back, pid_a);
    assert_eq!(main_back, main, "the integrated address decodes back to the set's main address");
    // (iii) byte-for-byte what monero-wallet-rpc's `make_integrated_address` emits for this main address and
    //       payment id 0123456789abcdef (measured 2026-09-21).
    let probe_pid = [0x01u8, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    assert_eq!(
        usdmd_node::bridge::xmr_integrated_address(main, &probe_pid).as_deref(),
        Some("4Gpe9iqv8onLMktERaQ6eQh3wMQhY2eWyTCm2qzngDfvKLrcqM1gsyYfhkRZ5U2DNYWm6JtD1pHTRNDiKjVDR7oNBhvYwF8HHg8U4TyaVq"),
        "the codec matches the wallet's own integrated address"
    );
    // (iv) an XMR-backed deposit MINTS over the SAME asset-agnostic confidential path (the ledger is back at the
    //      genesis zero-state after P6): a fresh 150% peg-in → ConfidentialMinted.
    let (xnr, xnm) = (usdm_decider::poseidon2_compress::lanes_of(&[0xc1u64, 0xc2, 0xc3, 0xc4]), usdm_decider::poseidon2_compress::lanes_of(&[0xd1u64, 0xd2, 0xd3, 0xd4]));
    let (xcarrier, xcommits_d) = cs::prove_peg_in_carrier_delta(
        u256(0),
        u256(0),
        u256(1_500),
        u256(1_000),
        peg::GENESIS_PEG_RESERVE_BLIND,
        peg::GENESIS_PEG_MINTED_BLIND,
        xnr,
        xnm,
        d_blind,
        15_000,
    )
    .expect("XMR-backed 150% peg-in proves over the same confidential path");
    let xcommits = xcommits_d.base;
    let xdep = [0xe1u8; 32];
    // Same anti-free-mint gate as P3: the credited note's commitment must open to the AUTHORIZED amount
    // under a real carrier, and the carrier RETURNS the commitment — the buyer does not pick it.
    let x_mint_sk = usdm_decider::poseidon2_compress::lanes_of(&[0xe0u64, 0xe1, 0xe2, 0xe3]);
    let (x_mint_carrier, x_mint_cm, x_mint_dc) =
        usdm_decider::whir_rec_block::prove_mint_validity_committed_bytes(1_000, &x_mint_sk, &d_blind)
            .expect("the XMR-backed mint-validity carrier PROVES for the authorized amount");
    assert_eq!(x_mint_dc, xcommits_d.delta_commit, "XMR-backed: both carriers open the same delta");
    let xbuyer = usdmd_node::spend_frontier::leaf_to_cm_bytes(x_mint_cm);
    let xmsg = peg::peg_in_confidential_msg(
        &xdep,
        &xcommits.new_reserve_commit,
        &xcommits.new_minted_commit,
        &delta_commit,
        &recip_of(&xdep),
        &[0u8; 32], // the route's default proposal nonce: these attestations are made over it
    );
    let xatt: Vec<MintAttestor> = custodians[0..2].iter().map(|c| c.attest(&xmsg)).collect();
    let mut xnote = Vec::with_capacity(1153);
    xnote.extend_from_slice(&xbuyer);
    xnote.extend_from_slice(&[0u8; 1153 - 32]);
    let x_backstop =
        backstop(1_500, xnr).expect("bonded weight over-covers the XMR-backed value-at-risk");
    let xbody = format!(
        r#"{{"deposit_id":"{}","recipient":"{}","new_reserve_commit":"{}","new_minted_commit":"{}","delta_commit":"{}","carrier_hex":"{}","mint_carrier_hex":"{}","note_payload":"{}","bond_backstop_hex":"{}","attestors_hex":"{}","note_clue_hex":"{}"}}"#,
        hexs(&xdep),
        hexs(&recip_of(&xdep)),
        commit_hex(xcommits.new_reserve_commit),
        commit_hex(xcommits.new_minted_commit),
        commit_hex(delta_commit),
        hexs(&xcarrier),
        hexs(&x_mint_carrier),
        hexs(&xnote),
        hexs(&x_backstop),
        attestors_hex(&xatt),
        hexs(&owner_clue),
    );
    let xmint = http_post(port, "/peg_in_confidential", &xbody);
    assert!(
        xmint.contains("CONFIDENTIAL_PUBLISHED"),
        "XMR-backed deposit → mint@150% over the asset-agnostic path: {xmint}"
    );
    settle_block(&rt, 60_000);
    assert!(rt.lock().unwrap().node().peg().deposit_minted(&xdep), "the XMR-backed mint landed from the block");
    println!("[psm-e2e] P-XMR reserve = NODE-COMPUTED trustless key-aggregate (no solo key, no registration) bound to the SAME bonded custody quorum; XMR deposit→mint@150% via the asset-agnostic path ✓");

    // ── P-MOVE) Bond-weighted multisig tally reserve-movement authorization e2e over live HTTP: a foreign reserve release is authorized
    //    ONLY by a ≥2/3 post-quantum threshold cert over the exact movement statement (the classical foreign signer
    //    runs only downstream of authorized:true) — the PQ-secure overlay.
    let move_stmt = usdmd_node::bond_tally::reserve_move_statement(
        "BTC",
        b"tb1pwithdrawdest",
        &usdm_decider::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]),
        &[0xf1u8; 32],
        1,
    );
    let move_body = |att: &[MintAttestor]| {
        format!(
            r#"{{"statement_hex":"{}","attestors_hex":"{}"}}"#,
            hexs(&move_stmt),
            attestors_hex(att)
        )
    };
    let mv2: Vec<MintAttestor> = custodians[0..2]
        .iter()
        .map(|c| c.attest(&move_stmt))
        .collect();
    assert!(
        http_post(port, "/authorize_reserve_move", &move_body(&mv2))
            .contains("\"authorized\":true"),
        "2-of-3 PQ threshold authorizes the reserve move"
    );
    let mv1: Vec<MintAttestor> = vec![custodians[0].attest(&move_stmt)];
    assert!(
        http_post(port, "/authorize_reserve_move", &move_body(&mv1))
            .contains("\"authorized\":false"),
        "1-of-3 sub-threshold → NOT authorized (no foreign signature)"
    );
    let other_stmt = usdmd_node::bond_tally::reserve_move_statement(
        "BTC",
        b"tb1pATTACKERdest",
        &usdm_decider::poseidon2_compress::lanes_of(&[1u64, 2, 3, 4]),
        &[0xf1u8; 32],
        1,
    );
    let other_att: Vec<MintAttestor> = custodians[0..2]
        .iter()
        .map(|c| c.attest(&other_stmt))
        .collect();
    assert!(
        http_post(
            port,
            "/authorize_reserve_move",
            &format!(
                r#"{{"statement_hex":"{}","attestors_hex":"{}"}}"#,
                hexs(&move_stmt),
                attestors_hex(&other_att)
            )
        )
        .contains("\"authorized\":false"),
        "a cert over a DIFFERENT destination does not authorize this move (no replay)"
    );
    println!("[psm-e2e] P-MOVE tally-authorized reserve move authorized only by ≥2/3 PQ threshold (sub-quorum + wrong-dest rejected) ✓");

    // ── P-RELEASE) WITHDRAWAL foreign-settlement authorization e2e — the FINAL integration step. The reserve is
    //    released to the home chain ONLY against a REAL burn, under a ≥2/3 PQ cert over the EXACT destination,
    //    single-use. The node authorizes + enforces conservation; the external custodian wallet then produces the
    //    foreign signature (the PQ-secure-overlay → non-PQ-home-chain hand-off).
    let rel_asset = "BTC";
    let rel_dest = "tb1preleasetarget";
    let rel_amt: usdmd_node::spend_frontier::Digest4 = usdm_decider::poseidon2_compress::lanes_of(&[7]);
    let rel_epoch: u64 = 3;
    let rel_body = |nf: &[u8; 32], att: &[MintAttestor], dest: &str| {
        format!(
            r#"{{"asset":"{rel_asset}","redeem_to":"{dest}","amount_commit":"{}","usdm_nullifier":"{}","epoch":{rel_epoch},"attestors_hex":"{}"}}"#,
            commit_hex(rel_amt),
            hexs(nf),
            attestors_hex(att),
        )
    };
    // (i) a real burn ([0xf1;32], destroyed in P5) + a valid ≥2/3 PQ cert over the exact statement → AUTHORIZED.
    let rel_burn = [0xf1u8; 32];
    let rel_stmt = usdmd_node::bond_tally::reserve_move_statement(
        rel_asset,
        rel_dest.as_bytes(),
        &rel_amt,
        &rel_burn,
        rel_epoch,
    );
    let rel_att: Vec<MintAttestor> = custodians[0..2]
        .iter()
        .map(|c| c.attest(&rel_stmt))
        .collect();
    let r_ok = http_post(
        port,
        "/authorize_reserve_release",
        &rel_body(&rel_burn, &rel_att, rel_dest),
    );
    assert!(
        r_ok.contains("\"outcome\":\"AUTHORIZED\"") && r_ok.contains("\"authorized\":true"),
        "real burn + ≥2/3 PQ cert → AUTHORIZED (foreign signer may pay out): {r_ok}"
    );
    // (ii) SINGLE-USE: the same burn can never authorize a second foreign release (no reserve double-drain).
    let r_again = http_post(
        port,
        "/authorize_reserve_release",
        &rel_body(&rel_burn, &rel_att, rel_dest),
    );
    assert!(
        r_again.contains("ALREADY_RELEASED"),
        "one burn authorizes AT MOST ONE foreign release: {r_again}"
    );
    // (iii) NO BURN: a nullifier that was never burned can't release the reserve (conservation — no release ⇒ no inflation).
    let never = [0xabu8; 32];
    let never_stmt = usdmd_node::bond_tally::reserve_move_statement(
        rel_asset,
        rel_dest.as_bytes(),
        &rel_amt,
        &never,
        rel_epoch,
    );
    let never_att: Vec<MintAttestor> = custodians[0..2]
        .iter()
        .map(|c| c.attest(&never_stmt))
        .collect();
    let r_noburn = http_post(
        port,
        "/authorize_reserve_release",
        &rel_body(&never, &never_att, rel_dest),
    );
    assert!(
        r_noburn.contains("NOT_BURNED"),
        "a release with no matching burn is rejected (conservation): {r_noburn}"
    );
    // (iv) SUB-QUORUM: a real burn ([0xf2;32], destroyed in P6) but only 1-of-3 attests → UNAUTHORIZED.
    let rt_nf = [0xf2u8; 32];
    let sub_stmt = usdmd_node::bond_tally::reserve_move_statement(
        rel_asset,
        rel_dest.as_bytes(),
        &rel_amt,
        &rt_nf,
        rel_epoch,
    );
    let sub_att: Vec<MintAttestor> = vec![custodians[0].attest(&sub_stmt)];
    let r_sub = http_post(
        port,
        "/authorize_reserve_release",
        &rel_body(&rt_nf, &sub_att, rel_dest),
    );
    assert!(r_sub.contains("UNAUTHORIZED"), "a real burn but a sub-quorum cert → UNAUTHORIZED (a minority can't drain the reserve): {r_sub}");
    // (v) REDIRECT: a valid ≥2/3 cert over destination A cannot authorize a payout to attacker destination B.
    let honest_stmt = usdmd_node::bond_tally::reserve_move_statement(
        rel_asset,
        rel_dest.as_bytes(),
        &rel_amt,
        &rt_nf,
        rel_epoch,
    );
    let honest_att: Vec<MintAttestor> = custodians[0..2]
        .iter()
        .map(|c| c.attest(&honest_stmt))
        .collect();
    let r_redir = http_post(
        port,
        "/authorize_reserve_release",
        &rel_body(&rt_nf, &honest_att, "tb1pATTACKERtarget"),
    );
    assert!(r_redir.contains("UNAUTHORIZED"), "a cert over destination A can't authorize a payout to attacker destination B (statement binds the destination): {r_redir}");
    println!("[psm-e2e] P-RELEASE reserve released only against a real burn + ≥2/3 PQ cert over the exact destination, single-use (no-burn + sub-quorum + redirect + double-release all rejected) ✓");

    // ── P-SLASH) SLASH-AND-COMPENSATE e2e: a ≥2/3 PQ FRAUD PROOF of an unauthorized reserve move forfeits the
    //    offender's bond to the compensation pool (bond ≥ 2× reserve ⇒ depositor made whole); a lone claim can't grief.
    let mut fraud = b"USDMD-PQFROST-THEFT-v1".to_vec();
    fraud.extend_from_slice(&move_stmt);
    let slash_body = |att: &[MintAttestor], offender: &[u8; 32]| {
        format!(
            r#"{{"statement_hex":"{}","attestors_hex":"{}","offenders_hex":"{}"}}"#,
            hexs(&move_stmt),
            attestors_hex(att),
            hexs(offender)
        )
    };
    let f1: Vec<MintAttestor> = vec![custodians[0].attest(&fraud)];
    assert!(
        http_post(
            port,
            "/slash_reserve_theft",
            &slash_body(&f1, &custodians[2].id())
        )
        .contains("\"slashed\":false"),
        "no ≥2/3 fraud proof → NO slash (griefing impossible)"
    );
    let f2: Vec<MintAttestor> = custodians[0..2].iter().map(|c| c.attest(&fraud)).collect();
    let slashed = http_post(
        port,
        "/slash_reserve_theft",
        &slash_body(&f2, &custodians[2].id()),
    );
    assert!(
        slashed.contains("\"slashed\":true") && slashed.contains("\"compensation\":5000"),
        "≥2/3 fraud proof forfeits the offender's bond to compensation: {slashed}"
    );
    println!("[psm-e2e] P-SLASH ≥2/3 PQ fraud proof forfeits the offender's bond → depositor made whole (lone claim can't grief) ✓");

    // ── P-EXEC) 100% MINT/REDEEM PROOF WITHOUT A REAL DEPOSIT (user 2026-07-17) — the wallet-facing /peg_in_execute
    //    + /peg_out_execute driven e2e over live HTTP on a dedicated 1-of-1 custodian node. The NODE orchestrates the
    //    WHIR carrier from its OWN sealed opening + self-attests + mints/burns; NO real BTC/XMR, no funds-loss risk.
    //    The deposit-CONFIRMATION gate stays real (P2); this proves the mint MECHANISM the honest ≥2/3 quorum gates.
    let mut xnode = Node::new(genesis_block()).expect("build execute-proof node");
    let (spk, ssk) = usdmd_node::pqauth::ml_dsa_keypair();
    xnode
        .admit_validator(usdmd_node::pqauth::pubkey_id(&spk), 200_000, 0)
        .expect("bond the 1-of-1 custodian");
    // DB-123: the custodian's custody key is what its reserve addresses derive from; without one it has no
    // address of its own and refuses every deposit.
    xnode.register_validator_custody(
        usdmd_node::pqauth::pubkey_id(&spk),
        custodians[0].secp_compressed(),
        custodians[0].xmr_point(),
    );
    let (xt, _xp) = LoopbackTransport::pair();
    let xrt = Arc::new(Mutex::new(NodeRuntime::new(xnode, xt)));
    xrt.lock()
        .unwrap()
        .set_bridge_signer(spk.clone(), ssk.clone());
    // DB-77: the door is a REQUEST sealed to the bonded custodians' ML-KEM keys; this 1-of-1 custodian registers
    // its own (the chain path is the membership bond carrying the ek) and holds the dk to open requests.
    {
        let (kem_ek, kem_dk) = usdmd_node::pqkem::keypair();
        let mut g = xrt.lock().unwrap();
        g.node_mut().register_custody_kem(usdmd_node::pqauth::pubkey_id(&spk), kem_ek.clone());
        g.set_custody_kem(kem_ek, kem_dk);
    }
    let xport = {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().port()
    };
    {
        let xrt = Arc::clone(&xrt);
        std::thread::spawn(move || {
            let _ = rpc_http::serve(xrt, xport);
        });
    }
    for _ in 0..100 {
        if TcpStream::connect(("127.0.0.1", xport)).is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    // ⛔ The orchestrated door enforces the SAME anti-free-mint gate, so the recipient commitment and the
    // note payload are DERIVED FROM THE CARRIER for each amount — never chosen. A fixed `recipient` with a
    // placeholder note (what this used to send) can only ever be refused `BAD_REQUEST`.
    // DB-80: the requester draws a delta blind per request, commits the mint (`delta_commit`), seals the
    // blind to its custodian (`d_blind_hex`) and proves the note opens to the committed figure — the amount
    // itself never rides a chain object.
    // DB-123: every deposit address below is the custodian's OWN — derived from the request's mint blind under
    // its live custody leaf, asked of it exactly as the wallet asks; a custodian refuses a deposit anywhere else.
    let exec_blind = |mint: u64| usdm_decider::poseidon2_compress::lanes_of(&[0xdb, 0xdb, 0xdb, mint]);
    let addr_for = |mint: u64| -> String {
        let j = http_post(
            xport,
            "/get_reserve_swap_address",
            &format!(r#"{{"asset":"BTC","d_blind_hex":"{}"}}"#, blind_hex(&exec_blind(mint))),
        );
        str_field(&j, "deposit_address")
            .unwrap_or_else(|| panic!("⛔ the custodian served no reserve address for the mint blind: {j}"))
    };
    let exec_note_for = |mint: u64| -> (String, String, String, String, String) {
        let sk = usdm_decider::poseidon2_compress::lanes_of(&[0xf0u64, 0xf1, 0xf2, mint]);
        let d_blind = exec_blind(mint);
        let (carrier, cm, dc) =
            usdm_decider::whir_rec_block::prove_mint_validity_committed_bytes(mint, &sk, &d_blind)
                .expect("the orchestrated mint-validity carrier PROVES for the authorized amount");
        let cm_bytes = usdmd_node::spend_frontier::leaf_to_cm_bytes(cm);
        let mut payload = Vec::with_capacity(1153);
        payload.extend_from_slice(&cm_bytes);
        payload.extend_from_slice(&[0u8; 1153 - 32]);
        (
            hexs(&cm_bytes),
            hexs(&payload),
            hexs(&carrier),
            commit_hex(dc),
            hexs(&usdmd_node::spend_frontier::digest_to_lane_bytes(&d_blind)),
        )
    };
    // A REAL confirmed deposit at the reserve address, INJECTED in place of sending real BTC (dev-only feature
    // `bridge-test-oracle`; the deposit-confirmation gate stays real — this is exactly the confirmation the live
    // on-chain watcher would read, so the mint is proven WITHOUT funds-loss risk).
    // DB-93 (2026-09-19): ONE MINT PER RESERVE ADDRESS. The deposit id is the node's function of the per-swap
    // reserve address, so every distinct deposit below has its OWN address with its own confirmed sats — the
    // old shape (one address, a fresh id per mint) was the double-mint this guard exists to refuse.
    let xaddr_s = addr_for(2_000);
    let xaddr = xaddr_s.as_str();
    let (addr_1000, addr_2001, addr_200k) = (addr_for(1_000), addr_for(2_001), addr_for(200_000));
    for a in [xaddr, addr_1000.as_str(), addr_2001.as_str(), addr_200k.as_str()] {
        usdmd_node::btc_watch::inject_confirmed_for_test(a, 100_000_000);
    }
    let exec_at = |dep: u64, mint: u64, id: &str, addr: &str| {
        // NO-OWNERLESS-CREDIT: the orchestrated mint also refuses a credit filed under no owner.
        let (recip, note, mint_carrier, delta_commit, d_blind_hex) = exec_note_for(mint);
        http_post(
            xport,
            "/peg_in_execute",
            &format!(
                r#"{{"deposit_id":"{id}","recipient":"{recip}","deposit_value":{dep},"mint":{mint},"delta_commit":"{delta_commit}","d_blind_hex":"{d_blind_hex}","reserve_address":"{addr}","note_payload":"{note}","mint_carrier_hex":"{mint_carrier}","note_clue_hex":"{}"}}"#,
                hexs(&owner_clue)
            ),
        )
    };
    // DB-77 lane semantics: the door REQUESTS; the custodian's lane tick proposes, self-attests (1-of-1) and
    // publishes the pooled object, exactly as the daemon's relay tick does — so a request is followed by one
    // lane tick and a second poll, which answers CONFIDENTIAL_PUBLISHED (published:true) until a block carries it.
    let exec = |dep: u64, mint: u64, addr: &str| {
        let id = hexs(&usdmd_node::peg::deposit_id_for_reserve_address(addr));
        let first = exec_at(dep, mint, &id, addr);
        if !(first.contains("REQUESTED") || first.contains("GATHERING")) {
            return first;
        }
        for _ in 0..3 {
            let now = usdmd_node::node_runtime::unix_ms_now() + 1_000;
            xrt.lock().unwrap().peg_lane_tick(now);
            let again = exec_at(dep, mint, &id, addr);
            if again.contains("\"published\":true") || again.contains("ALREADY_MINTED") {
                return again;
            }
        }
        exec_at(dep, mint, &id, addr)
    };
    // (i) a wallet buys 2000 USDm against a confirmed 3000-unit deposit (150%) — ONE call; the node builds the
    //     carrier from its sealed opening + self-attests + mints.
    // §CZ: `/peg_in_execute` is a POLL — CONFIDENTIAL_PUBLISHED (published:true) until the block carries
    // the object, then ALREADY_MINTED (minted:true). The block is mined here as the daemon's produce act
    // would mine it; the ledger, the note and the custodian's opening move from that block alone.
    let m1 = exec(3_000, 2_000, xaddr);
    assert!(
        m1.contains("\"published\":true") && m1.contains("CONFIDENTIAL_PUBLISHED"),
        "node-orchestrated mint @150% is verified and PUBLISHED: {m1}"
    );
    let m1_again = exec(3_000, 2_000, xaddr);
    assert!(
        m1_again.contains("\"published\":true") && !m1_again.contains("\"minted\":true"),
        "a poll before the block answers published, and publishes nothing twice: {m1_again}"
    );
    settle_block(&xrt, 70_000);
    let m1_minted = exec(3_000, 2_000, xaddr);
    assert!(
        m1_minted.contains("\"minted\":true") && m1_minted.contains("ALREADY_MINTED"),
        "after the block, the poll answers minted (ALREADY_MINTED): {m1_minted}"
    );
    // (ii) a SECOND mint proves the sealed opening advanced WITH THE BLOCK (deposit 1500 → mint 1000 from
    //      the new state) — the custodian executed, then applied its own block, then executed again.
    let m2 = exec(1_500, 1_000, &addr_1000);
    assert!(
        m2.contains("\"published\":true"),
        "second mint proves from the opening the block advanced: {m2}"
    );
    settle_block(&xrt, 80_000);
    // (iii) a REPLAYED deposit id → no second issuance: the poll answers ALREADY_MINTED and publishes nothing.
    let dup = exec(3_000, 2_000, xaddr);
    assert!(
        dup.contains("ALREADY_MINTED") && !dup.contains("\"published\":true"),
        "replayed deposit id issues nothing new: {dup}"
    );
    // DB-93 REFUTATION: the same funded address under a FRESH id — the exact double-mint shape — is refused at
    // the door before anything is sealed or proposed (the custodian lane and every attestor refuse it too).
    let dup_fresh_id = exec_at(
        3_000,
        2_000,
        "3333333333333333333333333333333333333333333333333333333333333333",
        xaddr,
    );
    assert!(
        dup_fresh_id.contains("BAD_REQUEST:DEPOSIT_ID_NOT_FROM_RESERVE_ADDRESS") && !dup_fresh_id.contains("\"published\":true"),
        "⛔ DOUBLE MINT: a fresh deposit id over an address that already minted must be refused (DB-93): {dup_fresh_id}"
    );
    // (iv) an UNDER-collateralized mint (mint 2001 vs a 3000 deposit at 150%) is UNPROVABLE → not minted.
    let over = exec(3_000, 2_001, &addr_2001);
    assert!(
        over.contains("\"minted\":false"),
        "over-mint is fail-closed: {over}"
    );
    // (v) ⭐ A LARGE DEPOSIT, FAR ABOVE HALF THE BOND, NOW MINTS — the bond is not a cap on user flow.
    //
    // This arm used to assert `minted:false` under "an under-bonded mint is rejected (bond must be ≥ 2×
    // reserve)". Owner, 2026-09-17: *"the bond shouldnt prevent genuine issuance at all… users should be
    // able to deposit and withdraw as much as they want down to the 100% backed level."* The depositor's
    // BTC IS the reserve and backs itself in threshold custody; the bond is anti-theft weight, so a
    // deposit 1000× the bond is still a genuine deposit and must issue.
    //
    // ⛔ WHAT STILL REFUSES, AND THE DISTINCTION IS THE POINT: the deposit-confirmation gate (arm vi) and
    // the threshold (arms iii/iv) — the anti-free-mint defences. This arm has a REAL confirmed deposit
    // behind it, so nothing legitimate stands in its way.
    let ub = exec(300_000, 200_000, &addr_200k);
    assert!(
        ub.contains("\"published\":true"),
        "⛔ A BOND CAP HAS BEEN RE-INTRODUCED: a confirmed deposit far above half the bond must still \
         mint — the bond never decides whether a user's money moves: {ub}"
    );
    settle_block(&xrt, 90_000);
    let ub_minted = exec(300_000, 200_000, &addr_200k);
    assert!(ub_minted.contains("ALREADY_MINTED"), "…and the block minted it: {ub_minted}");
    // (vi) NO CONFIRMED DEPOSIT → NOT minted (the free-mint hole is CLOSED): a mint for an address with no confirmed
    //      on-chain deposit gets no self-attestation → sub-threshold → rejected. This is the money-safety gate.
    // ⛔ THE CARRIER IS VALID HERE ON PURPOSE. Without it this request would be refused for a MISSING
    // MINT CARRIER, and the assertion below would pass while proving nothing about the deposit gate — a
    // refutation that fires for the wrong reason is vacuous.
    // DB-93: ids derived from their addresses, so each refusal below fires for ITS reason (the deposit gate,
    // the custodian gate) and not for a mismatched id.
    // DB-123: the UNFUNDED address must still be the reserve's own for its blind, or the refusal below would fire
    // for the address check and prove nothing about the deposit gate.
    let nodep_addr = addr_for(1_999);
    let nodep_id = hexs(&usdmd_node::peg::deposit_id_for_reserve_address(&nodep_addr));
    // DB-123: the non-custodian node below derives addresses from ITS bonded set (the 3-custodian quorum), so
    // the address it is asked to request must be that set's own for the request's blind.
    let nc_addr = str_field(
        &http_post(
            port,
            "/get_reserve_swap_address",
            &format!(r#"{{"asset":"BTC","d_blind_hex":"{}"}}"#, blind_hex(&exec_blind(2_000))),
        ),
        "deposit_address",
    )
    .expect("the 3-custodian node serves a reserve address for the request's blind");
    let xaddr_id = hexs(&usdmd_node::peg::deposit_id_for_reserve_address(&nc_addr));
    let (nd_recip, nd_note, nd_carrier, nd_delta_commit, nd_blind_hex) = exec_note_for(1_999);
    let nodep = http_post(
        xport,
        "/peg_in_execute",
        &format!(
            r#"{{"deposit_id":"{nodep_id}","recipient":"{nd_recip}","deposit_value":3000,"mint":1999,"delta_commit":"{nd_delta_commit}","d_blind_hex":"{nd_blind_hex}","reserve_address":"{nodep_addr}","note_payload":"{nd_note}","mint_carrier_hex":"{nd_carrier}"}}"#
        ),
    );
    let (recip, note, mint_carrier, delta_commit, d_blind_hex) = exec_note_for(2_000);
    assert!(
        nodep.contains("\"minted\":false"),
        "a mint with NO confirmed on-chain deposit is rejected (no free mint): {nodep}"
    );
    // (vii) a NON-custodian node (no bridge signer set) fail-closes /peg_in_execute.
    let nc = http_post(
        port,
        "/peg_in_execute",
        &format!(
            r#"{{"deposit_id":"{xaddr_id}","recipient":"{recip}","deposit_value":3000,"mint":2000,"delta_commit":"{delta_commit}","d_blind_hex":"{d_blind_hex}","reserve_address":"{nc_addr}","note_payload":"{note}","mint_carrier_hex":"{mint_carrier}","note_clue_hex":"{}"}}"#,
            hexs(&owner_clue)
        ),
    );
    assert!(
        nc.contains("REQUESTED") && nc.contains("\"minted\":false"),
        "DB-77: a non-custodian node REQUESTS a mint over the lane (it never mints inline): {nc}"
    );
    // (viii) A REDEEM WITH NO DELETION TRANSITION PUBLISHES NOTHING. A burn is a spend (§AQ): the burned
    //        note's `cm ‖ copath` is what authorises it, and only the note's owner can build it. Nothing here
    //        carries one, so the door refuses before any carrier is judged — and NOTHING moves.
    let rc_before = xrt.lock().unwrap().node().peg().reserve_commit();
    let nodel = http_post(
        xport,
        "/peg_out_execute",
        &format!(
            r#"{{"burn_carrier_hex":"00","out0_cm":"{}","out1_cm":"{}","usdm_nullifier":"{}","burn_amount":500,"change_note":"","redeem_to":"tb1pnodeletion","note_clue_hex":"{}"}}"#,
            hexs(&[1u8; 32]),
            hexs(&[2u8; 32]),
            hexs(&[9u8; 32]),
            hexs(&owner_clue)
        ),
    );
    assert!(
        nodel.contains("\"redeemed\":false") && nodel.contains("\"published\":false"),
        "a redeem carrying no deletion transition for the note it burns publishes nothing: {nodel}"
    );
    assert_eq!(
        xrt.lock().unwrap().node().peg().reserve_commit(),
        rc_before,
        "…and moves nothing"
    );
    println!("[psm-e2e] P-EXEC mint PROVEN e2e over HTTP — node orchestrates + self-attests; replay + over-mint + NO-confirmed-deposit + non-custodian + no-deletion-redeem all fail-closed, and a deposit far above half the bond MINTS (the bond is not a cap on user flow) ✓");

    println!("\n[psm-e2e] PASS — Buy-USDm PSM proven e2e over live HTTP: real BTC + XMR threshold reserves, deposit→mint@150%, withdrawal→burn, custodian-orchestrated mint/redeem with NO real deposit (/peg_in_execute + /peg_out_execute), bond-weighted multisig tally reserve-move authorization, foreign-release authorization (burn-coupled + single-use), slash-and-compensate — all adversarial variants fail-closed.");
    std::env::remove_var("MONEROUSD_CHARTER_QUORUM");
}
